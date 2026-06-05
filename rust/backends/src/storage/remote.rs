//! Remote ObjectStore — `ObjectStore` trait impl via tonic gRPC.
//!
//! Replaces Python `backends/storage/remote.py`. Content ops use typed
//! Read/Write/Delete RPCs (raw bytes, no base64). Directory ops and
//! stat fall back to the generic Call RPC.
//!
//! Issue #1134: Rust-first connector routing + REMOTE profile.
//! Issue #3786: read_content uses Call RPC (not native Read) so hub's
//!              Python dispatch builds a full zone_perms context.

use std::sync::Arc;

use kernel::abc::object_store::{ObjectStore, StorageError, WriteResult};
use kernel::rpc_transport::RpcTransport;

/// ObjectStore backed by a remote Nexus server via gRPC.
///
/// Server-side NexusFS is the SSOT — this backend is a thin proxy.
/// Path resolution: `backend_path` from kernel routing is mount-stripped
/// (e.g. for a mount at `/zone/shared`, the full path
/// `/zone/shared/file.txt` becomes `file.txt`).  The remote server
/// expects the original absolute path, so `to_server_path` re-prepends
/// the mount point.  For REMOTE-profile root mounts (`zone_path="/"`)
/// the backend_path is already the full path — no prefix is added.
pub struct RemoteBackend {
    transport: Arc<RpcTransport>,
    /// Mount point of this backend (e.g. "/zone/shared" or "/").
    /// Used to reconstruct the absolute path sent to the hub.
    /// Empty (or "/") means a root mount; the provider threads a
    /// non-root mount point via [`RemoteBackend::with_zone_path`]
    /// (Issue #4273, completing the Issue #3786 follow-up).
    zone_path: String,
}

impl RemoteBackend {
    pub fn new(transport: Arc<RpcTransport>) -> Self {
        Self {
            transport,
            zone_path: String::new(),
        }
    }

    pub fn with_zone_path(transport: Arc<RpcTransport>, zone_path: impl Into<String>) -> Self {
        Self {
            transport,
            zone_path: zone_path.into(),
        }
    }
}

/// Reconstruct the absolute server path from mount point + `backend_path`.
///
/// The `ObjectStore` API hands every method a single `backend_path`/`content_id`
/// slot that the kernel fills with one of two shapes, and (for sub-path mounts)
/// the backend is not told which:
///
///   * **Mount-relative route paths** — the VFS router strips the mount prefix,
///     so a file at `/zone/shared/file.txt` arrives as `file.txt`. Every op can
///     receive this: dir ops + `get_content_size` always do; `write_content`
///     does on a normal `sys_write`; `read_content` does on a metastore miss
///     (io.rs:228).
///   * **Server content IDs** — the hub's own zone-prefixed path id (e.g.
///     `zone/shared/file.txt`) that we persist verbatim. `read_content` gets it
///     on a metastore hit (io.rs:345); `write_content` gets it on the
///     federation read-repair cache-write (io.rs:455, `cache_key =
///     entry.content_id`). It is already absolute and must NOT be prefixed.
///
/// So this one rule serves both: prepend the mount point UNLESS `backend_path`
/// is already zone-prefixed on a path-component boundary (equals the mount or
/// starts with `"<mount>/"`). Root mounts (`zone_path` `""`/`"/"`) just ensure a
/// leading slash.
///
/// Issue #4273: the boundary check closes the security escape. The old code
/// used a bare `starts_with(zone_path)` with no separator, so a crafted sibling
/// `zone/acme2/file` under `/zone/acme` matched the `zone/acme` prefix and was
/// emitted as `/zone/acme2/file` — escaping to a sibling subtree. With the `/`
/// boundary, `zone/acme2/...` is treated as mount-relative and stays contained
/// at `/zone/acme/zone/acme2/...`.
///
/// KNOWN LIMITATION (kernel-API level): a route path that *literally re-uses*
/// the mount's own prefix — a real subdir at `/zone/acme/zone/acme/x`, route
/// `zone/acme/x` — is indistinguishable from the content id `zone/acme/x`, so it
/// is treated as already-absolute and maps to `/zone/acme/x`. This only ever
/// aliases WITHIN the mounted subtree (never a cross-tenant escape) and is
/// applied CONSISTENTLY across read/write/delete/rename (so a self-prefixed file
/// is read and deleted at the same place it was written). Fully resolving it
/// requires the kernel to signal route-vs-content-id to the backend (split the
/// `ObjectStore` API, or skip read-repair caching for path-addressed backends);
/// tracked as a #4273 follow-up. The normal (non-self-prefixed) case — every
/// real file — is exact.
fn to_server_path(zone_path: &str, backend_path: &str) -> String {
    let bp = if backend_path.is_empty() || backend_path == "/" {
        String::new()
    } else if backend_path.starts_with('/') {
        backend_path.to_string()
    } else {
        format!("/{backend_path}")
    };
    if zone_path.is_empty() || zone_path == "/" {
        if bp.is_empty() {
            "/".to_string()
        } else {
            bp
        }
    } else {
        let zp = zone_path.trim_matches('/'); // "zone/acme"
        let rel = bp.trim_start_matches('/'); // "zone/acme/file.txt" or "file.txt"
        if rel == zp || rel.starts_with(&format!("{zp}/")) {
            // Already zone-prefixed (a server content id) — absolute as-is.
            format!("/{rel}")
        } else {
            // Mount-relative route path — prepend the mount point.
            format!("/{zp}{bp}")
        }
    }
}

fn parse_write_result(path: &str, result: &serde_json::Value) -> Result<WriteResult, StorageError> {
    let content_id = result
        .get("content_id")
        .or_else(|| result.get("etag"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string();
    let size = result
        .get("size")
        .or_else(|| result.get("bytes_written"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            StorageError::IOError(std::io::Error::other(format!(
                "sys_write({path}): response missing size"
            )))
        })?;

    Ok(WriteResult {
        content_id: content_id.clone(),
        version: content_id,
        size,
    })
}

fn parse_stat_size_from_response(
    path: &str,
    response: &serde_json::Value,
) -> Result<u64, StorageError> {
    let result = response.get("result").unwrap_or(response);
    result
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| StorageError::NotFound(path.to_string()))
}

impl ObjectStore for RemoteBackend {
    fn name(&self) -> &str {
        "remote"
    }

    fn read_content(
        &self,
        content_id: &str,
        _ctx: &kernel::kernel::OperationContext,
    ) -> Result<Vec<u8>, StorageError> {
        let path = to_server_path(&self.zone_path, content_id);
        tracing::debug!(
            zone_path = %self.zone_path,
            server_path = %path,
            content_id = %content_id,
            "RemoteBackend::read_content → typed Read RPC"
        );

        // Typed Read carries the full OperationContext (incl. zone_perms)
        // because hub `resolve_context(token)` returns the same dict the
        // generic Call path used to build — the federation guards in the
        // typed handler were dropped once that became the SSOT.
        let result = self.transport.read(&path, "").map_err(|e| {
            tracing::warn!(path = %path, err = %e, "RemoteBackend::read_content transport error");
            StorageError::IOError(std::io::Error::other(e))
        })?;

        tracing::debug!(
            path = %path,
            bytes = result.content.len(),
            "RemoteBackend::read_content ok"
        );
        Ok(result.content)
    }

    fn write_content(
        &self,
        content: &[u8],
        content_id: &str,
        _ctx: &kernel::kernel::OperationContext,
        offset: u64,
    ) -> Result<WriteResult, StorageError> {
        // Partial writes are not supported by RemoteBackend.
        //
        // For offset == 0 the kernel passes route.backend_path as content_id,
        // so we can correctly map it to an absolute server path.  For
        // offset > 0 the kernel passes the OLD CAS etag as content_id — not
        // a path — which would be silently misrouted through to_server_path
        // and result in a full sys_write to "/zone/<mount>/<old-etag>"
        // (corrupting both the original file's metadata and creating an
        // orphan blob on the hub).  The trait does not yet thread
        // backend_path + offset together for path-addressed backends, so the
        // only correct behaviour is to reject the partial write.
        if offset != 0 {
            tracing::warn!(
                zone_path = %self.zone_path,
                content_id = %content_id,
                offset = offset,
                "RemoteBackend::write_content rejecting partial write \
                 (offset != 0 not supported — content_id is the old etag, not the path)"
            );
            return Err(StorageError::IOError(std::io::Error::other(
                "RemoteBackend does not support partial writes (offset != 0); \
                 use sys_write at offset=0 or read-modify-write at the caller",
            )));
        }
        let path = to_server_path(&self.zone_path, content_id);
        tracing::debug!(
            zone_path = %self.zone_path,
            content_id = %content_id,
            server_path = %path,
            bytes = content.len(),
            "RemoteBackend::write_content → Call RPC sys_write"
        );

        // Issue #3786: use Call RPC, not native Write RPC, so hub's Python
        // dispatch builds a full zone_perms context and can enforce read-only
        // zone restrictions (native Write bypasses Python enforcement).
        // Encode content as RPC codec bytes wrapper: {"__type__":"bytes","data":"<b64>"}
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(content);
        let payload = serde_json::json!({
            "path": path,
            "buf": { "__type__": "bytes", "data": b64 }
        });
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| StorageError::IOError(std::io::Error::other(e.to_string())))?;

        let (resp, is_error) = self.transport.call("sys_write", &bytes).map_err(|e| {
            tracing::warn!(path = %path, err = %e, "RemoteBackend::write_content transport error");
            StorageError::IOError(std::io::Error::other(e))
        })?;

        if is_error {
            let msg = String::from_utf8_lossy(&resp);
            tracing::warn!(
                path = %path,
                error = %msg,
                "RemoteBackend::write_content hub returned error"
            );
            return Err(StorageError::IOError(std::io::Error::other(format!(
                "sys_write({path}): {msg}"
            ))));
        }

        // Response envelope: {"result": {"bytes_written": N, "content_id": "...", "size": N, ...}}
        let value: serde_json::Value = serde_json::from_slice(&resp)
            .map_err(|e| StorageError::IOError(std::io::Error::other(e.to_string())))?;
        let result = value.get("result").ok_or_else(|| {
            StorageError::IOError(std::io::Error::other(format!(
                "sys_write({path}): no result key in response"
            )))
        })?;

        // Issue #4273: persist the hub's content id VERBATIM (zone-prefixed,
        // e.g. "zone/shared/file.txt"). The remote mount's `RemoteMetaStore`
        // writes this id straight back to the hub via `sys_setattr`, so it
        // must stay the hub's own server-relative id. Readback re-derives the
        // absolute path via `to_server_path`, whose boundary check recognises
        // the already-prefixed id and does not double-prefix it.
        let write_result = parse_write_result(&path, result)?;

        tracing::debug!(
            path = %path,
            content_id = %write_result.content_id,
            size = write_result.size,
            "RemoteBackend::write_content ok"
        );
        Ok(write_result)
    }

    fn delete_content(&self, _content_id: &str) -> Result<(), StorageError> {
        // Server handles content deletion via metastore delete (sys_unlink).
        // Content deletion by hash is not meaningful for remote backends.
        Ok(())
    }

    fn get_content_size(&self, content_id: &str) -> Result<u64, StorageError> {
        // Use sys_stat to get size.  For sub-path mounts (e.g. /zone/shared)
        // the kernel passes the mount-stripped backend_path as content_id, so
        // re-prepend zone_path to send the absolute path the hub expects.
        let path = to_server_path(&self.zone_path, content_id);
        let payload = serde_json::json!({ "path": path });
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| StorageError::IOError(std::io::Error::other(e.to_string())))?;
        let (resp, is_error) = self
            .transport
            .call("sys_stat", &bytes)
            .map_err(|e| StorageError::IOError(std::io::Error::other(e)))?;
        if is_error {
            return Err(StorageError::NotFound(content_id.to_string()));
        }
        let value: serde_json::Value = serde_json::from_slice(&resp)
            .map_err(|e| StorageError::IOError(std::io::Error::other(e.to_string())))?;
        parse_stat_size_from_response(content_id, &value)
    }

    fn mkdir(&self, path: &str, parents: bool, exist_ok: bool) -> Result<(), StorageError> {
        let server_path = to_server_path(&self.zone_path, path);
        let payload = serde_json::json!({
            "path": server_path,
            "parents": parents,
            "exist_ok": exist_ok,
        });
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| StorageError::IOError(std::io::Error::other(e.to_string())))?;
        let (_resp, is_error) = self
            .transport
            .call("mkdir", &bytes)
            .map_err(|e| StorageError::IOError(std::io::Error::other(e)))?;
        if is_error {
            return Err(StorageError::IOError(std::io::Error::other(format!(
                "mkdir failed: {server_path}"
            ))));
        }
        Ok(())
    }

    fn rmdir(&self, path: &str, recursive: bool) -> Result<(), StorageError> {
        let server_path = to_server_path(&self.zone_path, path);
        let payload = serde_json::json!({
            "path": server_path,
            "recursive": recursive,
        });
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| StorageError::IOError(std::io::Error::other(e.to_string())))?;
        let (_resp, is_error) = self
            .transport
            .call("sys_rmdir", &bytes)
            .map_err(|e| StorageError::IOError(std::io::Error::other(e)))?;
        if is_error {
            return Err(StorageError::IOError(std::io::Error::other(format!(
                "rmdir failed: {server_path}"
            ))));
        }
        Ok(())
    }

    fn delete_file(&self, path: &str) -> Result<(), StorageError> {
        // Same SSOT story as read_content: typed Delete hands the full
        // OperationContext (incl. zone_perms for federation tokens) to
        // KernelAbi::sys_unlink, so the read-only enforcement path the
        // legacy Issue #3786 comment cared about now fires identically
        // on the typed wire.
        let server_path = to_server_path(&self.zone_path, path);
        self.transport.delete(&server_path, false).map_err(|e| {
            tracing::warn!(path = %server_path, err = %e, "RemoteBackend::delete_file failed");
            StorageError::IOError(std::io::Error::other(e))
        })?;
        Ok(())
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<(), StorageError> {
        // Both endpoints of a rename are mount-stripped backend paths; remap
        // both to absolute server paths.  Cross-mount renames aren't
        // expressible through this trait — both paths share self.zone_path.
        let server_old = to_server_path(&self.zone_path, old_path);
        let server_new = to_server_path(&self.zone_path, new_path);
        let payload = serde_json::json!({
            "old_path": server_old,
            "new_path": server_new,
        });
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| StorageError::IOError(std::io::Error::other(e.to_string())))?;
        let (_resp, is_error) = self
            .transport
            .call("sys_rename", &bytes)
            .map_err(|e| StorageError::IOError(std::io::Error::other(e)))?;
        if is_error {
            return Err(StorageError::IOError(std::io::Error::other(format!(
                "rename failed: {server_old} -> {server_new}"
            ))));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_write_result_accepts_current_sys_write_content_id_shape() {
        let result = serde_json::json!({
            "content_id": "zone/shared/readback.txt",
            "size": 18
        });

        let parsed = parse_write_result("/zone/shared/readback.txt", &result).unwrap();

        assert_eq!(parsed.content_id, "zone/shared/readback.txt");
        assert_eq!(parsed.version, "zone/shared/readback.txt");
        assert_eq!(parsed.size, 18);
    }

    #[test]
    fn parse_stat_size_accepts_call_result_envelope() {
        let response = serde_json::json!({
            "result": {
                "path": "/zone/shared/existing.txt",
                "size": 42
            }
        });

        assert_eq!(
            parse_stat_size_from_response("/zone/shared/existing.txt", &response).unwrap(),
            42
        );
    }

    // ---- Issue #4273: sub-path mount path reconstruction ----

    #[test]
    fn to_server_path_root_mount_passes_through() {
        // Root mounts leave backend_path absolute (only ensure a leading slash).
        assert_eq!(to_server_path("", "file.txt"), "/file.txt");
        assert_eq!(to_server_path("/", "/zone/x/file.txt"), "/zone/x/file.txt");
        assert_eq!(to_server_path("", ""), "/");
    }

    #[test]
    fn to_server_path_subpath_prefixes_mount_relative_route() {
        // A mount-relative route path is prepended with the mount point.
        assert_eq!(
            to_server_path("/zone/acme", "file.txt"),
            "/zone/acme/file.txt"
        );
        assert_eq!(
            to_server_path("/zone/acme", "sub/dir/file.txt"),
            "/zone/acme/sub/dir/file.txt"
        );
        // Empty backend_path resolves to the mount root, not "/".
        assert_eq!(to_server_path("/zone/acme", ""), "/zone/acme");
    }

    #[test]
    fn to_server_path_subpath_contains_crafted_relative_path() {
        // A crafted relative path that shares a textual prefix with the mount
        // ("zone/acme" vs "zone/acme2") must NOT escape the mounted subtree.
        // It is treated as mount-relative and stays under "/zone/acme/".
        let out = to_server_path("/zone/acme", "zone/acme2/secret");
        assert!(
            out.starts_with("/zone/acme/"),
            "crafted path escaped the mount: {out}"
        );
        assert_eq!(out, "/zone/acme/zone/acme2/secret");
    }

    #[test]
    fn to_server_path_subpath_does_not_double_prefix_zone_content_id() {
        // The hub returns (and we persist verbatim) a zone-prefixed content id.
        // On readback it is already absolute and must NOT be prefixed again.
        assert_eq!(
            to_server_path("/zone/shared", "zone/shared/readback.txt"),
            "/zone/shared/readback.txt"
        );
        // A leading-slash content id is also recognised, not double-prefixed.
        assert_eq!(
            to_server_path("/zone/shared", "/zone/shared/sub/f.txt"),
            "/zone/shared/sub/f.txt"
        );
        // Exact-mount id maps to the mount root.
        assert_eq!(
            to_server_path("/zone/shared", "zone/shared"),
            "/zone/shared"
        );
    }

    #[test]
    fn subpath_content_id_round_trips_to_same_server_path() {
        // Invariant: write sends `server_path`; the hub echoes that path as a
        // (slash-stripped) content id which we persist VERBATIM; readback
        // `to_server_path(stored_id)` must land on the original `server_path`.
        let zone = "/zone/acme";
        for route in ["file.txt", "sub/dir/file.txt"] {
            let server_path = to_server_path(zone, route); // what write_content sends
            let stored = server_path.trim_start_matches('/').to_string(); // hub echo, stored as-is
            assert_eq!(
                to_server_path(zone, &stored),
                server_path,
                "round-trip mismatch for route {route}"
            );
        }
    }

    #[test]
    fn read_repair_content_id_is_not_double_prefixed() {
        // The federation read-repair cache-write (io.rs:455) hands write_content
        // a stored content id. It is already zone-prefixed, so it must map to
        // the same absolute path the hub wrote — NOT be doubled (which would
        // orphan/corrupt hub data). Same rule serves read_content's hit path.
        assert_eq!(
            to_server_path("/zone/acme", "zone/acme/file.txt"),
            "/zone/acme/file.txt"
        );
    }

    #[test]
    fn self_prefixed_route_aliases_consistently_known_limitation() {
        // KNOWN LIMITATION (kernel-API level): a route path that literally
        // re-uses the mount's own prefix is indistinguishable from a content id,
        // so it aliases to the collapsed path. This is applied CONSISTENTLY to
        // every op (read/write/delete/rename/stat all agree), so a self-prefixed
        // file is read and deleted at the same place it was written, and it never
        // escapes the mounted subtree. Pinning the behavior so a future
        // kernel-side fix (route-vs-content-id signal) updates it deliberately.
        let aliased = to_server_path("/zone/acme", "zone/acme/x");
        assert_eq!(aliased, "/zone/acme/x");
        assert!(
            aliased.starts_with("/zone/acme"),
            "must stay within the mount: {aliased}"
        );
    }
}
