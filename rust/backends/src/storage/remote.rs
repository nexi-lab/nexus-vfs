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
/// Thin wrapper around the shared [`super::mount_path::to_mount_path`]
/// helper.  Carries the Issue #4273 boundary rule
/// (mount-relative-vs-zone-rooted content id ambiguity, `/`-boundary
/// check, known self-prefix limitation) — see `mount_path.rs` for the
/// full rationale and the edge-case test suite.
fn to_server_path(zone_path: &str, backend_path: &str) -> String {
    super::mount_path::to_mount_path(zone_path, backend_path)
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

    // Issue #4273 boundary rule unit tests live in
    // `super::mount_path::tests` next to the helper itself — that
    // module is the SSOT for the rule and any future proxy backend
    // would reuse it.  One thin sanity test below proves
    // `to_server_path` (the wrapper) delegates with the right
    // `zone_path` argument; the rule's full edge cases live in the
    // shared module.

    #[test]
    fn to_server_path_delegates_with_zone_path_argument() {
        // Wrapper proves it threads `zone_path` through unchanged —
        // boundary-rule edge cases (escape, double-prefix, root-mount,
        // self-prefix limitation) are pinned in `mount_path::tests`.
        assert_eq!(
            to_server_path("/zone/acme", "file.txt"),
            "/zone/acme/file.txt"
        );
        assert_eq!(
            to_server_path("/zone/acme", "zone/acme/file.txt"),
            "/zone/acme/file.txt"
        );
    }
}
