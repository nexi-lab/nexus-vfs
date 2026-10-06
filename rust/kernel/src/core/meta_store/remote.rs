//! Remote MetaStore — `MetaStore` trait impl via tonic gRPC.
//!
//! Replaces Python `storage/remote_metastore.py`. Each method dispatches
//! a Call RPC to the remote server's VFS layer (sys_stat, sys_readdir,
//! sys_setattr, sys_unlink, access).
//!
//! Issue #1134: Rust-first connector routing + REMOTE profile.

use std::sync::Arc;

use dashmap::DashMap;

use crate::meta_store::{FileMetadata, MetaStore, MetaStoreError, PaginatedList};
use crate::rpc_transport::RpcTransport;

/// MetaStore backed by a remote Nexus server via gRPC Call RPC.
///
/// All metadata ops serialize to JSON, dispatch via `Call(method, payload)`,
/// and deserialize the response. Server-side NexusFS is the SSOT.
///
/// Internal cache (DashMap projection) accelerates repeated reads of
/// the same path — same shape as `LocalMetaStore` / `ZoneMetaStore`.
/// `get` consults the cache first; `put` is write-through; `delete`
/// invalidates pre-store-call.
pub struct RemoteMetaStore {
    transport: Arc<RpcTransport>,
    cache: DashMap<String, FileMetadata>,
}

impl RemoteMetaStore {
    pub fn new(transport: Arc<RpcTransport>) -> Self {
        Self {
            transport,
            cache: DashMap::new(),
        }
    }
}

fn unwrap_result_envelope(value: &serde_json::Value) -> &serde_json::Value {
    value.get("result").unwrap_or(value)
}

/// Interpret a `sys_unlink` Call response for `MetaStore::delete`.
///
/// Error envelopes are REAL failures and must surface as `Err` — the
/// old `Ok(!is_error)` collapsed them into "row absent", which let
/// fail-closed unmount callers (#4343) remove live routes while the
/// authoritative remote row persisted. Miss vs removed mirrors
/// `sys_unlink`'s `hit` field when present; an absent or malformed
/// body still acks the delete (`Ok(true)`).
fn interpret_unlink_response(
    path: &str,
    resp: &[u8],
    is_error: bool,
) -> Result<bool, MetaStoreError> {
    if is_error {
        return Err(MetaStoreError::IOError(format!(
            "sys_unlink failed for {path}"
        )));
    }
    let existed = serde_json::from_slice::<serde_json::Value>(resp)
        .ok()
        .map(|v| {
            unwrap_result_envelope(&v)
                .get("hit")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true)
        })
        .unwrap_or(true);
    Ok(existed)
}

impl MetaStore for RemoteMetaStore {
    fn get(&self, path: &str) -> Result<Option<FileMetadata>, MetaStoreError> {
        if let Some(cached) = self.cache.get(path) {
            return Ok(Some(cached.clone()));
        }
        let payload = serde_json::json!({ "path": path });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| MetaStoreError::IOError(e.to_string()))?;

        let (resp_bytes, is_error) = self
            .transport
            .call("sys_stat", &bytes)
            .map_err(MetaStoreError::IOError)?;

        if is_error {
            // Server reported error (path not found, etc.)
            return Ok(None);
        }

        let value: serde_json::Value = serde_json::from_slice(&resp_bytes)
            .map_err(|e| MetaStoreError::IOError(format!("decode sys_stat response: {e}")))?;

        let value = unwrap_result_envelope(&value);

        // Server returns None/null for missing paths
        if value.is_null() {
            return Ok(None);
        }

        let meta = parse_metadata_from_json(value)?;
        self.cache.insert(path.to_string(), meta.clone());
        Ok(Some(meta))
    }

    fn put(&self, path: &str, metadata: FileMetadata) -> Result<(), MetaStoreError> {
        // Use the kernel-syscall wire shape, not the old set_metadata handler
        // shape. The Python gRPC Call path routes `sys_setattr` through
        // `_kernel_syscall_dispatch`, which forwards flat kwargs into
        // NexusFS.sys_setattr.
        let payload = serde_json::json!({
            "path": path,
            "entry_type": metadata.entry_type,
            "size": metadata.size,
            "content_id": metadata.content_id,
            "gen": metadata.gen,
            "version": metadata.version,
            "zone_id": metadata.zone_id,
            "mime_type": metadata.mime_type,
            "last_writer_address": metadata.last_writer_address,
            "created_at_ms": metadata.created_at_ms,
            "modified_at_ms": metadata.modified_at_ms,
            "target_zone_id": metadata.target_zone_id,
            "link_target": metadata.link_target,
            "owner_id": metadata.owner_id,
        });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| MetaStoreError::IOError(e.to_string()))?;

        let (_resp, is_error) = self
            .transport
            .call("sys_setattr", &bytes)
            .map_err(MetaStoreError::IOError)?;

        if is_error {
            return Err(MetaStoreError::IOError(format!(
                "sys_setattr failed for {path}"
            )));
        }
        // Write-through: cache update after the remote ack so future
        // reads on this transport short-circuit the round trip.
        self.cache.insert(path.to_string(), metadata);
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<bool, MetaStoreError> {
        // Invalidate cache before the remote call (race-safe per the
        // LocalMetaStore reasoning).
        self.cache.remove(path);
        let payload = serde_json::json!({ "path": path });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| MetaStoreError::IOError(e.to_string()))?;

        let (resp, is_error) = self
            .transport
            .call("sys_unlink", &bytes)
            .map_err(MetaStoreError::IOError)?;

        interpret_unlink_response(path, &resp, is_error)
    }

    fn list(&self, prefix: &str) -> Result<Vec<FileMetadata>, MetaStoreError> {
        let payload = serde_json::json!({
            "path": prefix,
            "recursive": true,
        });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| MetaStoreError::IOError(e.to_string()))?;

        let (resp_bytes, is_error) = self
            .transport
            .call("sys_readdir", &bytes)
            .map_err(MetaStoreError::IOError)?;

        if is_error {
            return Ok(Vec::new());
        }

        let value: serde_json::Value = serde_json::from_slice(&resp_bytes)
            .map_err(|e| MetaStoreError::IOError(format!("decode sys_readdir: {e}")))?;

        let value = unwrap_result_envelope(&value);
        let files = value.get("files").unwrap_or(value);

        // Server returns an array of entries (path, entry_type pairs or full metadata)
        let entries = match files.as_array() {
            Some(arr) => arr
                .iter()
                .filter_map(|v| parse_metadata_from_json(v).ok())
                .collect(),
            None => Vec::new(),
        };

        Ok(entries)
    }

    fn exists(&self, path: &str) -> Result<bool, MetaStoreError> {
        let payload = serde_json::json!({ "path": path });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| MetaStoreError::IOError(e.to_string()))?;

        let (resp_bytes, is_error) = self
            .transport
            .call("access", &bytes)
            .map_err(MetaStoreError::IOError)?;

        if is_error {
            return Ok(false);
        }

        // Server returns a bool or a JSON object with an "exists" field
        let value: serde_json::Value = serde_json::from_slice(&resp_bytes)
            .map_err(|e| MetaStoreError::IOError(format!("decode access response: {e}")))?;
        let value = unwrap_result_envelope(&value);
        Ok(value.as_bool().unwrap_or_else(|| {
            value
                .get("exists")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        }))
    }

    fn is_implicit_directory(&self, path: &str) -> Result<bool, MetaStoreError> {
        let payload = serde_json::json!({ "path": path });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| MetaStoreError::IOError(e.to_string()))?;

        let (resp_bytes, is_error) = self
            .transport
            .call("is_directory", &bytes)
            .map_err(MetaStoreError::IOError)?;

        if is_error {
            return Ok(false);
        }

        let value: serde_json::Value = serde_json::from_slice(&resp_bytes)
            .map_err(|e| MetaStoreError::IOError(format!("decode is_directory response: {e}")))?;
        let value = unwrap_result_envelope(&value);
        Ok(value.as_bool().unwrap_or(false))
    }

    fn list_paginated(
        &self,
        prefix: &str,
        recursive: bool,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<PaginatedList, MetaStoreError> {
        let mut payload = serde_json::json!({
            "path": prefix,
            "recursive": recursive,
            "limit": limit,
        });
        if let Some(c) = cursor {
            payload["cursor"] = serde_json::Value::String(c.to_string());
        }
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| MetaStoreError::IOError(e.to_string()))?;

        let (resp_bytes, is_error) = self
            .transport
            .call("sys_readdir", &bytes)
            .map_err(MetaStoreError::IOError)?;

        if is_error {
            return Ok(PaginatedList::default());
        }

        let value: serde_json::Value = serde_json::from_slice(&resp_bytes)
            .map_err(|e| MetaStoreError::IOError(format!("decode paginated readdir: {e}")))?;
        let value = unwrap_result_envelope(&value);

        let items: Vec<FileMetadata> = value
            .get("items")
            .or_else(|| value.get("files"))
            .or(Some(value))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| parse_metadata_from_json(v).ok())
                    .collect()
            })
            .unwrap_or_default();

        let next_cursor = value
            .get("next_cursor")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let has_more = value
            .get("has_more")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let total_count = value
            .get("total_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(items.len() as u64) as usize;

        Ok(PaginatedList {
            items,
            next_cursor,
            has_more,
            total_count,
        })
    }
}

/// Parse FileMetadata from a JSON value (server sys_stat response).
/// Parse the `FileMetadata` a remote `sys_stat` answered with.
///
/// Derived, not hand-written: the JSON keys are `FileMetadata`'s field names,
/// so `serde` reads them directly and a field added to the struct arrives
/// without anyone editing this function. The ~50 lines of `obj.get("…")
/// .and_then(…)` this replaced were the third of the three hand-maintained
/// encodings in nexi-lab/nexus-vfs#371.
///
/// `#[serde(default)]` on the struct supplies a missing key, which is what the
/// old `unwrap_or` / `unwrap_or(0)` arms did — and it is load-bearing, not
/// tidiness: a `sys_stat` reply carrying only `{"size": N}` is a shape this
/// repo's own transport serves, and without `default` serde would reject it for
/// want of `path`.
///
/// Two deliberate differences from the hand-written version:
///
/// * `version` and `entry_type` are `u32`/`u8`. The old code read them as `u64`
///   and cast with `as`, so a malformed reply silently truncated; serde rejects
///   it. A metadata field out of its own range is a protocol error, not a value
///   to round down. Note the `readdir` callers drop unparseable entries via
///   `filter_map(….ok())`, so this trades a truncated field for a missing row —
///   both bad, and the second is at least not a plausible-looking lie.
/// * `target_subtree: ""` no longer maps to `None`. No server in this repo
///   emits that key at all (grep: nothing writes it as a JSON key), so the arm
///   guarded a case that does not arise; and now that `FileMetadata` also
///   derives `Serialize`, both ends agree exactly, `null` for absent. Should a
///   retired-Python peer still send `""`, every consumer already folds it to
///   "the whole zone" — `vfs_router::zone_relative_path` filters empty, and
///   `nexus_raft::zone_meta_store::subtree_or_whole_zone` maps it to `/`.
fn parse_metadata_from_json(value: &serde_json::Value) -> Result<FileMetadata, MetaStoreError> {
    serde_json::from_value(value.clone())
        .map_err(|e| MetaStoreError::IOError(format!("parse remote FileMetadata: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlink_response_error_envelope_is_err_not_miss() {
        // #4343: collapsing a remote error into Ok(false) ("row absent")
        // let unmount remove live routes while the remote row persisted.
        let r = interpret_unlink_response("/m", br#"{"error":"boom"}"#, true);
        assert!(r.is_err());
    }

    #[test]
    fn unlink_response_hit_false_is_clean_miss() {
        let r = interpret_unlink_response("/m", br#"{"hit":false}"#, false);
        assert!(!r.unwrap());
    }

    #[test]
    fn unlink_response_hit_true_and_bare_ack_are_removals() {
        assert!(interpret_unlink_response("/m", br#"{"hit":true}"#, false).unwrap());
        assert!(interpret_unlink_response("/m", b"", false).unwrap());
        assert!(!interpret_unlink_response("/m", br#"{"result":{"hit":false}}"#, false).unwrap());
    }

    #[test]
    fn parse_metadata_from_json_preserves_gen() {
        let meta = parse_metadata_from_json(&serde_json::json!({
            "path": "/remote.txt",
            "size": 5,
            "content_id": "hash",
            "gen": 23,
            "version": 2,
            "entry_type": 0,
        }))
        .unwrap();

        assert_eq!(meta.gen, 23);
        assert_eq!(meta.path, "/remote.txt");
        assert_eq!(meta.content_id.as_deref(), Some("hash"));
    }
}
