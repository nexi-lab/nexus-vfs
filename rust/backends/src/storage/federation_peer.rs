//! `FederationPeerBackend` — `ObjectStore` impl proxying every op to a
//! peer node over typed `NexusVFSService` gRPC.
//!
//! Installed by the kernel for every DT_MOUNT whose data lives on
//! another node (the federation "peer mount" case — the local node has
//! no LocalConnector / CAS / driver for the mount because the owning
//! node does).  Sister to [`RemoteBackend`](super::remote) — that one
//! speaks Call-RPC to a Python hub, this one speaks typed RPCs to a
//! peer Rust nexusd-cluster.  Wire forms differ enough that DRY-merging
//! them would be a net loss; they share the [`ObjectStore`] trait
//! surface and nothing below it.
//!
//! ## Address binding (late-bind)
//!
//! The peer address comes from the DT_MOUNT row's `last_writer_address`
//! at install time.  Federation discovery may not have resolved it when
//! the mount is first installed (zone join handshake races), so the
//! backend holds the address behind an `ArcSwapOption` and treats a
//! `None` slot as "peer address not yet known — refresh from the
//! resolver, error on miss".  The resolver hook can also be re-armed
//! when the SSOT-side voter changes (LWW re-write of the DT_MOUNT row).
//!
//! ## Why a single `FederationPeerClient` HAL trait
//!
//! Same DI pattern as `PeerBlobClient`: the kernel owns the slot and
//! the host binary installs a real impl at boot.  We do NOT name the
//! transport-tier `FederationClient` directly here — kernel layering
//! requires the contract to live at the kernel/HAL boundary, with
//! transport implementing it.  See
//! `kernel::hal::federation_peer::FederationPeerClient`.

use std::sync::Arc;

use kernel::abc::object_store::{BackendStat, ObjectStore, StorageError, WriteResult};
use kernel::hal::federation_peer::FederationPeerClient;
use parking_lot::RwLock;

/// ObjectStore backed by a remote peer's `NexusVFSService`.
///
/// `vfs_root` is the zone-canonical prefix the mount points into on the
/// peer (e.g. `/shared/cc-tasks/macos`).  The kernel hands every op a
/// mount-stripped `backend_path` (`file.txt`, `sub/x.json`, ...) which
/// this backend reassembles into the absolute peer path before issuing
/// the RPC — same reconstruction rule as `RemoteBackend::to_server_path`
/// (including the Issue #4273 `/`-boundary check that avoids
/// double-prefixing zone-prefixed content ids).
pub struct FederationPeerBackend {
    client: Arc<dyn FederationPeerClient>,
    /// Late-bound peer address (`host:port`).  `None` means the
    /// federation discovery handshake has not yet resolved it — the
    /// first RPC will surface a clear "peer address not yet known"
    /// error, and a follow-up `set_peer_addr` (from the address
    /// resolver) will populate the slot.  Cheap `RwLock` is fine —
    /// the read path is one short clone per RPC, the write path fires
    /// only on rare discovery events.
    peer_addr: RwLock<Option<String>>,
    /// Mount point on the peer (e.g. `/shared/cc-tasks/macos`).  Used by
    /// [`Self::to_peer_path`] to reconstruct the absolute peer path
    /// from the kernel's mount-stripped `backend_path`.
    vfs_root: String,
}

impl FederationPeerBackend {
    /// Build a federation-peer backend.  `vfs_root` is the mount-point
    /// path on the peer (`""` / `"/"` for root mounts).  `peer_addr` may
    /// be `None` if address resolution is pending — call
    /// [`Self::set_peer_addr`] once discovery completes.
    pub fn new(
        client: Arc<dyn FederationPeerClient>,
        peer_addr: Option<String>,
        vfs_root: impl Into<String>,
    ) -> Self {
        Self {
            client,
            peer_addr: RwLock::new(peer_addr),
            vfs_root: vfs_root.into(),
        }
    }

    /// Update the late-bound peer address.  Called by the kernel's
    /// address resolver when the DT_MOUNT row's `last_writer_address`
    /// is first discovered or LWW-updated.
    pub fn set_peer_addr(&self, addr: Option<String>) {
        *self.peer_addr.write() = addr;
    }

    #[inline]
    fn current_peer_addr(&self) -> Result<String, StorageError> {
        self.peer_addr.read().clone().ok_or_else(|| {
            StorageError::IOError(std::io::Error::other(
                "FederationPeerBackend: peer address not yet resolved (federation discovery pending)",
            ))
        })
    }

    /// Reassemble the absolute peer path from `vfs_root` + the
    /// mount-stripped `backend_path` the kernel hands us.  Delegates
    /// to the shared [`super::mount_path::to_mount_path`] helper —
    /// same rule the sibling [`RemoteBackend`](super::remote) applies
    /// against the Python hub (Issue #4273 boundary check).
    #[inline]
    fn to_peer_path(&self, backend_path: &str) -> String {
        super::mount_path::to_mount_path(&self.vfs_root, backend_path)
    }
}

fn map_err(op: &'static str, path: &str, err: String) -> StorageError {
    tracing::warn!(op = %op, path = %path, err = %err, "FederationPeerBackend RPC failed");
    StorageError::IOError(std::io::Error::other(err))
}

impl ObjectStore for FederationPeerBackend {
    fn name(&self) -> &str {
        "federation_peer"
    }

    fn read_content(
        &self,
        content_id: &str,
        _ctx: &kernel::kernel::OperationContext,
    ) -> Result<Vec<u8>, StorageError> {
        let addr = self.current_peer_addr()?;
        let path = self.to_peer_path(content_id);
        self.client
            .read(&addr, &path, 0)
            .map_err(|e| map_err("read", &path, e))
    }

    fn write_content(
        &self,
        content: &[u8],
        content_id: &str,
        _ctx: &kernel::kernel::OperationContext,
        offset: u64,
    ) -> Result<WriteResult, StorageError> {
        if offset != 0 {
            return Err(StorageError::IOError(std::io::Error::other(
                "FederationPeerBackend: partial writes not supported (offset != 0); \
                 caller must read-modify-write at offset=0",
            )));
        }
        let addr = self.current_peer_addr()?;
        let path = self.to_peer_path(content_id);
        self.client
            .write(&addr, &path, content)
            .map_err(|e| map_err("write", &path, e))
    }

    fn delete_content(&self, _content_id: &str) -> Result<(), StorageError> {
        // Content deletion by hash is not meaningful for a federation
        // peer — the peer's metastore manages content lifecycle via
        // sys_unlink (`delete_file` below).
        Ok(())
    }

    fn get_content_size(&self, content_id: &str) -> Result<u64, StorageError> {
        let addr = self.current_peer_addr()?;
        let path = self.to_peer_path(content_id);
        match self.client.stat(&addr, &path) {
            Ok(Some(s)) => Ok(s.size),
            Ok(None) => Err(StorageError::NotFound(path)),
            Err(e) => Err(map_err("get_content_size", &path, e)),
        }
    }

    fn mkdir(&self, path: &str, parents: bool, exist_ok: bool) -> Result<(), StorageError> {
        let addr = self.current_peer_addr()?;
        let peer_path = self.to_peer_path(path);
        self.client
            .mkdir(&addr, &peer_path, parents, exist_ok)
            .map_err(|e| map_err("mkdir", &peer_path, e))
    }

    fn rmdir(&self, path: &str, recursive: bool) -> Result<(), StorageError> {
        let addr = self.current_peer_addr()?;
        let peer_path = self.to_peer_path(path);
        self.client
            .rmdir(&addr, &peer_path, recursive)
            .map_err(|e| map_err("rmdir", &peer_path, e))
    }

    fn delete_file(&self, path: &str) -> Result<(), StorageError> {
        let addr = self.current_peer_addr()?;
        let peer_path = self.to_peer_path(path);
        self.client
            .delete_file(&addr, &peer_path)
            .map_err(|e| map_err("delete_file", &peer_path, e))
    }

    fn list_dir(&self, path: &str) -> Result<Vec<String>, StorageError> {
        let addr = self.current_peer_addr()?;
        let peer_path = self.to_peer_path(path);
        let entries = self
            .client
            .list_dir(&addr, &peer_path)
            .map_err(|e| map_err("list_dir", &peer_path, e))?;
        // DT_DIR = 4 (POSIX dirent.h).  Directories suffix `/` so callers
        // skip a follow-up stat — same convention as PathLocalBackend.
        const DT_DIR: u8 = 4;
        Ok(entries
            .into_iter()
            .map(|(name, et)| {
                if et == DT_DIR {
                    format!("{name}/")
                } else {
                    name
                }
            })
            .collect())
    }

    fn stat(&self, path: &str) -> Result<BackendStat, StorageError> {
        let addr = self.current_peer_addr()?;
        let peer_path = self.to_peer_path(path);
        match self.client.stat(&addr, &peer_path) {
            Ok(Some(s)) => Ok(s),
            Ok(None) => Err(StorageError::NotFound(peer_path)),
            Err(e) => Err(map_err("stat", &peer_path, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::sync::Arc as StdArc;

    /// Programmable stub — every method records its (addr, path) call
    /// and returns the canned reply.
    #[derive(Default)]
    struct StubClient {
        calls: Mutex<Vec<(String, String, String)>>, // (op, addr, path)
        read_reply: Mutex<Option<Vec<u8>>>,
        write_reply: Mutex<Option<WriteResult>>,
        stat_reply: Mutex<Option<Option<BackendStat>>>,
        list_dir_reply: Mutex<Option<Vec<(String, u8)>>>,
    }

    impl StubClient {
        fn record(&self, op: &str, addr: &str, path: &str) {
            self.calls
                .lock()
                .push((op.to_string(), addr.to_string(), path.to_string()));
        }
    }

    impl FederationPeerClient for StubClient {
        fn read(&self, addr: &str, path: &str, _offset: u64) -> Result<Vec<u8>, String> {
            self.record("read", addr, path);
            Ok(self.read_reply.lock().clone().unwrap_or_default())
        }
        fn write(&self, addr: &str, path: &str, _content: &[u8]) -> Result<WriteResult, String> {
            self.record("write", addr, path);
            Ok(self.write_reply.lock().take().unwrap_or(WriteResult {
                content_id: path.trim_start_matches('/').to_string(),
                version: path.trim_start_matches('/').to_string(),
                size: 0,
            }))
        }
        fn stat(&self, addr: &str, path: &str) -> Result<Option<BackendStat>, String> {
            self.record("stat", addr, path);
            Ok(self.stat_reply.lock().clone().unwrap_or(None))
        }
        fn list_dir(&self, addr: &str, path: &str) -> Result<Vec<(String, u8)>, String> {
            self.record("list_dir", addr, path);
            Ok(self.list_dir_reply.lock().clone().unwrap_or_default())
        }
        fn delete_file(&self, addr: &str, path: &str) -> Result<(), String> {
            self.record("delete_file", addr, path);
            Ok(())
        }
        fn rmdir(&self, addr: &str, path: &str, _recursive: bool) -> Result<(), String> {
            self.record("rmdir", addr, path);
            Ok(())
        }
        fn mkdir(
            &self,
            addr: &str,
            path: &str,
            _parents: bool,
            _exist_ok: bool,
        ) -> Result<(), String> {
            self.record("mkdir", addr, path);
            Ok(())
        }
    }

    fn ctx() -> kernel::kernel::OperationContext {
        kernel::kernel::OperationContext::new("", contracts::ROOT_ZONE_ID, true, None, true)
    }

    #[test]
    fn round_trips_every_method_with_resolved_address() {
        let stub = StdArc::new(StubClient::default());
        *stub.read_reply.lock() = Some(b"payload".to_vec());
        *stub.stat_reply.lock() = Some(Some(BackendStat {
            size: 42,
            is_dir: false,
        }));
        *stub.list_dir_reply.lock() = Some(vec![("a.json".to_string(), 8), ("sub".to_string(), 4)]);

        let backend = FederationPeerBackend::new(
            stub.clone(),
            Some("100.64.0.21:2126".to_string()),
            "/shared/cc-tasks/macos",
        );

        let ctx = ctx();
        // read
        let bytes = backend.read_content("session/1.json", &ctx).unwrap();
        assert_eq!(bytes, b"payload");

        // write — no offset
        let wr = backend
            .write_content(b"data", "session/2.json", &ctx, 0)
            .unwrap();
        assert_eq!(wr.size, 0); // stub default

        // stat
        let s = backend.stat("session/1.json").unwrap();
        assert_eq!(s.size, 42);
        assert!(!s.is_dir);

        // list_dir — DT_DIR (4) entries get the `/` suffix
        let entries = backend.list_dir("session").unwrap();
        assert_eq!(entries, vec!["a.json".to_string(), "sub/".to_string()]);

        // delete_file, mkdir, rmdir
        backend.delete_file("session/old.json").unwrap();
        backend.mkdir("session/new", true, true).unwrap();
        backend.rmdir("session/dead", true).unwrap();

        // Every RPC went to the resolved address with the reassembled path.
        let calls = stub.calls.lock().clone();
        for (_op, addr, path) in &calls {
            assert_eq!(addr, "100.64.0.21:2126", "wrong peer addr in {:?}", calls);
            assert!(
                path.starts_with("/shared/cc-tasks/macos/"),
                "path not under vfs_root: {path}"
            );
        }
        assert_eq!(calls.len(), 7);
    }

    #[test]
    fn errors_clearly_when_address_unresolved() {
        let stub = StdArc::new(StubClient::default());
        let backend = FederationPeerBackend::new(stub, None, "/shared/cc-tasks/macos");
        let err = backend.read_content("any", &ctx()).unwrap_err();
        match err {
            StorageError::IOError(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("peer address not yet resolved"),
                    "wrong err: {msg}"
                );
            }
            other => panic!("expected IOError, got {other:?}"),
        }
    }

    #[test]
    fn late_bind_address_via_set_peer_addr() {
        let stub = StdArc::new(StubClient::default());
        let backend = FederationPeerBackend::new(stub.clone(), None, "/shared/cc-tasks/macos");
        backend.set_peer_addr(Some("peer:2126".to_string()));
        backend.delete_file("orphan.json").unwrap();
        assert_eq!(stub.calls.lock()[0].1, "peer:2126");
    }

    #[test]
    fn rejects_partial_write_with_nonzero_offset() {
        let stub = StdArc::new(StubClient::default());
        let backend = FederationPeerBackend::new(
            stub,
            Some("peer:2126".to_string()),
            "/shared/cc-tasks/macos",
        );
        let err = match backend.write_content(b"x", "p.txt", &ctx(), 7) {
            Err(e) => e,
            Ok(_) => panic!("write_content with offset != 0 should error"),
        };
        match err {
            StorageError::IOError(e) => {
                assert!(format!("{e}").contains("partial writes not supported"));
            }
            other => panic!("expected IOError, got {other:?}"),
        }
    }

    #[test]
    fn to_peer_path_does_not_double_prefix_zone_rooted_content_id() {
        // Mirrors RemoteBackend::to_server_path's #4273 boundary check.
        let stub = StdArc::new(StubClient::default());
        let backend = FederationPeerBackend::new(
            stub,
            Some("peer:2126".to_string()),
            "/shared/cc-tasks/macos",
        );
        // Mount-relative → prefixed.
        assert_eq!(
            backend.to_peer_path("session/1.json"),
            "/shared/cc-tasks/macos/session/1.json"
        );
        // Already zone-rooted → not double-prefixed.
        assert_eq!(
            backend.to_peer_path("shared/cc-tasks/macos/session/1.json"),
            "/shared/cc-tasks/macos/session/1.json"
        );
        // Crafted sibling prefix — stays contained.
        let crafted = backend.to_peer_path("shared/cc-tasks/macos2/secret");
        assert!(
            crafted.starts_with("/shared/cc-tasks/macos/"),
            "escape: {crafted}"
        );
    }

    #[test]
    fn stat_none_maps_to_not_found() {
        let stub = StdArc::new(StubClient::default());
        *stub.stat_reply.lock() = Some(None);
        let backend = FederationPeerBackend::new(
            stub,
            Some("peer:2126".to_string()),
            "/shared/cc-tasks/macos",
        );
        match backend.stat("missing").unwrap_err() {
            StorageError::NotFound(p) => {
                assert_eq!(p, "/shared/cc-tasks/macos/missing");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}
