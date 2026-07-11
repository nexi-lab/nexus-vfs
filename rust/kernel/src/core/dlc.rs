//! DriverLifecycleCoordinator — kernel-internal mount lifecycle primitive.
//!
//! Linux analogue: `register_filesystem()` + `kern_mount()` + `kill_sb()`.
//!
//! Pure kernel internal — zero `#[pymethods]`. Python callers go through
//! `Kernel::sys_setattr(DT_MOUNT)` (codegen ABI). Rust callers (factory,
//! zone_manager) will call DLC directly when Rust-ified.
//!
//! Responsibilities:
//!   1. Add/remove backend in kernel VFSRouter via `Kernel::add_mount`
//!   2. Write DT_MOUNT metadata to per-mount metastore
//!   3. Populate dcache with mount point entry
//!   4. Upgrade LockManager to distributed for root zone federation mounts
//!
//! DLC owns no mount table of its own — `VFSRouter::entries` is the SSOT
//! for "what mounts exist".  Querying mount existence goes through
//! `Kernel::has_mount` (which delegates to the router); listing mount
//! points goes through `Kernel::get_mount_points`.

use crate::core::metadata_sync::MetadataSyncHandle;
use crate::kernel::{Kernel, KernelError};
use std::collections::HashMap;
use std::sync::Arc;

/// Kernel primitive: driver mount lifecycle.
///
/// `mount()` / `unmount()` thread mutations into the kernel's owned
/// tables (`VFSRouter`, per-mount metastore).  The one piece of state it
/// owns is the set of live [`MetadataSyncHandle`]s for mounts that opted
/// into kernel-side metadata sync (see [`crate::core::metadata_sync`]) —
/// each handle's Drop stops the reconcile thread, so keying them by
/// canonical mount point and dropping on `unmount()` ties the reconcile
/// lifetime to the mount.  Created once at `Kernel::new()`.
pub(crate) struct DriverLifecycleCoordinator {
    sync_handles: parking_lot::Mutex<HashMap<String, MetadataSyncHandle>>,
}

impl DriverLifecycleCoordinator {
    pub fn new() -> Self {
        Self {
            sync_handles: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Store the [`MetadataSyncHandle`] for a mount, keyed by canonical
    /// mount point.  Called by `Kernel::arm_metadata_sync` after it spawns
    /// the reconcile.  Replacing an existing entry drops the old handle
    /// (stopping its thread) — re-arming a mount is idempotent.
    pub(crate) fn store_sync_handle(
        &self,
        mount_point: &str,
        zone_id: &str,
        handle: MetadataSyncHandle,
    ) {
        let key = Kernel::canonical_mount_key(mount_point, zone_id);
        self.sync_handles.lock().insert(key, handle);
    }

    /// Whether the mount identified by `canonical_mount_key` has metadata
    /// sync armed.
    ///
    /// `sys_readdir` gates its synchronous on-access seeding (the third
    /// trigger of [`crate::core::metadata_sync`], alongside the initial
    /// walk and the periodic reconcile) on this, so only opted-in mounts —
    /// backends that receive content out-of-band — pay the seed cost; every
    /// other readdir skips it entirely (no stat, no propose).
    ///
    /// Takes the already-canonical key (`RouteResult.mount_point`)
    /// directly. Callers MUST NOT re-run [`Kernel::canonical_mount_key`] on
    /// it — canonicalization is not idempotent (it would prepend the zone a
    /// second time), and the handle map is keyed on exactly this form.
    pub(crate) fn is_sync_armed(&self, canonical_mount_key: &str) -> bool {
        self.sync_handles.lock().contains_key(canonical_mount_key)
    }

    /// Drop the [`MetadataSyncHandle`] for a mount (if armed), stopping
    /// its reconcile thread.  Idempotent.
    fn disarm_sync(&self, mount_point: &str, zone_id: &str) {
        let key = Kernel::canonical_mount_key(mount_point, zone_id);
        if self.sync_handles.lock().remove(&key).is_some() {
            tracing::debug!(
                target: "kernel::dlc",
                mount = mount_point,
                "metadata sync disarmed on unmount",
            );
        }
    }

    /// Mount a backend with full lifecycle: routing + metastore + lock.
    ///
    /// # Arguments
    /// - `kernel` — back-reference to the owning Kernel (interior mutability)
    /// - `mount_point` — virtual path (e.g. `/`, `/data`)
    /// - `zone_id` — zone identifier
    /// - `backend` — optional Rust backend (None = Python-side backend)
    /// - `metastore` — optional per-mount metastore (ZoneMetaStore or LocalMetaStore)
    /// - `raft_backend` — opaque raft handle for federation DI; downcast by
    ///   the `RaftDistributedCoordinator` impl when wiring distributed locks.
    #[allow(clippy::too_many_arguments)]
    pub fn mount(
        &self,
        kernel: &Kernel,
        mount_point: &str,
        zone_id: &str,
        backend: Option<Arc<dyn crate::abc::object_store::ObjectStore>>,
        metastore: Option<Arc<dyn crate::meta_store::MetaStore>>,
        raft_backend: Option<Box<dyn std::any::Any + Send + Sync>>,
        is_external: bool,
    ) -> Result<(), KernelError> {
        // Resolve the PARENT zone's metastore via longest-prefix routing
        // (e.g. `/corp` resolves up to the `/` root-zone mount) and write
        // the DT_MOUNT entry there.  This is the SSOT for federation
        // routing: the parent zone's raft state machine replicates the
        // entry to every peer, and federation's `mount_apply_cb` wired
        // on the parent zone fires on each follower's apply, calling
        // `wire_mount_core` so cross-zone routing lands on every node.
        //
        // `with_metastore(mount_point)` does an exact-match lookup, so
        // it would NOT find the right (parent) zone — use `route()`'s
        // longest-prefix walk to find the enclosing mount, then write
        // through that mount's metastore with the full path as the key.
        // Symmetric with `unmount()`: looking up `mount_point` itself
        // routes through an EXISTING mount at that exact path (the
        // remount/rebind case) and would persist the DT_MOUNT row into
        // the child's own store instead of the parent's — after a
        // restart the parent store would replay a stale or missing
        // entry. Walk up to the parent path first so longest-prefix
        // routing skips this mount and finds the actual parent.
        let parent_path = mount_point
            .rfind('/')
            .filter(|&i| i > 0)
            .map(|i| mount_point[..i].to_string())
            .unwrap_or_else(|| "/".to_string());
        let route = kernel.vfs_router_arc().route(&parent_path, "root");
        if route.is_none() && mount_point != "/" && !kernel.vfs_router_arc().is_empty() {
            // Fail closed (#4343): with EXISTING topology, a non-root
            // mount whose parent cannot be routed has nowhere to persist
            // its DT_MOUNT entry — installing it anyway would create a
            // route that silently vanishes on restart. An EMPTY router is
            // different: services bootstrap their subtree as the very
            // first mount on a bare kernel (e.g. the password vault
            // mounting /vault) — there is no parent zone to persist into
            // yet, exactly like the root bootstrap, so that shape is
            // allowed (pre-#4343 parity: no row is written).
            return Err(KernelError::IOError(format!(
                "no parent route for non-root mount {mount_point} with existing \
                 topology; mount the enclosing tree first so the DT_MOUNT entry \
                 can be persisted"
            )));
        }
        if let Some(parent_route) = route {
            // Cross-zone mounts are federation topology events: their
            // DT_MOUNT row should land in the parent zone's REPLICATED
            // metastore so raft replay and followers see it. If the
            // parent route carries no per-mount (zone) metastore, the
            // write below falls back to the node-local global store —
            // durable on THIS node, invisible to the cluster. This is
            // the documented `--mount-driver` boot shape today (the
            // cluster profile mounts "/" backend-only before zone
            // wiring), so hard-failing here would break boots; warn
            // loudly instead. Proper fix — attaching the root
            // ZoneMetaStore to the root route during coordinator
            // install — is tracked with the boot-ordering work in
            // nexus-vfs#44. Same-zone mounts are fine by construction:
            // in single-node mode the global store IS that zone's store.
            if zone_id != parent_route.zone_id && parent_route.metastore.is_none() {
                tracing::warn!(
                    target: "kernel::dlc",
                    mount = mount_point,
                    zone = zone_id,
                    parent = %parent_route.mount_point,
                    "cross-zone DT_MOUNT row persisted to the node-local fallback \
                     store (parent has no replicated metastore) — local-only \
                     durability; raft replay/followers will not see it (#44)",
                );
            }
            // RouteResult.mount_point is already a canonical key (e.g. "/root").
            let persist = kernel.with_metastore(&parent_route.mount_point, |ms| {
                // Idempotency (raft usage contract): the DT_MOUNT row is
                // committed, replicated state. On resume it is already
                // applied to the local state machine (replayed from disk),
                // so re-proposing it is BOTH redundant AND requires a raft
                // leader — which, during a multi-node cold restart, is not
                // yet elected because the peer is still booting. Coupling a
                // fail-loud `propose` to boot is exactly the 2-voter
                // `not leader, leader hint: None` deadlock both nodes hit
                // when restarted together. `get` reads the applied state
                // machine locally (no `propose`, no leader), so when the
                // routing pointer already matches we skip the write and let
                // the resuming node wire its local backend from committed
                // state without blocking boot on consensus. Only a
                // genuinely-new or re-pointed mount proposes.
                if let Ok(Some(existing)) = ms.get(mount_point) {
                    if existing.entry_type == 2
                        && existing.target_zone_id.as_deref() == Some(zone_id)
                    {
                        return Ok(());
                    }
                }
                let meta = crate::meta_store::FileMetadata {
                    path: mount_point.to_string(),
                    size: 0,
                    content_id: None,
                    gen: 0,
                    version: 1,
                    entry_type: 2, // DT_MOUNT
                    zone_id: Some(parent_route.zone_id.clone()),
                    mime_type: None,
                    created_at_ms: None,
                    modified_at_ms: None,
                    last_writer_address: None,
                    // DT_MOUNT routing pointer: the zone this mount points at.
                    target_zone_id: Some(zone_id.to_string()),
                    // DT_LINK target: only meaningful for DT_LINK entries.
                    link_target: None,
                    owner_id: None,
                };
                ms.put(mount_point, meta)
            });
            match persist {
                Some(Ok(())) => {}
                Some(Err(e)) => {
                    // Fail closed (#4343): installing a route whose DT_MOUNT
                    // entry never persisted means the mount silently vanishes
                    // (or goes stale) after a restart, with no error at mount
                    // time. Callers already handle mount errors — add_mount
                    // below returns through the same channel.
                    tracing::error!(
                        target: "kernel::dlc",
                        mount = mount_point,
                        zone = zone_id,
                        "DT_MOUNT metadata write failed; refusing to install unpersisted mount: {e:?}",
                    );
                    return Err(KernelError::IOError(format!(
                        "DT_MOUNT metadata persist failed for {mount_point}: {e:?}"
                    )));
                }
                // `with_metastore` falls back to the kernel global metastore,
                // so None means no per-mount AND no global store (possible
                // only between release_metastores and re-wiring). Same fail-
                // closed rationale as the write-failure arm.
                None => {
                    return Err(KernelError::IOError(format!(
                        "no metastore available to persist DT_MOUNT entry for \
                         {mount_point} (parent mount {})",
                        parent_route.mount_point
                    )));
                }
            }
        }

        // Apply-side cache coherence is the metastore impl's
        // responsibility now — each ``ZoneMetaStore`` self-registers an
        // invalidator on its consensus during construction. DLC stays
        // federation-unaware.
        //
        kernel.add_mount(
            mount_point,
            zone_id,
            backend,
            metastore,
            raft_backend,
            is_external,
        )?;
        // Metadata sync (for out-of-band backends) is armed separately by
        // `Kernel::arm_metadata_sync` — it needs the owning `Arc<Kernel>`
        // for the reconcile thread's callback, which `DLC.mount` (holding
        // only `&Kernel`) doesn't have. The cluster boot path arms it for
        // the mounts that opt in, after this returns.
        Ok(())
    }

    /// Unmount with full lifecycle: metastore delete + routing remove.
    ///
    /// Returns `Ok(true)` when something was actually removed (durable
    /// row, live route, or both), `Ok(false)` when neither existed.
    ///
    /// Fail-closed semantics (#4343): the durable row is the
    /// authoritative state. When its delete FAILS, the live route is
    /// NOT removed and the error propagates — otherwise the unmount
    /// looks successful while the stale row resurrects the mount on the
    /// next restart/replay. A row WITHOUT a live route is, by contrast,
    /// a normal shape (post-restart rows exist before any replay wires
    /// routes back), so unlinking it succeeds row-only with a debug log
    /// rather than an error.
    pub fn unmount(
        &self,
        kernel: &Kernel,
        mount_point: &str,
        zone_id: &str,
    ) -> Result<bool, KernelError> {
        // 1. Delete the DT_MOUNT metadata from the PARENT zone (the one
        //    that "owns" `mount_point`).  Symmetric with `mount()`:
        //    federation's apply-cb on the parent zone fires
        //    `unwire_mount_core` on every peer when this raft-replicated
        //    DeleteMetadata applies, so cross-node routing cleanup
        //    propagates the same way it was set up.  Looking up via
        //    `mount_point` itself routes through the new mount (the one
        //    being unmounted) and lands in the wrong state machine.
        //    Walk up to the parent path first so longest-prefix routing
        //    skips this mount and finds the actual parent.
        let parent_path = mount_point
            .rfind('/')
            .filter(|&i| i > 0)
            .map(|i| mount_point[..i].to_string())
            .unwrap_or_else(|| "/".to_string());
        let route = kernel.vfs_router_arc().route(&parent_path, "root");
        let mut row_existed = false;
        if let Some(parent_route) = route {
            let deleted =
                kernel.with_metastore(&parent_route.mount_point, |ms| ms.delete(mount_point));
            match deleted {
                // Ok(false) = row already absent — idempotent, fine.
                Some(Ok(existed)) => row_existed = existed,
                Some(Err(e)) => {
                    tracing::error!(
                        target: "kernel::dlc",
                        mount = mount_point,
                        zone = zone_id,
                        "DT_MOUNT metadata delete failed; refusing to remove live route while the durable row persists: {e:?}",
                    );
                    return Err(KernelError::IOError(format!(
                        "DT_MOUNT metadata delete failed for {mount_point}: {e:?}"
                    )));
                }
                // No metastore anywhere (only possible between
                // release_metastores and re-wiring): there is no durable
                // row to go stale, so removing the route is safe.
                None => {}
            }
        }

        // 2. Stop the metadata-sync reconcile thread (if this mount had
        // one) before tearing down the route, so it can't propose against
        // a mount that's going away.
        self.disarm_sync(mount_point, zone_id);

        // 3. Remove from routing table — the per-mount metastore Arc
        // (with its internal cache) drops with the MountEntry. A row
        // without a live route is a normal post-restart shape (rows
        // survive; routes wait for replay), so this is observational,
        // not an error.
        let route_removed = kernel.remove_mount(mount_point, zone_id);
        if row_existed && !route_removed {
            tracing::debug!(
                target: "kernel::dlc",
                mount = mount_point,
                zone = zone_id,
                "DT_MOUNT row removed with no live route present (normal before replay wires routes back)",
            );
        }
        Ok(row_existed || route_removed)
    }

    /// Test-only: number of live metadata-sync handles.  Lets the wiring
    /// integration test assert arm / drop-on-unmount.
    #[cfg(test)]
    pub(crate) fn sync_handle_count(&self) -> usize {
        self.sync_handles.lock().len()
    }
}

#[cfg(test)]
mod metadata_sync_wiring_tests {
    //! Integration test for the metadata-sync mount wiring: a real
    //! `Arc<Kernel>` + real `DriverLifecycleCoordinator` + real
    //! `MetadataSink` + real metastore, driven through a **plain
    //! `ObjectStore`** (no trait extension — exactly like a dylib backend
    //! the kernel sees as an opaque `DylibObjectStore`). Exercises
    //! `Kernel::arm_metadata_sync` → route lookup → generic walk over
    //! `list_dir`/`stat` → sink (mount-prefix join) →
    //! `observe_backend_entry` → metastore.
    //!
    //! Real user problem: after a node mounts a peer-shared connector over
    //! a host dir that already holds tasks, those tasks MUST become
    //! visible in the metastore (so peers see them via raft-replicated
    //! `metastore.list`) without any read/readdir-time cold-discovery.

    use crate::abc::object_store::{BackendStat, ObjectStore, StorageError, WriteResult};
    use crate::kernel::{Kernel, OperationContext};
    use crate::meta_store::{DT_DIR, DT_REG};
    use std::sync::Arc;

    /// Plain ObjectStore exposing a fixed tree via `list_dir`/`stat` —
    /// no `as_observer`, no trait extension. Stands in for any backend
    /// (dylib or built-in) the generic walk runs over.
    struct TreeBackend;

    impl ObjectStore for TreeBackend {
        fn name(&self) -> &str {
            "tree-mock"
        }
        fn list_dir(&self, path: &str) -> Result<Vec<String>, StorageError> {
            match path {
                "" => Ok(vec!["a.json".to_string(), "sub/".to_string()]),
                "sub" => Ok(vec!["b.json".to_string()]),
                other => Err(StorageError::NotFound(other.to_string())),
            }
        }
        fn stat(&self, path: &str) -> Result<BackendStat, StorageError> {
            match path {
                "a.json" => Ok(BackendStat {
                    size: 5,
                    is_dir: false,
                }),
                "sub/b.json" => Ok(BackendStat {
                    size: 11,
                    is_dir: false,
                }),
                "sub" => Ok(BackendStat {
                    size: 0,
                    is_dir: true,
                }),
                other => Err(StorageError::NotFound(other.to_string())),
            }
        }
        fn write_content(
            &self,
            _c: &[u8],
            _id: &str,
            _ctx: &OperationContext,
            _o: u64,
        ) -> Result<WriteResult, StorageError> {
            Err(StorageError::NotSupported("write_content"))
        }
        fn read_content(
            &self,
            _id: &str,
            _ctx: &OperationContext,
        ) -> Result<Vec<u8>, StorageError> {
            Err(StorageError::NotSupported("read_content"))
        }
    }

    /// Full-workflow: mount a plain-ObjectStore connector whose host dir
    /// already holds `a.json` + `sub/` + `sub/b.json`, arm metadata sync,
    /// assert every entry became an authoritative metastore row (type,
    /// size, content_id, prefix-join) via the generic walk, then unmount
    /// and assert the reconcile handle was dropped.
    #[test]
    fn arm_metadata_sync_populates_metastore_then_unmount_disarms() {
        let kernel = Arc::new(Kernel::new());
        let backend: Arc<dyn ObjectStore> = Arc::new(TreeBackend);

        // Step 1: mount the connector at /tasks, then arm metadata sync
        // (the two-step the cluster boot path performs). Arming runs the
        // synchronous initial walk over list_dir/stat and proposes rows.
        kernel
            .dlc
            .mount(&kernel, "/tasks", "root", Some(backend), None, None, false)
            .expect("mount connector");
        kernel.arm_metadata_sync("/tasks", "root");
        assert_eq!(
            kernel.dlc.sync_handle_count(),
            1,
            "sync armed for the mount"
        );

        // Step 2: every backend entry is now an authoritative metastore
        // row under the mount prefix — what a peer's `metastore.list`
        // replicates and sees.
        let file = kernel
            .metastore_get("/tasks/a.json")
            .expect("metastore_get ok")
            .expect("a.json row proposed");
        assert_eq!(file.entry_type, DT_REG);
        assert_eq!(file.size, 5, "DT_REG size carried from backend stat");
        assert_eq!(
            file.content_id.as_deref(),
            Some("a.json"),
            "DT_REG content_id is the backend-relative path read_content resolves"
        );

        let dir = kernel
            .metastore_get("/tasks/sub")
            .expect("metastore_get ok")
            .expect("sub row proposed");
        assert_eq!(dir.entry_type, DT_DIR);
        assert_eq!(dir.content_id, None, "DT_DIR rows carry no content_id");

        let nested = kernel
            .metastore_get("/tasks/sub/b.json")
            .expect("metastore_get ok")
            .expect("nested sub/b.json row proposed");
        assert_eq!(nested.size, 11, "nested file size + prefix-joined path");

        // Step 3: unmount drops the MetadataSyncHandle (its Drop stops the
        // reconcile thread).
        kernel
            .dlc
            .unmount(&kernel, "/tasks", "root")
            .expect("unmount");
        assert_eq!(
            kernel.dlc.sync_handle_count(),
            0,
            "sync disarmed on unmount"
        );
    }

    /// A mount that is never armed proposes nothing — arming is a
    /// deliberate per-mount opt-in, off by default.
    #[test]
    fn mount_without_arm_proposes_nothing() {
        let kernel = Arc::new(Kernel::new());
        let backend: Arc<dyn ObjectStore> = Arc::new(TreeBackend);
        kernel
            .dlc
            .mount(&kernel, "/tasks", "root", Some(backend), None, None, false)
            .expect("mount");
        // Deliberately NOT calling arm_metadata_sync.
        assert_eq!(kernel.dlc.sync_handle_count(), 0, "no handle without arm");
        assert!(
            matches!(kernel.metastore_get("/tasks/a.json"), Ok(None)),
            "no row proposed when the mount is not armed"
        );
    }

    /// Flat ObjectStore whose listing can grow AFTER arm — models a
    /// LocalConnector receiving out-of-band writes while mounted. Lets the
    /// on-access seed be tested in isolation from the initial walk, which
    /// sees an empty backend at arm time and seeds nothing.
    struct MutableFlatBackend {
        files: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    }

    impl MutableFlatBackend {
        fn new() -> Self {
            Self {
                files: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
        /// Simulate an out-of-band write landing directly in the backend,
        /// bypassing `sys_write`.
        fn add(&self, name: &str, size: u64) {
            self.files.lock().unwrap().insert(name.to_string(), size);
        }
    }

    impl ObjectStore for MutableFlatBackend {
        fn name(&self) -> &str {
            "mutable-flat-mock"
        }
        fn list_dir(&self, path: &str) -> Result<Vec<String>, StorageError> {
            if path.is_empty() {
                Ok(self.files.lock().unwrap().keys().cloned().collect())
            } else {
                Err(StorageError::NotFound(path.to_string()))
            }
        }
        fn stat(&self, path: &str) -> Result<BackendStat, StorageError> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .map(|&size| BackendStat {
                    size,
                    is_dir: false,
                })
                .ok_or_else(|| StorageError::NotFound(path.to_string()))
        }
        fn write_content(
            &self,
            _c: &[u8],
            _id: &str,
            _ctx: &OperationContext,
            _o: u64,
        ) -> Result<WriteResult, StorageError> {
            Err(StorageError::NotSupported("write_content"))
        }
        fn read_content(
            &self,
            _id: &str,
            _ctx: &OperationContext,
        ) -> Result<Vec<u8>, StorageError> {
            Err(StorageError::NotSupported("read_content"))
        }
    }

    /// On-access seed (metadata-sync trigger 3): a `sys_readdir` on an armed
    /// mount that surfaces a backend child the metastore does not yet carry
    /// materialises its authoritative row synchronously, in the same call —
    /// no wait for the reconcile interval. This is the regression the
    /// cc-tasks-share E2E's `last_writer`-at-once assertion depends on.
    #[test]
    fn armed_readdir_seeds_out_of_band_entry_synchronously() {
        let kernel = Arc::new(Kernel::new());
        let backend = Arc::new(MutableFlatBackend::new());
        let dyn_backend: Arc<dyn ObjectStore> = backend.clone();
        kernel
            .dlc
            .mount(
                &kernel,
                "/tasks",
                "root",
                Some(dyn_backend),
                None,
                None,
                false,
            )
            .expect("mount");
        kernel.arm_metadata_sync("/tasks", "root");
        // Initial walk saw an empty backend — nothing seeded yet.
        assert!(
            matches!(kernel.metastore_get("/tasks/a.json"), Ok(None)),
            "empty at arm time"
        );

        // Out-of-band write lands directly in the backend after arm.
        backend.add("a.json", 7);

        // A readdir on the armed mount discovers it and seeds the row in
        // the same call.
        let entries = kernel.sys_readdir("/tasks", "root", true);
        assert!(
            entries
                .iter()
                .any(|(p, t)| p == "/tasks/a.json" && *t == DT_REG),
            "readdir surfaces the out-of-band file: {entries:?}"
        );
        let row = kernel
            .metastore_get("/tasks/a.json")
            .expect("metastore_get ok")
            .expect("row seeded synchronously by readdir");
        assert_eq!(row.entry_type, DT_REG);
        assert_eq!(
            row.size, 7,
            "real backend size stamped (POSIX read short-circuits on 0)"
        );
        assert_eq!(
            row.content_id.as_deref(),
            Some("a.json"),
            "backend-relative content_id, identical to the reconcile walk's row"
        );
    }

    /// Gate-key consistency in the production shape: an armed mount in a
    /// non-root federation zone under a nested path. The on-access seed's
    /// gate is `is_sync_armed(route.mount_point)`, which must match the
    /// canonical key `arm` stored the handle under. Canonicalization is not
    /// idempotent, so a zone/prefix mismatch here would silently disarm the
    /// seed and re-open the last_writer regression — yet the other tests
    /// only exercise the `"root"` zone. This proves the key matches for the
    /// real `cc-tasks-share` shape (`/shared/cc-tasks/founder` @ sharedzone).
    #[test]
    fn armed_readdir_seeds_in_federation_zone_nested_mount() {
        let kernel = Arc::new(Kernel::new());
        let backend = Arc::new(MutableFlatBackend::new());
        let dyn_backend: Arc<dyn ObjectStore> = backend.clone();
        kernel
            .dlc
            .mount(
                &kernel,
                "/shared/cc-tasks/founder",
                "sharedzone",
                Some(dyn_backend),
                None,
                None,
                false,
            )
            .expect("mount federation-zone connector");
        kernel.arm_metadata_sync("/shared/cc-tasks/founder", "sharedzone");
        assert_eq!(kernel.dlc.sync_handle_count(), 1, "armed in sharedzone");

        // Out-of-band write, then a readdir on the nested federation-zone
        // mount must seed it — proving the gate key matched.
        backend.add("task-1.json", 9);
        let entries = kernel.sys_readdir("/shared/cc-tasks/founder", "sharedzone", true);
        assert!(
            entries
                .iter()
                .any(|(p, t)| p == "/shared/cc-tasks/founder/task-1.json" && *t == DT_REG),
            "readdir surfaces the out-of-band file in the federation zone: {entries:?}"
        );
        let row = kernel
            .metastore_get("/shared/cc-tasks/founder/task-1.json")
            .expect("metastore_get ok")
            .expect("row seeded synchronously — gate key matched in federation zone");
        assert_eq!(row.size, 9);
        assert_eq!(
            row.content_id.as_deref(),
            Some("task-1.json"),
            "backend-relative content_id, mount-prefix stripped"
        );
    }

    /// The on-access seed is gated on arming: an un-armed mount still unions
    /// backend content into the readdir result (list-your-writes) but
    /// proposes NO metastore row — every other readdir pays zero seed cost.
    #[test]
    fn unarmed_readdir_unions_but_does_not_seed() {
        let kernel = Arc::new(Kernel::new());
        let backend = Arc::new(MutableFlatBackend::new());
        let dyn_backend: Arc<dyn ObjectStore> = backend.clone();
        kernel
            .dlc
            .mount(
                &kernel,
                "/tasks",
                "root",
                Some(dyn_backend),
                None,
                None,
                false,
            )
            .expect("mount");
        // Deliberately NOT armed.
        backend.add("a.json", 7);

        let entries = kernel.sys_readdir("/tasks", "root", true);
        assert!(
            entries.iter().any(|(p, _)| p == "/tasks/a.json"),
            "readdir still unions backend content for list-your-writes: {entries:?}"
        );
        assert!(
            matches!(kernel.metastore_get("/tasks/a.json"), Ok(None)),
            "no row seeded when the mount is not armed"
        );
    }
}

#[cfg(test)]
mod dt_mount_idempotency_tests {
    //! Regression for the 2-voter cold-start deadlock: a DT_MOUNT install
    //! must NOT re-propose already-committed routing state on resume. A
    //! raft `ZoneMetaStore::put` is a `propose` (needs a leader); on a
    //! multi-node cold restart no leader exists yet (each voter waits on
    //! the other to boot), so re-proposing a replayed DT_MOUNT fail-louds
    //! and both nodes deadlock. `dlc.mount` must read the applied state
    //! (leader-free `get`) and skip the write when the row already exists.

    use crate::kernel::Kernel;
    use crate::meta_store::{FileMetadata, MetaStore, MetaStoreError, DT_MOUNT};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Models a resumed raft follower with NO leader: `get` serves
    /// already-applied state (leader-free), every `put` (propose) fails
    /// `not leader`. Counts puts so the test can assert the idempotent
    /// path issued zero writes.
    struct LeaderlessStore {
        seeded: Mutex<HashMap<String, FileMetadata>>,
        put_calls: AtomicUsize,
    }
    impl LeaderlessStore {
        fn new() -> Self {
            Self {
                seeded: Mutex::new(HashMap::new()),
                put_calls: AtomicUsize::new(0),
            }
        }
        fn seed(&self, path: &str, meta: FileMetadata) {
            self.seeded.lock().unwrap().insert(path.to_string(), meta);
        }
    }
    impl MetaStore for LeaderlessStore {
        fn get(&self, path: &str) -> Result<Option<FileMetadata>, MetaStoreError> {
            Ok(self.seeded.lock().unwrap().get(path).cloned())
        }
        fn put(&self, _path: &str, _m: FileMetadata) -> Result<(), MetaStoreError> {
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            Err(MetaStoreError::IOError(
                "not leader, leader hint: None".into(),
            ))
        }
        fn delete(&self, _p: &str) -> Result<bool, MetaStoreError> {
            Ok(false)
        }
        fn list(&self, _p: &str) -> Result<Vec<FileMetadata>, MetaStoreError> {
            Ok(vec![])
        }
        fn exists(&self, p: &str) -> Result<bool, MetaStoreError> {
            Ok(self.seeded.lock().unwrap().contains_key(p))
        }
    }

    fn dt_mount_row(path: &str, target_zone: &str) -> FileMetadata {
        FileMetadata {
            path: path.to_string(),
            size: 0,
            content_id: None,
            gen: 0,
            version: 1,
            entry_type: DT_MOUNT,
            zone_id: Some("root".to_string()),
            mime_type: None,
            created_at_ms: None,
            modified_at_ms: None,
            last_writer_address: None,
            target_zone_id: Some(target_zone.to_string()),
            link_target: None,
            owner_id: None,
        }
    }

    /// Resume path: the child sharedzone DT_MOUNT is already committed
    /// (seeded as applied state). The install reads it via a leader-free
    /// `get` and skips the propose → mount succeeds with ZERO puts even
    /// though every put on this store fails `not leader`. This is exactly
    /// the boot that used to deadlock a 2-voter cluster.
    #[test]
    fn resume_skips_propose_when_dt_mount_already_committed() {
        let kernel = Arc::new(Kernel::new());
        let store = Arc::new(LeaderlessStore::new());
        store.seed(
            "/shared/tasks-nexus-project",
            dt_mount_row("/shared/tasks-nexus-project", "sharedzone"),
        );

        // Parent mount carries the leaderless store; the child's persist
        // routes here via `with_metastore("/shared")`.
        kernel
            .dlc
            .mount(
                &kernel,
                "/shared",
                "root",
                None,
                Some(store.clone() as Arc<dyn MetaStore>),
                None,
                false,
            )
            .expect("mount parent /shared");

        kernel
            .dlc
            .mount(
                &kernel,
                "/shared/tasks-nexus-project",
                "sharedzone",
                None,
                None,
                None,
                false,
            )
            .expect("resume install must not block on a leader");

        assert_eq!(
            store.put_calls.load(Ordering::SeqCst),
            0,
            "already-committed DT_MOUNT must not be re-proposed (leader-free resume)"
        );
    }

    /// Control: a genuinely-new mount (no committed row) still proposes,
    /// so the leaderless store surfaces the `not leader` error. The fix is
    /// specific to already-committed state — it is NOT a blanket swallow
    /// of put failures (which would silently install unpersisted routes,
    /// the #4343 fail-closed hazard).
    #[test]
    fn new_mount_still_proposes_and_surfaces_leaderless_error() {
        let kernel = Arc::new(Kernel::new());
        let store = Arc::new(LeaderlessStore::new()); // nothing seeded
        kernel
            .dlc
            .mount(
                &kernel,
                "/shared",
                "root",
                None,
                Some(store.clone() as Arc<dyn MetaStore>),
                None,
                false,
            )
            .expect("mount parent /shared");

        let result = kernel.dlc.mount(
            &kernel,
            "/shared/tasks-nexus-project",
            "sharedzone",
            None,
            None,
            None,
            false,
        );
        assert!(
            result.is_err(),
            "a new mount with no committed row must still require a leader"
        );
        assert_eq!(
            store.put_calls.load(Ordering::SeqCst),
            1,
            "new mount attempts exactly one propose"
        );
    }
}
