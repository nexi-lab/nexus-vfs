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

use crate::extensions::observer_backend::{ObservationHandle, ObservationSink};
use crate::kernel::{Kernel, KernelError};
use std::collections::HashMap;
use std::sync::Arc;

/// Kernel primitive: driver mount lifecycle.
///
/// `mount()` / `unmount()` thread mutations into the kernel's owned
/// tables (`VFSRouter`, per-mount metastore).  The one piece of state it
/// owns is the set of live [`ObservationHandle`]s for observer-backed
/// mounts (`LocalConnectorBackend` et al.) — each handle's Drop stops the
/// backend's reconcile thread, so keying them by canonical mount point
/// and dropping on `unmount()` ties the reconcile lifetime to the mount.
/// Created once at `Kernel::new()`.
pub(crate) struct DriverLifecycleCoordinator {
    observation_handles: parking_lot::Mutex<HashMap<String, ObservationHandle>>,
}

impl DriverLifecycleCoordinator {
    pub fn new() -> Self {
        Self {
            observation_handles: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Arm an [`crate::extensions::observer_backend::ObserverBackend`]'s
    /// eager metastore sync for a freshly-installed mount, if the backend
    /// implements it.  No-op for non-observer backends (CAS / S3 / path).
    ///
    /// Skips arming when the kernel's self-weak is unset (a bare
    /// `Kernel::new()` without `install_self_weak` — the sink's `propose`
    /// would no-op anyway, so we don't spawn a useless reconcile thread).
    /// Errors from `install_observer` (unreadable backend root) are logged
    /// and swallowed: the mount itself already succeeded, and a failed
    /// initial walk shouldn't tear it down.
    fn arm_observer(
        &self,
        kernel: &Kernel,
        mount_point: &str,
        zone_id: &str,
        backend: &dyn crate::abc::object_store::ObjectStore,
    ) {
        let Some(observer) = backend.as_observer() else {
            return;
        };
        let weak = kernel.self_weak();
        if weak.upgrade().is_none() {
            tracing::debug!(
                target: "kernel::dlc",
                mount = mount_point,
                "ObserverBackend not armed: kernel self-weak unset (bare Kernel without install_self_weak)",
            );
            return;
        }
        let sink = ObservationSink::new(weak, zone_id.to_string(), mount_point.to_string());
        match observer.install_observer(sink) {
            Ok(handle) => {
                let key = Kernel::canonical_mount_key(mount_point, zone_id);
                self.observation_handles.lock().insert(key, handle);
                tracing::info!(
                    target: "kernel::dlc",
                    mount = mount_point,
                    zone = zone_id,
                    "ObserverBackend armed — metastore kept authoritative for this mount's contents via eager sync",
                );
            }
            Err(e) => {
                tracing::error!(
                    target: "kernel::dlc",
                    mount = mount_point,
                    "ObserverBackend install_observer failed: {e}",
                );
            }
        }
    }

    /// Drop the [`ObservationHandle`] for a mount (if armed), stopping its
    /// reconcile thread.  Idempotent.
    fn disarm_observer(&self, mount_point: &str, zone_id: &str) {
        let key = Kernel::canonical_mount_key(mount_point, zone_id);
        if self.observation_handles.lock().remove(&key).is_some() {
            tracing::debug!(
                target: "kernel::dlc",
                mount = mount_point,
                "ObserverBackend disarmed on unmount",
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
        // Clone the backend Arc before `add_mount` consumes it so we can
        // arm the ObserverBackend sync AFTER the mount is confirmed
        // installed — arming before a failed `add_mount` would leak a
        // reconcile thread for a mount that never landed.
        let observer_backend = backend.clone();
        kernel.add_mount(
            mount_point,
            zone_id,
            backend,
            metastore,
            raft_backend,
            is_external,
        )?;
        if let Some(backend_arc) = observer_backend {
            self.arm_observer(kernel, mount_point, zone_id, backend_arc.as_ref());
        }
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

        // 2. Stop the ObserverBackend reconcile thread (if this mount had
        // one) before tearing down the route, so it can't propose against
        // a mount that's going away.
        self.disarm_observer(mount_point, zone_id);

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

    /// Test-only: number of live ObserverBackend handles.  Lets the
    /// wiring integration test assert arm-on-mount / drop-on-unmount.
    #[cfg(test)]
    pub(crate) fn armed_observer_count(&self) -> usize {
        self.observation_handles.lock().len()
    }
}

#[cfg(test)]
mod observer_wiring_tests {
    //! Integration test for the ObserverBackend mount wiring: a real
    //! `Arc<Kernel>` + real `DriverLifecycleCoordinator` + real
    //! `ObservationSink` + real metastore.  A mock `ObserverBackend`
    //! whose `install_observer` proposes a fixed listing synchronously
    //! lets us assert the whole arm path deterministically (no reconcile
    //! thread timing): DLC.mount → arm_observer → self_weak upgrade →
    //! sink (mount-prefix join) → `observe_backend_entry` → metastore.
    //!
    //! Real user problem: after a node mounts a peer-shared LocalConnector
    //! over a host dir that already holds tasks, those tasks MUST become
    //! visible in the metastore (so peers see them via raft-replicated
    //! `metastore.list`) without any read/readdir-time cold-discovery.

    use crate::abc::object_store::{ObjectStore, StorageError, WriteResult};
    use crate::extensions::observer_backend::{
        ObservationHandle, ObservationSink, ObserverBackend,
    };
    use crate::kernel::{Kernel, OperationContext};
    use crate::meta_store::{DT_DIR, DT_REG};
    use std::sync::Arc;

    /// Backend that, on `install_observer`, synchronously proposes a
    /// fixed backend-relative listing through the sink, then returns a
    /// handle with no background thread — deterministic for assertions.
    struct MockObserverBackend {
        entries: Vec<(String, u8, u64)>,
    }

    impl ObjectStore for MockObserverBackend {
        fn name(&self) -> &str {
            "mock-observer"
        }
        fn as_observer(&self) -> Option<&dyn ObserverBackend> {
            Some(self)
        }
        fn write_content(
            &self,
            _content: &[u8],
            _content_id: &str,
            _ctx: &OperationContext,
            _offset: u64,
        ) -> Result<WriteResult, StorageError> {
            Err(StorageError::NotSupported("write_content"))
        }
        fn read_content(
            &self,
            _content_id: &str,
            _ctx: &OperationContext,
        ) -> Result<Vec<u8>, StorageError> {
            Err(StorageError::NotSupported("read_content"))
        }
    }

    impl ObserverBackend for MockObserverBackend {
        fn install_observer(
            &self,
            sink: ObservationSink,
        ) -> Result<ObservationHandle, crate::extensions::observer_backend::ObservationError>
        {
            for (rel, etype, size) in &self.entries {
                let content_id = if *etype == DT_REG {
                    Some(rel.clone())
                } else {
                    None
                };
                sink.propose(rel, *etype, *size, content_id);
            }
            let (handle, _rx) = ObservationHandle::new();
            Ok(handle)
        }
    }

    /// Full-workflow: mount an observer backend whose host dir already
    /// holds `a.json` + `sub/` + `sub/b.json`, assert every entry became
    /// an authoritative metastore row (correct type, size, content_id),
    /// then unmount and assert the handle was dropped.
    #[test]
    fn mount_arms_observer_and_populates_metastore_then_unmount_disarms() {
        // Real kernel with its Arc-self-weak installed (the boot step
        // that lets the sink's kernel weak-ref upgrade).
        let kernel = Arc::new(Kernel::new());
        kernel.install_self_weak();

        let backend = Arc::new(MockObserverBackend {
            entries: vec![
                ("a.json".to_string(), DT_REG, 5),
                ("sub".to_string(), DT_DIR, 0),
                ("sub/b.json".to_string(), DT_REG, 11),
            ],
        });

        // Step 1: mount over the (virtual) host dir at /tasks.  DLC arms
        // the observer, whose synchronous initial sync proposes the rows.
        kernel
            .dlc
            .mount(&kernel, "/tasks", "root", Some(backend), None, None, false)
            .expect("mount observer backend");
        assert_eq!(
            kernel.dlc.armed_observer_count(),
            1,
            "observer armed on mount"
        );

        // Step 2: every backend entry is now an authoritative metastore
        // row under the mount prefix — this is what a peer's
        // `metastore.list` would replicate and see.
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

        // Step 3: unmount drops the ObservationHandle (its Drop stops the
        // reconcile thread in a real backend).
        kernel
            .dlc
            .unmount(&kernel, "/tasks", "root")
            .expect("unmount");
        assert_eq!(
            kernel.dlc.armed_observer_count(),
            0,
            "observer disarmed on unmount"
        );
    }

    /// Without `install_self_weak` (bare `Kernel::new()`), arming is
    /// skipped — the sink's kernel weak-ref could not upgrade, so we
    /// don't spawn a useless reconcile thread and propose nothing.
    #[test]
    fn mount_without_self_weak_skips_arming() {
        let kernel = Arc::new(Kernel::new());
        // NOTE: deliberately NOT calling install_self_weak.

        let backend = Arc::new(MockObserverBackend {
            entries: vec![("x.json".to_string(), DT_REG, 1)],
        });
        kernel
            .dlc
            .mount(&kernel, "/tasks", "root", Some(backend), None, None, false)
            .expect("mount");

        assert_eq!(
            kernel.dlc.armed_observer_count(),
            0,
            "no handle stored when self-weak is unset"
        );
        assert!(
            matches!(kernel.metastore_get("/tasks/x.json"), Ok(None)),
            "no row proposed when arming is skipped"
        );
    }
}
