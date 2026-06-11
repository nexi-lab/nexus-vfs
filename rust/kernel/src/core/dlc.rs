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

use crate::kernel::{Kernel, KernelError};
use std::sync::Arc;

/// Kernel primitive: driver mount lifecycle.
///
/// Stateless coordinator — `mount()` / `unmount()` thread mutations into
/// the kernel's owned tables (`VFSRouter`, per-mount metastore) rather
/// than caching anything locally.  Created once at `Kernel::new()`.
pub(crate) struct DriverLifecycleCoordinator;

impl DriverLifecycleCoordinator {
    pub fn new() -> Self {
        Self
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
        if route.is_none() && mount_point != "/" {
            // Fail closed (#4343): a non-root mount with no enclosing route
            // has nowhere to persist its DT_MOUNT entry — installing it
            // anyway would create a route that silently vanishes on
            // restart. Mount the root first.
            return Err(KernelError::IOError(format!(
                "no parent route for non-root mount {mount_point}; \
                 mount the root first so the DT_MOUNT entry can be persisted"
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
        kernel.add_mount(
            mount_point,
            zone_id,
            backend,
            metastore,
            raft_backend,
            is_external,
        )?;
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

        // 2. Remove from routing table — the per-mount metastore Arc
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
}
