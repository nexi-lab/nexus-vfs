//! Federation syscalls + Control-Plane HAL §3.B.1 + §3.B.2 wiring.
//!
//! Per-family submodule extracted from the monolithic `kernel/mod.rs`
//! (consistent with other syscall-family submodules `io.rs`, `ipc.rs`,
//! `locks.rs`, `dispatch.rs`, `observability.rs`). Methods stay
//! members of [`Kernel`] via `impl Kernel { ... }` blocks — the split
//! is a file-organization change, not an API change.
//!
//! Per `docs/KERNEL-ARCHITECTURE.md` §3 the three-way directory split
//! is: `abc/` for §3.A Storage HAL pillars, `hal/` for §3.B
//! Control-Plane HAL **trait declarations + Noop fallbacks**, and
//! `core/` for kernel primitives.  This file is the kernel-side
//! WIRING for §3.B traits — Kernel-struct slot accessors + the
//! consumer-side dispatch convention that the kernel runs through.
//! Both [`DistributedCoordinator`] (§3.B.1) and [`FederationPeerClient`]
//! (§3.B.X, added 2026-06) follow the same shape, so they share this
//! file rather than scatter across `kernel/io.rs` (which is misplaced
//! for the federation-peer dispatch helpers added by PR #4427 and
//! relocated here).
//!
//! Owns:
//!
//! * **§3.B.1 DistributedCoordinator wiring** — slot accessors
//!   ([`Kernel::distributed_coordinator`],
//!   [`Kernel::set_distributed_coordinator`]).
//! * **Federation procfs** — `/__sys__/zones/` synthesisers
//!   ([`Kernel::zones_procfs_stat`], [`Kernel::zones_procfs_readdir`]).
//! * **Blob-fetcher slot plumbing** — boot-time stash for the
//!   raft-tier handler to drain
//!   ([`Kernel::stash_blob_fetcher_slot`],
//!   [`Kernel::take_pending_blob_fetcher_slot`]).
//! * **§3.B.X FederationPeerClient wiring** — slot accessors
//!   ([`Kernel::federation_peer_client_arc`],
//!   [`Kernel::set_federation_peer_client`]).
//! * **Federation-peer dispatch convention** — the kernel-side
//!   "iterate non-self voters, call the typed HAL method, return
//!   first hit" convention that every cross-node syscall short-
//!   circuit reaches through.  Generic core
//!   [`Kernel::dispatch_federation_peer`] plus per-syscall thin
//!   wrappers [`Kernel::federation_peer_readdir`] /
//!   [`Kernel::federation_peer_stat`] /
//!   [`Kernel::federation_peer_write`] /
//!   [`Kernel::federation_peer_setattr`] /
//!   [`Kernel::federation_peer_rename`] /
//!   [`Kernel::federation_peer_mkdir`] /
//!   [`Kernel::federation_peer_delete_file`].

use std::sync::Arc;

use super::{Kernel, StatResult};

impl Kernel {
    /// Replace the kernel's coordinator slot with a concrete
    /// `DistributedCoordinator` impl. Kernel boots with
    /// `NoopDistributedCoordinator`; the host binary's boot path calls
    /// this with the real `nexus_raft::distributed_coordinator` impl
    /// once per kernel. Mirrors `set_peer_client`.
    pub fn set_distributed_coordinator(
        &self,
        coordinator: Arc<dyn crate::hal::distributed_coordinator::DistributedCoordinator>,
    ) {
        *self.distributed_coordinator.write() = coordinator;
    }

    /// Borrow the current distributed coordinator — read-locked snapshot.
    /// Internal callers use this to issue federation calls without
    /// holding the lock across `.await`. After `set_distributed_coordinator`
    /// runs at boot, this returns the real raft-backed impl; before
    /// then, a `NoopDistributedCoordinator` that errors on every call.
    pub fn distributed_coordinator(
        &self,
    ) -> Arc<dyn crate::hal::distributed_coordinator::DistributedCoordinator> {
        Arc::clone(&self.distributed_coordinator.read())
    }

    /// Federation procfs: synthesise a `StatResult` for paths under the
    /// `/__sys__/zones/` virtual namespace.  Read-only — like Linux
    /// `/proc`, callers cannot create / remove a zone by writing to
    /// this path.  Returns `Some` for `/__sys__/zones/` (directory
    /// marker) and `/__sys__/zones/<id>` (per-zone synthesised entry);
    /// `None` otherwise so the caller falls through to normal routing.
    pub(crate) fn zones_procfs_stat(&self, path: &str) -> Option<StatResult> {
        let suffix = path.strip_prefix("/__sys__/zones")?;
        let provider = self.distributed_coordinator();
        // Directory marker.
        if suffix.is_empty() || suffix == "/" {
            return Some(StatResult {
                path: path.to_string(),
                size: 4096,
                content_id: None,
                mime_type: "inode/directory".to_string(),
                is_directory: true,
                entry_type: crate::meta_store::DT_DIR,
                mode: 0o555, // r-x — read-only namespace
                version: 0,
                gen: 0,
                zone_id: Some("root".to_string()),
                created_at_ms: None,
                modified_at_ms: None,
                last_writer_address: None,
                lock: None,
                link_target: None,
                owner_id: None,
            });
        }
        // /__sys__/zones/<id>: synthesise from federation list.
        let zone_id = suffix.trim_start_matches('/');
        if zone_id.is_empty() || zone_id.contains('/') {
            return None;
        }
        if !provider.list_zones(self).iter().any(|z| z == zone_id) {
            return None;
        }
        Some(StatResult {
            path: path.to_string(),
            size: 0,
            content_id: None,
            mime_type: "application/x-nexus-zone".to_string(),
            is_directory: false,
            entry_type: crate::meta_store::DT_REG,
            mode: 0o444,
            version: 0,
            gen: 0,
            zone_id: Some(zone_id.to_string()),
            created_at_ms: None,
            modified_at_ms: None,
            last_writer_address: self.self_address_string(),
            lock: None,
            link_target: None,
            owner_id: None,
        })
    }

    /// Federation procfs: list zones for `/__sys__/zones/` directory
    /// reads.  Returns `None` for paths outside the namespace so the
    /// caller falls through to normal routing.
    #[allow(dead_code)] // reserved for readdir `/__sys__/zones/` integration
    pub(crate) fn zones_procfs_readdir(&self, path: &str) -> Option<Vec<String>> {
        let suffix = path.strip_prefix("/__sys__/zones")?;
        if !suffix.is_empty() && suffix != "/" {
            return None;
        }
        Some(self.distributed_coordinator().list_zones(self))
    }

    /// Stash the raft-tier blob-fetcher slot. Drained by
    /// `nexus_raft::blob_fetcher_handler::install` during boot.
    /// Typed as `Box<dyn Any>` so kernel does not name the raft-side
    /// `BlobFetcherSlot` concrete type.
    pub fn stash_blob_fetcher_slot(&self, slot: Box<dyn std::any::Any + Send + Sync>) {
        *self.pending_blob_fetcher_slot.lock() = Some(slot);
    }

    /// Drain the previously stashed blob-fetcher slot. Returns `None`
    /// after the first drain so repeat-boot scenarios stay safe.
    pub fn take_pending_blob_fetcher_slot(&self) -> Option<Box<dyn std::any::Any + Send + Sync>> {
        self.pending_blob_fetcher_slot.lock().take()
    }

    // ── §3.B.X FederationPeerClient slot accessors ────────────────────
    //
    // The kernel boots with `NoopFederationPeerClient` (errors on
    // every call); the transport-tier `transport::federation::install`
    // hook swaps in the real `FederationClient` once per kernel.
    // `FederationPeerBackend` (in the `backends` crate) reads this
    // slot to make typed VFS RPCs against peer-owned mounts.

    /// Replace the kernel's federation-peer client slot with a
    /// concrete `FederationPeerClient` impl.  Mirrors
    /// [`Self::set_distributed_coordinator`].
    pub fn set_federation_peer_client(
        &self,
        client: Arc<dyn crate::hal::federation_peer::FederationPeerClient>,
    ) {
        *self.federation_peer_client.write() = client;
    }

    /// Borrow the federation-peer client — read-locked snapshot.
    pub fn federation_peer_client_arc(
        &self,
    ) -> Arc<dyn crate::hal::federation_peer::FederationPeerClient> {
        Arc::clone(&self.federation_peer_client.read())
    }

    // ── Federation-peer dispatch convention ───────────────────────────
    //
    // Generic core + per-syscall thin wrappers.  Every cross-node
    // syscall short-circuit in io.rs / mod.rs (sys_write §5a,
    // sys_unlink §5a, sys_mkdir §2.7, sys_rename §2.5, sys_setattr
    // §setattr_update.A, sys_stat federation-peer fallback,
    // sys_readdir federation-peer merge) reaches one of the `_X`
    // wrappers below.

    /// Generic federation-peer dispatch.
    ///
    /// Iterates non-self voters of [`route.target_zone_id`] via
    /// [`DistributedCoordinator::zone_peers`] and runs `op` against
    /// each one with the [`FederationPeerClient`] arc + the peer
    /// address.  The closure encodes which typed `NexusVFSService`
    /// method to call.  Returns the first successful hit; transport
    /// errors are logged at debug and the next peer is tried.
    ///
    /// Returns `None` when:
    ///   - the route has no `target_zone_id` (plain local mount, not
    ///     a federation peer mount — caller should not have dispatched);
    ///   - the zone has no peers loaded yet (federation discovery
    ///     pending — caller falls through to local not-found);
    ///   - every peer errored or returned `Ok(None)` (no SSOT-side
    ///     copy of the path under any voter).
    ///
    /// Loop-avoidance: sys_readdir's signature predates
    /// `OperationContext`, so the helper accepts dispatch from any
    /// syscall regardless of ctx state.  In the canonical 2-node
    /// cc-tasks-share topology only the non-SSOT side reaches a
    /// backend-less placeholder MountEntry — re-entry is structurally
    /// impossible.  For pathological multi-node topologies where two
    /// nodes both observe `backend=None` for the same path, the typed
    /// server-side handler sets `ctx.propagates_cross_node` (see
    /// `transport::grpc::VfsServiceImpl`) — when that wiring is
    /// threaded into sys_readdir / sys_stat / sys_unlink (their
    /// signatures currently lack ctx), this helper grows a guard.
    #[inline]
    pub(crate) fn dispatch_federation_peer<T, F>(
        &self,
        route: &crate::vfs_router::RouteResult,
        op_name: &'static str,
        peer_path: &str,
        mut op: F,
    ) -> Option<T>
    where
        F: FnMut(
            &std::sync::Arc<dyn crate::hal::federation_peer::FederationPeerClient>,
            &str,
        ) -> Result<Option<T>, String>,
    {
        let target_zone = route.target_zone_id.as_deref()?;
        let peers = self.distributed_coordinator().zone_peers(self, target_zone);
        if peers.is_empty() {
            return None;
        }
        let self_addr = self.self_address.read().clone();
        let client = self.federation_peer_client_arc();
        for peer_addr in peers {
            if let Some(ref s) = self_addr {
                if s == &peer_addr {
                    continue;
                }
            }
            match op(&client, &peer_addr) {
                Ok(Some(result)) => return Some(result),
                Ok(None) => continue,
                Err(e) => {
                    tracing::debug!(
                        op = op_name,
                        peer = %peer_addr,
                        path = %peer_path,
                        error = %e,
                        "federation peer dispatch failed; trying next voter"
                    );
                }
            }
        }
        None
    }

    /// `sys_readdir` arm of [`Self::dispatch_federation_peer`] — the
    /// per-syscall thin wrapper that names the op and threads the
    /// trait method.  Kept as a separate function so the caller stays
    /// readable.
    #[inline]
    pub(crate) fn federation_peer_readdir(
        &self,
        route: &crate::vfs_router::RouteResult,
        peer_path: &str,
    ) -> Option<Vec<(String, u8)>> {
        self.dispatch_federation_peer::<Vec<(String, u8)>, _>(
            route,
            "readdir",
            peer_path,
            |client, addr| {
                // Empty result is meaningful for readdir ("dir exists
                // but empty") — distinguish from not-found by ALWAYS
                // returning `Some(entries)` on transport success.
                client.list_dir(addr, peer_path).map(Some)
            },
        )
    }

    /// `sys_stat` arm — point-lookup metadata for a backend-less
    /// federation mount.  The trait method returns `Ok(None)` for
    /// not-found in-band; the dispatch helper forwards that as
    /// "try the next peer" so a stale voter doesn't shadow a fresh
    /// one's hit.
    #[inline]
    pub(crate) fn federation_peer_stat(
        &self,
        route: &crate::vfs_router::RouteResult,
        peer_path: &str,
    ) -> Option<crate::abc::object_store::BackendStat> {
        self.dispatch_federation_peer::<crate::abc::object_store::BackendStat, _>(
            route,
            "stat",
            peer_path,
            |client, addr| client.stat(addr, peer_path),
        )
    }

    /// `sys_write` arm for federation-peer mounts — delegates the
    /// FULL write lifecycle to the SSOT peer's `NexusVFSService.Write`.
    /// The peer's typed handler runs `backend.write_content` against
    /// its own LocalConnector + the single authoritative `metastore.put`
    /// (raft proposal).  The replicated apply lands back on every
    /// voter's local metastore — symmetric with the cleanup shape of
    /// `federation_peer_delete_file`.
    ///
    /// Returning the peer's `WriteResult` lets the caller fire its
    /// own OBSERVE event + native POST hook with the canonical
    /// `(content_id, size)` from the SSOT side.
    #[inline]
    pub(crate) fn federation_peer_write(
        &self,
        route: &crate::vfs_router::RouteResult,
        peer_path: &str,
        content: &[u8],
    ) -> Option<crate::abc::object_store::WriteResult> {
        self.dispatch_federation_peer::<crate::abc::object_store::WriteResult, _>(
            route,
            "write",
            peer_path,
            |client, addr| client.write(addr, peer_path, content).map(Some),
        )
    }

    /// `sys_setattr` arm for DT_REG metadata updates — delegates
    /// to the SSOT peer's `NexusVFSService.Setattr`.  Restricted
    /// to DT_REG because (1) DT_MOUNT mount-construction is
    /// node-local (per-node driver instance + backend wiring),
    /// (2) DT_PIPE / DT_STREAM are IPC endpoints that can't
    /// cross machine boundaries, (3) DT_LINK is path-internal
    /// symlink (kernel-internal, no cross-node concept).
    ///
    /// Mirror of `federation_peer_mkdir` / `_delete_file` /
    /// `_write` — same dispatch helper, same single-proposer
    /// semantics.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub(crate) fn federation_peer_setattr(
        &self,
        route: &crate::vfs_router::RouteResult,
        peer_path: &str,
        mime_type: Option<&str>,
        content_id: Option<&str>,
        modified_at_ms: Option<i64>,
        created_at_ms: Option<i64>,
        size: Option<u64>,
        version: Option<u32>,
    ) -> bool {
        self.dispatch_federation_peer::<(), _>(route, "setattr", peer_path, |client, addr| {
            client
                .setattr(
                    addr,
                    peer_path,
                    mime_type,
                    content_id,
                    modified_at_ms,
                    created_at_ms,
                    size,
                    version,
                )
                .map(|()| Some(()))
        })
        .is_some()
    }

    /// `sys_rename` arm — delegates to the SSOT peer's
    /// `NexusVFSService.Rename`.  The peer's typed handler runs
    /// `backend.rename` against its own LocalConnector + the
    /// authoritative metastore mutations (delete old key, put new
    /// key, raft propose).  Raft replicates the result back to
    /// every voter via apply.
    ///
    /// Cross-mount rename is rejected upstream by the peer's
    /// sys_rename (in-band error); the dispatch helper surfaces
    /// that as a `false` return value so the caller's miss()
    /// path fires.
    #[inline]
    pub(crate) fn federation_peer_rename(
        &self,
        route: &crate::vfs_router::RouteResult,
        old_peer_path: &str,
        new_peer_path: &str,
    ) -> bool {
        self.dispatch_federation_peer::<(), _>(route, "rename", old_peer_path, |client, addr| {
            client
                .rename(addr, old_peer_path, new_peer_path)
                .map(|()| Some(()))
        })
        .is_some()
    }

    /// `sys_mkdir` arm — delegates to the SSOT peer's
    /// `NexusVFSService.Mkdir`.  The peer's typed handler runs
    /// `backend.mkdir` against its own LocalConnector + the
    /// authoritative `metastore.put` for the new DT_DIR row.
    /// Raft replicates the put back to every voter via apply.
    ///
    /// Mirror of `federation_peer_delete_file` — same dispatch
    /// helper, same loop-avoidance caveat, same single-proposer
    /// semantics PR #80 established for sys_write.
    #[inline]
    pub(crate) fn federation_peer_mkdir(
        &self,
        route: &crate::vfs_router::RouteResult,
        peer_path: &str,
        parents: bool,
        exist_ok: bool,
    ) -> bool {
        self.dispatch_federation_peer::<(), _>(route, "mkdir", peer_path, |client, addr| {
            client
                .mkdir(addr, peer_path, parents, exist_ok)
                .map(|()| Some(()))
        })
        .is_some()
    }

    /// `sys_unlink` arm for regular files — delegates to the SSOT
    /// peer's `NexusVFSService.Delete`.  The peer's typed handler
    /// runs the full unlink lifecycle (metastore delete + backend
    /// delete_file + raft replication) so cleanup is symmetric:
    /// metadata removed from raft for every voter, host fs row gone
    /// from the SSOT side's LocalConnector.
    #[inline]
    pub(crate) fn federation_peer_delete_file(
        &self,
        route: &crate::vfs_router::RouteResult,
        peer_path: &str,
    ) -> bool {
        self.dispatch_federation_peer::<(), _>(route, "delete_file", peer_path, |client, addr| {
            client.delete_file(addr, peer_path).map(|()| Some(()))
        })
        .is_some()
    }
}
