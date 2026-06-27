//! `FederationPeerClient` slot + generic dispatch convention + per-syscall
//! thin wrappers.
//!
//! Every cross-node syscall short-circuit (sys_stat / sys_readdir /
//! sys_unlink / sys_write / sys_mkdir / sys_rename / sys_setattr) reaches
//! one of the `federation_peer_X` wrappers below; the generic
//! [`Kernel::dispatch_federation_peer`] encodes the "iterate non-self
//! voters, call the typed HAL method, return first hit" convention.

use std::sync::Arc;

use crate::kernel::Kernel;

impl Kernel {
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
    // syscall short-circuit (sys_stat / sys_readdir / sys_write §5a /
    // sys_unlink §5a) reaches one of the `federation_peer_X`
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

    /// `sys_mkdir` arm — fires the SSOT peer's
    /// `NexusVFSService.Mkdir` to materialise the directory on the
    /// peer's LocalConnector (host fs side effect).
    ///
    /// Unlike `federation_peer_write` / `federation_peer_delete_file`
    /// (whose callers DEFER ENTIRELY to the peer because the result
    /// is BYTES on the SSOT side), the `sys_mkdir` caller invokes
    /// this as a SUPPLEMENT — see
    /// `feedback_defer_to_peer_only_for_byte_ops`.  The local
    /// metastore.put for the DT_DIR row STILL runs locally so the
    /// joiner's VFSRouter can route children of the new directory
    /// IMMEDIATELY (sub-second), without waiting for the peer's
    /// metastore.put to round-trip through raft apply.  Raft LWW
    /// dedupes the peer's mirror put against ours.
    ///
    /// Returns `true` when the dispatch succeeded.  `false` is a
    /// silent miss (no reachable voter / RPC error / Noop client) —
    /// caller's local-side path proceeds regardless.
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

    /// `sys_rename` arm — fires the SSOT peer's
    /// `NexusVFSService.Rename` so the peer's LocalConnector renames
    /// the host fs entry (and the peer's metastore.rename_path
    /// raft-proposes the metadata move on its side).
    ///
    /// SUPPLEMENT, not replacement — same rationale as
    /// `federation_peer_mkdir`: rename produces ROUTING state (new
    /// path → metadata + backend mapping), and the joiner's VFSRouter
    /// must observe the rename LOCALLY and IMMEDIATELY for any child
    /// op on the new path to route correctly.  The local
    /// `metastore.rename_path` runs in the caller alongside this
    /// peer-side fire; raft LWW dedupes the two metastore mutations
    /// on `modified_at_ms`.
    ///
    /// Returns `true` when the dispatch succeeded.  `false` is a
    /// silent miss (no reachable voter / RPC error / Noop client) —
    /// caller's local-side path proceeds regardless.
    #[inline]
    pub(crate) fn federation_peer_rename(
        &self,
        route: &crate::vfs_router::RouteResult,
        old_path: &str,
        new_path: &str,
    ) -> bool {
        self.dispatch_federation_peer::<(), _>(route, "rename", old_path, |client, addr| {
            client.rename(addr, old_path, new_path).map(|()| Some(()))
        })
        .is_some()
    }

    /// `sys_setattr` UPDATE arm — fires the SSOT peer's
    /// `NexusVFSService.Setattr` so the peer's metastore.put for the
    /// DT_REG row commits authoritatively on the SSOT side.  Used
    /// for the entry_type=0 (UPDATE/upsert DT_REG) branch only;
    /// DT_MOUNT / DT_PIPE / DT_STREAM / DT_DIR / DT_LINK setattr
    /// branches are node-local (driver wiring, IPC endpoints,
    /// directory inodes, VFS-internal symlinks) and do not cross
    /// machine boundaries.
    ///
    /// SUPPLEMENT, not replacement — same rationale as
    /// `federation_peer_mkdir`: setattr produces metadata that the
    /// joiner's VFSRouter / dcache must observe LOCALLY and
    /// IMMEDIATELY for subsequent reads of the path to see the
    /// updated row.  The local `metastore.put` runs in the caller
    /// alongside this peer-side fire; raft LWW dedupes on
    /// `modified_at_ms`.
    ///
    /// Returns `true` when the dispatch succeeded.  `false` is a
    /// silent miss (no reachable voter / RPC error / Noop client) —
    /// caller's local-side path proceeds regardless.
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
}
