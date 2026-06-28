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
        let target_zone = match route.target_zone_id.as_deref() {
            Some(z) => z,
            None => {
                // RouteResult without a target_zone_id reached the
                // federation dispatch branch — the routing layer marked
                // this as a federation-peer mount (caller checked
                // `route.is_federation_peer_mount()`) but didn't fill
                // in which zone owns the SSOT.  Indicates a routing-
                // table SSOT regression; warn-loud because the caller
                // (e.g., FUSE readdir) sees the resulting None as an
                // empty directory and operators can't tell from the
                // outside.
                tracing::warn!(
                    op = op_name,
                    path = %peer_path,
                    "federation peer dispatch: route is federation-peer-mount but \
                     target_zone_id is None — routing-table SSOT regression, caller \
                     will see empty result indistinguishable from a real empty dir"
                );
                return None;
            }
        };
        let peers = self.distributed_coordinator().zone_peers(self, target_zone);
        if peers.is_empty() {
            // `zone_peers` returned empty for a zone we believe is
            // federated.  Three concrete deployment shapes hit this:
            //   * The joiner hasn't actually joined the target zone yet
            //     (boot-replay timing, sidecar didn't run, root SOLO
            //     misconfig — see [[feedback_distributed_ssot]]).
            //   * `zone_peers` is computed against a stale conf state
            //     that doesn't yet contain the SSOT peer.
            //   * The zone exists locally but has 0 voters configured
            //     (federation never bootstrapped on this side).
            // All three present to the caller as "directory is empty"
            // — exactly the Mac↔Win Direction-A wedge signature.
            // Surface at warn-level so operators can grep this single
            // line without enabling per-module trace logging.
            tracing::warn!(
                op = op_name,
                target_zone = %target_zone,
                path = %peer_path,
                "federation peer dispatch: zone_peers returned empty — caller will \
                 see empty result indistinguishable from a real empty dir; check that \
                 the joiner actually joined this zone (sidecar log + raft conf state)"
            );
            return None;
        }
        let self_addr = self.self_address.read().clone();
        let client = self.federation_peer_client_arc();
        let mut errors: Vec<String> = Vec::new();
        let mut attempted = 0usize;
        for peer_addr in &peers {
            if let Some(ref s) = self_addr {
                if s == peer_addr {
                    continue;
                }
            }
            attempted += 1;
            match op(&client, peer_addr) {
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
                    errors.push(format!("{peer_addr}: {e}"));
                }
            }
        }
        // Fell through every voter without a hit.  Distinguish three
        // sub-cases so operators can act:
        //   * `attempted == 0` — every voter in `peers` was self_addr
        //     (single-node federation arrangement; dispatch is
        //     impossible until a peer actually joins).
        //   * `errors.len() == attempted` — every non-self voter's
        //     RPC errored (network / cert / WinFsp-side panic).
        //     Surface at warn so it isn't lost in debug noise.
        //   * Otherwise — every non-self voter returned Ok(None),
        //     i.e., they all legitimately don't have the entry
        //     (true miss; remain debug-level — high-volume normal case).
        if attempted == 0 {
            tracing::warn!(
                op = op_name,
                target_zone = %target_zone,
                path = %peer_path,
                voters = peers.len(),
                "federation peer dispatch: all voters resolved to self_addr — no peer \
                 to dispatch to; caller will see empty result"
            );
        } else if errors.len() == attempted {
            tracing::warn!(
                op = op_name,
                target_zone = %target_zone,
                path = %peer_path,
                attempted,
                errors = %errors.join(" | "),
                "federation peer dispatch: every non-self voter's RPC failed; caller \
                 will see empty result indistinguishable from a real empty dir"
            );
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

#[cfg(test)]
mod tests {
    //! Behavioral pins for `dispatch_federation_peer` — the SSOT
    //! helper every federation-peer syscall (readdir / stat / write /
    //! delete_file / rmdir / mkdir / rename / setattr) goes through.
    //!
    //! The seven scenarios below pin the three silent-failure code
    //! paths the observability warn-lines name, plus the three
    //! happy-path returns.  If any of these regresses, an operator
    //! loses ground-truth signal in the next Mac↔Win Direction-A
    //! re-investigation — exactly the failure mode that led to the
    //! wrong-hypothesis loop closed by PR #93.

    use std::sync::{Arc, Mutex};

    use crate::core::vfs_router::RouteResult;
    use crate::federation::test_support::build_kernel_with_peers;
    use crate::hal::federation_peer::FederationPeerClient;

    /// Construct a `RouteResult` shaped like a federation-peer mount
    /// (`target_zone_id = Some(...)`) for the dispatch helper to
    /// iterate over.  All other fields take harmless defaults — the
    /// dispatch helper only reads `target_zone_id`.
    fn fed_route(target_zone: Option<&str>) -> RouteResult {
        RouteResult {
            mount_point: "/sharedzone/cc-tasks/founder".into(),
            backend_path: String::new(),
            zone_id: "sharedzone".into(),
            is_external: false,
            is_cas: false,
            metastore: None,
            backend: None,
            target_zone_id: target_zone.map(|s| s.to_string()),
        }
    }

    type DispatchClosure<T> =
        Box<dyn FnMut(&Arc<dyn FederationPeerClient>, &str) -> Result<Option<T>, String>>;

    /// Shared call recorder — every invocation of the dispatch closure
    /// pushes the `peer_addr` it was called with.  Lets each test
    /// assert which peers were actually iterated (loop-back skip,
    /// all-errors, early-return on first hit).
    type CallRecorder = Arc<Mutex<Vec<String>>>;

    fn new_recorder() -> CallRecorder {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn recorded(rec: &CallRecorder) -> Vec<String> {
        rec.lock().expect("recorder mutex").clone()
    }

    /// Build a dispatch closure with explicit per-peer-address results.
    /// `responses` is `(peer_addr, Result<Option<T>, String>)`; unmatched
    /// addresses default to `Ok(None)` (treated as a legit miss).
    fn closure_with_responses<T: Clone + 'static>(
        responses: Vec<(String, Result<Option<T>, String>)>,
        rec: CallRecorder,
    ) -> DispatchClosure<T> {
        Box::new(move |_client, addr| {
            rec.lock().expect("recorder mutex").push(addr.to_string());
            responses
                .iter()
                .find(|(a, _)| a == addr)
                .map(|(_, r)| r.clone())
                .unwrap_or(Ok(None))
        })
    }

    /// Failure path (a): `route.target_zone_id == None`.  Caller's
    /// `is_federation_peer_mount` check let it slip through to dispatch
    /// but the routing entry never filled in `target_zone_id` — must
    /// short-circuit None without consulting peers or invoking the op.
    #[test]
    fn dispatch_target_zone_none_returns_none_without_invoking_op() {
        let k = build_kernel_with_peers(Some("self:1"), Vec::<String>::new());
        let route = fed_route(None);
        let rec = new_recorder();
        let closure = closure_with_responses::<()>(Vec::new(), Arc::clone(&rec));
        let result = k.dispatch_federation_peer::<(), _>(&route, "readdir", "/x", closure);
        assert!(result.is_none(), "target_zone_id=None must yield None");
        let calls = recorded(&rec);
        assert!(
            calls.is_empty(),
            "op closure must NOT be invoked when target_zone_id is None; got {calls:?}"
        );
    }

    /// Failure path (b): `zone_peers` returns empty.  Joiner-not-joined
    /// / stale-conf / 0-voter-zone shape — must short-circuit None
    /// without invoking the op even once.
    #[test]
    fn dispatch_empty_zone_peers_returns_none_without_invoking_op() {
        let k = build_kernel_with_peers(Some("self:1"), Vec::<String>::new());
        let route = fed_route(Some("sharedzone"));
        let rec = new_recorder();
        let closure = closure_with_responses::<u32>(Vec::new(), Arc::clone(&rec));
        let result = k.dispatch_federation_peer::<u32, _>(&route, "stat", "/y", closure);
        assert!(result.is_none(), "empty peers must yield None");
        let calls = recorded(&rec);
        assert!(
            calls.is_empty(),
            "op closure must NOT be invoked when peers list is empty; got {calls:?}"
        );
    }

    /// Failure path (c): every non-self voter errors.  Dispatch must
    /// iterate every non-self peer, accumulate errors, and return None.
    #[test]
    fn dispatch_all_peers_err_iterates_all_then_returns_none() {
        let k = build_kernel_with_peers(Some("self:1"), ["self:1", "peer:a", "peer:b"]);
        let route = fed_route(Some("sharedzone"));
        let rec = new_recorder();
        let closure = closure_with_responses::<()>(
            vec![
                ("peer:a".to_string(), Err("connect refused".into())),
                ("peer:b".to_string(), Err("tls handshake failed".into())),
            ],
            Arc::clone(&rec),
        );
        let result = k.dispatch_federation_peer::<(), _>(&route, "readdir", "/p", closure);
        assert!(result.is_none(), "all-peers-error must yield None");
        assert_eq!(
            recorded(&rec),
            vec!["peer:a".to_string(), "peer:b".to_string()],
            "self:1 must be loop-back-skipped; every non-self peer must be \
             attempted exactly once and in the order zone_peers returned them"
        );
    }

    /// Sub-case of (c): every peer in `zone_peers` resolves to
    /// `self_addr` — loop-back guard skips all of them, the op closure
    /// is never invoked, and the helper returns None.  Tracks the
    /// "single-node arrangement" warn line.
    #[test]
    fn dispatch_all_peers_are_self_addr_skips_all_then_returns_none() {
        let k = build_kernel_with_peers(Some("self:1"), ["self:1", "self:1"]);
        let route = fed_route(Some("sharedzone"));
        let rec = new_recorder();
        let closure = closure_with_responses::<()>(Vec::new(), Arc::clone(&rec));
        let result = k.dispatch_federation_peer::<(), _>(&route, "mkdir", "/q", closure);
        assert!(
            result.is_none(),
            "all-voters-are-self must yield None (no peer to dispatch to)"
        );
        let calls = recorded(&rec);
        assert!(
            calls.is_empty(),
            "op closure must NOT be invoked when every voter is self_addr; got {calls:?}"
        );
    }

    /// Happy path: first non-self peer returns `Ok(Some(v))` — dispatch
    /// returns that value immediately without trying subsequent peers.
    #[test]
    fn dispatch_first_peer_hit_short_circuits_with_value() {
        let k = build_kernel_with_peers(Some("self:1"), ["self:1", "peer:a", "peer:b"]);
        let route = fed_route(Some("sharedzone"));
        let rec = new_recorder();
        let closure = closure_with_responses::<u64>(
            vec![
                ("peer:a".to_string(), Ok(Some(42u64))),
                ("peer:b".to_string(), Ok(Some(99u64))),
            ],
            Arc::clone(&rec),
        );
        let result = k.dispatch_federation_peer::<u64, _>(&route, "stat", "/r", closure);
        assert_eq!(
            result,
            Some(42),
            "first-hit short-circuit must return peer:a's Ok(Some(42)), not peer:b's"
        );
        assert_eq!(
            recorded(&rec),
            vec!["peer:a".to_string()],
            "peer:b must NOT be queried once peer:a returns Ok(Some(_))"
        );
    }

    /// Happy path: a peer returns `Ok(None)` (legit miss) — dispatch
    /// continues to the next peer.  This is the "no warn" sub-case of
    /// the all-fall-through return — true miss, no operator action.
    #[test]
    fn dispatch_ok_none_continues_to_next_peer() {
        let k = build_kernel_with_peers(Some("self:1"), ["peer:a", "peer:b"]);
        let route = fed_route(Some("sharedzone"));
        let rec = new_recorder();
        let closure = closure_with_responses::<String>(
            vec![
                ("peer:a".to_string(), Ok(None)),
                ("peer:b".to_string(), Ok(Some("found".to_string()))),
            ],
            Arc::clone(&rec),
        );
        let result = k.dispatch_federation_peer::<String, _>(&route, "stat", "/s", closure);
        assert_eq!(
            result.as_deref(),
            Some("found"),
            "peer:a's Ok(None) must be treated as miss-and-try-next, surfacing peer:b's value"
        );
        assert_eq!(
            recorded(&rec),
            vec!["peer:a".to_string(), "peer:b".to_string()],
            "both peers must be queried in zone_peers order; peer:b's value must surface"
        );
    }

    /// Mixed path: some peers err, some return Ok(None), one returns
    /// Ok(Some) later in the list — dispatch must surface the hit and
    /// iterate up to it (no further).
    #[test]
    fn dispatch_mixed_err_then_ok_none_then_hit_surfaces_hit() {
        let k = build_kernel_with_peers(
            Some("self:1"),
            ["self:1", "peer:a", "peer:b", "peer:c", "peer:d"],
        );
        let route = fed_route(Some("sharedzone"));
        let rec = new_recorder();
        let closure = closure_with_responses::<u8>(
            vec![
                ("peer:a".to_string(), Err("503".into())),
                ("peer:b".to_string(), Ok(None)),
                ("peer:c".to_string(), Ok(Some(7u8))),
            ],
            Arc::clone(&rec),
        );
        let result = k.dispatch_federation_peer::<u8, _>(&route, "write", "/t", closure);
        assert_eq!(result, Some(7), "peer:c's hit must surface");
        assert_eq!(
            recorded(&rec),
            vec![
                "peer:a".to_string(),
                "peer:b".to_string(),
                "peer:c".to_string()
            ],
            "iteration must stop at peer:c — peer:d MUST NOT be queried after a hit"
        );
    }
}
