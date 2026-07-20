//! Concrete `DistributedCoordinator` implementation.
//!
//! `RaftDistributedCoordinator` is the raft-crate impl of the
//! `DistributedCoordinator` trait the kernel exposes. The Cargo edge
//! runs `raft → kernel`; the kernel installs an
//! `Arc<dyn DistributedCoordinator>` into its `federation` slot from
//! the binary boot path, and federation-aware syscalls dispatch through
//! the trait.
//!
//! ## Provider shape
//!
//! `RaftDistributedCoordinator` owns the federation-side state:
//!
//! * `Arc<ZoneManager>` — per-zone Raft groups + gRPC server.
//! * `Arc<ZoneRaftRegistry>` — zone-id → ZoneConsensus lookup.
//! * `tokio::runtime::Handle` — kernel-shared runtime for raft proposes.
//! * `mount_reconciliation_done` — the "federation bootstrap finished"
//!   atomic flag previously read by `/healthz/ready`.
//!
//! Trait methods receive `kernel: &Kernel` so they can reach kernel-side
//! primitives (vfs_router, dcache, peer_client, set_self_address) without
//! holding back-references; the provider only owns the raft-side state.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use contracts::lock_state::Locks;
use dashmap::DashMap;
use kernel::abc::meta_store::MetaStore;
use kernel::abc::object_store::BackendStat;
use kernel::core::vfs_router::canonicalize_mount_path as canonicalize;
use kernel::federation::grpc_ops::FederationGrpcOps;
use kernel::hal::distributed_coordinator::{
    ClusterInfo, CoordinatorResult, DistributedCoordinator, ShareInfo,
};
use kernel::kernel::Kernel;

use crate::transport::NodeAddress;
use crate::zone_meta_store::ZoneMetaStore;
use crate::{ZoneHandle, ZoneManager};

/// Node-level random ID filename — opaque random u64 minted at first
/// daemon boot, persisted across restarts, regenerated after a wipe.
///
/// Format: 8 bytes BE u64.  Absent = fresh daemon — mint a new ID
/// and persist.  Present = restart — reuse the persisted ID.
///
/// Architecture: `docs/architecture/federation-memo.md` § 6.3.1.
const NODE_ID_FILE: &str = ".node_id";

/// Cadence for `bootstrap_or_join_zone`'s JoinZone retry loop when
/// every peer in NEXUS_PEERS is unreachable.  Indefinite by design —
/// the daemon waits for the operator to bring up the first peer with
/// `NEXUS_BOOTSTRAP_NEW=1`; any deadline here would just make the
/// failure mode "silently exit on misconfig" instead of "stay up and
/// retry".
const JOIN_ZONE_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Per-attempt timeout for the JoinZone RPC during bootstrap.
const JOIN_ZONE_RPC_TIMEOUT_SECS: u64 = 5;
const FOUNDER_REJOIN_PROBE_ATTEMPTS: u32 = 3;

/// Upper bound on the post-`JoinZone` wait for the joiner's local
/// raft state machine to receive + apply the leader's first
/// AppendEntries.  Bounds offline `nexusd-cluster join` so a stuck
/// leader / lossy network terminates the CLI with a clear error
/// rather than silently writing a half-baked data dir.  10 s easily
/// covers the typical 10 ms tick + replication round-trip; a stalled
/// AppendEntries past that point is operator-actionable.
const JOIN_ZONE_APPLY_WAIT: Duration = Duration::from_secs(10);
const JOIN_ZONE_APPLY_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Triple keyed by target zone: `(parent_zone_id, mount_path, global_path)`.
type CrossZoneMountTuple = (String, String, String);

/// Raft-backed `DistributedCoordinator` impl.
///
/// All state is `OnceLock` so the provider is `Send + Sync + 'static`
/// without interior mutability noise.  [`Self::install_with_kernel`]
/// populates the slots; subsequent calls observe a stable snapshot.
pub struct RaftDistributedCoordinator {
    zone_manager: OnceLock<Arc<ZoneManager>>,
    runtime: OnceLock<tokio::runtime::Handle>,
    bootstrap_done: AtomicBool,
    /// Reverse index `target_zone_id → [(parent_zone, mount_path, global_path)]`
    /// — derived cache for `wire_mount` reconstruction logic, populated as
    /// federation mounts get wired.  Node-local: replication SSOT lives in
    /// the DT_MOUNT entries on the metastore, this is only a fast-lookup
    /// shadow; rebuilt from scratch on process restart by the reconcile loop.
    ///
    /// Wrapped in `Arc` so the apply-cb closures (one per parent zone)
    /// can capture a cheap clone — they can't borrow from `&self`.
    cross_zone_mounts: Arc<DashMap<String, Vec<CrossZoneMountTuple>>>,
    /// Per-peer typed-RPC client used by `peer_*` to dispatch
    /// `NexusVFSService.{Read,Write,Stat,Readdir,Delete,Mkdir,Rename,Setattr}`
    /// against zone voters.  Set by `install_with_kernel`; unset means
    /// the coordinator's `peer_*` impls warn-loud and return None
    /// (every dispatch surfaces as a silent miss via the PR #94
    /// observability path — caller's empty-result fallback fires).
    grpc_ops: OnceLock<Arc<dyn FederationGrpcOps>>,
}

impl RaftDistributedCoordinator {
    pub fn new() -> Self {
        Self {
            zone_manager: OnceLock::new(),
            runtime: OnceLock::new(),
            bootstrap_done: AtomicBool::new(false),
            cross_zone_mounts: Arc::new(DashMap::new()),
            grpc_ops: OnceLock::new(),
        }
    }

    /// Canonical boot wiring for the cluster-profile binary
    /// (`nexusd-cluster`).
    ///
    /// Wires this provider against an already-built kernel, zone
    /// manager, and tokio runtime, then activates every DT_MOUNT
    /// entry on disk, publishes the kernel's federation self-address,
    /// hands the blob-fetcher slot to the raft gRPC server, and marks
    /// the coordinator initialised.  Idempotent.
    ///
    /// Without this method:
    ///   * the DT_MOUNT apply-cb is never installed on `root` (or any
    ///     other loaded zone) — DT_MOUNT entries committed via
    ///     `share --mount-at` / `join` / `apply_topology` write into
    ///     raft state but never make it into [`VFSRouter`];
    ///   * the kernel's `self_address` slot stays `None`, so every
    ///     write records `last_writer_address = None` and federation
    ///     reads on other nodes fail the `try_remote_fetch` origin
    ///     check before any RPC fires;
    ///   * the raft gRPC server's `BlobFetcherSlot` stays empty, so
    ///     ZoneApi/ReadBlob can't serve content even when peers know
    ///     where to fetch from;
    ///   * `bootstrap_done` stays `false`, so [`Self::is_initialized`]
    ///     reports the coordinator unready and `Kernel::setattr_mount`
    ///     silently falls through to self-bootstrap on operator
    ///     `mount source-addr:/zone /local` requests.
    ///
    /// The outbound side (`Kernel::peer_client`, i.e. the
    /// `PeerBlobClient` impl peers use to actually pull bytes) is
    /// wired separately by the caller via
    /// `transport::peer_blob::install`, kept out of this method
    /// because the `transport` crate sits above `raft` in the dep
    /// graph.
    ///
    /// Caller invariants:
    ///   * `zm.list_zones()` already includes every zone whose mounts
    ///     should be replayed — call this **after** the
    ///     restart/bootstrap dispatch that loads zones from disk.
    ///   * `runtime` is the tokio runtime that owns the zone manager's
    ///     transport loops (typically `zm.runtime_handle()`).
    ///   * `self_address` matches the address other nodes will use to
    ///     reach this node's raft / blob-fetch RPCs (typically
    ///     `<hostname>:<bind_port>`).
    pub fn install_with_kernel(
        self: &Arc<Self>,
        zm: Arc<ZoneManager>,
        runtime: tokio::runtime::Handle,
        self_address: &str,
        kernel: &Arc<Kernel>,
        grpc_ops: Arc<dyn FederationGrpcOps>,
    ) {
        // Slots are `OnceLock`; second-set silently drops, so calling
        // this twice with the same wiring is a no-op rather than an
        // error.
        let _ = self.zone_manager.set(zm.clone());
        let _ = self.runtime.set(runtime);
        let _ = self.grpc_ops.set(grpc_ops);

        // Federation self-identity — every subsequent write records
        // `last_writer_address`, the origin pointer that powers
        // `Kernel::try_remote_fetch` on peers.
        kernel.set_self_address(self_address);

        // Hand the raft gRPC server's `BlobFetcherSlot` up to the
        // kernel; `blob_fetcher_handler::install` below drains it and
        // wires the kernel-backed `KernelBlobFetcher` that serves
        // ZoneApi/ReadBlob.
        kernel.stash_blob_fetcher_slot(Box::new(zm.blob_fetcher_slot()));

        // Apply-cb install on every loaded zone — root, federation
        // zones from `NEXUS_FEDERATION_ZONES`, zones restored from
        // disk after restart.  `install_apply_cb_for_zone` bakes the
        // DT_MOUNT replay scan into the install (atomic "install +
        // catch up" semantics — see its docstring) so we don't need
        // a separate `replay_existing_mounts` call after the loop.
        for zone_id in zm.list_zones() {
            self.install_apply_cb_for_zone(kernel, &zone_id);
        }

        // Drain the pending blob-fetcher slot stashed above and bind
        // the kernel-backed `KernelBlobFetcher` to the raft gRPC
        // server's slot so peer ReadBlob RPCs route through this
        // node's VFSRouter.
        crate::blob_fetcher_handler::install(kernel);

        // Mark the coordinator initialised — `is_initialized()` reads
        // this flag, and `Kernel::setattr_mount` gates the operator-
        // driven joiner branch (`mount source-addr:/zone /path`) on it.
        // Without this store the cluster binary's coordinator never
        // reports ready and that branch silently falls through to
        // self-bootstrap semantics — same failure class as the
        // `last_writer_address` gap closed above.
        self.bootstrap_done.store(true, Ordering::Release);

        // Wire the kernel's `DistributedCoordinator` slot to this
        // provider — every accessor `kernel.distributed_coordinator()`
        // (sys_setattr DT_MOUNT's `federation_active`, the WAL stream
        // metastore lookup, `sys_read`'s cold cross-node fan-out via
        // `zone_peers`, the procfs `/__sys__/zones` synthesiser, …)
        // resolves through this slot.  Mirrors `set_peer_client`
        // (wired separately by `transport::peer_blob::install`); both
        // are required for the kernel's federation surface to behave.
        //
        // Done LAST so the federation-active guard above flips at the
        // same moment the slot becomes the real impl — callers polling
        // `is_initialized()` never observe a "ready but routes still
        // through Noop" half-state where create_zone / zone_peers /
        // metastore_for_zone return errors / empties.
        //
        // Federation E2E never exercised this path because its workflow
        // resolves cross-node reads through `Kernel::peer_client`'s
        // `try_remote_fetch` (slot wired separately by
        // `transport::peer_blob::install`); the kernel's DC slot
        // accessors aren't on that hot path.  cc-tasks-share's
        // host-fs-direct write workflow is the first to hit the cold
        // cross-node fan-out arm (`sys_read → zone_peers`), surfacing
        // the missing wiring.
        kernel.set_distributed_coordinator(Arc::clone(self) as Arc<dyn DistributedCoordinator>);
    }

    fn zm(&self) -> Option<&Arc<ZoneManager>> {
        self.zone_manager.get()
    }

    /// Install the DT_MOUNT apply-cb on `zone_id`'s consensus AND
    /// catch up on any DT_MOUNT entries already applied to the state
    /// machine.  Atomic "install + catch up" semantics — callers can
    /// never forget the pairing because the function does both.
    ///
    /// Why both: the apply-cb only fires on FUTURE log applies, but
    /// snapshots-from-leader (`join_cluster`) and disk-restore at
    /// boot deliver DT_MOUNT entries that applied BEFORE the cb was
    /// installed.  Without the catch-up scan, every cross-node
    /// sys_readdir / sys_stat / sys_unlink / sys_write against a
    /// snapshot-delivered federation mount silently fell through to
    /// root.  This was the cc-tasks-share Docker E2E regression
    /// fixed in PR #72 — originally as explicit
    /// `replay_existing_mounts` calls in each caller, then DRY'd
    /// into the install function so the bug is impossible to
    /// reintroduce.
    ///
    /// Idempotent: the apply-cb install replaces any existing
    /// closure on the same `coherence_id`; the replay's
    /// `wire_mount_core` no-ops on entries whose route is already
    /// installed (`vfs_router.has(...)` guard).
    fn install_apply_cb_for_zone(&self, kernel: &Kernel, zone_id: &str) {
        let Some(zm) = self.zm() else {
            return;
        };
        let Some(runtime) = self.runtime.get() else {
            return;
        };
        let Some(consensus) = zm.registry().get_node(zone_id) else {
            tracing::debug!(zone_id = %zone_id, "install_apply_cb_for_zone: zone not loaded yet");
            return;
        };
        let vfs_router = kernel.vfs_router_arc();
        let lock_manager = kernel.lock_manager_arc();
        install_mount_apply_cb_impl(
            &vfs_router,
            &lock_manager,
            &zm.registry(),
            runtime,
            &self.cross_zone_mounts,
            zone_id,
            &consensus,
        );
        // Catch up on past-applied DT_MOUNT entries.  `replay_existing_mounts`
        // scans every loaded zone (necessary for nested federation mounts
        // where a child needs its parent wired first — the function's
        // topological retry loop handles that ordering).  Calling it
        // per-zone here is redundant at boot when the loop calls us many
        // times, but the redundancy is bounded (M zones × N entries, each
        // wire_mount_core call is an O(1) DashMap lookup + early-out via
        // `vfs_router.has`) and the alternative — a non-atomic
        // "install + remember to replay" contract that join_cluster
        // forgot — is what shipped the original regression.  SSOT
        // alternative was rejected because per-zone replay can't
        // satisfy the cross-zone topological retry requirement.
        self.replay_existing_mounts(kernel);
    }

    /// Re-wire every DT_MOUNT entry already applied in any zone's state
    /// machine.  The apply-cb only fires on NEW raft applies, so without
    /// this replay a restart leaves restored mounts unwired in VFSRouter
    /// / DCache — followers fail every cross-zone read until the next
    /// fresh DT_MOUNT lands.  Topological retry handles parent→child
    /// ordering (a nested mount can't wire until its parent's mount is
    /// in `cross_zone_mounts`).
    ///
    /// State-machine catchup contract: `ZoneConsensus::iter_dt_mount_entries`
    /// uses `try_read` on the async state-machine RwLock, returning an
    /// empty Vec on contention — indistinguishable from "no DT_MOUNTs
    /// exist".  At boot on a restart, the driver loop is actively
    /// applying the entries restored from storage; if we scan during
    /// that window every try_read loses and `pending` ends up empty
    /// against a zone whose state machine actually holds DT_MOUNTs.  No
    /// retry mechanism above this catches it — `apply_topology` only
    /// processes the `pending_mounts` set populated from
    /// `NEXUS_FEDERATION_MOUNTS`, not restored entries.  So a restart
    /// silently boots a daemon whose `/shared` route is missing and
    /// every cross-zone read returns "found=false" until the operator
    /// notices and triggers a fresh mount.
    ///
    /// Wait for `applied_index >= commit_index` (state machine has
    /// applied everything the storage marked committed) before scanning.
    /// At that point the apply pass is done, no write lock is held by
    /// the driver, and the entry set is the truth.  Capped at 10s so a
    /// genuinely-stuck zone surfaces a warning rather than blocking boot.
    fn replay_existing_mounts(&self, kernel: &Kernel) {
        let Some(zm) = self.zm() else {
            return;
        };
        let Some(runtime) = self.runtime.get() else {
            return;
        };
        let registry = zm.registry();
        let vfs_router = kernel.vfs_router_arc();
        let lock_manager = kernel.lock_manager_arc();

        let mut pending: Vec<(String, String, String)> = Vec::new();
        for zone_id in zm.list_zones() {
            let Some(consensus) = registry.get_node(&zone_id) else {
                continue;
            };
            wait_for_state_machine_caught_up(
                &consensus,
                &zone_id,
                std::time::Duration::from_secs(10),
            );
            let entries = consensus.iter_dt_mount_entries(runtime).unwrap_or_default();
            for (key, target_zone_id) in entries {
                pending.push((zone_id.clone(), key, target_zone_id));
            }
        }

        if pending.is_empty() {
            return;
        }
        tracing::info!(
            count = pending.len(),
            "replay_existing_mounts: scanning DT_MOUNT entries"
        );

        // Topological retry: a nested mount needs its parent's
        // cross_zone_mounts entry to reconstruct the global path.  Cap
        // rounds at pending.len()+1 so a misconfigured cycle errors
        // instead of looping forever.
        let max_rounds = pending.len() + 1;
        for _ in 0..max_rounds {
            if pending.is_empty() {
                break;
            }
            let mut progressed = false;
            pending.retain(|(parent_zone_id, mount_path, target_zone_id)| {
                let r = wire_mount_core(
                    &vfs_router,
                    &lock_manager,
                    &registry,
                    runtime,
                    &self.cross_zone_mounts,
                    parent_zone_id,
                    mount_path,
                    target_zone_id,
                );
                match r {
                    Ok(()) => {
                        if self.cross_zone_mounts.contains_key(target_zone_id) {
                            progressed = true;
                            false // wired — drop from pending
                        } else {
                            true // wire_mount_core deferred (parent not ready) — retry
                        }
                    }
                    Err(_) => false, // permanent failure — give up
                }
            });
            if !progressed {
                break;
            }
        }
        if !pending.is_empty() {
            tracing::warn!(
                pending = pending.len(),
                "replay_existing_mounts: {} entries left unwired (likely missing parent zone)",
                pending.len(),
            );
        }
    }
}

impl Default for RaftDistributedCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl RaftDistributedCoordinator {
    /// Generic per-syscall federation-peer dispatch.
    ///
    /// Iterates non-self voters of `target_zone` (via the trait's own
    /// `zone_peers` accessor — same SSOT raft uses elsewhere) and runs
    /// `op` against each one with the installed grpc_ops arc + the
    /// peer address.  The closure encodes which typed `NexusVFSService`
    /// method to call.  Returns the first successful hit; transport
    /// errors are logged at debug and the next peer is tried.
    ///
    /// Returns `None` when:
    ///   * grpc_ops is not installed (coordinator was constructed via
    ///     `new()` but `install_with_kernel` was never called — caller
    ///     sees the silent miss with a warn-level log line);
    ///   * the zone has no peers loaded yet (federation discovery
    ///     pending — caller falls through to local not-found);
    ///   * every peer errored or returned `Ok(None)` (no SSOT-side
    ///     copy of the path under any voter).
    ///
    /// PR #94 observability — every silent-failure path emits a
    /// `tracing::warn!` line that an operator can grep for without
    /// enabling per-module trace logging.  Three failure shapes are
    /// distinguished:
    ///   * `grpc_ops not installed`
    ///   * `zone_peers returned empty`
    ///   * `every non-self voter's RPC failed`
    fn dispatch_to_peers<T, F>(
        &self,
        kernel: &Kernel,
        op_name: &'static str,
        target_zone: &str,
        peer_path: &str,
        op: F,
    ) -> Option<T>
    where
        F: FnMut(&Arc<dyn FederationGrpcOps>, &str) -> Result<Option<T>, String>,
    {
        let Some(client) = self.grpc_ops.get() else {
            tracing::warn!(
                op = op_name,
                target_zone = %target_zone,
                path = %peer_path,
                "federation peer dispatch: grpc_ops not installed in coordinator — caller \
                 will see empty result indistinguishable from a real empty dir; check that \
                 `install_with_kernel` was called with a real FederationGrpcOps impl"
            );
            return None;
        };
        let peers = self.zone_peers(kernel, target_zone);
        let self_addr = kernel.self_address_string();
        dispatch_to_peer_addrs(
            client,
            op_name,
            target_zone,
            peer_path,
            &peers,
            self_addr.as_deref(),
            op,
        )
    }
}

/// Per-syscall federation-peer iteration loop — pure function over an
/// already-resolved peer list.
///
/// Split out of [`RaftDistributedCoordinator::dispatch_to_peers`] so the
/// observability surface (the three PR #94 silent-miss `tracing::warn!`
/// paths) and the first-hit-wins iteration semantics can be pinned
/// directly in unit tests without standing up a `ZoneManager` /
/// `Kernel` fixture.  The wrapper on the coordinator handles the slot
/// + zone_peers lookups; this function handles the loop.
fn dispatch_to_peer_addrs<T, F>(
    client: &Arc<dyn FederationGrpcOps>,
    op_name: &'static str,
    target_zone: &str,
    peer_path: &str,
    peers: &[String],
    self_addr: Option<&str>,
    mut op: F,
) -> Option<T>
where
    F: FnMut(&Arc<dyn FederationGrpcOps>, &str) -> Result<Option<T>, String>,
{
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
    let mut errors: Vec<String> = Vec::new();
    let mut attempted = 0usize;
    for peer_addr in peers {
        if let Some(s) = self_addr {
            if s == peer_addr {
                continue;
            }
        }
        attempted += 1;
        match op(client, peer_addr) {
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

// S3 Phase G (2026-07-05): the operator-declared `BootstrapMode` enum
// + `validate_bootstrap_mode` fn were deleted.  Boot decision-making
// is now the sole responsibility of `nexus_raft::bootstrap::plan_boot_action`,
// which reads the authoritative signals (`data_dir_has_root`,
// `identity.persisted_peers`, `identity.zones`, `--peers`,
// `NEXUS_FEDERATION_ZONES`/`_MOUNTS`) and dispatches deterministically.
// The two-layer decision model (this fn + `plan_boot_action`) was a
// documented contract-complexity smell: this fn rejected `--peers`
// combinations that Phase A's row 3 needed, silently disabling
// DiscoverZones-based fresh-joiner auto-discovery.  See
// `docs/federation-architecture.md` § 6.3.1 for the unified matrix.

/// Read the persisted node ID, or mint a fresh random one and persist it.
///
/// SSOT for raft node identity under the opaque-ID contract.  See
/// [`NODE_ID_FILE`] for the rationale and on-disk format.
///
/// First-ever boot (and post-`rm -rf $NEXUS_DATA_DIR` rejoin) lands
/// in the mint branch: `rand::random::<u64>()` produces a fresh ID,
/// retried once if it happens to be 0 (raft-rs reserves 0 as
/// "no node").  The mint is atomic — `write` to `<file>.tmp` then
/// `rename` to `<file>` — so a crash between sample and persist
/// either leaves the old ID intact or no file at all (next boot
/// re-mints).  Two daemons sharing a data dir would race here, but
/// that configuration is operator error: a single
/// `<NEXUS_DATA_DIR>` is bound to a single daemon.
/// Mint or load the node-identity file at `<zones_dir>/.node_id`.
///
/// Public so the cluster-profile binary's `run_daemon` boot path
/// shares this single SSOT for raft node identity.  See
/// `bootstrap_or_join_zone` for why opaque random IDs are required
/// under raft-rs 0.7's stale-`Progress` heartbeat invariant.
pub fn read_or_mint_node_id(zones_dir: &str) -> Result<u64, String> {
    use std::io::Write;

    let dir = Path::new(zones_dir);
    let final_path = dir.join(NODE_ID_FILE);

    match std::fs::read(&final_path) {
        Ok(bytes) => {
            let arr: [u8; 8] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("node id file '{}' is not 8 bytes", final_path.display()))?;
            let id = u64::from_be_bytes(arr);
            if id == 0 {
                return Err(format!(
                    "node id file '{}' contains 0 (reserved by raft-rs); \
                     wipe `<NEXUS_DATA_DIR>` and retry",
                    final_path.display(),
                ));
            }
            tracing::info!(local_node_id = id, "local_node_id loaded from disk");
            Ok(id)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("create zones dir for node id '{}': {e}", dir.display(),))?;
            // raft-rs reserves 0 as "no node" — retry once on the
            // astronomically rare 1/2^64 collision.
            let mut id = rand::random::<u64>();
            if id == 0 {
                id = rand::random::<u64>();
                if id == 0 {
                    return Err("rand::random() returned 0 twice".to_string());
                }
            }
            let tmp_path = dir.join(format!("{NODE_ID_FILE}.tmp"));
            {
                let mut tmp = std::fs::File::create(&tmp_path).map_err(|e| {
                    format!("create tmp node id file '{}': {e}", tmp_path.display())
                })?;
                tmp.write_all(&id.to_be_bytes())
                    .map_err(|e| format!("write tmp node id file '{}': {e}", tmp_path.display()))?;
                tmp.sync_all()
                    .map_err(|e| format!("sync tmp node id file '{}': {e}", tmp_path.display()))?;
            }
            std::fs::rename(&tmp_path, &final_path).map_err(|e| {
                format!(
                    "rename '{}' -> '{}': {e}",
                    tmp_path.display(),
                    final_path.display(),
                )
            })?;
            tracing::info!(local_node_id = id, "local_node_id minted and persisted");
            Ok(id)
        }
        Err(e) => Err(format!("read node id '{}': {e}", final_path.display())),
    }
}

/// Return the peer address book with any entry that resolves to
/// `self_address` removed, warning once per dropped entry.
///
/// Contract under PR #3996+: the peer address book lists OTHER nodes only.
/// Self joins the ConfState via `create_zone(self)` on the founder or
/// `AddNode(self)` on a joiner — never via the address book. A self-entry can
/// still appear two ways: an operator lists self in `NEXUS_PEERS`/`--peers`, or
/// a stale learned entry survives in the persisted identity (e.g. a node that
/// briefly learned its own advertise address round-trips it through
/// `persist_peers`). Either way it is a routing no-op at best and a
/// JoinZone-self stall at worst.
///
/// This EXCLUDES self and warns rather than refusing to boot. An earlier
/// version hard-failed to surface operator misconfiguration, but that made a
/// stale persisted self-entry BRICK a restart (the daemon could never boot
/// again without a manual identity edit) — a far worse failure than a filtered
/// warning. Excluding self is always the correct interpretation: self is never
/// a transport peer. Raft membership (self as a voter) lives in `ConfState` and
/// is untouched here — this shapes only the transport peer address book.
pub fn peers_excluding_self(peer_addrs: &[NodeAddress], self_address: &str) -> Vec<NodeAddress> {
    peer_addrs
        .iter()
        .filter(|peer| {
            let peer_hostport = peer
                .endpoint
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            if peer_hostport == self_address {
                tracing::warn!(
                    self_address,
                    "peer address book contains self — excluding it; self joins \
                     via bootstrap / AddNode-on-leader, not the address book \
                     (PR #3996 opaque-ID contract). A stale self-entry is \
                     filtered, not fatal."
                );
                false
            } else {
                true
            }
        })
        .cloned()
        .collect()
}

fn joiner_local_zone_peer_seeds(peer_addrs: &[NodeAddress]) -> Vec<String> {
    let mut seeds: Vec<String> = peer_addrs
        .iter()
        .map(NodeAddress::to_raft_peer_str)
        .collect();
    seeds.sort();
    seeds
}

/// Operator-facing projection of [`joiner_local_zone_peer_seeds`] — bare
/// `host:port` strings, no local `hostname_to_node_id` hash prefix.  Used
/// ONLY for tracing::info log fields at boot boundary; the actual peer
/// list passed to `ZoneManager::join_zone` still uses the raft-internal
/// `id@host:port` form because the address-book key derivation there
/// needs the authoritative-id round-trip.  Keeping them separate prevents
/// the leak class where operators / peer AIs read the log line and
/// mistake local `hostname_to_node_id(peer_addr)` output for a
/// "transport-auto-resolved remote node_id" — the two concepts share zero
/// state.
fn joiner_local_zone_peer_seeds_display(peer_addrs: &[NodeAddress]) -> Vec<String> {
    let mut seeds: Vec<String> = peer_addrs
        .iter()
        .map(NodeAddress::to_operator_str)
        .collect();
    seeds.sort();
    seeds
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmptyStorageBootstrapPlan {
    FoundImmediately,
    ProbePeersThenFound,
    JoinPeers,
}

fn empty_storage_bootstrap_plan(
    bootstrap_new: bool,
    peer_addrs: &[NodeAddress],
) -> EmptyStorageBootstrapPlan {
    if peer_addrs.is_empty() {
        EmptyStorageBootstrapPlan::FoundImmediately
    } else if bootstrap_new {
        EmptyStorageBootstrapPlan::ProbePeersThenFound
    } else {
        EmptyStorageBootstrapPlan::JoinPeers
    }
}

fn create_founder_zone(
    zm: &ZoneManager,
    zone_id: &str,
    node_id: u64,
    self_address: &str,
    bootstrap_new: bool,
    peers_empty: bool,
) -> Result<(), String> {
    tracing::info!(
        local_node_id = node_id,
        zone = %zone_id,
        self_address = %self_address,
        bootstrap_new,
        peers_empty,
        "founder path — creating 1-voter zone. Other nodes JoinZone here.",
    );
    // Founder self-registration: encode `{node_id}@{self_address}` so
    // `ZoneManager::create_zone`'s round-trip through
    // `NodeAddress::parse` recovers `node_id` verbatim (raft-internal
    // parse accepts the id-prefixed shape).  The operator-facing
    // `parse_operator_addr` rejects `@` — but this is a raft-internal
    // site with both authoritative inputs in hand.
    let self_peer = format!("{node_id}@{self_address}");
    zm.create_zone(zone_id, vec![self_peer])
        .map_err(|e| format!("create_zone({zone_id}): {e}"))
        .map(|_| ())
}

fn block_on_zone_manager<F>(zm: &ZoneManager, fut: F) -> F::Output
where
    F: std::future::Future,
{
    let handle = zm.runtime_handle();
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        handle.block_on(fut)
    }
}

fn remove_local_probe_zone(zm: &ZoneManager, zone_id: &str) {
    if zm.get_zone(zone_id).is_none() {
        return;
    }
    if let Err(e) = block_on_zone_manager(zm, zm.registry().remove_zone(zone_id)) {
        tracing::warn!(
            zone = %zone_id,
            error = %e,
            "founder rejoin probe cleanup failed before local create",
        );
    }
}

/// Block until the joiner's local raft state machine has received,
/// committed, and persisted the leader's first AppendEntries after
/// a successful `JoinZone` RPC.
///
/// Contract this enforces (and the SSOT for it):
///
/// The JoinZone RPC returns "success" the moment the leader's
/// `AddNode`/`AddLearnerNode` proposal commits on the leader's log.
/// At that instant the joiner's persisted on-disk state still
/// reflects the pre-join `skip_bootstrap=true` registration —
/// `peers=0`, no `leader_id`, no log entries.  Authoritative
/// `ConfState` only lands on the joiner's disk once raft-rs replays
/// the leader's append-entries through its `Ready` cycle: the
/// driver loop calls `apply_entries`, which invokes
/// `storage.set_conf_state(&cs)` synchronously for the conf-change
/// entry, then `update_cached_status` refreshes `cached_commit_index`
/// from `raft_log.committed`.  Order matters: `cached_commit_index`
/// transitions 0 → ≥1 AFTER the `set_conf_state` write returns Ok.
///
/// Without this gate, an offline `nexusd-cluster join` CLI that
/// returns immediately after the RPC ack leaves the data dir in a
/// "solo cluster of self" state.  The next daemon restart loads
/// the pre-snapshot state, treats the zone as 1-voter (self only),
/// and floods `raft: cannot step as peer not found` when the
/// leader's heartbeats finally arrive — because the leader was
/// never added to the joiner's `Progress` map.
///
/// Termination signal: `leader_id().is_some()` (we have heard from
/// the leader) AND `commit_index() > 0` (the apply pipeline has
/// completed at least one cycle, which by construction includes the
/// conf-change containing our membership — `applied_index` would be
/// the stricter signal but it only advances for data entries, since
/// `FullStateMachine::apply(Noop)` short-circuits past
/// `last_applied.store(...)`; conf-only commits stay invisible to
/// it).  The pair is what `bootstrap_or_join_zone`'s "snapshot has
/// installed authoritative ConfState locally" comment promised —
/// this function makes the claim true instead of aspirational.
/// Operator-experience integrity check on a loaded zone before
/// short-circuiting `bootstrap_or_join_zone` to "resume from ConfState".
///
/// **Resumability invariant (this commit ships condition (a) only — see
/// commit body for (b)/(c) follow-up):**
///
/// (a) `last_log_index() >= 1` — every successful raft bootstrap or join
///     advances log_last past 0.  Founder writes `AddNode(self)` to log
///     index 1 during bootstrap (nexus-vfs#33).  Joiner receives the
///     leader's snapshot (which sets log_last to `snapshot.last_included_index`)
///     or the AppendEntries containing the AddNode/AddLearnerNode entry —
///     either way log_last lands at >= 1 by the time a successful join
///     CLI exits.  A zone whose log_last is still 0 at daemon restart
///     means the ConfState was persisted but the log entries that
///     followed were not — the half-installed state that wedged the
///     Mac↔Win L1 smoke for 8 hours.
///
/// Returns `Ok(())` when state is safely resumable, `Err(reason)`
/// otherwise.  Caller decides whether to refuse-and-error (daemon
/// restart with no peers — operator must repair) or fall-through to
/// re-JoinZone (CLI invocation with peer addresses).
fn check_zone_resumable(zh: &ZoneHandle) -> Result<(), String> {
    check_zone_resumable_from_indices(zh.last_log_index())
}

/// Pure-data variant for unit testing — the integrity invariants do
/// not depend on anything that isn't already an atomic-cached scalar
/// on `ZoneHandle`, so the check is reducible to a function over those
/// scalars.
///
/// Public so the `nexusd-cluster doctor` subcommand can cross-check
/// every persisted zone against the same invariant Branch 1 uses
/// (single SSOT for "resumable state").
pub fn check_zone_resumable_from_indices(last_log_index: u64) -> Result<(), String> {
    if last_log_index == 0 {
        return Err(
            "log_last_index = 0 (no persisted entries); ConfState may exist on disk \
             but no log entry has been fsynced past it — the half-installed state \
             that follows a crashed `nexusd-cluster join` between snapshot install \
             and log fsync"
                .to_string(),
        );
    }
    Ok(())
}

/// Block until the zone's state machine has applied every entry the
/// storage marked committed (i.e. `applied_index >= commit_index`), or
/// the timeout elapses.
///
/// SSOT precondition for sync readers of the state machine.  At boot,
/// the driver loop is asynchronously replaying restored log entries
/// into the state machine; any reader that takes `try_read` on the
/// state-machine RwLock during that window loses to the driver's
/// write lock and silently observes a partial state (the empty Vec
/// from `ZoneConsensus::iter_dt_mount_entries`).  `replay_existing_mounts`
/// is the canonical victim — it scans every zone's DT_MOUNT set once at
/// boot, with no retry above it, and a partial read leaves cross-zone
/// routing missing for the rest of the daemon's life.
///
/// Polling intentional: `applied_index` is the state machine's own
/// `last_applied` atomic, `commit_index` reads `cached_commit_index`
/// seeded from `RawNode::raft_log.committed` at construction (#40), so
/// both reflect durable storage truth from t=0 and the loop converges
/// the moment the driver finishes its catchup pass.  Timeout-then-warn
/// instead of timeout-then-error: a genuinely stuck zone shouldn't
/// block boot entirely — the partial-replay symptom is less bad than a
/// daemon that refuses to come up.
fn wait_for_state_machine_caught_up(
    consensus: &crate::raft::ZoneConsensus<crate::raft::FullStateMachine>,
    zone_id: &str,
    timeout: Duration,
) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let commit = consensus.commit_index();
        let applied = consensus.applied_index();
        if applied >= commit {
            return;
        }
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                zone = %zone_id,
                commit_index = commit,
                applied_index = applied,
                "replay_existing_mounts: state machine did not catch up within \
                 {timeout:?}; DT_MOUNT scan may observe partial state and leave \
                 cross-zone routes unwired.  Investigate driver loop / state \
                 machine apply backpressure for this zone."
            );
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn wait_for_join_to_apply(zh: &ZoneHandle, zone_id: &str, timeout: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let leader = zh.leader_id();
        // SSOT with Branch 1 (`check_zone_resumable_from_indices`) and the
        // `nexusd-cluster doctor` audit — the same "durable state landed"
        // signal across all three sites.  `last_log_index` reads the cache
        // populated by `update_cached_status`, which the driver loop runs
        // *after* `storage.append` / `set_hard_state` / `apply_snapshot`
        // commit to redb (see `raft/node.rs` process_ready ordering).
        // So `>= 1` here is gated on durable-or-better state — same
        // invariant Branch 1 uses to decide a zone is safely resumable.
        // The previous `commit_index > 0` gate was a different scalar
        // (in-memory `raft_log.committed`) that risked drifting from the
        // durable-state SSOT as the substrate evolved.
        let last_log = zh.last_log_index();
        if leader.is_some() && last_log >= 1 {
            tracing::info!(
                zone = %zone_id,
                leader_id = ?leader,
                last_log_index = last_log,
                "ConfState installed; local raft state caught up to leader",
            );
            return Ok(());
        }
        std::thread::sleep(JOIN_ZONE_APPLY_POLL_INTERVAL);
    }
    Err(format!(
        "JoinZone RPC succeeded on the leader but joiner's local raft \
         state did not install the resulting ConfState within {timeout:?} \
         (leader_id={:?}, last_log_index={}).  Data dir would be left in \
         a pre-membership state — daemon restart would treat the zone as \
         a solo cluster of self.  Refusing to exit on stale state.",
        zh.leader_id(),
        zh.last_log_index(),
    ))
}

// Same rationale as `bootstrap_or_join_zone` above — every arg is a
// primitive descriptor the caller already names, bundling them adds
// boilerplate without expressive gain.
#[allow(clippy::too_many_arguments)]
fn attempt_join_zone_round(
    zm: &ZoneManager,
    zone_id: &str,
    node_id: u64,
    self_address: &str,
    peer_addrs: &[NodeAddress],
    join_runtime: &tokio::runtime::Runtime,
    rpc_timeout_secs: u64,
    as_learner: bool,
) -> Result<(), String> {
    let mut last_err = String::new();
    for peer in peer_addrs {
        let mut endpoint = peer.endpoint.clone();
        let mut redirected_once = false;
        loop {
            // Order matters: register locally with skip_bootstrap
            // FIRST so this node's gRPC server can serve append-
            // entries from the leader once AddNode commits.
            if zm.get_zone(zone_id).is_none() {
                let zone_peers = joiner_local_zone_peer_seeds(peer_addrs);
                let zone_peers_display = joiner_local_zone_peer_seeds_display(peer_addrs);
                tracing::info!(
                    zone = %zone_id,
                    seed_count = zone_peers_display.len(),
                    seed_peers = ?zone_peers_display,
                    "local join_zone seed peers",
                );
                if let Err(e) = zm.join_zone(zone_id, zone_peers, /* learner */ as_learner) {
                    last_err = format!("local join_zone setup failed: {e}");
                    tracing::warn!(
                        endpoint = %endpoint,
                        zone = %zone_id,
                        error = %e,
                        "local join_zone setup failed; will retry next peer",
                    );
                    break;
                }
            }
            let attempt = join_runtime.block_on(crate::transport::call_join_zone_rpc(
                &endpoint,
                zone_id,
                node_id,
                self_address,
                as_learner,
                zm.registry().tls_config(),
                rpc_timeout_secs,
            ));
            match attempt {
                Ok(result) if result.success => {
                    tracing::info!(
                        endpoint = %endpoint,
                        zone = %zone_id,
                        local_node_id = node_id,
                        "joined zone via leader — waiting for ConfState install",
                    );
                    // The leader's `AddNode`/`AddLearnerNode` commit
                    // is asynchronous w.r.t. our local raft state.
                    // Block here until the resulting AppendEntries
                    // lands + applies on this node, so the data dir
                    // exits the join with authoritative ConfState
                    // persisted.  Without this, the offline
                    // `nexusd-cluster join` CLI would return rc=0
                    // while leaving the joiner in a "solo of self"
                    // state on disk — see `wait_for_join_to_apply`
                    // for the full failure mode.
                    let zh = zm.get_zone(zone_id).ok_or_else(|| {
                        format!(
                            "zone '{zone_id}' missing from registry after \
                             successful JoinZone — internal invariant broken",
                        )
                    })?;
                    wait_for_join_to_apply(&zh, zone_id, JOIN_ZONE_APPLY_WAIT)?;
                    return Ok(());
                }
                Ok(result) => {
                    if let Some(addr) = result.leader_address.as_ref() {
                        if !redirected_once && !addr.is_empty() && addr != &endpoint {
                            tracing::info!(
                                from = %endpoint,
                                to = %addr,
                                zone = %zone_id,
                                "JoinZone redirect to leader",
                            );
                            endpoint = addr.clone();
                            redirected_once = true;
                            continue;
                        }
                    }
                    last_err = format!("{}: {:?}", endpoint, result.error);
                    tracing::debug!(
                        endpoint = %endpoint,
                        zone = %zone_id,
                        error = ?result.error,
                        "JoinZone non-success; trying next peer",
                    );
                    break;
                }
                Err(e) => {
                    last_err = format!("{}: {e}", endpoint);
                    tracing::debug!(
                        endpoint = %endpoint,
                        zone = %zone_id,
                        error = %e,
                        "JoinZone RPC error; trying next peer",
                    );
                    break;
                }
            }
        }
    }
    Err(last_err)
}

fn record_join_attempt(
    attempt: Result<(), String>,
    attempts: &mut u32,
    max_attempts: Option<u32>,
    zone_id: &str,
) -> Result<bool, String> {
    match attempt {
        Ok(()) => Ok(true),
        Err(last_err) => {
            *attempts = attempts.saturating_add(1);
            if let Some(max) = max_attempts {
                if *attempts >= max {
                    let attempt_count = *attempts;
                    return Err(format!(
                        "JoinZone({zone_id}): no peer accepted after {attempt_count} attempts; \
                         leader unreachable or quorum lost on remote zone. Last error: {last_err}",
                    ));
                }
            }
            Ok(false)
        }
    }
}

/// Bring a zone online — dispatch table for the three bootstrap
/// branches under the opaque-ID contract.  Generalised over `zone_id`
/// so the same SSOT machinery serves:
///
///   * `nexusd-cluster::run_daemon` for the root zone
///     (`zone_id="root"`, `max_attempts=None` — daemon boot path
///     wants forever-retry on misconfig).
///   * `nexusd-cluster::run_join` for non-root zones via the offline
///     `join` subcommand (`zone_id=<remote_zone>`,
///     `max_attempts=Some(N)` — CLI must terminate, so cap retries).
///   * Future Python `nexusd` `federation_create_zone` /
///     `federation_join` RPC handlers can call the same helper.
///
/// Branches:
///
///   1. **Restart** — `zm.get_zone(zone_id).is_some()` means
///      `open_existing_zones_from_disk` already loaded the local
///      replica from `<zones_dir>/<zone_id>/raft/raft.redb`.  Persisted
///      ConfState is authoritative; we just resume from it.
///
///   2. **Fresh create** — `bootstrap_new=true`.  Create a 1-voter
///      cluster consisting of `self.node_id` only.  Other nodes will
///      land in branch 3 and JoinZone here.  Without the operator
///      flag this path is forbidden — accidentally creating a second
///      1-voter cluster on a joiner would partition the federation.
///
///   3. **Wait-and-join** — empty storage, no flag.  Loop calling
///      JoinZone RPC against each peer in the address book.  The
///      leader's response commits a `ConfChangeV2(AddNode(self))`;
///      we locally `join_zone(skip_bootstrap=true)` first so the
///      leader's snapshot installs the authoritative ConfState.
///      `max_attempts=None` retries forever (daemon boot — misconfig
///      surfaces as "daemon stays up retrying" rather than a silent
///      exit); `max_attempts=Some(N)` bounds the loop to N rounds
///      (CLI — operator command must terminate).
///
/// Returns `Err` with a descriptive string if `max_attempts` was
/// exhausted without a successful JoinZone — caller surfaces this to
/// the operator.
///
/// `as_learner` selects the membership role on the **joiner** branch
/// (branch 3) — the leader proposes `AddLearnerNode` instead of
/// `AddNode`, so the new node receives full replication but does not
/// count toward quorum.  Picking the right value is a contract
/// distinction, not an operator knob:
///
///   * **`as_learner=false`** (voter) — root zone bootstrap OR
///     symmetric-peer subtree share (cc-tasks-share-style).  Every
///     voter can propose `sys_setattr` writes through raft consensus
///     — the joiner forwards to whichever voter currently holds
///     leadership.  Quorum is essential for any write; for root
///     clusters use ≥3 voters (+optional witness) so single-node
///     loss does not lose quorum.  Symmetric-peer 2-voter setups
///     work as long as both peers stay online together; once one is
///     unreachable the other can't commit until it returns.
///   * **`as_learner=true`** — owner-pattern subtree share / mount.
///     One authoritative voter (the `share` creator); joiners receive
///     full replication but cannot propose writes (every `vfs_write`
///     on a learner surfaces `NotLeader`).  Wipe-rejoin safe by
///     construction — losing a learner has zero quorum impact, so
///     SSD swap / OS reinstall / device migration cannot strand the
///     zone in `not leader` deadlock the way a 2-voter pattern can.
///     A per-call EC opt-in (`zone_handle::set_metadata(.., Consistency::Ec)`)
///     lets a learner write metadata without quorum when the caller
///     can tolerate async cross-node visibility — not the kernel hot
///     path yet (see `ZoneMetaStore` module docstring).
///
/// The branch-1 (restart) and branch-2 (founder) paths ignore
/// `as_learner` — restart resumes from persisted ConfState (which
/// already reflects historical role assignments), and a founder
/// always seeds itself as the 1-voter author of the cluster.
// `clippy::too_many_arguments`: every argument here is a primitive
// boot-time descriptor (zone id, node id, address, peer list, three
// flags).  Bundling them into a struct would force every caller —
// `run_daemon`, `run_join`, future boot paths — to import that
// struct just to populate the fields one by one with the same
// names.  Net readability loss for zero expressive gain, so we keep
// the explicit signature and silence the lint locally.
#[allow(clippy::too_many_arguments)]
pub fn bootstrap_or_join_zone(
    zm: &ZoneManager,
    zone_id: &str,
    node_id: u64,
    self_address: &str,
    peer_addrs: &[NodeAddress],
    bootstrap_new: bool,
    max_attempts: Option<u32>,
    as_learner: bool,
) -> Result<(), String> {
    // Root-SOLO invariant: every nexus daemon owns its own per-node `root`
    // zone (1-voter, local namespace).  Federation between independent
    // nodes happens through NAMED zones (e.g. `sharedzone`) joined via
    // the `nexusd-cluster join` sidecar — never by adding another node
    // into a peer's root cluster.
    //
    // Reject peers-against-root at the only kernel-internal entry point
    // that could JOIN root into a peer's cluster, so the operator-facing
    // misconfig surfaces here with a clear error instead of cascading
    // through ConfChange / heartbeat / clamping / cross-federation
    // pollution.  The common misuse this catches is setting
    // `NEXUS_PEERS=<peer-addr>` on a node that intended to federate
    // with `<peer-addr>` over a named zone — `NEXUS_PEERS` is consumed
    // by the boot path that calls this function with `zone_id="root"`,
    // and a non-empty list there would trigger `JoinPeers` /
    // `ProbePeersThenFound`, sending `JoinZone(root)` to the peer.
    //
    // Same-zone restart (Branch 1 below) is unaffected: zone loaded
    // from disk resumes via persisted ConfState regardless of this
    // gate, so an existing multi-voter root data dir (legacy) still
    // boots — only NEW JoinZone / Found probes are rejected.  Named
    // federation zones (non-root) pass through unchanged.
    if zone_id == contracts::ROOT_ZONE_ID && !peer_addrs.is_empty() {
        let peer_list: Vec<String> = peer_addrs
            .iter()
            .map(NodeAddress::to_operator_str)
            .collect();
        return Err(format!(
            "root zone is per-node SOLO by design (each nexus daemon owns its \
             own 1-voter root namespace).  NEXUS_PEERS={peer_list:?} was \
             applied to root, which would JoinZone(root) into the peer's \
             cluster — that's misuse for federation.  Fix: leave NEXUS_PEERS \
             empty on this node, then federate via a named zone \
             (`nexusd-cluster join <host:port> <named-zone> <mount-path>` \
             sidecar, or `--mount-driver local-connector:<named-zone>:...`).  \
             See docs/federation-architecture.md §6.3.1."
        ));
    }

    // Branch 1: zone already loaded from disk.  Resume only when the
    // persisted state is consistent — the previous short-circuit accepted
    // any registered zone, which silently admitted half-installed states
    // (e.g. ConfState set by a crashed `nexusd-cluster join` whose log
    // entries weren't fsynced).  See `check_zone_resumable` for the
    // invariant set.
    if let Some(zh) = zm.get_zone(zone_id) {
        match check_zone_resumable(zh.as_ref()) {
            Ok(()) => {
                tracing::info!(
                    local_node_id = node_id,
                    zone = %zone_id,
                    last_log_index = zh.last_log_index(),
                    "zone loaded from persisted storage; resuming from ConfState",
                );
                return Ok(());
            }
            Err(reason) => {
                if peer_addrs.is_empty() {
                    return Err(format!(
                        "loaded {zone_id} state is not safely resumable ({reason}).  \
                         This typically indicates a previous `nexusd-cluster join` \
                         crashed between updating ConfState and fsyncing the log entries \
                         that followed.  Daemon restart cannot self-repair without peer \
                         addresses to re-JoinZone against — to recover, either:\n  \
                         (a) stop the daemon, run `nexusd-cluster join \
                         <leader_host:port> {zone_id} /<mount> \
                         --data-dir <data_dir> --no-tls`, then restart in restart mode; or\n  \
                         (b) `rm -rf <data_dir>/{zone_id}` (this zone's subdirectory only) \
                         and restart in static mode."
                    ));
                }
                tracing::warn!(
                    local_node_id = node_id,
                    zone = %zone_id,
                    reason = %reason,
                    "loaded zone state not safely resumable; falling through to JoinZone \
                     against the configured peers (substrate will re-install ConfState + \
                     log entries from the leader)",
                );
                // Fall through to Branch 3 — the existing JoinZone loop
                // re-sends the RPC and re-installs state from the leader.
                // Branch 3 sees `get_zone()` still returns Some and skips
                // local registration, which is exactly what we want
                // (preserve the live driver / msg channel).
            }
        }
    }

    // Branch 2: founder — either operator explicit (`bootstrap_new`)
    // or implicit (empty peers = single-node alone).
    //
    // Every raft cluster starts as a 1-voter group; whether the
    // operator declares founder intent via the flag or by simply
    // not configuring peers, the next step is the same: create the
    // zone with self as the only voter.  Other nodes will JoinZone
    // here later.
    //
    //   * `bootstrap_new=true`  → explicit founder declaration.
    //     Required for multi-node deployments where the founder
    //     does list peer addresses (so it can dial them once they
    //     come up) but is the one originating the cluster.
    //   * `peer_addrs.is_empty()` → no peers configured = alone.
    //     Single-node default — create own root.
    let plan = empty_storage_bootstrap_plan(bootstrap_new, peer_addrs);
    if matches!(plan, EmptyStorageBootstrapPlan::FoundImmediately) {
        create_founder_zone(
            zm,
            zone_id,
            node_id,
            self_address,
            bootstrap_new,
            peer_addrs.is_empty(),
        )?;
        return Ok(());
    }

    // Branch 3: peers configured, no flag, storage empty — joiner.
    // Loop on JoinZone RPC until a leader accepts.
    tracing::info!(
        local_node_id = node_id,
        zone = %zone_id,
        peer_count = peer_addrs.len(),
        max_attempts = ?max_attempts,
        "empty storage with peers, no bootstrap flag — retrying JoinZone",
    );

    // Spin a small temporary multi-thread runtime for the JoinZone
    // RPCs.  ZoneManager owns the long-lived runtime, but `block_on`
    // on its handle from this thread (the kernel boot thread) is
    // unsafe if the boot thread is itself a worker of an outer
    // runtime.  A fresh multi-thread runtime with one worker
    // sidesteps the issue cleanly — we drop it once we've joined.
    let join_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .thread_name("nexus-bootstrap-join")
        .build()
        .map_err(|e| format!("bootstrap join runtime: {e}"))?;

    if matches!(plan, EmptyStorageBootstrapPlan::ProbePeersThenFound) {
        tracing::info!(
            local_node_id = node_id,
            zone = %zone_id,
            peer_count = peer_addrs.len(),
            attempts = FOUNDER_REJOIN_PROBE_ATTEMPTS,
            "founder path — probing peers for an existing live cluster before creating local root",
        );
        let mut last_err = String::new();
        for _ in 0..FOUNDER_REJOIN_PROBE_ATTEMPTS {
            match attempt_join_zone_round(
                zm,
                zone_id,
                node_id,
                self_address,
                peer_addrs,
                &join_runtime,
                JOIN_ZONE_RPC_TIMEOUT_SECS,
                as_learner,
            ) {
                Ok(()) => return Ok(()),
                Err(e) => last_err = e,
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        tracing::info!(
            local_node_id = node_id,
            zone = %zone_id,
            last_error = %last_err,
            "founder probe found no existing cluster; creating local 1-voter zone",
        );
        remove_local_probe_zone(zm, zone_id);
        create_founder_zone(
            zm,
            zone_id,
            node_id,
            self_address,
            bootstrap_new,
            peer_addrs.is_empty(),
        )?;
        return Ok(());
    }

    let mut attempts: u32 = 0;
    loop {
        let joined = record_join_attempt(
            attempt_join_zone_round(
                zm,
                zone_id,
                node_id,
                self_address,
                peer_addrs,
                &join_runtime,
                JOIN_ZONE_RPC_TIMEOUT_SECS,
                as_learner,
            ),
            &mut attempts,
            max_attempts,
            zone_id,
        )?;
        if joined {
            return Ok(());
        }
        std::thread::sleep(JOIN_ZONE_RETRY_INTERVAL);
    }
}

impl DistributedCoordinator for RaftDistributedCoordinator {
    fn list_zones(&self, _kernel: &Kernel) -> Vec<String> {
        self.zm().map(|zm| zm.list_zones()).unwrap_or_default()
    }

    fn is_initialized(&self, _kernel: &Kernel) -> bool {
        // SSOT — `bootstrap_done` is set at the end of
        // [`Self::install_with_kernel`] regardless of whether any zones
        // were bootstrapped.  The default trait impl falls back to
        // `!list_zones().is_empty()`, which is a SHADOW of init
        // readiness that misclassifies dynamic-bootstrap mode (init
        // complete, zones empty until `create_zone("root")` is
        // invoked).  Override it.
        self.bootstrap_done.load(Ordering::Acquire)
    }

    fn zone_peers(&self, _kernel: &Kernel, zone_id: &str) -> Vec<String> {
        // SSOT — `ZoneManager::zone_peers` enumerates the ConfState
        // roster.  Filter out:
        //   * The local node — it's already the caller of the
        //     fan-out, no point fanning back to ourselves.
        //   * Witnesses — vote-only nodes that never serve content.
        let Some(zm) = self.zm() else {
            tracing::debug!(zone = %zone_id, "zone_peers: zm not available, returning empty");
            return Vec::new();
        };
        let local_id = zm.node_id();
        let raw = zm.zone_peers(zone_id);
        let raw_len = raw.len();
        let filtered: Vec<String> = raw
            .into_iter()
            .filter(|(id, _, _, is_witness)| !is_witness && *id != local_id)
            .map(|(_, _, endpoint, _)| endpoint)
            .collect();
        tracing::debug!(
            zone = %zone_id,
            local_id,
            raw_peer_count = raw_len,
            filtered_count = filtered.len(),
            peers = ?filtered,
            "zone_peers: result"
        );
        filtered
    }

    fn metastore_for_zone(
        &self,
        _kernel: &Kernel,
        zone_id: &str,
    ) -> CoordinatorResult<Arc<dyn MetaStore>> {
        let zm = self.zm().ok_or("federation not active")?;
        let consensus = zm
            .registry()
            .get_node(zone_id)
            .ok_or_else(|| format!("zone {zone_id} not loaded"))?;
        let runtime = self.runtime.get().cloned().ok_or("runtime missing")?;
        // Mount point: root zone shows under "/", named zones under "/<id>".
        let mount_point = if zone_id == "root" {
            "/".to_string()
        } else {
            format!("/{zone_id}")
        };
        let store: Arc<dyn MetaStore> = Arc::new(crate::zone_meta_store::ZoneMetaStore::new(
            consensus,
            runtime,
            mount_point,
        ));
        Ok(store)
    }

    fn locks_for_zone(&self, kernel: &Kernel, zone_id: &str) -> CoordinatorResult<Arc<dyn Locks>> {
        let zm = self.zm().ok_or("federation not active")?;
        let runtime = self
            .runtime
            .get()
            .ok_or("federation runtime not initialised")?;
        let consensus = zm
            .registry()
            .get_node(zone_id)
            .ok_or_else(|| format!("zone '{zone_id}' not loaded locally"))?;
        let kernel_state = kernel.lock_manager_arc().advisory_state_arc();
        let backend =
            crate::federation::DistributedLocks::new(consensus, runtime.clone(), kernel_state);
        Ok(Arc::new(backend))
    }

    fn wire_mount(
        &self,
        kernel: &Kernel,
        parent_zone: &str,
        mount_path: &str,
        target_zone: &str,
    ) -> CoordinatorResult<()> {
        wire_mount_impl(self, kernel, parent_zone, mount_path, target_zone)
    }

    fn unwire_mount(
        &self,
        kernel: &Kernel,
        parent_zone: &str,
        mount_path: &str,
    ) -> CoordinatorResult<()> {
        let vfs_router = kernel.vfs_router_arc();
        unwire_mount_core(
            &vfs_router,
            &self.cross_zone_mounts,
            parent_zone,
            mount_path,
        );
        Ok(())
    }

    /// Create or join a federation zone at runtime.
    ///
    /// Coordinated through the root-zone leader to avoid split-brain
    /// under the opaque-ID contract — random data-plane node IDs make
    /// hostname-derived ConfState convergence (the old contract's
    /// implicit serializer) impossible.
    ///
    ///   - **Root-zone leader**: founder.  Creates `zone_id` as a
    ///     1-voter cluster locally.  Subsequent JoinZone calls from
    ///     followers grow the voter set.
    ///   - **Root-zone follower**: joiner.  Loops `JoinZone` RPC at
    ///     the root-leader's address (and other peers as a fallback)
    ///     until the leader has created the zone and the AddNode
    ///     for this node commits.  Bounded by 30s so syscall
    ///     callers see a fail rather than hang forever; operators
    ///     re-issue.
    #[allow(clippy::result_large_err)]
    fn create_zone(&self, kernel: &Kernel, zone_id: &str) -> CoordinatorResult<()> {
        let zm = self.zm().ok_or("federation not active")?;
        if zm.get_zone(zone_id).is_some() {
            self.install_apply_cb_for_zone(kernel, zone_id);
            return Ok(());
        }
        let runtime = self
            .runtime
            .get()
            .ok_or("federation runtime not initialised")?;
        let self_id = zm.node_id();
        let registry = zm.registry();
        let self_address = registry.self_address();

        // Root-leader path: founder creates 1-voter cluster locally.
        let am_root_leader = zm.get_zone("root").map(|h| h.is_leader()).unwrap_or(false);
        if am_root_leader {
            // Founder self-registration string — see `create_founder_zone`
            // for the encoding rationale.
            let self_peer = format!("{self_id}@{self_address}");
            zm.create_zone(zone_id, vec![self_peer])
                .map_err(|e| format!("create_zone({zone_id}): {e}"))?;
            self.install_apply_cb_for_zone(kernel, zone_id);

            // 1-voter zone — campaign immediately so this node is the
            // leader for the AddNode proposals below.  Without an
            // explicit campaign, raft-rs waits a full election_tick
            // (~100 ms) before self-voting, and any propose_conf_change
            // in that window returns NotLeader.
            let zone_handle = zm
                .get_zone(zone_id)
                .ok_or_else(|| format!("create_zone({zone_id}): just-created zone not visible"))?;
            let consensus = zone_handle.consensus_node();
            let campaign_fut = consensus.campaign();
            let campaign_result = if tokio::runtime::Handle::try_current().is_ok() {
                tokio::task::block_in_place(|| runtime.block_on(campaign_fut))
            } else {
                runtime.block_on(campaign_fut)
            };
            campaign_result.map_err(|e| format!("create_zone({zone_id}) campaign: {e}"))?;

            // Auto-invite witness voters present in NEXUS_PEERS.  The
            // witness's id is hostname-derived (well-known per F3) so
            // the leader can address it directly without waiting for
            // JoinZone.  Without this, witness never receives raft
            // traffic for new federation zones (its ConfState lacks
            // them) and the cluster loses witness's quorum-1
            // protection on every dynamically-created zone.
            //
            // If the witness is unreachable at create time the AddNode
            // still commits (1-voter quorum on this leader) but the
            // resulting 2-voter ConfState raises quorum-required to
            // 2/2 until witness comes up — same exposure as the OLD
            // hostname-deterministic ConfState bootstrap, operationally
            // equivalent.
            let root_peers = registry.get_peers("root").unwrap_or_default();
            for peer in root_peers.values() {
                if !peer.hostname.to_ascii_lowercase().starts_with("witness") {
                    continue;
                }
                let address_bytes = peer.endpoint.as_bytes().to_vec();
                let fut = consensus.propose_conf_change(
                    raft::eraftpb::ConfChangeType::AddNode,
                    peer.id,
                    address_bytes,
                );
                let result = if tokio::runtime::Handle::try_current().is_ok() {
                    tokio::task::block_in_place(|| runtime.block_on(fut))
                } else {
                    runtime.block_on(fut)
                };
                if let Err(e) = result {
                    tracing::warn!(
                        zone = %zone_id,
                        witness_id = peer.id,
                        endpoint = %peer.endpoint,
                        error = %e,
                        "auto-invite witness AddNode failed; cluster proceeds 1-voter",
                    );
                } else {
                    tracing::info!(
                        zone = %zone_id,
                        witness_id = peer.id,
                        endpoint = %peer.endpoint,
                        "Witness auto-invited as voter on federation zone create",
                    );
                }
            }
            return Ok(());
        }

        // Follower path: JoinZone via peers.  Address book comes from
        // root zone's peer map (populated via inbound StepMessage).
        let peer_addrs = registry.get_peers("root").unwrap_or_default();
        if peer_addrs.is_empty() {
            return Err(format!(
                "create_zone({zone_id}): not root-leader and no peers known",
            ));
        }

        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last_err = String::new();
        while Instant::now() < deadline {
            // Re-resolve root leader on each iteration — it may emerge
            // (election) or change (failover) during retry.
            let leader_id = zm.get_zone("root").and_then(|h| h.leader_id()).unwrap_or(0);
            let candidates: Vec<NodeAddress> = if leader_id != 0 {
                peer_addrs.get(&leader_id).into_iter().cloned().collect()
            } else {
                peer_addrs.values().cloned().collect()
            };

            // Register the zone locally with skip_bootstrap=true so
            // the leader's snapshot can install the authoritative
            // ConfState the moment AddNode commits.  Idempotent.
            if zm.get_zone(zone_id).is_none() {
                let peer_seed_addrs: Vec<NodeAddress> = peer_addrs.values().cloned().collect();
                let local_peer_seeds = joiner_local_zone_peer_seeds(&peer_seed_addrs);
                if !local_peer_seeds.is_empty() {
                    let local_peer_seeds_display =
                        joiner_local_zone_peer_seeds_display(&peer_seed_addrs);
                    tracing::info!(
                        zone = %zone_id,
                        seed_count = local_peer_seeds_display.len(),
                        seed_peers = ?local_peer_seeds_display,
                        "local federation zone seed peers",
                    );
                    let _ = zm.join_zone(zone_id, local_peer_seeds, false);
                }
            }

            for peer in &candidates {
                if peer.id == self_id {
                    continue;
                }
                let fut = crate::transport::call_join_zone_rpc(
                    &peer.endpoint,
                    zone_id,
                    self_id,
                    &self_address,
                    /* as_learner */ false,
                    zm.registry().tls_config(),
                    5,
                );
                let attempt = if tokio::runtime::Handle::try_current().is_ok() {
                    tokio::task::block_in_place(|| runtime.block_on(fut).map_err(|e| e.to_string()))
                } else {
                    runtime.block_on(fut).map_err(|e| e.to_string())
                };
                match attempt {
                    Ok(r) if r.success => {
                        self.install_apply_cb_for_zone(kernel, zone_id);
                        return Ok(());
                    }
                    Ok(r) => last_err = format!("{}: {:?}", peer.endpoint, r.error),
                    Err(e) => last_err = format!("{}: {e}", peer.endpoint),
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(format!(
            "create_zone({zone_id}): JoinZone exhausted after 30s: {last_err}"
        ))
    }

    fn remove_zone(&self, _kernel: &Kernel, zone_id: &str, force: bool) -> CoordinatorResult<()> {
        let zm = self.zm().ok_or("federation not active")?;
        let runtime = self
            .runtime
            .get()
            .ok_or("federation runtime not initialised")?;
        // Cascade-unmount every DT_MOUNT pointing at `zone_id` BEFORE
        // dropping the consensus.  Apply-cb on each parent zone fires
        // `unwire_mount_core` so VFSRouter / DCache cleanup propagates
        // to every peer via raft.  Without this, parents keep stale
        // routing entries and reads under the dead mount-point silently
        // succeed against the (now-orphaned) target consensus Arc.
        let mounts = self
            .cross_zone_mounts
            .get(zone_id)
            .map(|v| v.clone())
            .unwrap_or_default();
        tracing::debug!(
            zone_id = %zone_id,
            force = force,
            mount_count = mounts.len(),
            "remove_zone cascade-unmount entry"
        );
        for (parent_zone_id, mount_path, _global) in &mounts {
            if let Some(parent) = zm.registry().get_node(parent_zone_id) {
                if let Err(e) =
                    crate::zone_manager::propose_delete_metadata(runtime, &parent, mount_path)
                {
                    if !force {
                        return Err(format!(
                            "cascade-unmount {parent_zone_id}:{mount_path} failed: {e}"
                        ));
                    }
                    tracing::warn!(
                        parent = %parent_zone_id,
                        mount = %mount_path,
                        error = %e,
                        "remove_zone(force=true): DT_MOUNT delete propose failed; continuing"
                    );
                }
            }
        }
        zm.remove_zone(zone_id, force).map_err(|e| e.to_string())
    }

    fn join_zone(&self, kernel: &Kernel, zone_id: &str, as_learner: bool) -> CoordinatorResult<()> {
        let zm = self.zm().ok_or("federation not active")?;
        let peers = zm.current_peer_strings();
        zm.join_zone(zone_id, peers, as_learner)
            .map_err(|e| e.to_string())?;
        // install_apply_cb_for_zone now atomically pairs the cb
        // install with a DT_MOUNT replay scan (see its docstring),
        // so snapshot-delivered entries that applied before this
        // call wire correctly without a separate replay step.
        self.install_apply_cb_for_zone(kernel, zone_id);
        Ok(())
    }

    fn join_cluster(
        &self,
        kernel: &Kernel,
        zone_id: &str,
        leader_addr: &str,
        as_learner: bool,
    ) -> CoordinatorResult<()> {
        let zm = self.zm().ok_or("federation not active")?;
        let runtime = self
            .runtime
            .get()
            .ok_or("federation runtime not initialised")?;
        if leader_addr.trim().is_empty() {
            return Err("join_cluster: leader_addr must not be empty".to_string());
        }

        // Step 1: set up local raft replica with skip_bootstrap=true so the
        // leader's snapshot is the authoritative ConfState source.  We seed
        // the address book with the leader so outgoing AppendEntries acks
        // and vote responses can reach it from the moment the snapshot
        // installs.
        let leader_peer = vec![leader_addr.to_string()];
        if zm.get_zone(zone_id).is_none() {
            zm.join_zone(zone_id, leader_peer, as_learner)
                .map_err(|e| format!("join_cluster local setup: {e}"))?;
        }

        // Step 2: send JoinZone RPC to the leader.  Followers self-redirect
        // via JoinZoneResponse.leader_address; we follow the redirect once
        // before surfacing the failure.
        let self_id = zm.node_id();
        let self_address = kernel
            .self_address_string()
            .ok_or("join_cluster: self_address not published — federation not initialised")?;
        let mut endpoint = leader_addr.to_string();
        let mut redirected_once = false;
        loop {
            let attempt = runtime.block_on(crate::transport::call_join_zone_rpc(
                &endpoint,
                zone_id,
                self_id,
                &self_address,
                as_learner,
                zm.registry().tls_config(),
                10,
            ));
            match attempt {
                Ok(result) if result.success => {
                    tracing::info!(
                        zone_id = %zone_id,
                        endpoint = %endpoint,
                        self_id = self_id,
                        "join_cluster: leader committed ConfChangeV2 AddNode"
                    );
                    // install_apply_cb_for_zone now atomically pairs
                    // the cb install with a DT_MOUNT replay scan (see
                    // its docstring), so the leader's snapshot-
                    // delivered entries that applied before this call
                    // wire correctly on the joiner without a separate
                    // replay step.  The original cc-tasks-share E2E
                    // regression (joiner-empty cross-node readdir)
                    // was a missed pairing here.
                    self.install_apply_cb_for_zone(kernel, zone_id);
                    return Ok(());
                }
                Ok(result) => {
                    if let Some(addr) = result.leader_address.as_ref() {
                        if !redirected_once && !addr.is_empty() && addr != &endpoint {
                            endpoint = addr.clone();
                            redirected_once = true;
                            continue;
                        }
                    }
                    return Err(format!(
                        "join_cluster: peer {endpoint} rejected — error={:?}",
                        result.error
                    ));
                }
                Err(e) => {
                    return Err(format!("join_cluster: RPC to {endpoint} failed: {e}"));
                }
            }
        }
    }

    fn share_zone(
        &self,
        kernel: &Kernel,
        local_path: &str,
        new_zone_id: &str,
    ) -> CoordinatorResult<ShareInfo> {
        let zm = self.zm().ok_or("federation not active")?;
        // Atomic create + copy + register: materialise the zone first
        // so it is visible to followers before content lands.
        zm.get_or_create_zone(new_zone_id)
            .map_err(|e| e.to_string())?;
        self.install_apply_cb_for_zone(kernel, new_zone_id);
        // Decompose `local_path` via VFSRouter — the closest mount
        // point's zone_id is the parent, and the path tail under that
        // mount is the prefix passed to `share_subtree_core`.
        let route = kernel
            .vfs_router_arc()
            .route(local_path, contracts::ROOT_ZONE_ID)
            .ok_or_else(|| format!("share_zone route '{local_path}': no mount covers path"))?;
        let parent_zone = route.zone_id.clone();
        let prefix = if route.backend_path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", route.backend_path)
        };
        let copied = zm
            .share_subtree_core(&parent_zone, &prefix, new_zone_id)
            .map_err(|e| e.to_string())?;
        zm.register_share(local_path, new_zone_id)
            .map_err(|e| e.to_string())?;
        Ok(ShareInfo {
            zone_id: new_zone_id.to_string(),
            copied_entries: copied as u64,
        })
    }

    fn lookup_share(
        &self,
        _kernel: &Kernel,
        remote_path: &str,
    ) -> CoordinatorResult<Option<ShareInfo>> {
        let zm = self.zm().ok_or("federation not active")?;
        let zone_id = zm.lookup_share(remote_path).map_err(|e| e.to_string())?;
        Ok(zone_id.map(|zid| ShareInfo {
            zone_id: zid,
            copied_entries: 0,
        }))
    }

    fn cluster_info(&self, _kernel: &Kernel, zone_id: &str) -> CoordinatorResult<ClusterInfo> {
        let zm = self.zm().ok_or("federation not active")?;
        let status = zm.cluster_status(zone_id);
        // links_count comes from the coordinator's reverse index
        // (mounts pointing at `zone_id`). Node-local cache derived
        // from DT_MOUNT entries — matches what `wire_mount` populates
        // as apply-cb fires.
        let links_count = self
            .cross_zone_mounts
            .get(zone_id)
            .map(|v| v.len() as i64)
            .unwrap_or(0);
        Ok(ClusterInfo {
            zone_id: status.zone_id,
            node_id: status.node_id,
            has_store: status.has_store,
            is_leader: status.is_leader,
            leader_id: status.leader_id,
            term: status.term,
            commit_index: status.commit_index,
            applied_index: status.applied_index,
            voter_count: status.voter_count,
            witness_count: status.witness_count,
            links_count,
        })
    }

    // ── Cross-node peer dispatch ─────────────────────────────────────
    //
    // Each `peer_*` override resolves the SSOT peer via
    // `dispatch_to_peers` (the generic iteration helper) and runs
    // the typed `FederationGrpcOps` method against each non-self
    // voter.  Bool-returning ops (delete_file/rmdir/mkdir/rename/
    // setattr) collapse the dispatch_to_peers `Option<()>` to a
    // bool — `Some(())` ⇒ at least one peer's RPC succeeded.

    fn peer_read(
        &self,
        kernel: &Kernel,
        target_zone: &str,
        peer_path: &str,
        offset: u64,
    ) -> Option<Vec<u8>> {
        self.dispatch_to_peers::<Vec<u8>, _>(
            kernel,
            "read",
            target_zone,
            peer_path,
            |client, addr| client.read(addr, peer_path, offset).map(Some),
        )
    }

    fn peer_stat(
        &self,
        kernel: &Kernel,
        target_zone: &str,
        peer_path: &str,
    ) -> Option<BackendStat> {
        // grpc_ops.stat already returns `Result<Option<BackendStat>, String>`
        // matching the dispatch_to_peers closure shape — pass through.
        self.dispatch_to_peers::<BackendStat, _>(
            kernel,
            "stat",
            target_zone,
            peer_path,
            |client, addr| client.stat(addr, peer_path),
        )
    }

    fn peer_list_dir(
        &self,
        kernel: &Kernel,
        target_zone: &str,
        peer_path: &str,
    ) -> Option<Vec<(String, u8)>> {
        // Empty Vec is meaningful for readdir ("dir exists but
        // empty") — distinguish from not-found by ALWAYS returning
        // `Some(entries)` on transport success.
        self.dispatch_to_peers::<Vec<(String, u8)>, _>(
            kernel,
            "list_dir",
            target_zone,
            peer_path,
            |client, addr| client.list_dir(addr, peer_path).map(Some),
        )
    }

    fn peer_delete_file(&self, kernel: &Kernel, target_zone: &str, peer_path: &str) -> bool {
        self.dispatch_to_peers::<(), _>(
            kernel,
            "delete_file",
            target_zone,
            peer_path,
            |client, addr| client.delete_file(addr, peer_path).map(|()| Some(())),
        )
        .is_some()
    }

    fn peer_rmdir(
        &self,
        kernel: &Kernel,
        target_zone: &str,
        peer_path: &str,
        recursive: bool,
    ) -> bool {
        self.dispatch_to_peers::<(), _>(kernel, "rmdir", target_zone, peer_path, |client, addr| {
            client.rmdir(addr, peer_path, recursive).map(|()| Some(()))
        })
        .is_some()
    }

    fn peer_mkdir(
        &self,
        kernel: &Kernel,
        target_zone: &str,
        peer_path: &str,
        parents: bool,
        exist_ok: bool,
    ) -> bool {
        self.dispatch_to_peers::<(), _>(kernel, "mkdir", target_zone, peer_path, |client, addr| {
            client
                .mkdir(addr, peer_path, parents, exist_ok)
                .map(|()| Some(()))
        })
        .is_some()
    }

    fn peer_rename(
        &self,
        kernel: &Kernel,
        target_zone: &str,
        old_path: &str,
        new_path: &str,
    ) -> bool {
        self.dispatch_to_peers::<(), _>(kernel, "rename", target_zone, old_path, |client, addr| {
            client.rename(addr, old_path, new_path).map(|()| Some(()))
        })
        .is_some()
    }

    fn peer_setattr(
        &self,
        kernel: &Kernel,
        target_zone: &str,
        peer_path: &str,
        mime_type: Option<&str>,
        content_id: Option<&str>,
        modified_at_ms: Option<i64>,
        created_at_ms: Option<i64>,
        size: Option<u64>,
        version: Option<u32>,
    ) -> bool {
        self.dispatch_to_peers::<(), _>(
            kernel,
            "setattr",
            target_zone,
            peer_path,
            |client, addr| {
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
            },
        )
        .is_some()
    }
}

/// Reconstruct the global VFS path for a DT_MOUNT entry.  Root-zone parents
/// already publish a global path; nested mounts pre-pend the parent's own
/// global path looked up via `cross_zone_mounts`.
fn reconstruct_global_path(
    cross_zone_mounts: &DashMap<String, Vec<CrossZoneMountTuple>>,
    parent_zone_id: &str,
    mount_path: &str,
) -> Option<String> {
    if parent_zone_id == contracts::ROOT_ZONE_ID || parent_zone_id.is_empty() {
        return Some(mount_path.to_string());
    }
    let parent_global = cross_zone_mounts
        .get(parent_zone_id)
        .and_then(|v| v.iter().map(|(_, _, g)| g.clone()).min())?;
    if mount_path == parent_global || mount_path.starts_with(&format!("{}/", parent_global)) {
        Some(mount_path.to_string())
    } else if mount_path == "/" {
        Some(parent_global)
    } else {
        Some(format!("{}{}", parent_global, mount_path))
    }
}

// `install_dcache_coherence_impl` is gone — migrated to
// `Kernel::install_zone_apply_invalidator`.  The closure body
// (translate zone-relative key → every global mount point → evict
// dcache) lives kernel-side now so federation no longer holds
// `Arc<DCache>`.

/// Kernel-built dcache mutation helpers, threaded into the federation
/// `&Kernel`-free core of `wire_mount` — same body, but every kernel
/// dependency comes through pre-cloned `Arc`s.  Lets the apply-cb
/// closure (which has no `&Kernel` access) drive the same logic on
/// every follower when raft applies a DT_MOUNT commit.
#[allow(clippy::too_many_arguments)]
fn wire_mount_core(
    vfs_router: &Arc<kernel::core::vfs_router::VFSRouter>,
    lock_manager: &Arc<kernel::core::lock::LockManager>,
    registry: &Arc<crate::raft::ZoneRaftRegistry>,
    runtime: &tokio::runtime::Handle,
    cross_zone_mounts: &DashMap<String, Vec<CrossZoneMountTuple>>,
    parent_zone_id: &str,
    // RENAMED: the apply event delivers this in parent-zone's
    // ZoneMetaStore-stripped form (e.g. `/cc-tasks/founder` for a
    // row written at global `/shared/cc-tasks/founder`).  Routing
    // entries MUST use the global form, not this one — see
    // `global_path` derivation immediately below.  The only
    // legitimate consumer of this zone-relative form is the
    // `cross_zone_mounts` reverse-index bookkeeping at the end of
    // the cross-zone branch (used by `unwire_mount_core` to find
    // the tuple by zone-relative key when the row is deleted).
    zone_relative_mount_path: &str,
    target_zone_id: &str,
) -> CoordinatorResult<()> {
    tracing::debug!(
        parent_zone_id = %parent_zone_id,
        zone_relative_mount_path = %zone_relative_mount_path,
        target_zone_id = %target_zone_id,
        "wire_mount_core entered"
    );

    // ── SSOT: translate to the global VFS path ONCE, up front ──────
    //
    // The SSOT-side `kernel.add_mount` installs its routing entry
    // using the GLOBAL form, and federation routing recursion looks
    // the entry up by canonicalizing the GLOBAL form against the
    // parent zone.  So every branch below MUST install routing
    // entries keyed by `global_path`, not by the zone-relative
    // parameter — otherwise we install at a canonical key the
    // consumer never queries.
    //
    // PR #70's original C3 same-zone branch took the zone-relative
    // parameter as-is and installed at `/sharedzone/cc-tasks/founder`;
    // routing looked for `/sharedzone/shared/cc-tasks/founder`;
    // placeholder was never found on the joiner; cross-node readdir
    // silently returned empty (cc-tasks-share E2E regression).
    // Lifting the reconstruct here + the parameter rename above
    // makes the form-mismatch impossible to reintroduce by reading
    // the code casually: the un-translated parameter spells its
    // zone-relative-ness in the name; the safe form is named
    // `global_path`.
    let global_path = match reconstruct_global_path(
        cross_zone_mounts,
        parent_zone_id,
        zone_relative_mount_path,
    ) {
        Some(g) => g,
        None => {
            tracing::warn!(
                parent_zone_id = %parent_zone_id,
                zone_relative_mount_path = %zone_relative_mount_path,
                "wire_mount_core: reconstruct_global_path returned None — \
                 parent mount not yet in cross_zone_mounts, deferring"
            );
            return Ok(());
        }
    };

    // Same-zone short-circuit: when target == parent, the DT_MOUNT is
    // a driver-mount inside an already-routed zone (e.g.
    // `--mount-driver local-connector:sharedzone:/shared/cc-tasks/founder`
    // — parent path `/shared/cc-tasks` routes to sharedzone, mount
    // target zone is also sharedzone).  On the SSOT node `kernel.add_mount`
    // already registered its LocalConnector at the global path; on
    // follower nodes we install a backend-less placeholder MountEntry
    // so the io.rs `FederationGrpcOps` dispatch (sys_readdir /
    // sys_stat / sys_unlink / sys_write) can route through to the
    // SSOT peer.
    //
    // Cross-zone DT_MOUNTs (e.g. /shared → sharedzone, a true
    // federation mount) fall through to the wire below and install
    // the federation routing as before.
    if parent_zone_id == target_zone_id {
        // Driver-mount path: the SSOT node ran `--mount-driver` and
        // `kernel.add_mount` already registered its LocalConnector
        // at `global_path` BEFORE the DT_MOUNT row replicated.  On
        // that node the canonical entry exists — re-installing here
        // would clobber the live backend with a backend-less
        // placeholder.  Detect via `vfs_router.has` and bail.
        if vfs_router.has(&global_path, parent_zone_id) {
            tracing::debug!(
                parent_zone_id = %parent_zone_id,
                global_path = %global_path,
                "wire_mount_core: same-zone DT_MOUNT — driver-mount backend \
                 already installed locally, nothing to wire"
            );
            return Ok(());
        }

        // Follower / non-SSOT node: install a placeholder MountEntry
        // that routes through to the federation-peer client at io.rs
        // dispatch time.  `backend = None` is the boundary signal
        // (`route.backend.is_none() && route.target_zone_id.is_some()`
        // means "this mount lives on a peer node — route through
        // FederationPeerClient against a peer voter").  Symmetric to
        // the cross-zone branch below: same shape (None backend +
        // Some target_zone_id), same routing surface.
        vfs_router.add_federation_mount(&global_path, parent_zone_id, None, target_zone_id, false);

        // CRITICAL: inherit the parent federation gateway's metastore.
        // The cross-zone gateway (e.g. /shared/cc-tasks → sharedzone)
        // installs a ZoneMetaStore at its canonical key — that store
        // is where federation-replicated DT_REG / DT_DIR metadata
        // rows land (raft replicates them under the gateway's
        // ZoneMetaStore namespace).  Our more-specific placeholder
        // entry at /<parent_zone>/<global_path> SHADOWS the gateway
        // for routing AND with_metastore_route; without inheriting
        // the gateway's metastore, the placeholder has `metastore =
        // None` and `with_metastore_route` falls back to the global
        // LocalMetaStore — which doesn't carry the replicated rows.
        // Joiner sys_stat / sys_read then report "not found" for
        // paths the founder wrote through FUSE, even though the row
        // is present in raft on the joiner's side.
        //
        // Mirrors what `--mount-driver` does on the SSOT side via
        // `MountOptions.with_metastore(parent_metastore)` (cluster
        // main.rs:947): the LocalConnector mount inherits its parent
        // federation gateway's metastore.  Same SSOT inheritance —
        // the placeholder is the joiner-side analogue of that mount.
        let parent_path_for_metastore = global_path
            .rsplit_once('/')
            .map(|(p, _)| if p.is_empty() { "/" } else { p })
            .unwrap_or("/");
        if let Some(parent_metastore) = vfs_router
            .route(parent_path_for_metastore, contracts::ROOT_ZONE_ID)
            .and_then(|r| r.metastore)
        {
            let canonical_key = canonicalize(&global_path, parent_zone_id);
            vfs_router.install_metastore(&canonical_key, parent_metastore);
        }

        tracing::info!(
            parent_zone_id = %parent_zone_id,
            global_path = %global_path,
            "wire_mount_core: same-zone DT_MOUNT — installed federation-peer \
             placeholder MountEntry (no local backend present)"
        );
        return Ok(());
    }

    // 1. Look up target zone.
    let Some(target_consensus) = registry.get_node(target_zone_id) else {
        tracing::warn!(
            target_zone_id = %target_zone_id,
            "wire_mount: target zone not loaded locally — deferring"
        );
        return Ok(());
    };

    // 3. Build a ZoneMetaStore rooted at global_path against the target's
    //    state machine — reuses the root mount's CAS backend.
    let metastore: Arc<dyn MetaStore> = ZoneMetaStore::new_arc(
        target_consensus.clone(),
        runtime.clone(),
        global_path.clone(),
    );
    let root_canonical = canonicalize("/", contracts::ROOT_ZONE_ID);
    let root_backend = vfs_router
        .get_canonical(&root_canonical)
        .and_then(|e| e.backend.clone());

    // 4. Install into VFSRouter under the root zone.
    vfs_router.add_federation_mount(
        &global_path,
        contracts::ROOT_ZONE_ID,
        root_backend,
        target_zone_id,
        false,
    );
    let canonical = canonicalize(&global_path, contracts::ROOT_ZONE_ID);
    vfs_router.install_metastore(&canonical, metastore);

    // 5. LockManager upgrade on first federated mount — distributed
    //    locks bound to the ROOT zone's consensus.
    if !lock_manager.locks_installed() {
        match registry.get_node(contracts::ROOT_ZONE_ID) {
            Some(root_consensus) => {
                tracing::info!(
                    parent_zone = %parent_zone_id,
                    global_path = %global_path,
                    "wire_mount: installing distributed locks bound to ROOT zone"
                );
                let kernel_state = lock_manager.advisory_state_arc();
                let backend = crate::federation::DistributedLocks::new(
                    root_consensus,
                    runtime.clone(),
                    kernel_state,
                );
                lock_manager.install_locks(Arc::new(backend));
            }
            None => {
                tracing::warn!(
                    "wire_mount: root zone not loaded — distributed locks NOT installed; sys_lock stays local-only until next mount"
                );
            }
        }
    }

    // 6. DT_MOUNT mount-point synthesis: ``sys_stat`` /``sys_unlink``
    // synthesise a DT_MOUNT result directly from the routing structure
    // (kernel/io.rs); no kernel-side cache row needs seeding here.
    //
    // 7. Apply-side cache coherence: each ZoneMetaStore self-registers
    // an invalidator on its consensus during ``ZoneMetaStore::new``
    // (raft/zone_meta_store.rs), so installing one here would just
    // duplicate the registration.

    // 8. Update reverse index.  The middle field holds the
    // ZONE-RELATIVE form so `unwire_mount_core` can find the tuple
    // by the same form the DT_MOUNT-delete apply event delivers.
    // This is the ONLY legitimate use of the zone-relative arg in
    // this function — every routing call above used `global_path`.
    let mut bucket = cross_zone_mounts
        .entry(target_zone_id.to_string())
        .or_default();
    let tuple = (
        parent_zone_id.to_string(),
        zone_relative_mount_path.to_string(),
        global_path,
    );
    if !bucket.contains(&tuple) {
        bucket.push(tuple);
    }
    Ok(())
}

/// Reverse the bookkeeping done by `wire_mount_core` for a DT_MOUNT
/// delete event: drop the VFSRouter slot and remove the reverse-index
/// entry. Cache eviction for the unwired mount happens automatically:
/// ``vfs_router.remove`` drops the per-mount ``Arc<dyn MetaStore>``
/// (its internal ``DashMap`` cache goes with it), and the unwired
/// mount no longer routes so subsequent ``sys_stat`` synthesises the
/// absence of a DT_MOUNT directly from the empty routing entry.
fn unwire_mount_core(
    vfs_router: &Arc<kernel::core::vfs_router::VFSRouter>,
    cross_zone_mounts: &DashMap<String, Vec<CrossZoneMountTuple>>,
    parent_zone_id: &str,
    mount_path: &str,
) {
    tracing::debug!(parent_zone_id = %parent_zone_id, mount_path = %mount_path, "unwire_mount_core entered");
    let mut remove_empty: Option<String> = None;
    let mut unwired_global: Option<String> = None;
    for mut entry in cross_zone_mounts.iter_mut() {
        let bucket = entry.value_mut();
        if let Some(pos) = bucket
            .iter()
            .position(|(p, m, _)| p == parent_zone_id && m == mount_path)
        {
            let (_, _, global) = bucket.remove(pos);
            unwired_global = Some(global);
            if bucket.is_empty() {
                remove_empty = Some(entry.key().clone());
            }
            break;
        }
    }
    if let Some(target) = remove_empty {
        cross_zone_mounts.remove(&target);
    }
    if let Some(global) = unwired_global {
        vfs_router.remove(&global, contracts::ROOT_ZONE_ID);
    }
}

/// Install the apply-side DT_MOUNT callback on `consensus` so every
/// raft-replicated DT_MOUNT commit drives `wire_mount_core` /
/// `unwire_mount_core` — the mechanism that keeps cross-zone routing
/// in sync on **every** follower (not just the leader that handled
/// the original `sys_setattr`).
#[allow(clippy::too_many_arguments)]
fn install_mount_apply_cb_impl(
    vfs_router: &Arc<kernel::core::vfs_router::VFSRouter>,
    lock_manager: &Arc<kernel::core::lock::LockManager>,
    registry: &Arc<crate::raft::ZoneRaftRegistry>,
    runtime: &tokio::runtime::Handle,
    cross_zone_mounts: &Arc<DashMap<String, Vec<CrossZoneMountTuple>>>,
    parent_zone_id: &str,
    consensus: &crate::raft::ZoneConsensus<crate::raft::FullStateMachine>,
) {
    if consensus.apply_observers_slot().is_none() {
        tracing::warn!(parent_zone_id = %parent_zone_id, "install_mount_apply_cb: no observer slot (witness?)");
        return;
    }
    let vfs_router = Arc::clone(vfs_router);
    let lock_manager = Arc::clone(lock_manager);
    let registry = Arc::clone(registry);
    let runtime = runtime.clone();
    let cross_zone_mounts = Arc::clone(cross_zone_mounts);
    let parent_zone_owned = parent_zone_id.to_string();

    use crate::raft::{AppliedEntry, FullStateMachine, MountApplyEvent};
    // Mount observer: translate the applied command into a
    // MountApplyEvent (matching only DT_MOUNT set/remove; the pre-image
    // arrives via entry.removed_mount_key) and wire / unwire. Every other
    // command variant yields None and is ignored — behavior-preserving
    // vs. the pre-unification dedicated DT_MOUNT slot.
    //
    // Registered under the "federation_mount" dedup key so the 7+
    // re-installs per zone (boot resume / join / mount / rewire) REPLACE
    // rather than accumulate — matching the old single-Option slot's
    // "idempotent replace on same coherence_id" contract.
    let cb: Arc<dyn Fn(&AppliedEntry) + Send + Sync> = Arc::new(move |entry: &AppliedEntry| {
        let Some(event) =
            FullStateMachine::mount_apply_event_from(entry.command, entry.removed_mount_key)
        else {
            return;
        };
        match event {
            MountApplyEvent::Set {
                key,
                target_zone_id,
            } => {
                let _ = wire_mount_core(
                    &vfs_router,
                    &lock_manager,
                    &registry,
                    &runtime,
                    &cross_zone_mounts,
                    &parent_zone_owned,
                    &key,
                    &target_zone_id,
                );
            }
            MountApplyEvent::Delete { key } => {
                unwire_mount_core(&vfs_router, &cross_zone_mounts, &parent_zone_owned, &key);
            }
        }
    });
    consensus.register_keyed_apply_observer("federation_mount", cb);
    tracing::info!(parent_zone_id = %parent_zone_id, "install_mount_apply_cb: observer registered");
}

/// Wire a federation mount synchronously from the leader's
/// `sys_setattr` path.  Followers reach the same logic through the
/// `mount_apply_cb` installed by `install_mount_apply_cb_impl` —
/// kernel.rs's `wire_mount` call is best-effort fast-path; correctness
/// rests on the apply-cb.
fn wire_mount_impl(
    provider: &RaftDistributedCoordinator,
    kernel: &Kernel,
    parent_zone_id: &str,
    mount_path: &str,
    target_zone_id: &str,
) -> CoordinatorResult<()> {
    let zm = provider.zm().ok_or("federation not active")?;
    let runtime = provider
        .runtime
        .get()
        .ok_or("federation runtime not initialised")?;
    let registry = zm.registry();
    let vfs_router = kernel.vfs_router_arc();
    let lock_manager = kernel.lock_manager_arc();

    // Quorum-replication contract: a DT_MOUNT entry committed on the
    // parent zone is observed by every voter via raft replication, so
    // every peer's apply-cb fires here.  If the target zone's raft
    // replica isn't loaded locally yet, create it now using the same
    // peer roster as root — every peer derives the identical
    // ConfState seed and the new zone's raft group converges on a
    // leader once a quorum of peers have run through this path.
    //
    // Without this auto-create, only the originating peer's local
    // sys_setattr ever instantiates the target zone; followers stay
    // empty, the new zone's voter set has no quorum, and `cluster_info`
    // never reports a leader_id — the symptom that broke
    // `_wait_zone_ready` in the federation E2E suite.
    if registry.get_node(target_zone_id).is_none() {
        let zone_peers = zm.current_peer_strings();
        if !zone_peers.is_empty() {
            tracing::info!(
                target_zone_id = %target_zone_id,
                peers = ?zone_peers,
                "wire_mount: target zone not loaded locally — auto-creating raft replica"
            );
            if let Err(e) = zm.create_zone(target_zone_id, zone_peers) {
                tracing::warn!(
                    target_zone_id = %target_zone_id,
                    error = %e,
                    "wire_mount: target zone auto-create failed; wire_mount_core will defer"
                );
            } else {
                provider.install_apply_cb_for_zone(kernel, target_zone_id);
            }
        }
    }

    wire_mount_core(
        &vfs_router,
        &lock_manager,
        &registry,
        runtime,
        &provider.cross_zone_mounts,
        parent_zone_id,
        mount_path,
        target_zone_id,
    )?;

    // Best-effort: also install the apply-cb on the parent zone so future
    // DT_MOUNT commits (this one or later) on every follower fire
    // `wire_mount_core`.  Idempotent — re-installing replaces the closure
    // with an equivalent one.
    provider.install_apply_cb_for_zone(kernel, parent_zone_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn read_or_mint_node_id_mints_then_loads() {
        // Round-trip: first call mints + persists, second call returns
        // the same value from disk.  Pin the file format (8 bytes BE).
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().to_str().expect("utf-8");
        let id1 = read_or_mint_node_id(path).expect("first mint");
        assert_ne!(id1, 0, "minted id must be non-zero");
        let id2 = read_or_mint_node_id(path).expect("second load");
        assert_eq!(id1, id2, "load must return persisted id");

        // Sanity: file is exactly 8 bytes BE u64.
        let bytes = std::fs::read(dir.path().join(NODE_ID_FILE)).expect("read");
        assert_eq!(bytes.len(), 8, ".node_id must be 8 bytes");
        let parsed = u64::from_be_bytes(bytes.try_into().expect("array"));
        assert_eq!(parsed, id1);
    }

    #[test]
    fn read_or_mint_node_id_rejects_zero_on_disk() {
        // Pre-write 0 — operator panic-recover scenario, surface
        // loudly rather than silently re-minting (which would change
        // the cluster's view of this node's identity).
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join(NODE_ID_FILE);
        std::fs::write(&path, [0u8; 8]).expect("write zero");
        let result = read_or_mint_node_id(dir.path().to_str().expect("utf-8"));
        assert!(result.is_err(), "must reject zero id on disk");
    }

    /// `check_zone_resumable` accepts any persisted zone whose log has
    /// advanced past the bootstrap / join entry — that's every healthy
    /// daemon restart by raft contract.
    #[test]
    fn check_zone_resumable_passes_when_log_advanced() {
        // Founder bootstrap writes AddNode(self) to index 1 — log_last
        // is at least 1 on a healthy founder restart.
        assert!(check_zone_resumable_from_indices(1).is_ok());
        // Joiner that completed snapshot install lands at >= snapshot
        // last_included_index, which is the AddLearnerNode commit index
        // (typically 3 on the canonical sharedzone join).
        assert!(check_zone_resumable_from_indices(3).is_ok());
        // Long-running cluster — many entries, still resumable.
        assert!(check_zone_resumable_from_indices(1_000_000).is_ok());
    }

    /// Regression for the Mac↔Win L1 smoke half-installed-state wedge:
    /// the joiner's `nexusd-cluster join` advanced the in-memory
    /// commit_index to 3 (`wait_for_join_to_apply` gated on it) but
    /// crashed before fsyncing the log entries.  At daemon restart the
    /// loaded zone has ConfState present but log_last == 0 — the
    /// previous Branch 1 short-circuit returned Ok and the daemon
    /// then spent hours floods "Clamping inbound raft commit hint" /
    /// "raft step error: cannot step as peer not found" before the
    /// operator deduced the root cause.  This commit makes the same
    /// state a hard error.
    #[test]
    fn check_zone_resumable_rejects_empty_log_with_confstate_present() {
        let err = check_zone_resumable_from_indices(0).unwrap_err();
        assert!(
            err.contains("log_last_index = 0"),
            "expected explicit log_last_index = 0 framing, got: {err}"
        );
        // The error message must point operators at the recovery path
        // it documents (offline join CLI or wipe + rebootstrap) —
        // that's what the caller appends to the error before
        // propagating; here we only sanity-check the empty-log framing
        // landed.
        assert!(
            err.contains("ConfState may exist on disk"),
            "expected ConfState-exists framing, got: {err}"
        );
    }

    fn parse_peer(s: &str) -> NodeAddress {
        NodeAddress::parse(s, /* use_tls */ false).expect("parse peer")
    }

    #[test]
    fn peers_excluding_self_keeps_other_peers_only() {
        // Address book lists OTHER nodes — happy path under the
        // PR #3996 contract; nothing is filtered.
        let peers = vec![parse_peer("100.64.0.21:2126")];
        let kept = peers_excluding_self(&peers, "100.64.0.26:2126");
        assert_eq!(kept.len(), 1, "other-peers-only pass through unchanged");
        assert_eq!(kept[0].endpoint, peers[0].endpoint);
    }

    #[test]
    fn peers_excluding_self_drops_self_without_bricking() {
        // A self-entry — operator-listed in NEXUS_PEERS, or a stale learned
        // entry that survived in the persisted identity — must be FILTERED
        // (warn), never fatal. A hard-fail here would brick a restart: the
        // daemon could not boot again until someone hand-edited identity.json.
        // Self is never a transport peer; it joins via bootstrap / AddNode.
        let peers = vec![
            parse_peer("100.64.0.26:2126"), // self
            parse_peer("100.64.0.21:2126"),
        ];
        let kept = peers_excluding_self(&peers, "100.64.0.26:2126");
        assert_eq!(kept.len(), 1, "self dropped, the real peer kept");
        assert_eq!(
            kept[0].endpoint.trim_start_matches("http://"),
            "100.64.0.21:2126",
        );
    }

    #[test]
    fn parse_operator_addr_rejects_legacy_id_at_host_form() {
        // Operator-facing parse rejects `id@host:port` — operators
        // never had a reason to sync peer node_ids
        // (`learn_peer_address` populates the real id from the first
        // inbound raft message).  Raft-internal `parse` still accepts
        // the form for authoritative-id round-trips.  Pin at the raft
        // crate boundary so a regression on the operator-facing
        // rejection surfaces here.
        let err =
            NodeAddress::parse_operator_addr("9999@100.64.0.26:2126", /* use_tls */ false)
                .expect_err("legacy id@host:port form must be rejected on operator boundary");
        let msg = err.to_string();
        assert!(
            msg.contains("legacy 'id@host:port' form"),
            "error must name the retired form: {msg}"
        );
    }

    #[test]
    fn peers_excluding_self_empty_is_empty() {
        // Founder mode with no other peers yet.
        assert!(peers_excluding_self(&[], "100.64.0.26:2126").is_empty());
    }

    #[test]
    fn bootstrap_joiner_local_seed_includes_all_configured_peers() {
        let peers = vec![
            parse_peer("nexus-1:2126"),
            parse_peer("witness:2126"),
            parse_peer("nexus-3:2126"),
        ];

        let seeds = joiner_local_zone_peer_seeds(&peers);

        let mut expected = vec![
            parse_peer("nexus-1:2126").to_raft_peer_str(),
            parse_peer("nexus-3:2126").to_raft_peer_str(),
            parse_peer("witness:2126").to_raft_peer_str(),
        ];
        expected.sort();

        assert_eq!(
            seeds, expected,
            "joiner local root registration must seed the full address book, not just the dialed peer",
        );
    }

    #[test]
    fn founder_with_peers_probes_existing_cluster_before_creating() {
        let peers = vec![parse_peer("nexus-2:2126"), parse_peer("witness:2126")];

        assert_eq!(
            empty_storage_bootstrap_plan(true, &peers),
            EmptyStorageBootstrapPlan::ProbePeersThenFound,
            "a wiped static founder with live peers must try to rejoin before founding a split-brain root",
        );
        assert_eq!(
            empty_storage_bootstrap_plan(true, &[]),
            EmptyStorageBootstrapPlan::FoundImmediately,
            "single-node founder still creates immediately",
        );
        assert_eq!(
            empty_storage_bootstrap_plan(false, &peers),
            EmptyStorageBootstrapPlan::JoinPeers,
            "joiners keep the indefinite JoinZone retry behavior",
        );
    }

    #[test]
    fn join_retry_loop_stops_after_successful_join() {
        let mut attempts = 3;

        let joined = record_join_attempt(Ok(()), &mut attempts, None, "root").unwrap();

        assert!(joined, "successful JoinZone must break the retry loop");
        assert_eq!(
            attempts, 3,
            "successful JoinZone must not count as a failed retry",
        );
    }

    #[test]
    fn join_retry_loop_counts_failures_and_honors_max_attempts() {
        let mut attempts = 0;

        let joined = record_join_attempt(
            Err("leader unavailable".to_string()),
            &mut attempts,
            Some(2),
            "root",
        )
        .unwrap();
        assert!(!joined);
        assert_eq!(attempts, 1);

        let err = record_join_attempt(
            Err("leader still unavailable".to_string()),
            &mut attempts,
            Some(2),
            "root",
        )
        .expect_err("second failed attempt should hit max_attempts");

        assert!(err.contains("after 2 attempts"));
        assert!(err.contains("leader still unavailable"));
    }

    // Phase G (2026-07-05): `BootstrapMode` + `validate_bootstrap_mode`
    // deleted along with their unit tests.  Boot decision-making moved
    // wholesale to `nexus_raft::bootstrap::plan_boot_action`, which has
    // its own comprehensive matrix tests in `rust/raft/src/bootstrap.rs`
    // (17 unit tests) plus integration tests
    // (`test_unified_bringup.rs`, `test_identity_zone_mirror.rs`).

    // ── dispatch_to_peer_addrs behavioral pins ──────────────────────────
    //
    // The kernel-side syscall sites (route.via_federation_X /
    // supplement_X) reach federation peers through
    // `RaftDistributedCoordinator::peer_*` which delegates the
    // iteration to `dispatch_to_peer_addrs`.  Three silent-failure
    // paths and the first-hit-wins iteration semantics together form
    // the contract every cross-node read / write / stat / unlink /
    // mkdir / rename / setattr depends on — pinning them here without
    // standing up a full ZoneManager fixture keeps regressions cheap
    // to catch.

    use kernel::abc::object_store::BackendStat;
    use kernel::federation::grpc_ops::{FederationGrpcOps, FederationPeerResult};
    use parking_lot::Mutex;

    /// Programmable per-peer fake.  Each method either consults its
    /// canned reply map or panics — every test wires only the methods
    /// it exercises so an accidental call to an unrelated method
    /// trips an obvious failure.
    #[derive(Default)]
    struct FakeFederationGrpcOps {
        /// Recorded `(op, addr)` for every call — pins the iteration
        /// order without the test poking at internal state.
        calls: Mutex<Vec<(&'static str, String)>>,
        /// Per-addr canned reply for `read`.  Returned by value so
        /// the iteration can race-reload via the Mutex.
        reads: Mutex<std::collections::HashMap<String, FederationPeerResult<Vec<u8>>>>,
    }

    impl FakeFederationGrpcOps {
        fn record(&self, op: &'static str, addr: &str) {
            self.calls.lock().push((op, addr.to_string()));
        }
        fn set_read(&self, addr: &str, reply: FederationPeerResult<Vec<u8>>) {
            self.reads.lock().insert(addr.to_string(), reply);
        }
        fn calls(&self) -> Vec<(&'static str, String)> {
            self.calls.lock().clone()
        }
    }

    impl FederationGrpcOps for FakeFederationGrpcOps {
        fn read(&self, addr: &str, _path: &str, _offset: u64) -> FederationPeerResult<Vec<u8>> {
            self.record("read", addr);
            self.reads
                .lock()
                .remove(addr)
                .unwrap_or_else(|| Err(format!("no canned reply for {addr}")))
        }
        fn stat(&self, _addr: &str, _path: &str) -> FederationPeerResult<Option<BackendStat>> {
            unreachable!("stat not exercised by these pins");
        }
        fn list_dir(&self, _addr: &str, _path: &str) -> FederationPeerResult<Vec<(String, u8)>> {
            unreachable!("list_dir not exercised by these pins");
        }
        fn delete_file(&self, _addr: &str, _path: &str) -> FederationPeerResult<()> {
            unreachable!("delete_file not exercised by these pins");
        }
        fn rmdir(&self, _addr: &str, _path: &str, _recursive: bool) -> FederationPeerResult<()> {
            unreachable!("rmdir not exercised by these pins");
        }
        fn mkdir(
            &self,
            _addr: &str,
            _path: &str,
            _parents: bool,
            _exist_ok: bool,
        ) -> FederationPeerResult<()> {
            unreachable!("mkdir not exercised by these pins");
        }
        fn rename(
            &self,
            _addr: &str,
            _old_path: &str,
            _new_path: &str,
        ) -> FederationPeerResult<()> {
            unreachable!("rename not exercised by these pins");
        }
        fn setattr(
            &self,
            _addr: &str,
            _path: &str,
            _mime_type: Option<&str>,
            _content_id: Option<&str>,
            _modified_at_ms: Option<i64>,
            _created_at_ms: Option<i64>,
            _size: Option<u64>,
            _version: Option<u32>,
        ) -> FederationPeerResult<()> {
            unreachable!("setattr not exercised by these pins");
        }
    }

    fn fake_arc() -> (Arc<FakeFederationGrpcOps>, Arc<dyn FederationGrpcOps>) {
        let fake = Arc::new(FakeFederationGrpcOps::default());
        let dyn_arc: Arc<dyn FederationGrpcOps> = fake.clone();
        (fake, dyn_arc)
    }

    /// Read op via the helper.  Threads the closure shape every
    /// per-syscall coordinator method uses (read returns Vec<u8> on
    /// hit, `op` wraps it in `Ok(Some(_))`).
    fn dispatch_read(
        client: &Arc<dyn FederationGrpcOps>,
        peers: &[String],
        self_addr: Option<&str>,
    ) -> Option<Vec<u8>> {
        dispatch_to_peer_addrs::<Vec<u8>, _>(
            client,
            "read",
            "sharedzone",
            "/p",
            peers,
            self_addr,
            |c, addr| c.read(addr, "/p", 0).map(Some),
        )
    }

    #[test]
    fn dispatch_empty_zone_peers_returns_none_without_invoking_op() {
        let (fake, dyn_arc) = fake_arc();
        let out = dispatch_read(&dyn_arc, &[], None);
        assert!(out.is_none(), "empty peers must return None");
        assert!(
            fake.calls().is_empty(),
            "no op invocation expected when peers is empty"
        );
    }

    #[test]
    fn dispatch_all_peers_are_self_addr_skips_all_then_returns_none() {
        let (fake, dyn_arc) = fake_arc();
        let peers = vec!["100.64.0.21:2126".to_string()];
        let out = dispatch_read(&dyn_arc, &peers, Some("100.64.0.21:2126"));
        assert!(out.is_none(), "all-self peers must return None");
        assert!(
            fake.calls().is_empty(),
            "self-addr peer must be skipped without invoking op"
        );
    }

    #[test]
    fn dispatch_first_peer_hit_short_circuits_with_value() {
        let (fake, dyn_arc) = fake_arc();
        fake.set_read("a:2126", Ok(b"hit-a".to_vec()));
        fake.set_read("b:2126", Ok(b"hit-b".to_vec()));
        let peers = vec!["a:2126".to_string(), "b:2126".to_string()];
        let out = dispatch_read(&dyn_arc, &peers, None);
        assert_eq!(out.as_deref(), Some(&b"hit-a"[..]));
        // Only the first peer was invoked — the second was never
        // touched because the loop short-circuited.
        let calls = fake.calls();
        assert_eq!(calls, vec![("read", "a:2126".to_string())]);
    }

    #[test]
    fn dispatch_all_peers_err_iterates_all_then_returns_none() {
        let (fake, dyn_arc) = fake_arc();
        fake.set_read("a:2126", Err("unreachable".into()));
        fake.set_read("b:2126", Err("unreachable".into()));
        let peers = vec!["a:2126".to_string(), "b:2126".to_string()];
        let out = dispatch_read(&dyn_arc, &peers, None);
        assert!(out.is_none(), "all-error must yield None");
        // EVERY non-self peer must have been attempted before
        // giving up — partial iteration would mask a peer that
        // later recovers.
        let calls: Vec<String> = fake.calls().into_iter().map(|(_, a)| a).collect();
        assert_eq!(calls, vec!["a:2126", "b:2126"]);
    }

    #[test]
    fn dispatch_ok_none_continues_to_next_peer() {
        // `Ok(None)` semantically means "this peer answered the RPC
        // but reports no value" (e.g. stat in-band found=false).
        // The loop must KEEP TRYING the next peer rather than
        // treating Ok(None) as a hit — a stale voter that returns
        // None for a freshly-replicated key must not shadow the
        // SSOT-side voter that has the value.
        let (fake, dyn_arc) = fake_arc();
        let peers = vec!["a:2126".to_string(), "b:2126".to_string()];
        // Use a custom closure that returns Ok(None) for `a` and
        // Ok(Some(hit)) for `b`, so we can pin the "skip on None,
        // surface the next hit" semantics without relying on the
        // fake having to support per-peer Ok(None)/Ok(Some).
        let out = dispatch_to_peer_addrs::<Vec<u8>, _>(
            &dyn_arc,
            "read",
            "sharedzone",
            "/p",
            &peers,
            None,
            |_c, addr| {
                fake.record("probe", addr);
                if addr == "a:2126" {
                    Ok(None)
                } else {
                    Ok(Some(b"hit-b".to_vec()))
                }
            },
        );
        assert_eq!(out.as_deref(), Some(&b"hit-b"[..]));
        let calls: Vec<String> = fake.calls().into_iter().map(|(_, a)| a).collect();
        assert_eq!(calls, vec!["a:2126", "b:2126"]);
    }

    #[test]
    fn dispatch_mixed_err_then_ok_none_then_hit_surfaces_hit() {
        // Err -> next; Ok(None) -> next; Ok(Some) -> return.
        // Combined ordering pin: the loop must navigate all three
        // outcomes in sequence.
        let (fake, dyn_arc) = fake_arc();
        let peers = vec![
            "a:2126".to_string(),
            "b:2126".to_string(),
            "c:2126".to_string(),
        ];
        let out = dispatch_to_peer_addrs::<Vec<u8>, _>(
            &dyn_arc,
            "read",
            "sharedzone",
            "/p",
            &peers,
            None,
            |_c, addr| {
                fake.record("probe", addr);
                match addr {
                    "a:2126" => Err("rpc-down".into()),
                    "b:2126" => Ok(None),
                    "c:2126" => Ok(Some(b"hit-c".to_vec())),
                    _ => unreachable!(),
                }
            },
        );
        assert_eq!(out.as_deref(), Some(&b"hit-c"[..]));
        let calls: Vec<String> = fake.calls().into_iter().map(|(_, a)| a).collect();
        assert_eq!(calls, vec!["a:2126", "b:2126", "c:2126"]);
    }

    #[test]
    fn dispatch_self_addr_filter_threads_through_to_non_self_voter() {
        // Two-voter zone with self_addr == peers[0]; the loop must
        // skip peers[0] silently and reach peers[1].  Pins the
        // self-filter integration with the iteration body.
        let (fake, dyn_arc) = fake_arc();
        fake.set_read("b:2126", Ok(b"hit-b".to_vec()));
        let peers = vec!["a:2126".to_string(), "b:2126".to_string()];
        let out = dispatch_read(&dyn_arc, &peers, Some("a:2126"));
        assert_eq!(out.as_deref(), Some(&b"hit-b"[..]));
        let calls: Vec<String> = fake.calls().into_iter().map(|(_, a)| a).collect();
        assert_eq!(
            calls,
            vec!["b:2126"],
            "self_addr peer 'a' must not be invoked"
        );
    }
}
