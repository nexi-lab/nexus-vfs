//! Multi-zone Raft registry — manages multiple independent Raft groups per process.
//!
//! Each zone is an independent Raft group with its own:
//! - sled database (at `{base_path}/{zone_id}/`)
//! - ZoneConsensus handle + ZoneConsensusDriver actor
//! - TransportLoop background task
//!
//! The registry is thread-safe (DashMap) and supports dynamic zone creation/removal.
//!
//! # Architecture
//!
//! ```text
//!   ZoneRaftRegistry
//!   ├── "zone-alpha" → ZoneEntry { ZoneConsensus, TransportLoop task, shutdown_tx }
//!   ├── "zone-beta"  → ZoneEntry { ZoneConsensus, TransportLoop task, shutdown_tx }
//!   └── ...
//! ```

use crate::raft::{
    FullStateMachine, RaftConfig, RaftStorage, ReplicationLog, StateMachine, ZoneConsensus,
    ZonePersistence,
};
use crate::storage::RedbStore;
use crate::transport::{
    ClientConfig, NodeAddress, PeerMap, RaftClientPool, SharedPeerMap, TlsConfig, TransportError,
    TransportLoop,
};
use dashmap::DashMap;
use raft::eraftpb::ConfState;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Reconcile a static peer roster with persisted Raft membership.
///
/// Dynamic voter replacement can preserve a node's hostname/port while changing
/// its Raft node ID. On restart, NEXUS_PEERS still contains the cold ID, but
/// persisted ConfState is authoritative. If there is exactly one stale ID and
/// one persisted ID missing from the transport map, carry the known address over
/// to the persisted ID so membership checks and message routing agree.
pub(crate) fn reconcile_peers_with_conf_state(
    zone_id: &str,
    peers: &mut [NodeAddress],
    conf_state: &ConfState,
) {
    let conf_ids: HashSet<u64> = conf_state
        .voters
        .iter()
        .chain(conf_state.voters_outgoing.iter())
        .chain(conf_state.learners.iter())
        .chain(conf_state.learners_next.iter())
        .copied()
        .collect();
    if conf_ids.is_empty() {
        return;
    }

    let peer_ids: HashSet<u64> = peers.iter().map(|peer| peer.id).collect();
    let missing_conf_ids: Vec<u64> = conf_ids.difference(&peer_ids).copied().collect();
    let stale_peer_ids: Vec<u64> = peer_ids.difference(&conf_ids).copied().collect();
    if missing_conf_ids.len() != 1 || stale_peer_ids.len() != 1 {
        return;
    }

    let old_id = stale_peer_ids[0];
    let new_id = missing_conf_ids[0];
    if let Some(peer) = peers.iter_mut().find(|peer| peer.id == old_id) {
        tracing::warn!(
            zone = %zone_id,
            old_id,
            new_id,
            endpoint = %peer.endpoint,
            "Reconciled peer ID from persisted Raft ConfState",
        );
        peer.id = new_id;
    }
}

/// Per-zone concurrent-op guard. Prevents concurrent `setup_zone` and
/// `remove_zone` calls for the same zone_id from interleaving their
/// disk-dir ops. Different zone_ids proceed in parallel.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ZoneOp {
    Creating,
    Removing,
}

const AUTO_JOIN_REMOVAL_SUPPRESSION: Duration = Duration::from_secs(60);

/// How long resuming a persisted zone waits for its state machine to apply
/// what its log already says is committed.
///
/// Opening a zone from disk is not the same as the zone being READY: raft-rs
/// re-emits the committed-but-unapplied tail on the first ready, and until the
/// state machine has chewed through it, reads see a partial zone. Boot used to
/// hide this — every zone opened long before any request arrived — but a zone
/// that materializes ON a request has no such grace, and would answer that
/// very request out of an empty state machine.
///
/// The wait is local work (replaying this node's own log), so it is short in
/// practice; the cap exists so a wedged apply loop surfaces as a warning
/// rather than an unbounded hang on the caller's thread.
const RESUME_CATCHUP_BUDGET: Duration = Duration::from_secs(10);

/// Block until `consensus` has applied everything its log says is committed,
/// or `timeout` expires (warning loudly if so).
///
/// Shared by zone resume and by federation mount replay: both need the same
/// "this zone's state machine is caught up with its own log" guarantee before
/// they read it, and neither can get it from `applied_index` alone at a single
/// instant.
pub(crate) fn wait_until_caught_up(
    consensus: &ZoneConsensus<FullStateMachine>,
    zone_id: &str,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let commit = consensus.commit_index();
        let applied = consensus.applied_index();
        if applied >= commit {
            return;
        }
        if Instant::now() >= deadline {
            tracing::warn!(
                zone = %zone_id,
                commit_index = commit,
                applied_index = applied,
                "zone did not catch up with its own log within {timeout:?}; reads may \
                 observe partial state. Investigate the driver loop / state-machine \
                 apply backpressure for this zone."
            );
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Which hosted zones this process is allowed to materialize.
///
/// The daemon uses [`ZoneLoadPolicy::OnDemand`]: any zone on disk becomes
/// resident the first time something asks for it. Offline tooling (e.g.
/// `nexusd-cluster auth mint`, which only needs the SOLO `root` zone's
/// credential store) uses [`ZoneLoadPolicy::Only`]: opening a FEDERATED zone
/// offline would spin up its raft group as a lone node with no reachable
/// peers, which then campaigns and mutates that zone's persisted `HardState`
/// (term/vote) — corrupting a zone the offline process has no business
/// driving, so the real daemon resumes diverged.
///
/// `Only` is enforced at every lookup rather than only at boot, so an offline
/// tool cannot reach a federated zone through some later call path either.
#[derive(Debug, Clone)]
pub enum ZoneLoadPolicy {
    /// Materialize any hosted zone on first access (the daemon).
    OnDemand,
    /// Materialize only these zone ids, ever; every other lookup reports the
    /// zone as absent.
    Only(Vec<String>),
}

impl ZoneLoadPolicy {
    fn may_materialize(&self, zone_id: &str) -> bool {
        match self {
            ZoneLoadPolicy::OnDemand => true,
            ZoneLoadPolicy::Only(ids) => ids.iter().any(|id| id == zone_id),
        }
    }
}

/// What a hosted zone needs to become resident, captured once at boot.
///
/// The peer address book is cluster-wide, not per-zone (every zone in a
/// federation shares the same raft topology), which is why one snapshot taken
/// at boot serves every later materialization — it is the same list the old
/// open-everything boot passed to each zone.
struct Materialization {
    peers: Vec<NodeAddress>,
    runtime: tokio::runtime::Handle,
    policy: ZoneLoadPolicy,
}

/// A single zone entry in the registry.
struct ZoneEntry {
    /// ZoneConsensus handle (Clone + Send + Sync).
    node: ZoneConsensus<FullStateMachine>,
    /// Known peers for this zone. Shared with TransportLoop for runtime ConfChange updates.
    peers: SharedPeerMap,
    /// This node's ID within the zone.
    #[expect(
        dead_code,
        reason = "reserved for future ConfChange use; remove expect when used"
    )]
    node_id: u64,
    /// Shutdown signal for the transport loop.
    shutdown_tx: watch::Sender<bool>,
    /// Transport loop task handle (for join on removal).
    transport_handle: JoinHandle<()>,
    /// On-disk lifecycle owner. Committed (not armed) post-insert —
    /// Drop on process shutdown is a no-op; explicit `destroy()` during
    /// `remove_zone` deletes the dir.
    persistence: ZonePersistence,
}

/// Registry of multiple Raft zones running in a single process.
///
/// Thread-safe: all operations are safe to call from multiple threads concurrently.
pub struct ZoneRaftRegistry {
    /// zone_id → ZoneEntry — the zones whose runtime is MATERIALIZED: redb
    /// handles open, state machine in memory, transport loop running.
    ///
    /// A subset of [`Self::hosted`]. Membership here is a runtime fact, not a
    /// durable one: a zone is materialized on first access and stays until
    /// shutdown.
    zones: DashMap<String, ZoneEntry>,
    /// Every zone id this node HOSTS on disk, materialized or not.
    ///
    /// Disk stays the source of truth for "which zones does this node host?"
    /// (the etcd / CockroachDB / TiKV rule); this is its in-memory index,
    /// built once by [`Self::index_persisted_zones`] and maintained by the two
    /// places that create and destroy zone directories ([`Self::setup_zone`]
    /// and [`Self::remove_zone`]), which already serialize on `creating`.
    ///
    /// Splitting the catalog from the runtimes above is what decouples boot
    /// cost from zone count: enumerating 10k zone directories is one readdir,
    /// while opening 10k raft groups is 10k × (two redb opens + several
    /// fsyncs). A zone nobody has touched since the last restart is not doing
    /// anything that needs to be resident.
    hosted: dashmap::DashSet<String>,
    /// Base path for sled databases. Each zone gets `{base_path}/{zone_id}/`.
    base_path: PathBuf,
    /// This node's global ID (same across all zones on this node).
    node_id: u64,
    /// Shared TLS config — can be updated at runtime for plaintext→mTLS upgrade.
    /// All zones' client pools read from this on new connections.
    tls: Arc<RwLock<Option<TlsConfig>>>,
    /// This node's advertise address — carried in outbound StepMessage
    /// `sender_address` so peers learn `(self.node_id -> address)` on
    /// inbound contact.  Set once at boot via [`Self::set_self_address`];
    /// transport tasks read it when they spawn.  Empty disables
    /// advertisement.
    self_address: Arc<RwLock<String>>,
    /// Optional identity directory for the S3 Phase B ConfState apply
    /// mirror.  When set, every zone the registry creates or joins
    /// installs a [`crate::raft::ConfStateAppliedCb`] that mirrors the
    /// fresh ConfState into `identity.json` via
    /// [`crate::identity::persist_zone_members`] so a subsequent
    /// `data_dir` wipe can auto-rejoin without operator sidecar.
    /// Empty (default) disables the mirror — matches test-harness
    /// and embedded-mode expectations.  Set once at boot via
    /// [`Self::set_identity_dir`].
    identity_dir: Arc<RwLock<Option<PathBuf>>>,
    /// Per-zone concurrent-op guard: tracks zone_ids currently undergoing
    /// setup or removal. Prevents two threads from concurrently opening
    /// the same RedbStore ("Database already open") and from racing a
    /// removal against a re-create. Not a global mutex, so different
    /// zone_ids proceed in parallel.
    creating: DashMap<String, ZoneOp>,
    /// Recently removed zone IDs. Transport-side auto-join consults this
    /// guard so stale Raft messages cannot resurrect a deleted dynamic zone.
    recently_removed: DashMap<String, Instant>,
    /// Set at boot by [`Self::arm_materialization`] — what a hosted zone needs
    /// to become resident on first access. `None` (the default) means this
    /// registry never materializes anything on its own: an embedded or test
    /// registry only ever holds the zones it was explicitly given.
    materialization: RwLock<Option<Materialization>>,
    /// Fired once per zone, right after its runtime is published.
    ///
    /// The hook exists because "a zone became resident" is now an event that
    /// happens at any time, not a boot-time list to walk: everything that has
    /// to be wired per zone — the coordinator's DT_MOUNT apply observer and
    /// mount replay, the A2A stream-wakeup and retention-GC observers — rides
    /// the zone's own lifecycle instead of a sweep over all of them. That also
    /// closes a gap the sweep had: a zone that arrived AFTER boot (joined at
    /// runtime, or reached for the first time) was never wired at all.
    ///
    /// A list, because those subscribers live in different layers and each
    /// owns its own wiring.
    on_materialized: RwLock<Vec<ZoneMaterializedCb>>,
}

/// Callback fired when a zone's runtime becomes resident — see
/// [`ZoneRaftRegistry::add_on_materialized`].
///
/// Receives the zone id and the freshly-published handle, so a subscriber
/// never has to look the zone back up (which, mid-materialization, would be
/// the one lookup that could recurse).
pub type ZoneMaterializedCb =
    Arc<dyn Fn(&str, &ZoneConsensus<FullStateMachine>) + Send + Sync + 'static>;

impl ZoneRaftRegistry {
    /// Create a new empty registry.
    ///
    /// # Arguments
    /// * `base_path` — Base directory for zone sled databases.
    /// * `node_id` — This node's ID (used across all zones).
    pub fn new(base_path: PathBuf, node_id: u64) -> Self {
        Self {
            zones: DashMap::new(),
            hosted: dashmap::DashSet::new(),
            base_path,
            node_id,
            tls: Arc::new(RwLock::new(None)),
            self_address: Arc::new(RwLock::new(String::new())),
            identity_dir: Arc::new(RwLock::new(None)),
            creating: DashMap::new(),
            recently_removed: DashMap::new(),
            materialization: RwLock::new(None),
            on_materialized: RwLock::new(Vec::new()),
        }
    }

    /// Create a new empty registry with TLS configuration.
    pub fn with_tls(base_path: PathBuf, node_id: u64, tls: Option<TlsConfig>) -> Self {
        Self {
            zones: DashMap::new(),
            hosted: dashmap::DashSet::new(),
            base_path,
            node_id,
            tls: Arc::new(RwLock::new(tls)),
            self_address: Arc::new(RwLock::new(String::new())),
            identity_dir: Arc::new(RwLock::new(None)),
            creating: DashMap::new(),
            recently_removed: DashMap::new(),
            materialization: RwLock::new(None),
            on_materialized: RwLock::new(Vec::new()),
        }
    }

    pub(crate) fn is_auto_join_suppressed(&self, zone_id: &str) -> bool {
        let Some(removed_at) = self.recently_removed.get(zone_id) else {
            return false;
        };
        let expired = removed_at.elapsed() >= AUTO_JOIN_REMOVAL_SUPPRESSION;
        drop(removed_at);
        if expired {
            self.recently_removed.remove(zone_id);
            false
        } else {
            true
        }
    }

    fn clear_auto_join_suppression(&self, zone_id: &str) {
        self.recently_removed.remove(zone_id);
    }

    /// Set this node's advertise address — see [`Self::self_address`].
    /// Idempotent; may be called multiple times if the operator
    /// updates the advertise address at runtime.
    pub fn set_self_address(&self, address: String) {
        *self.self_address.write().unwrap() = address;
    }

    /// Set the identity directory for the S3 Phase B ConfState apply
    /// mirror.  Call before any zone is created; already-created zones
    /// carry a snapshot of the value at their setup time (the callback
    /// is installed at zone-setup time, not runtime-poked).
    pub fn set_identity_dir(&self, dir: PathBuf) {
        *self.identity_dir.write().unwrap() = Some(dir);
    }

    /// Current identity directory, if set.
    pub fn identity_dir(&self) -> Option<PathBuf> {
        self.identity_dir.read().unwrap().clone()
    }

    /// Allow this registry to materialize a hosted zone on first access.
    ///
    /// Call once at boot, with the same peer address book and runtime the old
    /// open-everything path handed to each zone, plus the policy that says
    /// which zones this process may open at all. Until it is called (embedded
    /// and test registries), a lookup only ever finds an already-resident zone.
    pub fn arm_materialization(
        &self,
        peers: Vec<NodeAddress>,
        runtime: tokio::runtime::Handle,
        policy: ZoneLoadPolicy,
    ) {
        *self.materialization.write().unwrap() = Some(Materialization {
            peers,
            runtime,
            policy,
        });
    }

    /// Subscribe to per-zone materialization — see [`ZoneMaterializedCb`].
    ///
    /// Subscribers must be idempotent per zone: boot arms what is already
    /// resident and then subscribes, so a zone can legitimately be wired
    /// twice. (Both in-tree subscribers register KEYED apply observers, which
    /// replace rather than accumulate.)
    pub fn add_on_materialized(&self, cb: ZoneMaterializedCb) {
        self.on_materialized.write().unwrap().push(cb);
    }

    /// Get this node's advertise address (empty when unset).
    pub fn self_address(&self) -> String {
        self.self_address.read().unwrap().clone()
    }

    /// Get a snapshot of the current TLS config.
    pub fn tls_config(&self) -> Option<TlsConfig> {
        self.tls.read().unwrap().clone()
    }

    /// Create a new zone with its own Raft group.
    ///
    /// Sync — `setup_zone` does only sync work (open redb, construct
    /// `ZoneConsensus`, `Handle::spawn` the transport loop, register in
    /// the DashMap). `Handle::spawn` is callable from any thread that
    /// has a runtime handle, regardless of whether the calling thread
    /// is itself running inside a tokio runtime, so this fn is safe
    /// from both `#[tokio::main]` async callers (e.g. `nexusd-cluster`)
    /// and bare-sync callers (e.g. cluster binary boot).
    ///
    /// raft contract: leader election is owned by raft-rs's `tick()`
    /// loop. For single-voter clusters, the election timer fires once
    /// and the sole voter self-elects. For multi-voter, the standard
    /// randomized timeout + MsgVote dance picks one. We do not call
    /// `campaign()` externally; the loop converges on its own.
    ///
    /// # Arguments
    /// * `zone_id` — Unique zone identifier.
    /// * `peers` — The full cluster roster for this zone (may include
    ///   this node's own `NodeAddress`; self is filtered out before
    ///   passing to raft-rs per the `RaftConfig.peers` contract).
    /// * `runtime_handle` — Tokio runtime handle for spawning the transport loop.
    #[allow(clippy::result_large_err)]
    pub fn create_zone(
        &self,
        zone_id: &str,
        peers: Vec<NodeAddress>,
        runtime_handle: &tokio::runtime::Handle,
    ) -> Result<ZoneConsensus<FullStateMachine>, TransportError> {
        self.clear_auto_join_suppression(zone_id);
        // Filter self out of the voter ID list. Callers (federation bootstrap,
        // zone_manager) commonly pass the full cluster roster from NEXUS_PEERS
        // which includes this node's own address; raft-rs expects
        // `config.peers` to list OTHER peers only, so including self would
        // produce a duplicate voter ID in ConfState.
        let peer_ids: Vec<u64> = peers
            .iter()
            .map(|p| p.id)
            .filter(|&id| id != self.node_id)
            .collect();
        let config = RaftConfig {
            id: self.node_id,
            peers: peer_ids,
            // Carry the registry's advertise address through to the
            // bootstrap `AddNode(self)` entry's `context` field so
            // joiners that later replay the log learn how to dial the
            // founder (see `RaftConfig::bootstrap_self_address` for
            // the rationale).
            bootstrap_self_address: self.self_address(),
            ..Default::default()
        };

        // Founder authors the zone as a voter.
        self.setup_zone(
            zone_id,
            config,
            peers,
            runtime_handle,
            crate::identity::IdentityZoneRole::Voter,
        )
    }

    /// Join an existing zone as a Voter or Learner.
    ///
    /// Unlike `create_zone`, this does NOT bootstrap ConfState. The
    /// leader's snapshot will bring the correct voter set after
    /// ConfChange commit.
    ///
    /// `learner` is informational here — the actual Voter/Learner classification is
    /// determined by the ConfChange the leader proposes (AddNode vs AddLearnerNode).
    /// Callers must send a JoinZone RPC to the leader with the same learner flag via
    /// PyFederationClient::request_join_zone.
    #[allow(clippy::result_large_err)]
    pub fn join_zone(
        &self,
        zone_id: &str,
        peers: Vec<NodeAddress>,
        learner: bool,
        runtime_handle: &tokio::runtime::Handle,
    ) -> Result<ZoneConsensus<FullStateMachine>, TransportError> {
        self.clear_auto_join_suppression(zone_id);
        // Per raft contract: joining nodes start uninitialized (empty ConfState).
        // The leader will send a snapshot with the correct voter set after
        // the ConfChange(AddNode/AddLearnerNode) is committed.
        let config = RaftConfig {
            id: self.node_id,
            peers: vec![],
            skip_bootstrap: true,
            ..Default::default()
        };

        // `learner` is the caller's role INTENT: it's persisted as the
        // durable desired role (SSOT for rejoin), and the matching JoinZone
        // RPC carries the same flag so the leader's learner-then-promote
        // reaches the intended role. The achieved role is ConfState-derived
        // at runtime and never persisted.
        let intended_role = if learner {
            crate::identity::IdentityZoneRole::Learner
        } else {
            crate::identity::IdentityZoneRole::Voter
        };
        self.setup_zone(zone_id, config, peers, runtime_handle, intended_role)
    }

    /// Open a previously-persisted zone from disk WITHOUT bootstrapping.
    ///
    /// Used by boot (eager set) and by on-demand materialization. Unlike
    /// `create_zone`, this uses `skip_bootstrap=true` so the ConfState
    /// restored from `RaftStorage::initial_state()` is the authority —
    /// no new voters are written.
    ///
    /// R15.e: replaces the old `step_message` auto-reopen-from-disk
    /// side-effect. Enumeration at startup runs before the gRPC server
    /// accepts traffic, so by the time a vote/append arrives the zone
    /// is already registered.
    #[allow(clippy::result_large_err)]
    pub fn open_persisted_zone(
        &self,
        zone_id: &str,
        peers: Vec<NodeAddress>,
        runtime_handle: &tokio::runtime::Handle,
    ) -> Result<ZoneConsensus<FullStateMachine>, TransportError> {
        self.clear_auto_join_suppression(zone_id);
        let config = RaftConfig {
            id: self.node_id,
            peers: vec![],
            skip_bootstrap: true,
            ..Default::default()
        };
        // Restart preserves the persisted role intent (SSOT) — don't re-guess.
        let intended_role = self.persisted_intent(zone_id);
        let node = self.setup_zone(zone_id, config, peers, runtime_handle, intended_role)?;
        wait_until_caught_up(&node, zone_id, RESUME_CATCHUP_BUDGET);
        Ok(node)
    }

    /// The DURABLE role intent persisted for `zone_id` in `identity.json`,
    /// or Voter if none is recorded.  Used by the restart path so a resumed
    /// zone keeps its declared role rather than re-deriving one.
    fn persisted_intent(&self, zone_id: &str) -> crate::identity::IdentityZoneRole {
        self.identity_dir()
            .and_then(|dir| crate::identity::load(&dir).ok())
            .and_then(|id| {
                id.zones
                    .into_iter()
                    .find(|z| z.zone_id == zone_id)
                    .map(|z| z.as_role)
            })
            .unwrap_or_default()
    }

    /// Enumerate `base_path/*/raft/` into the catalog, materializing nothing.
    ///
    /// Called once at boot, before the gRPC server accepts RPCs, so that by
    /// the time a vote / append / VFS call arrives this node already KNOWS
    /// which zones it hosts — it just has not opened them yet. Local storage
    /// stays the source of truth for "which groups does this node host?" (the
    /// etcd / CockroachDB / TiKV pattern); this reads that truth into
    /// [`Self::hosted`] so every later lookup is an in-memory hit.
    ///
    /// The R15.e invariant — a persisted zone must never be invisible to a
    /// request — is upheld more strongly than by the old open-everything boot:
    /// an unknown zone id used to mean "not on this node" only because boot had
    /// already opened every directory, whereas now [`Self::get_node`]
    /// materializes anything in the catalog on demand. What boot no longer does
    /// is pay for zones nobody asks about: 10k persisted zones cost one readdir
    /// instead of 10k raft-group openings.
    ///
    /// Finishes any interrupted removal it finds (a tombstoned dir from a crash
    /// mid-`remove_zone`), which is where that cleanup has always happened.
    ///
    /// Idempotent. Returns the number of hosted zones now indexed.
    #[allow(clippy::result_large_err)]
    pub fn index_persisted_zones(&self) -> Result<usize, TransportError> {
        if !self.base_path.exists() {
            return Ok(0);
        }
        let entries = std::fs::read_dir(&self.base_path).map_err(|e| {
            TransportError::Connection(format!(
                "Failed to read base_path {}: {}",
                self.base_path.display(),
                e
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                TransportError::Connection(format!("Failed to read dir entry: {}", e))
            })?;
            // Only consider directories: each zone lives under its own
            // `{base_path}/{zone_id}/` subdir.
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let zone_id = entry.file_name().to_string_lossy().into_owned();
            if self.index_persisted_zone_if_present(&zone_id) {
                self.hosted.insert(zone_id);
            }
        }
        tracing::info!(
            hosted_zones = self.hosted.len(),
            base_path = %self.base_path.display(),
            "Indexed persisted zones (materialized on first access)",
        );
        Ok(self.hosted.len())
    }

    /// Is `zone_id` present + resumable on disk? Finishes an interrupted
    /// removal (tombstone) rather than resurrecting a zombie zone that would
    /// send raft messages to peers who — correctly — return NotFound.
    fn index_persisted_zone_if_present(&self, zone_id: &str) -> bool {
        if ZonePersistence::has_tombstone(&self.base_path, zone_id) {
            match ZonePersistence::cleanup_tombstoned(&self.base_path, zone_id) {
                Ok(()) => {
                    tracing::info!(zone = %zone_id, "Cleaned up tombstoned zone dir at startup")
                }
                Err(e) => tracing::warn!(
                    zone = %zone_id,
                    error = %e,
                    "Failed to clean up tombstoned zone dir at startup",
                ),
            }
            return false;
        }
        // If `{zone}/raft/` doesn't exist, this isn't a persisted zone — skip.
        // Matches `RaftStorage::open`, which is what creates that subdir.
        self.base_path.join(zone_id).join("raft").exists()
    }

    /// Materialize the named zones NOW, if they are present on disk.
    ///
    /// Everything else waits for its first access. Boot uses this for the zones
    /// that must be resident before the daemon can serve anything at all — the
    /// root zone, whose DT_MOUNT entries define the federation namespace, and
    /// the credential zone that authenticates the very requests that would
    /// otherwise trigger materialization. Returns the number actually opened.
    #[allow(clippy::result_large_err)]
    pub fn materialize_now(
        &self,
        zone_ids: &[String],
        peers: Vec<NodeAddress>,
        runtime_handle: &tokio::runtime::Handle,
    ) -> Result<usize, TransportError> {
        let mut count: usize = 0;
        for zone_id in zone_ids {
            if !self.index_persisted_zone_if_present(zone_id) {
                continue;
            }
            self.hosted.insert(zone_id.clone());
            self.open_persisted_zone(zone_id, peers.clone(), runtime_handle)?;
            count += 1;
        }
        Ok(count)
    }

    /// Internal: open sled, create ZoneConsensus + driver, spawn transport loop, register zone.
    ///
    /// Sync — every operation here is sync-callable: redb open, raft
    /// storage open, `FullStateMachine::new`, optional snapshot
    /// rehydration, `ZoneConsensus::new` (no I/O), and
    /// `runtime_handle.spawn` (submits the future without requiring
    /// the calling thread to be a runtime worker). Leader election is
    /// driven by raft-rs's tick loop inside the spawned transport
    /// task — no external `campaign()` call is needed; raft-rs
    /// converges on its own (single voter self-elects on the first
    /// election timeout, multi-voter runs the standard randomized
    /// MsgVote dance).
    #[allow(clippy::result_large_err)]
    fn setup_zone(
        &self,
        zone_id: &str,
        config: RaftConfig,
        mut peers: Vec<NodeAddress>,
        runtime_handle: &tokio::runtime::Handle,
        // This node's DURABLE role intent for the zone (voter/learner as
        // declared at join). Persisted once here as the SSOT for "what role
        // do I want"; the apply cb persists only the members list, never the
        // ephemeral achieved role. See `identity::persist_zone_intent`.
        intended_role: crate::identity::IdentityZoneRole,
    ) -> Result<ZoneConsensus<FullStateMachine>, TransportError> {
        // Fast path: zone already exists — no work needed.
        if let Some(entry) = self.zones.get(zone_id) {
            return Ok(entry.node.clone());
        }

        // Per-zone concurrent-op guard using DashMap::entry for atomic
        // check-and-insert. Prevents (a) two threads concurrently opening the
        // same RedbStore ("Database already open") and (b) a fresh setup
        // racing an in-progress remove on the same zone_id. Different
        // zone_ids proceed in parallel — no global mutex.
        let setup_wait_started = std::time::Instant::now();
        loop {
            use dashmap::mapref::entry::Entry;
            match self.creating.entry(zone_id.to_string()) {
                Entry::Occupied(_occupied) => {
                    drop(_occupied);
                    // Another setup is in progress, or a remove is tearing the
                    // zone down. Dynamic zone creation can race with the
                    // transport auto-join path on followers, so wait for the
                    // first setup to publish the handle before treating it as
                    // an actual conflict.
                    if let Some(entry) = self.zones.get(zone_id) {
                        return Ok(entry.node.clone());
                    }
                    if setup_wait_started.elapsed() >= std::time::Duration::from_secs(3) {
                        return self
                            .zones
                            .get(zone_id)
                            .map(|e| e.node.clone())
                            .ok_or_else(|| {
                                TransportError::Connection(format!(
                                    "Zone '{}' concurrent op in progress",
                                    zone_id,
                                ))
                            });
                    }
                    // sync sleep — `setup_zone` is now sync (no campaign
                    // dependency means no `.await`). Contention is rare
                    // (only when concurrent `setup_zone` calls collide on
                    // the same zone_id) and capped at 3s, so a worker
                    // thread blocking here is acceptable.
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Entry::Vacant(v) => {
                    v.insert(ZoneOp::Creating);
                    break;
                }
            }
        }

        // Release the guard on any exit path (success or failure).
        struct CreatingGuard<'a> {
            creating: &'a DashMap<String, ZoneOp>,
            zone_id: String,
        }
        impl<'a> Drop for CreatingGuard<'a> {
            fn drop(&mut self) {
                self.creating.remove(&self.zone_id);
            }
        }
        let _guard = CreatingGuard {
            creating: &self.creating,
            zone_id: zone_id.to_string(),
        };

        // Re-check: zone may have been created between the fast-path check
        // and acquiring the per-zone guard.
        if let Some(entry) = self.zones.get(zone_id) {
            return Ok(entry.node.clone());
        }

        // Open the zone dir via ZonePersistence. Existing dir →
        // `open()` (not armed). Fresh zone → `create()` (armed; rolled back
        // on any `?` return between here and the DashMap insert). Tombstone
        // check is redundant in practice — `index_persisted_zones`
        // cleans these up at startup before setup_zone is called for them
        // — but the guard below means a crash mid-remove produces a clean
        // error on the next create attempt.
        if ZonePersistence::has_tombstone(&self.base_path, zone_id) {
            return Err(TransportError::Connection(format!(
                "Zone '{}' has a pending tombstone; cleanup before recreate",
                zone_id
            )));
        }
        let zone_dir = self.base_path.join(zone_id);
        let mut persistence = if zone_dir.exists() {
            ZonePersistence::open(&self.base_path, zone_id).map_err(|e| {
                TransportError::Connection(format!(
                    "Failed to open existing zone dir for '{}': {}",
                    zone_id, e
                ))
            })?
        } else {
            ZonePersistence::create(&self.base_path, zone_id).map_err(|e| {
                TransportError::Connection(format!(
                    "Failed to create zone dir for '{}': {}",
                    zone_id, e
                ))
            })?
        };

        // Open zone-specific redb + state machine
        let store = RedbStore::open(persistence.sm_path())
            .map_err(|e| TransportError::Connection(format!("Failed to open store: {}", e)))?;
        let raft_storage = RaftStorage::open(persistence.raft_path()).map_err(|e| {
            TransportError::Connection(format!("Failed to open raft storage: {}", e))
        })?;
        use raft::Storage;
        if let Ok(initial_state) = raft_storage.initial_state() {
            reconcile_peers_with_conf_state(zone_id, &mut peers, &initial_state.conf_state);
        }
        let mut state_machine = FullStateMachine::new(&store).map_err(|e| {
            TransportError::Connection(format!("Failed to create state machine: {}", e))
        })?;

        // R14 raft-rs contract fix: rehydrate advisory lock state from
        // any persisted snapshot before raft-rs gets the state machine.
        //
        // raft-rs's RaftLog::new sets `applied = first_index - 1`. If
        // the log was compacted at index X, first_index = X+1 and
        // raft-rs will only re-emit committed entries in [X+1..commit]
        // on startup. It does NOT re-emit the stored snapshot itself
        // — Ready's `snapshot` field is only populated by a *new*
        // snapshot received from the leader at runtime.
        //
        // Pre-R14 this didn't matter: advisory lock state was persisted
        // row-by-row in redb, so FullStateMachine::new loaded it from
        // there. After R14 the BTreeMap is in-memory only; without
        // this rehydration, any advisory holders committed before the
        // last compact would be lost on restart. Rehydrating here
        // keeps the post-restart state machine consistent with other
        // replicas that are caught up via the normal log-replay path.
        if let Ok(snap) = raft_storage.snapshot(0, 0) {
            let meta = snap.get_metadata();
            if meta.index > 0 && !snap.data.is_empty() {
                state_machine.restore_snapshot(&snap.data).map_err(|e| {
                    TransportError::Connection(format!(
                        "Failed to rehydrate state machine from stored snapshot at index {}: {}",
                        meta.index, e
                    ))
                })?;
                tracing::info!(
                    zone = %zone_id,
                    snapshot_index = meta.index,
                    snapshot_term = meta.term,
                    "Rehydrated advisory lock state from stored snapshot on startup",
                );
            }
        }

        // Create EC replication log (non-witness nodes only)
        let replication_log = if !config.is_witness {
            let log = ReplicationLog::new(&store, config.id).map_err(|e| {
                TransportError::Connection(format!("Failed to create ReplicationLog: {}", e))
            })?;
            Some(Arc::new(log))
        } else {
            None
        };

        // Create ZoneConsensus handle + driver
        let (mut handle, mut driver) =
            ZoneConsensus::new(config, raft_storage, state_machine, replication_log).map_err(
                |e| TransportError::Connection(format!("Failed to create ZoneConsensus: {}", e)),
            )?;

        // Peer map — shared between ZoneEntry, TransportLoop, and ZoneConsensusDriver.
        // `PeerMap::with_peers` drops any self-entry in the seed (self is a ConfState
        // member, not a transport peer — see `PeerMap` invariant).
        let peer_map: HashMap<u64, NodeAddress> = peers.into_iter().map(|p| (p.id, p)).collect();
        let shared_peers: SharedPeerMap =
            Arc::new(RwLock::new(PeerMap::with_peers(self.node_id, peer_map)));

        driver.set_peer_map(shared_peers.clone(), self.tls_config().is_some());

        // S3 Phase B: install ConfState apply mirror if the coordinator
        // has an identity_dir in scope.  Callback captures zone_id +
        // identity_dir + shared_peers (for u64 → NodeAddress lookup) +
        // self.node_id (for self-address inclusion when peer_map has
        // not yet learned it).  Emits `persist_zone_members` calls that
        // survive `data_dir` wipes and drive the joiner auto-reconnect
        // path in [`crate::bootstrap`].
        if let Some(id_dir) = self.identity_dir() {
            // Record the DURABLE role intent ONCE, up front — the SSOT for
            // "what role do I want" that boot reads to reissue JoinZone.
            // The apply cb below persists ONLY the members address book and
            // never the (ephemeral, ConfState-derived) achieved role.
            match crate::identity::load(&id_dir) {
                Ok(existing) => {
                    if let Err(e) = crate::identity::persist_zone_intent(
                        &id_dir,
                        &existing,
                        zone_id,
                        intended_role,
                    ) {
                        tracing::warn!(
                            zone = %zone_id,
                            error = %e,
                            "identity persist_zone_intent failed — setup continues",
                        );
                    }
                }
                Err(e) => tracing::warn!(
                    zone = %zone_id,
                    error = %e,
                    "identity load failed before intent persist — setup continues",
                ),
            }

            let zone_id_owned = zone_id.to_string();
            let peers_for_cb = shared_peers.clone();
            let self_addr_for_cb = self.self_address();
            let self_node_id_for_cb = self.node_id;
            let cb: crate::raft::ConfStateAppliedCb =
                Arc::new(move |cs: &raft::eraftpb::ConfState, _self_id: u64| {
                    let all_ids: Vec<u64> = cs
                        .voters
                        .iter()
                        .chain(cs.learners.iter())
                        .copied()
                        .collect();
                    let members: Vec<String> = {
                        let peers = peers_for_cb.read().unwrap();
                        all_ids
                            .iter()
                            .filter_map(|id| {
                                if *id == self_node_id_for_cb {
                                    // peer_map does not carry self —
                                    // fill in from the registry.
                                    (!self_addr_for_cb.is_empty()).then(|| self_addr_for_cb.clone())
                                } else {
                                    peers.get(id).map(NodeAddress::to_operator_str)
                                }
                            })
                            .collect()
                    };
                    // Members only — the durable address book. The role
                    // intent is owned by `persist_zone_intent` above and is
                    // NOT overwritten with the achieved ConfState role here.
                    match crate::identity::load(&id_dir) {
                        Ok(existing) => {
                            if let Err(e) = crate::identity::persist_zone_members(
                                &id_dir,
                                &existing,
                                &zone_id_owned,
                                members,
                            ) {
                                tracing::warn!(
                                    zone = %zone_id_owned,
                                    error = %e,
                                    "identity persist_zone_members failed — apply continues",
                                );
                            }
                        }
                        Err(e) => tracing::warn!(
                            zone = %zone_id_owned,
                            error = %e,
                            "identity load failed inside apply callback — apply continues",
                        ),
                    }
                });
            driver.set_conf_state_applied_cb(cb);
        }

        let client_config = ClientConfig {
            tls: self.tls.clone(),
            ..Default::default()
        };

        // Set up transparent leader forwarding on the handle.
        // When propose() is called on a follower, it forwards to the leader
        // via gRPC instead of returning NotLeader.
        handle.set_forward_ctx(
            RaftClientPool::with_config(client_config.clone()),
            shared_peers.clone(),
            zone_id.to_string(),
        );

        let transport_loop = TransportLoop::new(
            driver,
            shared_peers.clone(),
            RaftClientPool::with_config(client_config),
        )
        .with_zone_id(zone_id.to_string())
        .with_self_address(self.self_address());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let transport_handle = runtime_handle.spawn(transport_loop.run(shutdown_rx));

        // Leader election is owned by raft-rs's tick loop inside the
        // spawned transport task. We do NOT call `campaign()` here —
        // that was an optimisation to short-circuit the election timer
        // for single-voter zones, but it forced setup_zone to be async
        // (and via the `nexusd-cluster` `#[tokio::main]` async path
        // that produced a nested-runtime `block_on` panic at startup).
        // Letting raft-rs handle election keeps the protocol contract
        // pure: single-voter self-elects on the first election timeout,
        // multi-voter runs the standard randomized MsgVote dance.
        // Callers that need leader-confirmed semantics should poll via
        // `ZoneConsensus::is_leader` / `leader_id` after returning.

        tracing::info!(
            "Zone '{}' registered (local_node_id={}, peers={})",
            zone_id,
            self.node_id,
            shared_peers.read().unwrap().len()
        );

        // Commit the on-disk handle before publishing the entry.
        // Post-commit, Drop is a no-op on disk (process shutdown preserves
        // persisted zones). Only explicit `destroy()` in `remove_zone`
        // deletes the dir.
        persistence.commit();

        self.zones.insert(
            zone_id.to_string(),
            ZoneEntry {
                node: handle.clone(),
                peers: shared_peers,
                node_id: self.node_id,
                shutdown_tx,
                transport_handle,
                persistence,
            },
        );
        // The dir is committed and the runtime is published, so this node
        // hosts the zone whichever way we got here — created, joined, or
        // materialized from disk.
        self.hosted.insert(zone_id.to_string());

        // Per-zone wiring rides the zone's own lifecycle. Fired after the
        // insert above, and with the lock released, because a subscriber can
        // legitimately reach back into the registry (wiring a mount can
        // materialize its target zone).
        let hooks: Vec<ZoneMaterializedCb> = self.on_materialized.read().unwrap().clone();
        for cb in hooks {
            cb(zone_id, &handle);
        }

        Ok(handle)
    }

    /// The ZoneConsensus handle for a zone this node hosts, materializing it
    /// first if this is its first access since boot.
    ///
    /// This is the ONE place a zone id becomes a runtime, which is what lets
    /// every caller — the VFS data path, the raft server's `step_message`
    /// dispatch, federation bookkeeping — stay written as "do I host this
    /// zone?" without any of them knowing about residency. `None` still means
    /// exactly what it always meant: not this node's zone.
    ///
    /// Hot path unchanged: a resident zone is one `DashMap` hit. The slow path
    /// runs once per zone per process and does the same synchronous open the
    /// old boot loop did (two redb opens and a few fsyncs, single-digit ms on
    /// an SSD), so a caller on an async worker blocks for that first touch.
    pub fn get_node(&self, zone_id: &str) -> Option<ZoneConsensus<FullStateMachine>> {
        if let Some(entry) = self.zones.get(zone_id) {
            return Some(entry.node.clone());
        }
        self.materialize(zone_id)
    }

    /// Slow path of [`Self::get_node`]: open a hosted-but-not-resident zone.
    fn materialize(&self, zone_id: &str) -> Option<ZoneConsensus<FullStateMachine>> {
        if !self.hosted.contains(zone_id) {
            return None;
        }
        let (peers, runtime) = {
            let guard = self.materialization.read().unwrap();
            let m = guard.as_ref()?;
            if !m.policy.may_materialize(zone_id) {
                tracing::debug!(
                    zone = %zone_id,
                    "zone is hosted but this process may not materialize it (load policy)",
                );
                return None;
            }
            (m.peers.clone(), m.runtime.clone())
        };
        match self.open_persisted_zone(zone_id, peers, &runtime) {
            Ok(node) => {
                tracing::info!(zone = %zone_id, "Zone materialized on first access");
                Some(node)
            }
            Err(e) => {
                // Loud: a hosted zone that cannot be opened is a broken data
                // dir, and the caller can only report it as absent. Boot used
                // to fail hard on this; keep it visible now that it surfaces
                // at first touch instead.
                tracing::error!(
                    zone = %zone_id,
                    error = %e,
                    "Failed to materialize a hosted zone — it will read as absent",
                );
                None
            }
        }
    }

    /// Get a snapshot of the peers map for a zone.
    /// Get the base path for zone storage directories.
    pub fn base_path(&self) -> &PathBuf {
        &self.base_path
    }

    pub fn get_peers(&self, zone_id: &str) -> Option<HashMap<u64, NodeAddress>> {
        self.zones
            .get(zone_id)
            .map(|e| e.peers.read().unwrap().snapshot())
    }

    /// Get cluster peer addresses from any existing zone (all zones share the same peers).
    /// Used by auto-join for new zones that don't have their own peer map yet.
    pub fn get_all_peers(&self) -> Vec<NodeAddress> {
        for entry in self.zones.iter() {
            let peers = entry.peers.read().unwrap();
            if !peers.is_empty() {
                return peers.values().cloned().collect();
            }
        }
        Vec::new()
    }

    /// Record a peer's advertise address learned from an inbound
    /// `StepMessage`.  The transport peer-map's runtime SSOT under
    /// the opaque-ID contract: every received raft message proves
    /// the sender's reachable address, so we update on every
    /// arrival rather than persist + hope.  Returns `true` if the
    /// map changed (insert or address update), `false` otherwise.
    ///
    /// Empty `endpoint` is treated as "no advertise — keep existing
    /// entry".  The caller is responsible for verifying `peer_id`
    /// is a legitimate cluster member (zone authorization upstream
    /// gates that).
    pub fn learn_peer_address(&self, zone_id: &str, peer_id: u64, endpoint: &str) -> bool {
        if endpoint.is_empty() || peer_id == 0 {
            return false;
        }
        // Self-exclusion is enforced structurally by `PeerMap::insert` (self is a
        // ConfState member, not a transport peer — PR #3996 opaque-ID contract);
        // the insert below returns `false` for a self-entry, so this method
        // reports "no change" without a scattered `== self.node_id` guard.
        let Some(entry) = self.zones.get(zone_id) else {
            return false;
        };
        let mut peers = entry.peers.write().unwrap();
        if let Some(existing) = peers.get(&peer_id) {
            if existing.endpoint == endpoint {
                return false;
            }
        }
        // The peer advertises a bare `host:port` authority; scheme it with
        // THIS node's transport posture (the cluster's SSOT — the registry
        // TLS config), not by sniffing the string. A scheme-less address
        // under mTLS must become `https://` or the dial fails the handshake.
        // An already-qualified `https://` address parses the same either way.
        let use_tls = self.tls_config().is_some();
        let parsed = match NodeAddress::parse(endpoint, use_tls) {
            Ok(mut p) => {
                p.id = peer_id;
                p
            }
            Err(_) => return false,
        };
        // `PeerMap::insert` returns `false` iff the entry was self — propagate
        // that as "map unchanged".
        peers.insert(peer_id, parsed)
    }

    /// Get the node_id for a zone (same across all zones on this node).
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Remove a zone — shut down its transport loop and delete its on-disk
    /// dir atomically via tombstone.
    ///
    /// Sequence:
    /// 1. Take the entry out of the DashMap (further `get_node` returns None).
    /// 2. Write the tombstone file — the durable commit point of "this zone
    ///    is being torn down". A crash after this leaves a tombstoned dir;
    ///    next startup's `index_persisted_zones` completes cleanup.
    /// 3. Signal shutdown to the transport loop, await its JoinHandle so
    ///    the spawned task has fully exited before we drop `ZoneConsensus`.
    /// 4. Drop `ZoneConsensus` (entry goes out of scope). Driver task
    ///    exits, closing all redb table handles so `remove_dir_all` can
    ///    succeed on Windows (which refuses to delete open-handle files).
    /// 5. `persistence.destroy()` — the `rmdir -r`.
    #[allow(clippy::result_large_err)]
    pub async fn remove_zone(&self, zone_id: &str) -> Result<(), TransportError> {
        // Serialize against setup_zone on the same zone_id.
        {
            use dashmap::mapref::entry::Entry;
            match self.creating.entry(zone_id.to_string()) {
                Entry::Occupied(_occupied) => {
                    drop(_occupied);
                    return Err(TransportError::Connection(format!(
                        "Zone '{}' concurrent op in progress; retry remove shortly",
                        zone_id,
                    )));
                }
                Entry::Vacant(v) => {
                    v.insert(ZoneOp::Removing);
                }
            }
        }
        struct RemovingGuard<'a> {
            creating: &'a DashMap<String, ZoneOp>,
            zone_id: String,
        }
        impl<'a> Drop for RemovingGuard<'a> {
            fn drop(&mut self) {
                self.creating.remove(&self.zone_id);
            }
        }
        let _guard = RemovingGuard {
            creating: &self.creating,
            zone_id: zone_id.to_string(),
        };

        let (_, entry) = self
            .zones
            .remove(zone_id)
            .ok_or_else(|| TransportError::Connection(format!("Zone '{}' not found", zone_id)))?;

        let ZoneEntry {
            node,
            peers: _,
            node_id: _,
            shutdown_tx,
            transport_handle,
            persistence,
        } = entry;
        self.recently_removed
            .insert(zone_id.to_string(), Instant::now());
        // Out of the catalog too — the dir is about to go. A crash between
        // here and `destroy()` leaves a tombstone that the next boot's
        // `index_persisted_zones` finishes cleaning up.
        self.hosted.remove(zone_id);

        // Commit point: the tombstone is what makes teardown crash-safe.
        // If this write fails, the caller sees the error and the zone is
        // re-registered (we already did `zones.remove`). Accept this edge
        // case: the zone is gone from memory, dir is still on disk; on
        // next restart re-indexes it. No
        // zombie — no remote peers were told this zone is dying.
        if let Err(e) = persistence.write_tombstone() {
            // Best-effort: put the zone back so state isn't lost from memory.
            self.zones.insert(
                zone_id.to_string(),
                ZoneEntry {
                    node,
                    peers: Arc::new(RwLock::new(PeerMap::new(self.node_id))),
                    node_id: self.node_id,
                    shutdown_tx,
                    transport_handle,
                    persistence,
                },
            );
            self.recently_removed.remove(zone_id);
            self.hosted.insert(zone_id.to_string());
            return Err(TransportError::Connection(format!(
                "Failed to write tombstone for zone '{}': {}",
                zone_id, e
            )));
        }

        // Signal transport shutdown and await its exit so Windows release
        // of file handles completes before we try to rmdir.
        let _ = shutdown_tx.send(true);
        if let Err(e) = transport_handle.await {
            tracing::warn!(
                zone = %zone_id,
                error = %e,
                "Transport loop task failed during remove_zone; continuing with destroy",
            );
        }

        // Explicitly drop the ZoneConsensus handle so the driver task's
        // last reference goes away. On Windows, any surviving redb handle
        // would fail remove_dir_all with PermissionDenied.
        drop(node);

        // Short yield to let the driver task observe the dropped handle
        // and exit before we attempt rmdir. The driver uses an internal
        // channel with this as the only external reference (besides the
        // clones given to the zone's own transport/gRPC surfaces, all of
        // which are already gone by this point).
        tokio::task::yield_now().await;

        if let Err(e) = persistence.destroy() {
            // Dir deletion failed — log but don't resurrect the zone.
            // Tombstone is still on disk; next startup will retry cleanup.
            tracing::warn!(
                zone = %zone_id,
                error = %e,
                "Failed to delete zone dir; tombstone preserved for startup cleanup",
            );
        }

        tracing::info!("Zone '{}' removed", zone_id);
        Ok(())
    }

    /// Every zone this node hosts, materialized or not.
    ///
    /// The catalog, not the resident set: "which zones does this node host?"
    /// is a durable question, and answering it with whatever happens to be
    /// open would make the answer depend on who has been asked for what since
    /// boot. Callers that need to act ON each zone should go through
    /// [`Self::get_node`], which materializes — and should think about whether
    /// they want to, since that is exactly the sweep this design removes.
    pub fn list_zones(&self) -> Vec<String> {
        self.hosted.iter().map(|e| e.key().clone()).collect()
    }

    /// The zones whose runtime is currently resident — a runtime fact, for
    /// shutdown and diagnostics only.
    pub fn resident_zones(&self) -> Vec<String> {
        self.zones.iter().map(|e| e.key().clone()).collect()
    }

    /// Does this node host `zone_id`? Answers from the catalog WITHOUT
    /// materializing it.
    ///
    /// For callers whose question is existence rather than access — "is there
    /// anything to found here?" — which must not drag a zone into residency
    /// just to learn that it is already there.
    pub fn hosts(&self, zone_id: &str) -> bool {
        self.hosted.contains(zone_id)
    }

    /// Shutdown all zones.
    pub fn shutdown_all(&self) {
        for entry in self.zones.iter() {
            let _ = entry.shutdown_tx.send(true);
        }
        self.zones.clear();
        tracing::info!("All zones shut down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn index_persisted_zones_on_empty_base_path() {
        // Empty (nonexistent) base_path returns Ok(0) — nothing hosted.
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let reg = ZoneRaftRegistry::new(missing, 1);
        assert_eq!(reg.index_persisted_zones().unwrap(), 0);
        assert!(reg.list_zones().is_empty());
    }

    /// Wait for a transport task's held Arc<RedbStore> to be released
    /// after `shutdown_all`. The transport loop's tick period is ~100ms,
    /// so 500ms is a generous margin. Test-only — production paths use
    /// the explicit transport shutdown handshake, not a sleep.
    async fn await_shutdown_cleanup() {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    #[test]
    fn test_reconcile_peers_with_conf_state_repairs_single_rotated_id() {
        let mut peers = vec![
            NodeAddress::parse("nexus-1:2126", false).unwrap(),
            NodeAddress::parse("nexus-2:2126", false).unwrap(),
            NodeAddress::parse("witness:2126", false).unwrap(),
        ];
        let stale_id = peers[1].id;
        let rotated_id = 13569616949052319723;
        let conf_state = ConfState {
            voters: vec![peers[0].id, rotated_id, peers[2].id],
            ..Default::default()
        };

        reconcile_peers_with_conf_state("root", &mut peers, &conf_state);

        assert!(!peers.iter().any(|peer| peer.id == stale_id));
        let repaired = peers
            .iter()
            .find(|peer| peer.id == rotated_id)
            .expect("rotated peer id should be present");
        assert_eq!(repaired.hostname, "nexus-2");
        assert_eq!(repaired.endpoint, "http://nexus-2:2126");
    }

    #[test]
    fn test_reconcile_peers_with_conf_state_ignores_ambiguous_mismatch() {
        let mut peers = vec![
            NodeAddress::parse("nexus-1:2126", false).unwrap(),
            NodeAddress::parse("nexus-2:2126", false).unwrap(),
            NodeAddress::parse("witness:2126", false).unwrap(),
        ];
        let original = peers.clone();
        let conf_state = ConfState {
            voters: vec![peers[0].id, 42],
            ..Default::default()
        };

        reconcile_peers_with_conf_state("root", &mut peers, &conf_state);

        assert_eq!(peers, original);
    }

    #[tokio::test]
    async fn a_persisted_zone_is_hosted_at_boot_and_materializes_on_first_access() {
        // The restart contract, in the two halves the split makes distinct:
        // indexing makes the zone HOSTED (cheap, no raft group opened), and
        // the first access makes it RESIDENT with its persisted ConfState
        // (skip_bootstrap=true — `RaftStorage::initial_state()` is
        // authoritative, no new voters written).
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        let reg = ZoneRaftRegistry::new(base.clone(), 1);
        reg.create_zone("corp-eng", vec![], &tokio::runtime::Handle::current())
            .unwrap();
        assert_eq!(reg.list_zones(), vec!["corp-eng".to_string()]);
        // Simulate process restart: shutdown tasks, release file locks.
        reg.shutdown_all();
        drop(reg);
        await_shutdown_cleanup().await;

        // New registry, same base_path — index from disk.
        let reg2 = ZoneRaftRegistry::new(base, 1);
        assert_eq!(reg2.index_persisted_zones().unwrap(), 1);
        assert_eq!(reg2.list_zones(), vec!["corp-eng".to_string()]);
        assert!(
            reg2.resident_zones().is_empty(),
            "indexing must not open anything — that is the whole point",
        );

        reg2.arm_materialization(
            vec![],
            tokio::runtime::Handle::current(),
            ZoneLoadPolicy::OnDemand,
        );
        assert!(
            reg2.get_node("corp-eng").is_some(),
            "a hosted zone materializes on first access",
        );
        assert_eq!(reg2.resident_zones(), vec!["corp-eng".to_string()]);

        reg2.shutdown_all();
        await_shutdown_cleanup().await;
    }

    #[tokio::test]
    async fn index_persisted_zones_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let reg = ZoneRaftRegistry::new(base.clone(), 1);
        reg.create_zone("zone-a", vec![], &tokio::runtime::Handle::current())
            .unwrap();
        reg.shutdown_all();
        drop(reg);
        await_shutdown_cleanup().await;

        let reg2 = ZoneRaftRegistry::new(base, 1);
        assert_eq!(reg2.index_persisted_zones().unwrap(), 1);
        assert_eq!(reg2.index_persisted_zones().unwrap(), 1);
        assert_eq!(reg2.list_zones().len(), 1);
    }

    #[tokio::test]
    async fn only_policy_keeps_offline_tooling_out_of_federated_raft() {
        // With two zones persisted, an offline tool scoped to "root" must open
        // root and be UNABLE to open the federated zone — not just at boot but
        // through any later lookup, because opening it would campaign and
        // mutate a term/vote the real daemon then resumes against.
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let reg = ZoneRaftRegistry::new(base.clone(), 1);
        reg.create_zone("root", vec![], &tokio::runtime::Handle::current())
            .unwrap();
        reg.create_zone("sharedzone", vec![], &tokio::runtime::Handle::current())
            .unwrap();
        reg.shutdown_all();
        drop(reg);
        await_shutdown_cleanup().await;

        let reg2 = ZoneRaftRegistry::new(base, 1);
        assert_eq!(reg2.index_persisted_zones().unwrap(), 2, "both are hosted");
        reg2.arm_materialization(
            vec![],
            tokio::runtime::Handle::current(),
            ZoneLoadPolicy::Only(vec!["root".to_string()]),
        );
        let n = reg2
            .materialize_now(
                &["root".to_string()],
                vec![],
                &tokio::runtime::Handle::current(),
            )
            .unwrap();
        assert_eq!(n, 1, "only root should open");
        assert_eq!(reg2.resident_zones(), vec!["root".to_string()]);
        assert!(
            reg2.get_node("sharedzone").is_none(),
            "a root-scoped process must not reach the federated zone, even on demand",
        );
        assert_eq!(
            reg2.resident_zones(),
            vec!["root".to_string()],
            "and the refused lookup must not have opened it either",
        );

        reg2.shutdown_all();
        await_shutdown_cleanup().await;
    }

    // Zone lifecycle regression tests — zone lifecycle is crash-safe
    // and disk-dir existence is the authoritative answer to "does
    // this node host zone X?".

    #[tokio::test]
    async fn test_remove_zone_deletes_disk_dir() {
        // remove_zone() must delete {base}/{zone_id}/ so the next
        // index_persisted_zones doesn't resurrect it as a zombie.
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let reg = ZoneRaftRegistry::new(base.clone(), 1);
        reg.create_zone("temp-zone", vec![], &tokio::runtime::Handle::current())
            .unwrap();
        assert!(
            base.join("temp-zone").exists(),
            "zone dir should exist after create"
        );

        reg.remove_zone("temp-zone").await.unwrap();
        assert!(
            !base.join("temp-zone").exists(),
            "zone dir must be gone after remove_zone",
        );
        assert!(reg.get_node("temp-zone").is_none());
        assert!(reg.list_zones().is_empty());

        reg.shutdown_all();
        await_shutdown_cleanup().await;
    }

    #[tokio::test]
    async fn test_remove_zone_suppresses_transport_auto_join_until_explicit_recreate() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let reg = ZoneRaftRegistry::new(base, 1);
        reg.create_zone("temp-zone", vec![], &tokio::runtime::Handle::current())
            .unwrap();

        reg.remove_zone("temp-zone").await.unwrap();
        assert!(
            reg.is_auto_join_suppressed("temp-zone"),
            "stale raft messages must not resurrect a just-removed zone",
        );

        reg.join_zone(
            "temp-zone",
            vec![],
            false,
            &tokio::runtime::Handle::current(),
        )
        .unwrap();
        assert!(
            !reg.is_auto_join_suppressed("temp-zone"),
            "explicit recreate/join must clear the transport suppression marker",
        );

        reg.shutdown_all();
        await_shutdown_cleanup().await;
    }

    #[tokio::test]
    async fn test_remove_then_reopen_existing_excludes_removed_zone() {
        // After a remove, a fresh registry on the same base_path must not
        // resurrect the removed zone — matching the zombie-zone fix.
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let reg = ZoneRaftRegistry::new(base.clone(), 1);
        reg.create_zone("keep", vec![], &tokio::runtime::Handle::current())
            .unwrap();
        reg.create_zone("gone", vec![], &tokio::runtime::Handle::current())
            .unwrap();
        reg.remove_zone("gone").await.unwrap();
        reg.shutdown_all();
        drop(reg);
        await_shutdown_cleanup().await;

        let reg2 = ZoneRaftRegistry::new(base.clone(), 1);
        let n = reg2.index_persisted_zones().unwrap();
        assert_eq!(n, 1);
        assert_eq!(reg2.list_zones(), vec!["keep".to_string()]);
        assert!(!base.join("gone").exists());

        reg2.shutdown_all();
        await_shutdown_cleanup().await;
    }

    #[tokio::test]
    async fn test_tombstone_cleanup_on_startup() {
        // Simulate a crash between write_tombstone() and destroy(): the
        // zone dir is still on disk along with a .removed marker. Startup
        // must finish the cleanup instead of resurrecting the zombie.
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let reg = ZoneRaftRegistry::new(base.clone(), 1);
        reg.create_zone("crash-zone", vec![], &tokio::runtime::Handle::current())
            .unwrap();
        reg.shutdown_all();
        drop(reg);
        await_shutdown_cleanup().await;

        // Plant a tombstone by hand to mimic a crashed-mid-teardown run.
        std::fs::write(base.join("crash-zone").join(".removed"), b"").unwrap();
        assert!(base.join("crash-zone").exists());

        let reg2 = ZoneRaftRegistry::new(base.clone(), 1);
        let n = reg2.index_persisted_zones().unwrap();
        assert_eq!(n, 0, "tombstoned zone must not be reopened");
        assert!(
            !base.join("crash-zone").exists(),
            "tombstoned dir must be cleaned up on startup",
        );
        assert!(reg2.list_zones().is_empty());

        reg2.shutdown_all();
        await_shutdown_cleanup().await;
    }

    #[tokio::test]
    async fn test_shutdown_all_preserves_disk() {
        // Regression guard: process shutdown must NOT delete zone dirs
        // (post-commit `armed == false`; Drop is a no-op on disk).
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let reg = ZoneRaftRegistry::new(base.clone(), 1);
        reg.create_zone("persist", vec![], &tokio::runtime::Handle::current())
            .unwrap();
        reg.shutdown_all();
        drop(reg);
        await_shutdown_cleanup().await;

        assert!(
            base.join("persist").exists(),
            "shutdown must preserve zone dir"
        );
    }
}
