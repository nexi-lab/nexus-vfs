//! Transport loop — background task that drives the Raft actor event loop.
//!
//! This task owns the [`ZoneConsensusDriver`] exclusively and calls
//! [`process_messages()`] + [`advance()`] sequentially to maintain the
//! raft-rs single-owner invariant.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────┐  process_messages()  ┌──────────────┐
//! │  mpsc channel msgs   │ ───────────────────> │ ZoneConsensusDriver│
//! │  (step/propose/etc.) │                      │ (owns RawNode)│
//! └──────────────────────┘                      └──────┬───────┘
//!                                                      │ advance()
//!                                                      ▼
//!                                              ┌──────────────────┐
//!                                              │  Outgoing msgs   │
//!                                              │  → RaftClientPool│
//!                                              └──────────────────┘
//!                                                      │
//!                                              ┌──────────────────┐
//!                                              │  EC bg replicate │
//!                                              │  drain WAL →     │
//!                                              │  replicate peers │
//!                                              └──────────────────┘
//! ```

use super::client::RaftClientPool;
use super::proto::nexus::raft::EcReplicationEntry;
use super::{NodeAddress, SharedPeerMap};
use crate::raft::{Command, StateMachine, ZoneConsensusDriver};
use protobuf::Message as ProtobufV2Message;
use raft::eraftpb::MessageType;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

use std::time::Duration as StdDuration;

/// A transport send that failed — surfaced back from a spawned send task
/// to the driver loop so raft-rs can be told and the affected peer's
/// `Progress` tracker can leave its stuck state.
///
/// `is_snapshot` distinguishes a `MsgSnapshot` failure (needs
/// `report_snapshot(peer, Failure)`) from any other message-type
/// failure (needs `report_unreachable(peer)`).  Both are required
/// to keep raft-rs's state machine honest under flaky transports.
#[derive(Debug, Clone, Copy)]
struct TransportFailure {
    peer_id: u64,
    is_snapshot: bool,
}

/// Outcome of an EC replication attempt — surfaced back from a spawned
/// send task to the driver loop so `ec_peer_state` can be updated
/// without taking a lock across `await` points.  Mirrors the
/// `TransportFailure` pattern: per-peer state lives only on the
/// run-loop side and is mutated only via drained channel events.
#[derive(Debug)]
enum EcCompletion {
    Acked { peer_id: u64, applied_up_to: u64 },
    Failed { peer_id: u64, error: String },
}

/// Base backoff interval for EC replication retries.
const EC_BACKOFF_BASE: Duration = Duration::from_millis(100);
/// Maximum backoff interval (cap) for EC replication retries.
///
/// The cap and the default `wait_nodes_caught_up` test budget used to
/// match exactly at 60 s — once a peer hit the cap the next retry was
/// scheduled past every test's timeout, so a single transient send
/// failure looked like a permanent stall (nexi-lab/nexus-vfs#64).
/// 10 s bounds the at-cap latency well under those budgets while
/// still letting genuinely-unreachable peers compress their retry
/// rate.  Backoff climbs only on a real send failure and resets to
/// [`EC_BACKOFF_BASE`] on the first `Acked`, so a peer that was
/// briefly down reconverges within at most one cap interval once it
/// is reachable again.
///
/// There is deliberately NO "fresh WAL entries reset `next_attempt`"
/// path: new writes must not override the failure backoff.  A
/// fast-failing peer (connection refused, sub-millisecond error)
/// clears `in_flight` immediately, so a per-write reset would re-probe
/// it every ~10 ms tick — hammering, not recovery.  The `in_flight`
/// gate only rate-limits *timing-out* peers (held for `EC_SEND_TIMEOUT`),
/// so backoff is the sole floor for fast-fails and must be respected.
/// Genuine unreachability is surfaced by tonic H2 keep-alive and
/// raft-rs `Progress` (`report_unreachable`), not by this cap.
const EC_BACKOFF_CAP: Duration = Duration::from_secs(10);

/// Timeout for individual Raft consensus message sends.
///
/// Sized to absorb a `MsgSnapshot` transfer (KB-MB of state machine
/// bytes over a WAN path) plus initial connect setup, not just a
/// bare heartbeat round-trip.  The previous 5s was tuned for "raft
/// heartbeats must be fast" and is correct for that case alone, but
/// the same `send_raft_message` call also delivers snapshots to a
/// newly joined Learner — those routinely exceed 5s over Tailscale
/// or DERP, leading to client-side cancellation that the *peer*
/// never sees as a failure (the server-side receive may complete
/// after our timeout already aborted the RPC), keeping replication
/// permanently stuck after Mac (Learner) join.  30 s aligns with
/// the keep-alive interval (PR #4234) and gives the snapshot path
/// adequate room while still bounding the spawned task lifetime.
///
/// Real unreachable-peer detection lives elsewhere: tonic's H2
/// keep-alive (30 s ping / 10 s timeout) and raft-rs `Progress`
/// state managed via `report_unreachable` (PR #4230) handle it on
/// their own time scales without depending on this per-call cap.
const RAFT_SEND_TIMEOUT: StdDuration = StdDuration::from_secs(30);

/// Timeout for a single EC replication send.
///
/// EC replication is background data movement; it must not stall the
/// transport loop that drives Raft ticks and elections.  Unreachable
/// peers are retried by the per-peer backoff below.
///
/// Sized for a cold gRPC client first-connect: `client_pool.get`
/// performs a tonic/H2 handshake (TLS negotiation when enabled, DNS
/// resolution, and on Tailscale a DERP warm-up) before the EC
/// replication call itself can even start.  Over a cross-machine
/// Tailscale path the round-trip on a freshly-minted channel
/// routinely sits in the 300-700 ms band, well above the previous
/// 250 ms budget; one spurious timeout would put the peer into the
/// backoff loop even though the link was fine.  2 s gives the cold
/// path adequate room while staying within tonic's H2 keep-alive
/// window so it cannot mask genuine peer unreachability — the keep-
/// alive will surface a dead peer on its own time scale and the
/// per-peer backoff still bounds the retry rate.
const EC_SEND_TIMEOUT: StdDuration = StdDuration::from_secs(2);

/// Timeout for an anti-entropy `SnapshotEcState` transfer.
///
/// Unlike an incremental batch (bounded by `EC_MAX_ENTRIES_PER_BATCH`), a
/// snapshot re-materializes the whole metadata state, so it can be large and
/// take proportionally longer to serialize and ship.  Reuse the raft snapshot
/// budget (30 s) rather than the tight 2 s incremental budget; this path is
/// rare (only a peer lagging past `EC_WAL_RETENTION` triggers it) and the
/// per-peer backoff still bounds the retry rate on a genuinely dead peer.
const EC_SNAPSHOT_TIMEOUT: StdDuration = StdDuration::from_secs(30);

/// Maximum entries to send per peer per EC replication cycle.
/// Caps memory and prevents the tonic request timeout from being exceeded
/// on large backlogs.
const EC_MAX_ENTRIES_PER_BATCH: usize = 500;

/// WAL retention window (entries) for EC compaction.
///
/// Compaction normally holds every entry any known peer still needs
/// (including a peer that has never acked), so a briefly-offline peer
/// catches up by plain WAL replay on reconnect — no snapshot, no loss.
/// But a peer that is gone or wedged must not pin the WAL forever, so a
/// peer lagging more than this many entries behind `max_seq` is
/// sacrificed to an anti-entropy snapshot (`needs_snapshot`) and the WAL
/// is compacted past it. 10k bounds WAL growth (~20 `EC_MAX_ENTRIES_PER_BATCH`
/// batches) while giving a slow peer a wide replay window before it costs
/// a snapshot.
///
/// This is the default; a deployment can override it via the
/// `NEXUS_EC_WAL_RETENTION` env var (read once into `TransportLoop`), e.g. a
/// memory-constrained edge node that prefers a tighter WAL and accepts more
/// anti-entropy snapshots.
const EC_WAL_RETENTION: u64 = 10_000;

/// Per-peer EC replication state.
struct PeerReplicationState {
    /// Highest sequence number this peer has acknowledged.
    acked_seq: u64,
    /// Current backoff duration (exponential, capped at [`EC_BACKOFF_CAP`]).
    backoff: Duration,
    /// Earliest time to attempt the next replication to this peer.
    next_attempt: Instant,
    /// Peer has fallen behind compacted WAL — needs full snapshot to catch up.
    needs_snapshot: bool,
    /// True between spawning a fire-and-forget EC send task and
    /// receiving its [`EcCompletion`] back through the run-loop
    /// channel.  Prevents the next tick from spawning a duplicate
    /// concurrent send to the same peer — without this gate, a peer
    /// stuck on a slow handshake would accumulate one detached task
    /// per tick and the acks would race in arbitrary order through
    /// the completion channel.
    in_flight: bool,
}

impl PeerReplicationState {
    fn new() -> Self {
        Self {
            acked_seq: 0,
            backoff: EC_BACKOFF_BASE,
            next_attempt: Instant::now(),
            needs_snapshot: false,
            in_flight: false,
        }
    }

    /// Reset backoff after a successful replication.
    fn reset_backoff(&mut self) {
        self.backoff = EC_BACKOFF_BASE;
        self.next_attempt = Instant::now();
    }

    /// Double the backoff (capped) after a failed replication.
    fn increase_backoff(&mut self) {
        self.backoff = (self.backoff * 2).min(EC_BACKOFF_CAP);
        self.next_attempt = Instant::now() + self.backoff;
    }
}

/// Background task that drives the Raft event loop and sends messages to peers.
///
/// Owns the [`ZoneConsensusDriver`] exclusively — this is the single task that
/// touches `RawNode`.
pub struct TransportLoop<S: StateMachine + 'static> {
    /// The ZoneConsensusDriver to drive (exclusive ownership).
    driver: ZoneConsensusDriver<S>,
    /// Known peers (node_id → address). Shared so ConfChange can add peers at runtime.
    peers: SharedPeerMap,
    /// Connection pool for sending messages to peers.
    client_pool: RaftClientPool,
    /// How often to call advance() (default: 10ms).
    tick_interval: Duration,
    /// Zone ID for multi-zone message routing.
    zone_id: String,
    /// This node's ID (for EC replication sender identification).
    node_id: u64,
    /// This node's advertise address.  Carried in every outbound
    /// `StepMessageRequest.sender_address` so receivers learn
    /// `(self.node_id -> self_address)` on first contact — the
    /// transport peer-map's runtime SSOT under the opaque-ID
    /// contract.  Empty string means "no advertise address known"
    /// and disables learning on the receiver.
    self_address: String,
    /// Per-peer EC replication tracking (peer_id → state).
    ec_peer_state: HashMap<u64, PeerReplicationState>,
    /// EC WAL retention window (entries).  Defaults to [`EC_WAL_RETENTION`];
    /// overridable via `NEXUS_EC_WAL_RETENTION` for memory-constrained
    /// deployments (a smaller window bounds the WAL tighter at the cost of
    /// more anti-entropy snapshots for slow peers).  Read once at construction.
    ec_wal_retention: u64,
    /// Sender half of the transport-failure channel.  Cloned into each
    /// `send_messages_fire_and_forget` task so a transport-level send
    /// error (network down, HTTP/2 keepalive timeout, tonic transport
    /// error) can be reported back to this loop without holding a
    /// reference to the driver across `await` points.
    failure_tx: mpsc::UnboundedSender<TransportFailure>,
    /// Receiver half of the transport-failure channel.  Drained at the
    /// top of each [`Self::run`] iteration and translated into
    /// `driver.report_unreachable` / `driver.report_snapshot(_, Failure)`
    /// calls — without those, raft-rs's `Progress` tracker stays in
    /// `Replicate` / `Snapshot` state forever after a single failure.
    failure_rx: mpsc::UnboundedReceiver<TransportFailure>,
    /// Sender half of the EC-completion channel.  Cloned into each
    /// `spawn_ec_replications` task so success/failure can be reported
    /// back without taking a lock on `ec_peer_state` across `await`
    /// points.  Mirrors `failure_tx` — same fire-and-forget pattern.
    ec_completion_tx: mpsc::UnboundedSender<EcCompletion>,
    /// Receiver half of the EC-completion channel.  Drained at the top
    /// of each [`Self::run`] iteration; ack updates land before the
    /// next round of `spawn_ec_replications` consults `ec_peer_state`.
    ec_completion_rx: mpsc::UnboundedReceiver<EcCompletion>,
}

impl<S: StateMachine + Send + Sync + 'static> TransportLoop<S> {
    /// Create a new transport loop.
    ///
    /// `peers` is a `SharedPeerMap` shared with the `ZoneConsensusDriver` and `ZoneRaftRegistry`,
    /// so ConfChange can insert new peers visible to the transport loop at runtime.
    pub fn new(
        driver: ZoneConsensusDriver<S>,
        peers: SharedPeerMap,
        client_pool: RaftClientPool,
    ) -> Self {
        let tick_interval = driver.config().tick_interval;
        let node_id = driver.config().id;
        let (failure_tx, failure_rx) = mpsc::unbounded_channel();
        let (ec_completion_tx, ec_completion_rx) = mpsc::unbounded_channel();
        Self {
            driver,
            peers,
            client_pool,
            tick_interval,
            zone_id: String::new(),
            node_id,
            self_address: String::new(),
            ec_peer_state: HashMap::new(),
            ec_wal_retention: std::env::var("NEXUS_EC_WAL_RETENTION")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|&r| r > 0)
                .unwrap_or(EC_WAL_RETENTION),
            failure_tx,
            failure_rx,
            ec_completion_tx,
            ec_completion_rx,
        }
    }

    /// Set the zone ID for multi-zone message routing.
    pub fn with_zone_id(mut self, zone_id: String) -> Self {
        self.zone_id = zone_id;
        self
    }

    /// Set this node's advertise address — see [`Self::self_address`].
    pub fn with_self_address(mut self, self_address: String) -> Self {
        self.self_address = self_address;
        self
    }

    /// Set the tick interval (default: 10ms).
    pub fn with_tick_interval(mut self, interval: Duration) -> Self {
        self.tick_interval = interval;
        self
    }

    /// Run the transport loop until shutdown is signaled.
    ///
    /// Each iteration: drain channel messages → advance raft → send outgoing → EC replicate.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(self.tick_interval);
        tracing::info!(
            "Transport loop started (zone={}, tick_interval={}ms, peers={})",
            if self.zone_id.is_empty() {
                "<single>"
            } else {
                &self.zone_id
            },
            self.tick_interval.as_millis(),
            self.peers.read().unwrap().len()
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Periodic tick — drives heartbeat and election timeouts
                }
                _ = shutdown.changed() => {
                    tracing::info!("Transport loop shutting down");
                    break;
                }
            }

            // 0a. Drain any transport send failures reported by previously
            //     spawned send tasks and forward them to raft-rs.  Must
            //     run before `process_messages` / `advance` so the next
            //     tick's outgoing-message set reflects the updated
            //     `Progress` state (peer in Probe rather than stuck in
            //     Replicate / Snapshot).  Cheap: non-blocking try_recv
            //     drain, returns immediately when the channel is empty
            //     (the steady-state happy path).
            while let Ok(failure) = self.failure_rx.try_recv() {
                self.driver.report_unreachable(failure.peer_id);
                if failure.is_snapshot {
                    self.driver
                        .report_snapshot(failure.peer_id, raft::SnapshotStatus::Failure);
                }
            }

            // 0b. Drain EC replication completions from previously
            //     spawned send tasks.  Must run before
            //     `spawn_ec_replications` below so the next round of
            //     peer scheduling sees up-to-date `acked_seq` /
            //     `backoff` / `in_flight` state.  Cheap non-blocking
            //     drain — same pattern as the failure drain above.
            while let Ok(completion) = self.ec_completion_rx.try_recv() {
                match completion {
                    EcCompletion::Acked {
                        peer_id,
                        applied_up_to,
                    } => {
                        if let Some(state) = self.ec_peer_state.get_mut(&peer_id) {
                            state.in_flight = false;
                            state.acked_seq = state.acked_seq.max(applied_up_to);
                            state.reset_backoff();
                            tracing::debug!(
                                peer_node_id = peer_id,
                                applied_up_to,
                                "EC entries replicated to peer"
                            );
                        }
                    }
                    EcCompletion::Failed { peer_id, error } => {
                        if let Some(state) = self.ec_peer_state.get_mut(&peer_id) {
                            state.in_flight = false;
                            state.increase_backoff();
                            tracing::debug!(
                                peer_node_id = peer_id,
                                backoff_ms = state.backoff.as_millis(),
                                "EC replication failed: {}",
                                error
                            );
                        }
                    }
                }
            }

            // 1. Drain all pending channel messages (step, propose, campaign)
            self.driver.process_messages();

            // 2. Advance raft state + apply entries + get outgoing messages
            match self.driver.advance().await {
                Ok(messages) => {
                    if !messages.is_empty() {
                        self.send_messages_fire_and_forget(messages);
                    }
                }
                Err(e) => {
                    tracing::error!("advance() error: {}", e);
                }
            }

            // 3. EC Phase C: fire-and-forget replication to peers.  Each
            //    peer's send runs as a detached task; completion lands
            //    back via `ec_completion_rx` and is drained at the top
            //    of the next tick.  The transport loop never awaits an
            //    EC send — raft heartbeats and elections are not held
            //    behind a slow EC handshake.
            self.spawn_ec_replications();
        }
    }

    /// Take a point-in-time snapshot of the peer map (read lock, released immediately).
    ///
    /// Used by both `send_messages_fire_and_forget` and `replicate_ec_entries` to
    /// get a consistent view of peers without holding the read lock across async work.
    fn snapshot_peers(&self) -> HashMap<u64, NodeAddress> {
        self.peers
            .read()
            .unwrap()
            .iter()
            .map(|(id, addr)| (*id, addr.clone()))
            .collect()
    }

    /// Send Raft messages to peers concurrently using JoinSet.
    ///
    /// Each peer send gets its own task with an independent timeout.
    /// Slow peers don't block fast peers. If a send fails or times out,
    /// the error is logged and the client is evicted from the pool.
    /// Send Raft messages to peers — fire and forget.
    ///
    /// Each message is spawned as an independent task with its own timeout.
    /// The transport loop does NOT await results — this ensures tick() is
    /// never blocked by slow/unreachable peers.  Raft handles retransmission
    /// via its own heartbeat/election timeout mechanism.
    ///
    /// Failed sends log a warning and evict the client from the pool
    /// (reconnected on next attempt).
    fn send_messages_fire_and_forget(&self, messages: Vec<raft::eraftpb::Message>) {
        let peers_snapshot = self.snapshot_peers();

        for msg in messages {
            let target_id = msg.to;
            let addr = match peers_snapshot.get(&target_id) {
                Some(a) => a.clone(),
                None => {
                    tracing::warn!(
                        peer_node_id = target_id,
                        "No address for peer — dropping message (peer_map has no entry yet)",
                    );
                    continue;
                }
            };

            // Capture the message type *before* the move into the spawned
            // task so we can report a `MsgSnapshot` failure correctly.
            // A failed snapshot send needs both `report_unreachable` and
            // `report_snapshot(_, Failure)` — without the latter, the
            // peer's Progress stays in the `Snapshot` state and raft-rs
            // never retries.
            let is_snapshot = msg.get_msg_type() == MessageType::MsgSnapshot;

            let client_pool = self.client_pool.clone();
            let zone_id = self.zone_id.clone();
            let self_address = self.self_address.clone();
            let failure_tx = self.failure_tx.clone();

            tokio::spawn(async move {
                let result = tokio::time::timeout(
                    RAFT_SEND_TIMEOUT,
                    send_raft_message(&client_pool, target_id, &addr, msg, zone_id, self_address),
                )
                .await;

                let send_failed = match result {
                    Ok(Ok(())) => false,
                    Ok(Err(e)) => {
                        tracing::warn!(
                            peer_node_id = target_id,
                            peer_addr = %addr.to_operator_str(),
                            "Raft message send failed: {}",
                            e,
                        );
                        client_pool.remove(target_id).await;
                        true
                    }
                    Err(_elapsed) => {
                        tracing::warn!(
                            peer_node_id = target_id,
                            peer_addr = %addr.to_operator_str(),
                            "Raft message send timeout after {:?}",
                            RAFT_SEND_TIMEOUT,
                        );
                        client_pool.remove(target_id).await;
                        true
                    }
                };

                if send_failed {
                    // Best-effort signal back to the driver loop.  If the
                    // receiver was dropped (loop is shutting down) the
                    // send is a no-op; that is fine because the driver
                    // is on its way out anyway.
                    let _ = failure_tx.send(TransportFailure {
                        peer_id: target_id,
                        is_snapshot,
                    });
                }
            });
        }
    }

    // =========================================================================
    // EC Phase C: Background replication
    // =========================================================================

    /// Drain unreplicated EC entries and spawn fire-and-forget sends
    /// to eligible peers.
    ///
    /// Architecture mirror of [`Self::send_messages_fire_and_forget`]:
    /// each per-peer send runs as a detached `tokio::spawn` task; the
    /// run loop never awaits the result.  Success / failure is
    /// reported back through [`Self::ec_completion_rx`] and drained
    /// at the top of the next tick (the only site that mutates
    /// `ec_peer_state`).  Raft heartbeats and elections are therefore
    /// never blocked behind a slow EC handshake, even with
    /// `EC_SEND_TIMEOUT` measured in seconds.
    ///
    /// Per-peer exponential backoff (base=100ms, capped at
    /// [`EC_BACKOFF_CAP`]) still rate-limits sends; `in_flight`
    /// suppresses duplicate concurrent sends to the same peer.
    ///
    /// After spawning, computes the voter-majority quorum watermark
    /// and advances the `ReplicationLog`.  The watermark uses the
    /// `acked_seq` state as of the last completion drain (one-tick
    /// lag), which is the correct conservative pin — we only mark
    /// "safe to read" what we know was acked.
    fn spawn_ec_replications(&mut self) {
        let repl_log = match self.driver.replication_log() {
            Some(log) => Arc::clone(log),
            None => return, // No replication log (witness node)
        };

        // Drain unreplicated entries
        let entries = match repl_log.drain_unreplicated() {
            Ok(entries) => entries,
            Err(e) => {
                tracing::error!("Failed to drain unreplicated entries: {}", e);
                return;
            }
        };

        // Get current peer snapshot (read lock, released immediately).
        // Peer-map carries voters AND learners; we replicate to both
        // but quorum sizing must be voter-only (see `voter_ids` below).
        let peer_map = self.snapshot_peers();
        let peer_snapshot: Vec<(u64, NodeAddress)> = peer_map.into_iter().collect();

        // Voter set is the raft-rs SSOT — never derive total_voters from
        // `peer_snapshot.len() + 1`, which over-counts whenever any
        // learner is in the peer-map.  In a 1V+1L topology that
        // over-count required a learner ack for quorum; the learner is
        // not part of consensus so its `acked_seq` stayed 0 in backoff
        // and the watermark could never advance (nexi-lab/nexus-vfs#64).
        let voter_ids = self.driver.voter_ids();
        let total_voters = voter_ids.len();

        // Single-voter cluster: self is the majority — advance watermark
        // unilaterally.  Do NOT return early when learner peers exist:
        // they still need EC replication so they can serve reads of
        // already-watermarked metadata.
        if total_voters <= 1 {
            let max_seq = repl_log.max_seq();
            if max_seq > 1 {
                let _ = repl_log.advance_watermark(max_seq - 1);
            }
            if peer_snapshot.is_empty() {
                return;
            }
        }

        // Compaction lower bound.  Fetched once — compaction runs only at the
        // end of this pass, so `earliest` is stable throughout, and the
        // per-peer loop reuses it instead of re-reading redb per iteration.
        let earliest = repl_log.earliest_seq();

        // Skip the pass only when there is genuinely nothing to do: no fresh
        // entries to replicate AND no peer lagging behind the compacted WAL.
        // A peer whose next-needed seq (`acked_seq + 1`) was compacted away
        // still needs an anti-entropy snapshot even when the zone is otherwise
        // idle — the early return must not starve that path, or a peer that
        // reconnects to an idle zone would never catch up until the next write.
        let any_peer_behind = peer_snapshot.iter().any(|(id, _)| {
            let acked = self.ec_peer_state.get(id).map_or(0, |s| s.acked_seq);
            acked + 1 < earliest
        });
        if entries.is_empty() && !any_peer_behind {
            return;
        }

        let now = Instant::now();

        // Collect work items for eligible peers
        struct EcSendTask {
            peer_id: u64,
            peer_addr: NodeAddress,
            entries: Vec<EcReplicationEntry>,
        }

        let mut tasks: Vec<EcSendTask> = Vec::new();
        // Peers that fell behind the compacted WAL and need a full-state
        // anti-entropy snapshot instead of an incremental batch.
        let mut snapshot_tasks: Vec<(u64, NodeAddress)> = Vec::new();

        for (peer_id, peer_addr) in &peer_snapshot {
            let state = self
                .ec_peer_state
                .entry(*peer_id)
                .or_insert_with(PeerReplicationState::new);

            // Skip if a previous send is still in flight — its
            // completion will land via `ec_completion_rx` and update
            // `acked_seq` / `backoff` before the next tick reaches
            // here.  Without this gate, a peer stuck on a slow
            // handshake would accumulate one detached task per tick.
            if state.in_flight {
                continue;
            }

            // Skip if in backoff period
            if now < state.next_attempt {
                continue;
            }

            // Anti-entropy check reuses the `earliest` hoisted above (stable
            // for this pass).

            // Clear needs_snapshot if peer has caught up (e.g., via external
            // snapshot delivery or WAL re-expansion)
            if state.needs_snapshot {
                if state.acked_seq >= earliest {
                    tracing::info!(
                        peer_node_id = peer_id,
                        acked = state.acked_seq,
                        earliest,
                        "Peer caught up — clearing needs_snapshot"
                    );
                    state.needs_snapshot = false;
                } else {
                    // Still behind the compacted region: incremental replay
                    // can't reach this peer, so ship a full-state snapshot.
                    // The `in_flight`/backoff gates above already bound how
                    // often this fires; the actual SM read + send happens in a
                    // fire-and-forget task after the loop.
                    tracing::info!(
                        peer_node_id = peer_id,
                        acked = state.acked_seq,
                        earliest,
                        "Peer needs snapshot — dispatching anti-entropy transfer"
                    );
                    snapshot_tasks.push((*peer_id, peer_addr.clone()));
                    continue;
                }
            }

            // A peer needs a snapshot iff the next entry it needs
            // (`acked_seq + 1`) has already been compacted away
            // (`< earliest`).  The old `acked_seq > 0 && acked_seq < earliest`
            // was wrong twice: it excluded a never-acked peer (`acked_seq==0`),
            // which is exactly the peer most likely to have been left behind by
            // compaction, and it false-flagged a peer sitting exactly at the
            // boundary (`acked_seq == earliest - 1`), whose needed entry
            // (`earliest`) is still present and replicable incrementally.
            if state.acked_seq + 1 < earliest {
                tracing::warn!(
                    peer_node_id = peer_id,
                    acked = state.acked_seq,
                    earliest,
                    "Peer fell behind compacted WAL — needs snapshot"
                );
                state.needs_snapshot = true;
                continue; // Skip — incremental replication impossible
            }

            // Filter entries: only send what this peer hasn't acked yet.
            // Cap at EC_MAX_ENTRIES_PER_BATCH to bound memory and stay
            // within the tonic request timeout on large backlogs.
            let filtered: Vec<EcReplicationEntry> = entries
                .iter()
                .filter(|(seq, _)| *seq > state.acked_seq)
                .take(EC_MAX_ENTRIES_PER_BATCH)
                .map(|(seq, entry)| EcReplicationEntry {
                    seq: *seq,
                    command: entry.command.clone(),
                    timestamp: entry.timestamp,
                    node_id: entry.node_id,
                })
                .collect();

            if filtered.is_empty() {
                continue;
            }

            tasks.push(EcSendTask {
                peer_id: *peer_id,
                peer_addr: peer_addr.clone(),
                entries: filtered,
            });
        }

        // Fire-and-forget per-peer send tasks.  Mark each peer
        // `in_flight = true` BEFORE spawning so the next tick (which
        // may run before the spawn even starts work) skips a duplicate
        // send.  Cleared in the run-loop drain when the completion
        // arrives.
        for task in tasks {
            if let Some(state) = self.ec_peer_state.get_mut(&task.peer_id) {
                state.in_flight = true;
            }

            let client_pool = self.client_pool.clone();
            let zone_id = self.zone_id.clone();
            let node_id = self.node_id;
            let completion_tx = self.ec_completion_tx.clone();

            tokio::spawn(async move {
                let send = send_ec_entries(
                    &client_pool,
                    &task.peer_addr,
                    zone_id,
                    task.entries,
                    node_id,
                );
                let completion = match tokio::time::timeout(EC_SEND_TIMEOUT, send).await {
                    Ok(Ok(applied_up_to)) => EcCompletion::Acked {
                        peer_id: task.peer_id,
                        applied_up_to,
                    },
                    Ok(Err(e)) => EcCompletion::Failed {
                        peer_id: task.peer_id,
                        error: e,
                    },
                    Err(_) => EcCompletion::Failed {
                        peer_id: task.peer_id,
                        error: format!("EC replication timed out after {:?}", EC_SEND_TIMEOUT),
                    },
                };
                // Best-effort signal back.  Receiver drop only happens
                // at shutdown, in which case a missed completion is
                // harmless.
                let _ = completion_tx.send(completion);
            });
        }

        // Fire-and-forget anti-entropy snapshots for peers that fell behind the
        // compacted WAL.  Same `in_flight` discipline as the incremental sends:
        // mark before spawning so the next tick skips a duplicate.  The state
        // read + entry materialization run INSIDE the task because the state
        // machine's `RwLock` read is async; it is a shared read (the apply loop
        // takes the write lock) and never touches the driver's exclusive
        // `RawNode`, so the drain tick stays cheap and lock-free.
        for (peer_id, peer_addr) in snapshot_tasks {
            if let Some(state) = self.ec_peer_state.get_mut(&peer_id) {
                state.in_flight = true;
            }

            let client_pool = self.client_pool.clone();
            let zone_id = self.zone_id.clone();
            let node_id = self.node_id;
            let completion_tx = self.ec_completion_tx.clone();
            let sm_arc = self.driver.state_machine_arc();
            // A lower bound on what the snapshot covers: the SM read below
            // reflects every write applied so far, so the materialized state is
            // >= `covering_seq`.  On ack the peer's `acked_seq` jumps here and
            // incremental replication resumes from `covering_seq + 1` (re-
            // applying entries already folded into the snapshot is idempotent
            // under LWW).
            let covering_seq = repl_log.max_seq().saturating_sub(1);

            tokio::spawn(async move {
                // Re-materialize the whole metadata state as SetMetadata
                // commands.  Sc-plane keys the peer already holds via raft are
                // byte-identical, so LWW no-ops them; only the EC keys the peer
                // missed actually change.  (A delta/chunked snapshot is a future
                // optimization — this path is rare, correctness over bytes.)
                let state_pairs = sm_arc.read().await.ec_state_snapshot();
                let entries: Vec<EcReplicationEntry> = state_pairs
                    .into_iter()
                    .map(|(key, value)| EcReplicationEntry {
                        seq: covering_seq,
                        command: bincode::serialize(&Command::SetMetadata { key, value })
                            .unwrap_or_default(),
                        // SetMetadata LWW uses the value's own embedded
                        // modified-at, so this envelope timestamp is unused.
                        timestamp: 0,
                        node_id,
                    })
                    .collect();

                let send = send_ec_snapshot(
                    &client_pool,
                    &peer_addr,
                    zone_id,
                    entries,
                    covering_seq,
                    node_id,
                );
                let completion = match tokio::time::timeout(EC_SNAPSHOT_TIMEOUT, send).await {
                    Ok(Ok(acked_up_to)) => EcCompletion::Acked {
                        peer_id,
                        applied_up_to: acked_up_to,
                    },
                    Ok(Err(e)) => EcCompletion::Failed { peer_id, error: e },
                    Err(_) => EcCompletion::Failed {
                        peer_id,
                        error: format!("EC snapshot timed out after {:?}", EC_SNAPSHOT_TIMEOUT),
                    },
                };
                let _ = completion_tx.send(completion);
            });
        }

        // Compute quorum watermark and advance.  Only voter peers count
        // toward the quorum — learner acks are ignored here even though
        // we still replicate to them above.  The single-voter case is
        // handled in the unilateral fast path earlier in this function,
        // so `compute_ec_watermark` is only meaningful for total_voters >= 2.
        if total_voters >= 2 {
            let new_watermark = compute_ec_watermark(&self.ec_peer_state, &voter_ids, self.node_id);
            if let Some(wm) = new_watermark {
                if let Err(e) = repl_log.advance_watermark(wm) {
                    tracing::error!("Failed to advance EC watermark: {}", e);
                }
            }
        }

        // WAL compaction floor: keep every entry any KNOWN peer still needs
        // (incl. never-acked peers) bounded by `EC_WAL_RETENTION`.  See
        // `ec_compact_floor` for the full rationale.  A peer lagging past the
        // retention window is compacted past and flagged `needs_snapshot` on
        // its next drain pass (per-peer loop above); `compact()` is monotonic
        // and no-ops when `up_to < earliest`.
        let compact_up_to = ec_compact_floor(
            peer_snapshot
                .iter()
                .filter_map(|(id, _)| self.ec_peer_state.get(id).map(|s| s.acked_seq)),
            repl_log.max_seq(),
            self.ec_wal_retention,
        );

        if compact_up_to > 0 {
            if let Err(e) = repl_log.compact(compact_up_to) {
                tracing::error!("WAL compaction failed: {}", e);
            }
        }
    }
}

/// Send a single Raft message to a peer (used by parallel send tasks).
async fn send_raft_message(
    client_pool: &RaftClientPool,
    target_id: u64,
    addr: &NodeAddress,
    msg: raft::eraftpb::Message,
    zone_id: String,
    self_address: String,
) -> std::result::Result<(), String> {
    let bytes = msg
        .write_to_bytes()
        .map_err(|e| format!("serialize error for node {}: {}", target_id, e))?;

    let mut client = client_pool
        .get(addr)
        .await
        .map_err(|e| format!("connect to node {} ({}): {}", target_id, addr.endpoint, e))?;

    client
        .step_message(bytes, zone_id, self_address)
        .await
        .map_err(|e| format!("send to node {} ({}): {}", target_id, addr.endpoint, e))
}

/// Send EC replication entries to a peer (used by parallel EC tasks).
async fn send_ec_entries(
    client_pool: &RaftClientPool,
    peer_addr: &NodeAddress,
    zone_id: String,
    entries: Vec<EcReplicationEntry>,
    sender_node_id: u64,
) -> std::result::Result<u64, String> {
    let mut client = client_pool.get(peer_addr).await.map_err(|e| {
        format!(
            "connect to {} ({}): {}",
            peer_addr.id, peer_addr.endpoint, e
        )
    })?;

    client
        .replicate_entries(zone_id, entries, sender_node_id)
        .await
        .map_err(|e| {
            format!(
                "replicate to {} ({}): {}",
                peer_addr.id, peer_addr.endpoint, e
            )
        })
}

/// Ship a full-state anti-entropy snapshot to a peer that fell behind the
/// compacted WAL (used by the fire-and-forget snapshot tasks).  `covering_seq`
/// is the lower bound the snapshot covers; the peer advances its `acked_seq` to
/// it on success and resumes incremental replay from `covering_seq + 1`.
async fn send_ec_snapshot(
    client_pool: &RaftClientPool,
    peer_addr: &NodeAddress,
    zone_id: String,
    entries: Vec<EcReplicationEntry>,
    covering_seq: u64,
    sender_node_id: u64,
) -> std::result::Result<u64, String> {
    let mut client = client_pool.get(peer_addr).await.map_err(|e| {
        format!(
            "connect to {} ({}): {}",
            peer_addr.id, peer_addr.endpoint, e
        )
    })?;

    client
        .snapshot_ec_state(zone_id, entries, covering_seq, sender_node_id)
        .await
        .map_err(|e| {
            format!(
                "snapshot to {} ({}): {}",
                peer_addr.id, peer_addr.endpoint, e
            )
        })
}

/// Compute the EC replication watermark based on voter acknowledgements.
///
/// `voter_ids` is the full raft voter set including self (raft-rs SSOT).
/// Self always counts as having applied all entries; we need
/// `voter_ids.len() / 2` additional acks from the non-self voters for a
/// majority (integer division).  Learners are NEVER considered here —
/// they are not part of consensus and a learner sitting in backoff
/// would otherwise pin the watermark indefinitely
/// (nexi-lab/nexus-vfs#64).
///
/// Returns `None` if quorum cannot be reached (not enough voter peer
/// acks).  The single-voter case is handled by the caller and is also
/// guarded here by returning `None` when no peer acks are needed.
fn compute_ec_watermark(
    peer_state: &HashMap<u64, PeerReplicationState>,
    voter_ids: &[u64],
    self_id: u64,
) -> Option<u64> {
    let total_voters = voter_ids.len();
    let needed_peer_acks = total_voters / 2; // self already counted
    if needed_peer_acks == 0 {
        return None; // single voter — caller advances watermark unilaterally
    }

    // Collect acked_seq for the non-self VOTER peers.  Learners in
    // `peer_state` are skipped because they are not in `voter_ids`.
    let mut acks: Vec<u64> = voter_ids
        .iter()
        .filter(|id| **id != self_id)
        .filter_map(|id| peer_state.get(id).map(|s| s.acked_seq))
        .collect();

    // Sort descending: highest acks first
    acks.sort_unstable_by(|a, b| b.cmp(a));

    // The (needed_peer_acks - 1)-th element (0-indexed) is the watermark:
    // it's the highest seq that at least `needed_peer_acks` peers have acked.
    acks.get(needed_peer_acks - 1).copied().filter(|&wm| wm > 0)
}

/// Highest WAL seq that is safe to compact up to for EC replication.
///
/// Keeps every entry any KNOWN peer still needs: the min over ALL peers'
/// `acked_seq`, **including a peer that has never acked** (`acked_seq == 0`,
/// which pins the floor at 0 → nothing compacted).  The prior code filtered
/// `acked_seq > 0`, so a never-acked peer did not hold the floor and
/// compaction silently deleted entries it still needed — the peer then hit
/// the compacted region and lost those writes with no way to catch up.
///
/// Bounded by `retention`: a peer that is gone or wedged must not pin the WAL
/// forever, so the floor is raised to at least `max_seq - retention`.  A peer
/// lagging past that window is compacted past (and flagged `needs_snapshot`
/// by the drain) rather than stalling the whole zone's WAL.  With no peers,
/// the WAL is still bounded to `retention` (the entries are already applied
/// locally; the WAL is only the replication buffer).  Returns 0 to mean
/// "compact nothing".
fn ec_compact_floor(
    peer_acked_seqs: impl Iterator<Item = u64>,
    max_seq: u64,
    retention: u64,
) -> u64 {
    let min_peer_acked = peer_acked_seqs.min().unwrap_or(0);
    let retention_floor = max_seq.saturating_sub(retention);
    min_peer_acked.max(retention_floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_floor_holds_for_never_acked_peer_within_retention() {
        // A peer at acked_seq==0 (never acked) must pin the floor at 0 so its
        // still-needed entries are not compacted away — the silent-loss bug.
        assert_eq!(ec_compact_floor([0u64, 5].into_iter(), 6, 10_000), 0);
        // Even with only a never-acked peer.
        assert_eq!(ec_compact_floor([0u64].into_iter(), 100, 10_000), 0);
    }

    #[test]
    fn compact_floor_advances_to_min_acked_when_all_caught_up() {
        // All peers acked past the retention floor → compact up to the min ack
        // (keep what the laggard among them still needs).
        assert_eq!(
            ec_compact_floor([1000u64, 1005].into_iter(), 1006, 10_000),
            1000
        );
    }

    #[test]
    fn compact_floor_bounds_wal_past_retention_sacrificing_laggard() {
        // A wedged peer (acked 0) past the retention window no longer pins the
        // WAL: the floor rises to max_seq - retention (it will be flagged
        // needs_snapshot by the drain).
        assert_eq!(
            ec_compact_floor([0u64, 14_000].into_iter(), 15_000, 10_000),
            5_000
        );
    }

    #[test]
    fn compact_floor_bounds_wal_with_no_peers() {
        // No peers: still bound the WAL to retention (entries are applied
        // locally; the WAL is only the replication buffer).
        assert_eq!(ec_compact_floor(std::iter::empty(), 500, 10_000), 0);
        assert_eq!(ec_compact_floor(std::iter::empty(), 15_000, 10_000), 5_000);
    }

    fn mk_peer_state(acked_seq: u64) -> PeerReplicationState {
        PeerReplicationState {
            acked_seq,
            backoff: EC_BACKOFF_BASE,
            next_attempt: Instant::now(),
            needs_snapshot: false,
            in_flight: false,
        }
    }

    #[test]
    fn test_compute_ec_watermark_3_voters() {
        // 3 voters: self (1) + voter peers 2, 3. Need 1 peer ack for majority.
        let mut peer_state = HashMap::new();
        peer_state.insert(2, mk_peer_state(5));
        peer_state.insert(3, mk_peer_state(3));

        let voter_ids = vec![1, 2, 3];

        // total_voters = 3, needed_peer_acks = 3/2 = 1
        // sorted acks desc: [5, 3], take index 0 = 5
        let wm = compute_ec_watermark(&peer_state, &voter_ids, 1);
        assert_eq!(wm, Some(5));
    }

    #[test]
    fn test_compute_ec_watermark_5_voters() {
        // 5 voters: self (1) + voter peers 2..5. Need 2 peer acks.
        let mut peer_state = HashMap::new();
        for (id, ack) in [(2, 10), (3, 8), (4, 5), (5, 3)] {
            peer_state.insert(id, mk_peer_state(ack));
        }
        let voter_ids = vec![1, 2, 3, 4, 5];

        // total_voters = 5, needed = 5/2 = 2
        // sorted acks desc: [10, 8, 5, 3], take index 1 = 8
        let wm = compute_ec_watermark(&peer_state, &voter_ids, 1);
        assert_eq!(wm, Some(8));
    }

    #[test]
    fn test_compute_ec_watermark_no_acks() {
        let peer_state = HashMap::new();
        let voter_ids = vec![1, 2, 3];

        // No acks yet — should return None
        let wm = compute_ec_watermark(&peer_state, &voter_ids, 1);
        assert_eq!(wm, None);
    }

    #[test]
    fn test_compute_ec_watermark_single_voter() {
        let peer_state = HashMap::new();
        let voter_ids = vec![1];

        // Single voter: needed = 0, returns None (caller advances unilaterally)
        let wm = compute_ec_watermark(&peer_state, &voter_ids, 1);
        assert_eq!(wm, None);
    }

    #[test]
    fn test_compute_ec_watermark_ignores_learner_acks() {
        // 1V+1L topology — bug nexi-lab/nexus-vfs#64:
        // self (1) is the only voter; peer 2 is a learner sitting at acked=0
        // in backoff. Before the fix, total_voters was derived from
        // peer_snapshot.len()+1=2 and the function required a learner ack
        // for quorum; the watermark could never advance. After the fix,
        // voter_ids contains only [1] so the function returns None and
        // the caller advances the watermark unilaterally.
        let mut peer_state = HashMap::new();
        peer_state.insert(2, mk_peer_state(0)); // learner, never acked
        let voter_ids = vec![1]; // only self

        let wm = compute_ec_watermark(&peer_state, &voter_ids, 1);
        assert_eq!(wm, None);
    }

    #[test]
    fn test_compute_ec_watermark_skips_learner_in_2v1l() {
        // 2V+1L: voters {1=self, 2}, learner {3}. needed_peer_acks = 1.
        // Voter peer 2 has acked seq=5; learner 3 has acked seq=99.
        // The learner's ack must NOT advance the watermark past the
        // voter peer's ack.
        let mut peer_state = HashMap::new();
        peer_state.insert(2, mk_peer_state(5)); // voter
        peer_state.insert(3, mk_peer_state(99)); // learner — must be ignored
        let voter_ids = vec![1, 2];

        let wm = compute_ec_watermark(&peer_state, &voter_ids, 1);
        assert_eq!(wm, Some(5));
    }

    #[test]
    fn test_backoff_cap_is_test_budget_safe() {
        // Regression pin for the original test-timing race that
        // surfaced in PR #61: with EC_BACKOFF_CAP == 60s and a 60s
        // wait-budget on the caller side, a single transient send
        // failure looked like a permanent stall.  10s gives us a
        // comfortable margin under realistic test budgets while still
        // compressing the retry rate for genuinely unreachable peers.
        assert!(
            EC_BACKOFF_CAP <= Duration::from_secs(10),
            "EC_BACKOFF_CAP must stay <= 10s so test budgets clear it; \
             see nexi-lab/nexus-vfs#64"
        );
    }

    #[test]
    fn test_peer_replication_state_backoff() {
        let mut state = PeerReplicationState::new();
        assert_eq!(state.backoff, EC_BACKOFF_BASE);

        state.increase_backoff();
        assert_eq!(state.backoff, EC_BACKOFF_BASE * 2);

        state.increase_backoff();
        assert_eq!(state.backoff, EC_BACKOFF_BASE * 4);

        // Reset
        state.reset_backoff();
        assert_eq!(state.backoff, EC_BACKOFF_BASE);

        // Test cap
        for _ in 0..20 {
            state.increase_backoff();
        }
        assert_eq!(state.backoff, EC_BACKOFF_CAP);
    }

    #[test]
    fn test_peer_send_timeout_constant() {
        // Verify timeout is reasonable
        assert!(RAFT_SEND_TIMEOUT.as_secs() >= 1);
        assert!(RAFT_SEND_TIMEOUT.as_secs() <= 30);
    }
}
