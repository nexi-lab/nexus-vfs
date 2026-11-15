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
use crate::raft::message_bound::MAX_RAFT_PAYLOAD_BYTES;
use crate::raft::{RaftMessageProtocol, StateMachine, ZoneConsensusDriver};
use protobuf::Message as ProtobufV2Message;
use raft::eraftpb::MessageType;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

use std::time::Duration as StdDuration;

/// The outcome of one outbound Raft message, owed to raft-rs by the loop that
/// owns the driver.
///
/// raft-rs's transport contract has two parts, and a peer's `Progress` stalls
/// if either is skipped:
///
/// * every message that did not reach its peer is answered with
///   `report_unreachable`, so a `Replicate` peer falls back to probing;
/// * every `MsgSnapshot` is answered with exactly one `report_snapshot` —
///   `Finish` once the receiver accepted it, `Failure` otherwise. Sending a
///   snapshot moves the peer to `Snapshot`, where `Progress::is_paused` is
///   unconditionally true: heartbeats keep flowing but no append or snapshot
///   is generated again until the report (or the receiver's own append
///   response) arrives. A `Finish` moves it to `Probe`, so the next heartbeat
///   response probes the receiver's log and a snapshot that was accepted but
///   never installed is detected and re-sent.
#[derive(Debug)]
struct SendReport {
    peer_id: u64,
    payload: Payload,
    /// `None` when the message was held back without being sent (see
    /// [`HeldBack`]): raft-rs is still told, the peer's send health is not.
    outcome: Option<Result<(), SendFailure>>,
}

/// Why a message did not reach its peer — each kind is handled differently.
#[derive(Debug)]
enum SendFailure {
    /// The message exceeds a message bound: ours, checked before sending, or
    /// the receiver's, which answered `OutOfRange` / `ResourceExhausted`.
    /// Re-sent unchanged it fails the same way, so it is held back
    /// ([`HeldBack`]). The channel is healthy.
    Oversized(String),
    /// The channel is broken, or the call outlasted its deadline: the pooled
    /// client is dropped and re-dialed on the next send.
    Connection(String),
    /// The receiver answered and refused. The channel is healthy.
    Refused(String),
}

impl std::fmt::Display for SendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (Self::Oversized(why) | Self::Connection(why) | Self::Refused(why)) = self;
        write!(f, "{}: {why}", self.kind())
    }
}

impl SendFailure {
    /// The failure's class, as reported: a run of failures is one problem
    /// only while its class stays the same.
    fn kind(&self) -> &'static str {
        match self {
            Self::Oversized(_) => "message too large",
            Self::Connection(_) => "connection",
            Self::Refused(_) => "refused",
        }
    }

    fn of(error: super::TransportError) -> Self {
        use super::TransportError;
        match error {
            TransportError::Status(status) => match status.code() {
                tonic::Code::OutOfRange | tonic::Code::ResourceExhausted => {
                    Self::Oversized(status.to_string())
                }
                tonic::Code::Unavailable => Self::Connection(status.to_string()),
                _ => Self::Refused(status.to_string()),
            },
            TransportError::Rpc(why) => Self::Refused(why),
            other => Self::Connection(other.to_string()),
        }
    }
}

/// What raft-rs is sending a peer, as far as re-sending it is concerned: the
/// same append regenerated after a failure has the same type and index range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Payload {
    msg_type: MessageType,
    /// The append's previous index; zero for other types.
    index: u64,
    /// The last index carried: the append's last entry, or the snapshot's.
    last: u64,
}

impl Payload {
    fn of(message: &raft::eraftpb::Message) -> Self {
        let last = match message.get_msg_type() {
            MessageType::MsgSnapshot => message.get_snapshot().get_metadata().index,
            _ => message.get_entries().last().map_or(0, |entry| entry.index),
        };
        Self {
            msg_type: message.get_msg_type(),
            index: message.index,
            last,
        }
    }

    fn snapshot(&self) -> bool {
        self.msg_type == MessageType::MsgSnapshot
    }

    /// Whether the message feeds the peer's log, as opposed to a control
    /// message (heartbeat, vote, response) that may keep arriving while
    /// every append is refused.
    fn carries_log(&self) -> bool {
        matches!(
            self.msg_type,
            MessageType::MsgAppend | MessageType::MsgSnapshot
        )
    }
}

/// A peer's message that was too large, held back from being re-sent.
///
/// raft-rs regenerates an undelivered append on every heartbeat response —
/// tens of times a second — and an oversized one fails identically each
/// time, burning the link on a transfer the receiver discards. Until
/// `retry_at` the same payload is reported undelivered without being sent;
/// heartbeats and every other message still flow. The retry backs off so a
/// receiver that is upgraded (raising its bound) is found again.
struct HeldBack {
    payload: Payload,
    retry_at: Instant,
    backoff: StdDuration,
}

/// First hold-back of an oversized payload; doubles per failed retry.
const OVERSIZED_RETRY_FIRST: StdDuration = StdDuration::from_secs(1);
const OVERSIZED_RETRY_MAX: StdDuration = StdDuration::from_secs(60);

/// How long a voter must be continuously unreachable before the quorum-at-risk
/// WARN fires — short enough to catch a stuck bring-up fast, long enough to
/// ignore a transient blip or normal election churn.
const VOTER_UNREACHABLE_WARN_AFTER: StdDuration = StdDuration::from_secs(5);
/// A voter with no send failure for this long is treated as recovered: its
/// episode state is dropped so a later failure re-arms a fresh WARN. Kept well
/// above the raft-rs probe interval so a still-dead voter (which keeps
/// generating probe-send failures) is never prematurely reset to "healthy".
const VOTER_RECOVERED_AFTER: StdDuration = StdDuration::from_secs(10);

/// Fail-loud on a persistently-unreachable VOTER that blocks quorum.
///
/// Diagnostic only — it changes NO raft behavior. It exists because a voter the
/// leader admitted but cannot reach silently stalls commit (`safe_commit` never
/// advances); the operator otherwise has to reverse-engineer node IDs from
/// send-failure spam. State is in-memory only (never persisted), and the voter
/// set is read from the raft-rs `ProgressTracker` SSOT on each check — no shadow
/// membership list.
#[derive(Default)]
struct QuorumHealth {
    /// peer_id → (episode start, last failure seen). An "episode" is a run of
    /// send failures with no ≥ [`VOTER_RECOVERED_AFTER`] gap.
    failing: HashMap<u64, (Instant, Instant)>,
    /// Peers already WARNed this episode — the WARN fires ONCE per episode, not
    /// every tick, so it never spams the hot loop.
    warned: HashSet<u64>,
}

impl QuorumHealth {
    /// Record a transport send failure for `peer_id`.
    fn note_failure(&mut self, peer_id: u64, now: Instant) {
        self.failing
            .entry(peer_id)
            .and_modify(|(_, last)| *last = now)
            .or_insert((now, now));
    }

    /// Voters that just crossed into "unreachable long enough that quorum is
    /// actually at risk" and haven't been WARNed yet this episode. GCs
    /// recovered peers. Only the leader evaluates — it owns commit progress.
    fn newly_at_risk(
        &mut self,
        voters: &[u64],
        is_leader: bool,
        now: Instant,
    ) -> Vec<(u64, StdDuration)> {
        // Drop recovered peers (no recent failure) so a fresh failure re-arms.
        let recovered: Vec<u64> = self
            .failing
            .iter()
            .filter_map(|(peer, (_, last))| {
                (now.duration_since(*last) > VOTER_RECOVERED_AFTER).then_some(*peer)
            })
            .collect();
        for peer in recovered {
            self.failing.remove(&peer);
            self.warned.remove(&peer);
        }
        if !is_leader {
            return Vec::new();
        }
        let unreachable: Vec<u64> = voters
            .iter()
            .copied()
            .filter(|peer| {
                self.failing.get(peer).is_some_and(|(first, _)| {
                    now.duration_since(*first) >= VOTER_UNREACHABLE_WARN_AFTER
                })
            })
            .collect();
        // Only shout when quorum is ACTUALLY threatened (reachable < majority) —
        // a single dead voter in a healthy 3-voter zone is not a deadlock.
        let quorum = voters.len() / 2 + 1;
        if voters.len().saturating_sub(unreachable.len()) >= quorum {
            return Vec::new();
        }
        unreachable
            .into_iter()
            .filter(|peer| self.warned.insert(*peer))
            .map(|peer| {
                let since = self
                    .failing
                    .get(&peer)
                    .map(|(first, _)| now.duration_since(*first))
                    .unwrap_or_default();
                (peer, since)
            })
            .collect()
    }
}

/// Outcome of an EC replication attempt — surfaced back from a spawned
/// send task to the driver loop so `ec_peer_state` can be updated
/// without taking a lock across `await` points.  Mirrors the
/// `SendReport` pattern: per-peer state lives only on the
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

/// The slowest link a message up to the raft message bound is still
/// expected to cross.
///
/// A fixed deadline makes every message larger than `deadline × bandwidth`
/// undeliverable: each attempt is cancelled, reported as a failure and
/// re-sent from the first byte, forever. An entry may be as large as
/// `message_bound::MAX_ENTRY_BYTES`, so the deadline grows with the encoded
/// message at this rate (1 Mbit/s, below a relayed WAN path). A dead
/// connection still fails early through the HTTP/2 keep-alive.
const SEND_FLOOR_BYTES_PER_SEC: u64 = 128 * 1024;

/// Deadline for one outbound Raft message of `bytes` encoded bytes.
fn send_deadline(bytes: usize) -> StdDuration {
    RAFT_SEND_TIMEOUT + StdDuration::from_secs((bytes as u64).div_ceil(SEND_FLOOR_BYTES_PER_SEC))
}

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

/// What ended a [`TransportLoop::run`] wait.
///
/// Named rather than inlined so the `select!` stays a pure "what happened"
/// decision and every consequence is handled in one `match` outside the
/// borrow scope the arms need.
enum Woken {
    /// The zone is shutting down.
    Shutdown,
    /// A [`RaftMsg`] arrived and was handled by the driver.
    Message,
    /// Every handle for this zone is gone; the message channel is closed.
    MessageChannelClosed,
    /// Raft's next tick came due.
    Deadline,
}

/// Sleep until `deadline`, or forever when there is none.
///
/// `None` is the parked case: raft has no timed work and there is no peer, so
/// the only thing that can matter is an arriving message, which the sibling
/// `select!` arm covers.  Returning a never-completing future — rather than a
/// long sleep — is what makes an idle zone cost literally zero wakeups instead
/// of merely fewer.
async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending::<()>().await,
    }
}

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
    /// Sender half of the send-report channel. Cloned into each
    /// `send_messages_fire_and_forget` task, which reports a failed send and
    /// the outcome of every `MsgSnapshot` back to this loop without holding a
    /// reference to the driver across `await` points.
    report_tx: mpsc::UnboundedSender<SendReport>,
    /// Receiver half of the send-report channel. Drained at the top of each
    /// [`Self::run`] iteration into `driver.report_unreachable` /
    /// `driver.report_snapshot` — see [`SendReport`].
    report_rx: mpsc::UnboundedReceiver<SendReport>,
    /// Sender half of the EC-completion channel.  Cloned into each
    /// `spawn_ec_replications` task so success/failure can be reported
    /// back without taking a lock on `ec_peer_state` across `await`
    /// points.  Mirrors `report_tx` — same fire-and-forget pattern.
    ec_completion_tx: mpsc::UnboundedSender<EcCompletion>,
    /// Receiver half of the EC-completion channel.  Drained at the top
    /// of each [`Self::run`] iteration; ack updates land before the
    /// next round of `spawn_ec_replications` consults `ec_peer_state`.
    ec_completion_rx: mpsc::UnboundedReceiver<EcCompletion>,
    /// Per-peer send-failure tracking behind the quorum-at-risk WARN.
    /// Ephemeral diagnostic state — never persisted, never feeds raft.
    quorum_health: QuorumHealth,
    /// Members whose last message had no route, warned about once. An id
    /// leaves the set when it routes again, so losing a route warns once per
    /// loss rather than once per message. Ephemeral diagnostic state.
    unrouted: HashSet<u64>,
    /// Per peer, the oversized payload being held back — see [`HeldBack`].
    held_back: HashMap<u64, HeldBack>,
    /// EC anti-entropy snapshot tasks. Each reads the state machine, so it
    /// holds the zone's store: the loop joins them before it returns, and the
    /// zone's storage is released when [`Self::run`] ends.
    snapshot_readers: tokio::task::JoinSet<()>,
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
        let node_id = driver.config().id;
        let (report_tx, report_rx) = mpsc::unbounded_channel();
        let (ec_completion_tx, ec_completion_rx) = mpsc::unbounded_channel();
        Self {
            driver,
            peers,
            client_pool,
            zone_id: String::new(),
            node_id,
            self_address: String::new(),
            ec_peer_state: HashMap::new(),
            ec_wal_retention: std::env::var("NEXUS_EC_WAL_RETENTION")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|&r| r > 0)
                .unwrap_or(EC_WAL_RETENTION),
            report_tx,
            report_rx,
            ec_completion_tx,
            ec_completion_rx,
            quorum_health: QuorumHealth::default(),
            unrouted: HashSet::new(),
            held_back: HashMap::new(),
            snapshot_readers: tokio::task::JoinSet::new(),
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

    /// Run the transport loop until shutdown is signaled.
    ///
    /// Each iteration: drain channel messages → advance raft → send outgoing → EC replicate.
    ///
    /// # Waking
    ///
    /// The loop is **event-driven with a raft deadline**, not a fixed-rate
    /// poller.  It wakes on whichever comes first: a message for this zone (a
    /// proposal, a peer's step, a campaign — every [`RaftMsg`] variant), the
    /// instant raft next needs a `tick()`, or shutdown.
    ///
    /// Two consequences, both intended:
    ///
    /// * A write no longer waits out a timer.  Previously a proposal that
    ///   landed just after a tick sat in the channel for up to
    ///   `tick_interval` before anyone looked at it; that latency is gone from
    ///   every zone, busy or idle.  Batching is preserved where it matters:
    ///   [`ZoneConsensusDriver::process_messages`] still drains the whole
    ///   queue before `advance`, so proposals that arrive while we are
    ///   fsyncing coalesce into the next append exactly as group commit
    ///   intends — the batch size now follows the offered load instead of a
    ///   fixed window.
    /// * A zone with nothing to do sleeps with **no timer at all**.  See
    ///   [`ZoneConsensusDriver::tick_is_noop`] for the raft-rs argument that
    ///   its ticks are unobservable; combined with an empty peer map (nothing
    ///   to replicate to, so [`Self::spawn_ec_replications`] has no deadline
    ///   of its own) the correct wait is "until someone calls", which is what
    ///   parking expresses.  Idle zone count stops being a CPU variable.
    ///
    /// The loop does NOT select on the send-report or EC-completion
    /// channels: both are fed only by sends to peers, and a zone with any peer
    /// never parks — it keeps the `tick_interval` cadence, which drains those
    /// channels at least as promptly as before.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        tracing::info!(
            "Transport loop started (zone={}, tick_interval={}ms, peers={})",
            if self.zone_id.is_empty() {
                "<single>"
            } else {
                &self.zone_id
            },
            self.driver.config().tick_interval.as_millis(),
            self.peers.read().unwrap().len()
        );

        // Cleared once every `ZoneConsensus` handle for this zone is gone and
        // the driver's channel closes.  A closed channel resolves instantly and
        // forever, so its arm must leave the `select!` or the loop spins.
        let mut msg_channel_open = true;

        loop {
            // Decide how to wait, then wait.  Scoped so the disjoint field
            // borrows the `select!` needs end before the body takes `&mut self`.
            let woken_by = {
                let Self {
                    driver,
                    peers,
                    zone_id,
                    ..
                } = &mut self;

                // Park only when nothing can need us on a timer: raft has no
                // observable tick (`tick_is_noop`), no `Ready` is outstanding,
                // and there is no peer to replicate to.  Any of those turning
                // true again arrives as a message (ConfChange, inbound step,
                // local propose), which wakes us.
                let park = driver.tick_is_noop()
                    && !driver.has_ready()
                    && peers.read().unwrap().is_empty();
                let deadline = (!park).then(|| driver.next_tick_at());
                if park {
                    tracing::trace!(zone = %zone_id, "transport loop parked (no timed work)");
                }

                tokio::select! {
                    biased;
                    _ = shutdown.changed() => Woken::Shutdown,
                    still_open = driver.recv_and_handle(), if msg_channel_open => {
                        if still_open { Woken::Message } else { Woken::MessageChannelClosed }
                    }
                    _ = sleep_until_opt(deadline) => Woken::Deadline,
                }
            };
            match woken_by {
                Woken::Shutdown => {
                    tracing::info!("Transport loop shutting down");
                    break;
                }
                Woken::MessageChannelClosed => msg_channel_open = false,
                Woken::Message | Woken::Deadline => {}
            }

            // 0a. Hand raft-rs the outcome of previously spawned sends. Must
            //     run before `process_messages` / `advance` so the next
            //     tick's outgoing-message set reflects the updated
            //     `Progress` state. Cheap: non-blocking try_recv drain,
            //     returns immediately when the channel is empty.
            let failure_scan_now = Instant::now();
            while let Ok(report) = self.report_rx.try_recv() {
                self.apply_send_report(report, failure_scan_now);
            }
            // Fail-loud when a VOTER (read from `driver.voter_ids()` — the
            // ProgressTracker SSOT) has been unreachable past the threshold and
            // that costs us quorum. Once per episode; diagnostic only, no raft
            // behavior change.
            {
                let voters = self.driver.voter_ids();
                let is_leader = self.driver.is_leader();
                for (peer_id, since) in
                    self.quorum_health
                        .newly_at_risk(&voters, is_leader, failure_scan_now)
                {
                    let voter_addr = self
                        .peers
                        .read()
                        .unwrap()
                        .route(peer_id)
                        .map(|a| a.to_operator_str())
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let quorum = voters.len() / 2 + 1;
                    tracing::warn!(
                        zone = %self.zone_id,
                        voter = peer_id,
                        %voter_addr,
                        unreachable_secs = since.as_secs(),
                        voters = voters.len(),
                        quorum,
                        "voter unreachable long enough to BLOCK QUORUM — this zone cannot commit \
                         (safe_commit stalls). Most common cause: a stale-identity join (a node that \
                         changed its node_id after joining, or rejoined a re-founded zone — \
                         identity.json survives data-dir wipes). Fix: `nexusd-cluster remove-voter \
                         <peer_addr> <zone>` to drop the dead voter, or re-found with a fresh \
                         --identity-dir on EVERY node."
                    );
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
                    tracing::error!(zone = %self.zone_id, error = %e, "Raft driver stopped; durable recovery required");
                    break;
                }
            }

            // 3. EC Phase C: fire-and-forget replication to peers.  Each
            //    peer's send runs as a detached task; completion lands
            //    back via `ec_completion_rx` and is drained at the top
            //    of the next tick.  The transport loop never awaits an
            //    EC send — raft heartbeats and elections are not held
            //    behind a slow EC handshake.
            self.spawn_ec_replications();
            while self.snapshot_readers.try_join_next().is_some() {}
        }
        // The driver — owner of the raft storage and the state machine — drops
        // with `self`; a snapshot reader still running is the last other holder.
        self.snapshot_readers.shutdown().await;
    }

    /// Select routes for this zone's current Raft members. Learned or retained
    /// addresses carry no authority to receive metadata, WAL or EC snapshots.
    fn snapshot_replication_peers(&self) -> Vec<(u64, NodeAddress)> {
        self.peers
            .read()
            .unwrap()
            .routes()
            .filter(|(id, _)| *id != self.node_id && self.driver.is_replication_member(*id))
            .map(|(id, address)| (id, address.clone()))
            .collect()
    }

    /// Hand raft-rs one send outcome — see [`SendReport`] for the contract —
    /// and record the peer's send health.
    fn apply_send_report(&mut self, report: SendReport, now: Instant) {
        let SendReport {
            peer_id,
            payload,
            outcome,
        } = report;
        let delivered = matches!(outcome, Some(Ok(())));
        if !delivered {
            self.driver.report_unreachable(peer_id);
            // Track the failure episode so a voter that stays unreachable
            // long enough to block quorum surfaces ONE loud, actionable
            // WARN instead of a silent commit stall.
            self.quorum_health.note_failure(peer_id, now);
        }
        if payload.snapshot() {
            let status = if delivered {
                raft::SnapshotStatus::Finish
            } else {
                raft::SnapshotStatus::Failure
            };
            self.driver.report_snapshot(peer_id, status);
        }
        let Some(outcome) = outcome else {
            return;
        };
        let carries_log = payload.carries_log();
        match &outcome {
            // Only a delivered append or snapshot shows the peer accepts what
            // it is fed; a heartbeat arriving says nothing about that.
            Ok(()) if carries_log => {
                self.held_back.remove(&peer_id);
            }
            Ok(()) => {}
            Err(SendFailure::Oversized(_)) => {
                let backoff = match self.held_back.get(&peer_id) {
                    Some(held) if held.payload == payload => {
                        (held.backoff * 2).min(OVERSIZED_RETRY_MAX)
                    }
                    _ => OVERSIZED_RETRY_FIRST,
                };
                self.held_back.insert(
                    peer_id,
                    HeldBack {
                        payload,
                        retry_at: now + backoff,
                        backoff,
                    },
                );
            }
            Err(_) => {}
        }
        let error = outcome
            .as_ref()
            .err()
            .map(|failure| (failure.kind(), failure.to_string()));
        let streak = self.driver.record_send(
            peer_id,
            carries_log,
            error.as_ref().map(|(kind, text)| (*kind, text.as_str())),
            now,
        );
        match (&outcome, streak) {
            // A streak's first failure and every doubling: a peer failing on
            // every heartbeat is named a dozen times an hour, not ten times
            // a second.
            (Err(failure), failures) if failures.is_power_of_two() => tracing::warn!(
                zone = %self.zone_id,
                peer_node_id = peer_id,
                msg_type = ?payload.msg_type,
                consecutive_failures = failures,
                "Raft message send failed: {failure}",
            ),
            (Err(failure), failures) => tracing::debug!(
                zone = %self.zone_id,
                peer_node_id = peer_id,
                consecutive_failures = failures,
                "Raft message send failed: {failure}",
            ),
            (Ok(()), ended) if ended > 0 => tracing::info!(
                zone = %self.zone_id,
                peer_node_id = peer_id,
                failed_sends = ended,
                "Raft sends to peer recovered",
            ),
            (Ok(()), _) => {}
        }
    }

    /// Send Raft messages to peers — fire and forget.
    ///
    /// Each message is spawned as an independent task with its own deadline,
    /// so slow or unreachable peers never block `tick()` or each other. The
    /// outcome raft-rs needs (see [`SendReport`]) comes back through
    /// `report_tx`; a message that is not sent — no route, beyond the raft
    /// message bound, or a held-back oversized payload — is reported here,
    /// synchronously.
    fn send_messages_fire_and_forget(&mut self, messages: Vec<raft::eraftpb::Message>) {
        let protocol = self.driver.raft_message_protocol();
        let now = Instant::now();
        let mut unsent = Vec::new();
        // One shared lock resolves the whole batch; only the routes the batch
        // uses are cloned out.
        let routed: Vec<(NodeAddress, raft::eraftpb::Message)> = {
            let peers = Arc::clone(&self.peers);
            let peers = peers.read().unwrap();
            messages
                .into_iter()
                .filter_map(|msg| match peers.route(msg.to) {
                    Some(address) => {
                        if !self.unrouted.is_empty() {
                            self.unrouted.remove(&msg.to);
                        }
                        Some((address.clone(), msg))
                    }
                    None => {
                        if self.unrouted.insert(msg.to) {
                            tracing::warn!(
                                zone = %self.zone_id,
                                peer_node_id = msg.to,
                                msg_type = ?msg.get_msg_type(),
                                "member has no registered or observed address — its \
                                 messages are dropped until it registers its address \
                                 or reaches this node",
                            );
                        }
                        unsent.push(SendReport {
                            peer_id: msg.to,
                            payload: Payload::of(&msg),
                            outcome: Some(Err(SendFailure::Connection(
                                "no registered or observed address".into(),
                            ))),
                        });
                        None
                    }
                })
                .collect()
        };

        for (addr, msg) in routed {
            let target_id = msg.to;
            let payload = Payload::of(&msg);
            if self
                .held_back
                .get(&target_id)
                .is_some_and(|held| held.payload == payload && now < held.retry_at)
            {
                unsent.push(SendReport {
                    peer_id: target_id,
                    payload,
                    outcome: None,
                });
                continue;
            }
            let bytes = msg.compute_size() as usize;
            if bytes > MAX_RAFT_PAYLOAD_BYTES {
                unsent.push(SendReport {
                    peer_id: target_id,
                    payload,
                    outcome: Some(Err(SendFailure::Oversized(format!(
                        "{bytes}-byte {:?} exceeds the {MAX_RAFT_PAYLOAD_BYTES}-byte raft \
                         message bound",
                        payload.msg_type
                    )))),
                });
                continue;
            }
            let deadline = send_deadline(bytes);
            let client_pool = self.client_pool.clone();
            let zone_id = self.zone_id.clone();
            let self_address = self.self_address.clone();
            let report_tx = self.report_tx.clone();

            tokio::spawn(async move {
                let outcome = match tokio::time::timeout(
                    deadline,
                    send_raft_message(&client_pool, &addr, msg, zone_id, self_address, protocol),
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(_elapsed) => Err(SendFailure::Connection(format!(
                        "no answer within {deadline:?}"
                    ))),
                };
                // Only a broken channel is re-dialed: a refusal or an
                // oversized message says nothing about the connection, and
                // dropping it there turned every failed send into a dial.
                if matches!(outcome, Err(SendFailure::Connection(_))) {
                    client_pool.remove(target_id).await;
                }
                // A closed receiver means the loop is shutting down and the
                // driver goes with it; nothing is owed then.
                let _ = report_tx.send(SendReport {
                    peer_id: target_id,
                    payload,
                    outcome: Some(outcome),
                });
            });
        }
        for report in unsent {
            self.apply_send_report(report, now);
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

        let peer_snapshot = self.snapshot_replication_peers();
        self.ec_peer_state
            .retain(|id, _| self.driver.is_replication_member(*id));

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
        //
        // The peerless return happens BEFORE the WAL drain below, and that
        // ordering is load-bearing, not incidental: `drain_unreplicated` is a
        // redb range scan + a bincode deserialize of every entry still in the
        // WAL, and a single-voter zone with no peers never compacts (nothing
        // pins a floor, so the entries stay).  Draining first meant such a zone
        // re-materialized its whole, monotonically growing WAL on every tick —
        // 100 times a second, to then throw the result away here.  A zone with
        // EC traffic (the A2A mailbox plane writes EC) paid that unboundedly.
        if total_voters <= 1 {
            let max_seq = repl_log.max_seq();
            if max_seq > 1 {
                let _ = repl_log.advance_watermark(max_seq - 1);
            }
            if peer_snapshot.is_empty() {
                return;
            }
        }

        // Drain unreplicated entries — only now that we know some peer could
        // actually receive them.
        let entries = match repl_log.drain_unreplicated() {
            Ok(entries) => entries,
            Err(e) => {
                tracing::error!("Failed to drain unreplicated entries: {}", e);
                return;
            }
        };

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
                report_ec_completion(
                    task.peer_id,
                    EC_SEND_TIMEOUT,
                    "EC replication",
                    &completion_tx,
                    send,
                )
                .await;
            });
        }

        // Anti-entropy snapshots for peers that fell behind the compacted WAL,
        // run as `snapshot_readers` tasks.  Same `in_flight` discipline as the
        // incremental sends: mark before spawning so the next tick skips a
        // duplicate.  The state
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

            self.snapshot_readers.spawn(async move {
                // Materialization and serialization participate in the same
                // completion path as transmission. Failed reads cannot become
                // an acknowledged empty snapshot and advance the peer's floor.
                let send = async {
                    let commands = sm_arc
                        .read()
                        .await
                        .ec_state_snapshot()
                        .map_err(|error| format!("materialize EC snapshot: {error}"))?;
                    let entries = commands
                        .into_iter()
                        .map(|command| {
                            Ok(EcReplicationEntry {
                                seq: covering_seq,
                                command: bincode::serialize(&command)
                                    .map_err(|error| format!("serialize EC snapshot: {error}"))?,
                                timestamp: 0,
                                node_id,
                            })
                        })
                        .collect::<std::result::Result<Vec<_>, String>>()?;
                    send_ec_snapshot(
                        &client_pool,
                        &peer_addr,
                        zone_id,
                        entries,
                        covering_seq,
                        node_id,
                    )
                    .await
                };
                report_ec_completion(
                    peer_id,
                    EC_SNAPSHOT_TIMEOUT,
                    "EC snapshot",
                    &completion_tx,
                    send,
                )
                .await;
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
    addr: &NodeAddress,
    msg: raft::eraftpb::Message,
    zone_id: String,
    self_address: String,
    protocol: RaftMessageProtocol,
) -> std::result::Result<(), SendFailure> {
    let bytes = msg
        .write_to_bytes()
        .map_err(|e| SendFailure::Refused(format!("serialize: {e}")))?;
    let mut client = match protocol {
        RaftMessageProtocol::Legacy => client_pool.get(addr).await,
        RaftMessageProtocol::ReplicaControlV1 => client_pool.get_node(addr).await,
    }
    .map_err(|e| SendFailure::Connection(format!("connect to {}: {e}", addr.endpoint)))?;
    match protocol {
        RaftMessageProtocol::Legacy => client.step_message(bytes, zone_id, self_address).await,
        RaftMessageProtocol::ReplicaControlV1 => {
            client
                .step_replica_control_v1(bytes, zone_id, self_address)
                .await
        }
    }
    .map_err(SendFailure::of)
}

/// Await an EC send future under `timeout` and report the outcome back on the
/// completion channel.  Shared by the incremental-batch and anti-entropy
/// snapshot sends so the `Acked` / `Failed` / timeout mapping lives in one
/// place.  `send` resolves to the peer's acked-up-to seq on success.
async fn report_ec_completion(
    peer_id: u64,
    timeout: StdDuration,
    what: &str,
    completion_tx: &mpsc::UnboundedSender<EcCompletion>,
    send: impl std::future::Future<Output = std::result::Result<u64, String>>,
) {
    let completion = match tokio::time::timeout(timeout, send).await {
        Ok(Ok(applied_up_to)) => EcCompletion::Acked {
            peer_id,
            applied_up_to,
        },
        Ok(Err(error)) => EcCompletion::Failed { peer_id, error },
        Err(_) => EcCompletion::Failed {
            peer_id,
            error: format!("{what} timed out after {timeout:?}"),
        },
    };
    // Best-effort signal back.  Receiver drop only happens at shutdown, in
    // which case a missed completion is harmless.
    let _ = completion_tx.send(completion);
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
    use crate::raft::{FullStateMachine, RaftConfig, RaftStorage, ReplicationLog, ZoneConsensus};
    use crate::storage::RedbStore;
    use raft::eraftpb::{ConfChangeType, ConfState};

    fn membership_fixture(
        membership: ConfState,
    ) -> (
        tempfile::TempDir,
        ZoneConsensus<FullStateMachine>,
        TransportLoop<FullStateMachine>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let storage = RaftStorage::open(directory.path()).unwrap();
        storage.set_conf_state(&membership).unwrap();
        let store = RedbStore::open(directory.path().join("state")).unwrap();
        let config = RaftConfig {
            id: 1,
            skip_bootstrap: true,
            ..Default::default()
        };
        let (handle, driver) = ZoneConsensus::new(
            config,
            storage,
            FullStateMachine::new(&store).unwrap(),
            Some(Arc::new(ReplicationLog::new(&store, 1).unwrap())),
        )
        .unwrap();
        let mut addresses = crate::transport::PeerMap::new(1);
        for id in 1..=5 {
            addresses.observe(
                id,
                NodeAddress::new(id, format!("http://127.0.0.1:{}", 25000 + id)),
            );
        }
        let transport = TransportLoop::new(
            driver,
            Arc::new(std::sync::RwLock::new(addresses)),
            RaftClientPool::new(),
        );
        (directory, handle, transport)
    }

    fn recipients(transport: &TransportLoop<FullStateMachine>) -> Vec<u64> {
        let mut ids: Vec<_> = transport
            .snapshot_replication_peers()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        ids.sort_unstable();
        ids
    }

    #[test]
    fn ec_recipients_follow_joint_membership_instead_of_learned_addresses() {
        let (_directory, handle, transport) = membership_fixture(ConfState {
            voters: vec![1, 2],
            voters_outgoing: vec![1, 3],
            learners: vec![4],
            learners_next: vec![3],
            ..Default::default()
        });
        assert_eq!(recipients(&transport), vec![2, 3, 4]);
        assert!(transport.peers.read().unwrap().route(5).is_some());
        assert_eq!(transport.driver.voter_ids(), vec![1, 2, 3]);
        for id in 1..=5 {
            assert_eq!(
                handle.is_replication_member(id),
                transport.driver.is_replication_member(id)
            );
        }
    }

    #[tokio::test]
    async fn committed_learner_removal_excludes_its_retained_route() {
        let (_directory, handle, mut transport) = membership_fixture(ConfState {
            voters: vec![1],
            learners: vec![2],
            ..Default::default()
        });
        assert_eq!(recipients(&transport), vec![2]);
        assert!(handle.is_replication_member(2));
        transport.ec_peer_state.insert(2, mk_peer_state(7));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !handle.is_leader() {
                transport.driver.process_messages();
                transport.driver.advance().await.unwrap();
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("single voter becomes leader");
        let caller = handle.clone();
        let change = tokio::spawn(async move {
            caller
                .propose_conf_change(ConfChangeType::RemoveNode, 2, Vec::new())
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !change.is_finished() {
                transport.driver.process_messages();
                transport.driver.advance().await.unwrap();
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("learner removal commits");
        let committed = change.await.unwrap().unwrap();
        assert_eq!(committed.voters, vec![1]);
        assert!(committed.learners.is_empty());
        assert!(
            !handle.is_replication_member(2),
            "committed removal updates admission before returning"
        );
        assert!(transport.peers.read().unwrap().route(2).is_some());
        assert!(recipients(&transport).is_empty());
        // A retired peer's progress cannot pin future compaction or count as
        // an acknowledgement when this zone subsequently changes membership.
        transport.spawn_ec_replications();
        assert!(!transport.ec_peer_state.contains_key(&2));
    }

    /// A member without a route is reported once per loss of its route,
    /// not once per dropped message.
    #[tokio::test]
    async fn an_unrouted_member_is_reported_once_until_it_routes_again() {
        let (_directory, _handle, mut transport) = membership_fixture(ConfState {
            voters: vec![1],
            learners: vec![9],
            ..Default::default()
        });
        let to = |id: u64| {
            let mut message = raft::eraftpb::Message::default();
            message.set_msg_type(MessageType::MsgHeartbeat);
            message.to = id;
            message
        };
        transport.send_messages_fire_and_forget(vec![to(9), to(9)]);
        transport.send_messages_fire_and_forget(vec![to(9)]);
        assert_eq!(
            transport.unrouted.iter().copied().collect::<Vec<_>>(),
            vec![9]
        );

        transport
            .peers
            .write()
            .unwrap()
            .observe(9, NodeAddress::new(9, "http://127.0.0.1:1"));
        transport.send_messages_fire_and_forget(vec![to(9)]);
        assert!(
            transport.unrouted.is_empty(),
            "a routed send re-arms the warning for a later loss"
        );
        transport.send_messages_fire_and_forget(vec![to(7)]);
        assert_eq!(
            transport.unrouted.iter().copied().collect::<Vec<_>>(),
            vec![7]
        );
    }

    /// A snapshot raft-rs generated for a member with no route is reported as
    /// failed, so the member's `Progress` leaves `Snapshot` and the snapshot is
    /// generated again once the member is reachable. Dropping it silently
    /// held the member in `Snapshot` — heartbeats only — for good.
    #[tokio::test]
    async fn an_undeliverable_snapshot_is_reported_failed() {
        use crate::raft::{Command, ReplicationState};

        let (_directory, handle, mut transport) = membership_fixture(ConfState {
            voters: vec![1],
            learners: vec![9],
            ..Default::default()
        });
        transport.driver.set_snapshot_threshold(4);
        async fn drive(transport: &mut TransportLoop<FullStateMachine>) -> Vec<Message> {
            transport.driver.process_messages();
            let messages = transport.driver.advance().await.unwrap();
            transport.send_messages_fire_and_forget(messages.clone());
            tokio::task::yield_now().await;
            messages
        }
        type Message = raft::eraftpb::Message;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !handle.is_leader() {
                drive(&mut transport).await;
            }
        })
        .await
        .expect("single voter becomes leader");
        for i in 0..12 {
            handle
                .propose_ec(Command::SetMetadata {
                    key: format!("/k/{i}"),
                    value: vec![1],
                })
                .await
                .unwrap();
            drive(&mut transport).await;
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while handle.applied_index() < 12 {
                drive(&mut transport).await;
            }
        })
        .await
        .expect("entries apply and the log compacts");

        // The learner answers a heartbeat: raft-rs resumes it and, its next
        // index being compacted away, sends it a snapshot it cannot route.
        let mut answer = Message::default();
        answer.set_msg_type(MessageType::MsgHeartbeatResponse);
        answer.from = 9;
        answer.to = 1;
        answer.term = handle.term();
        handle.step(answer).await.unwrap();
        let sent = drive(&mut transport).await;
        assert!(
            sent.iter()
                .any(|m| m.to == 9 && m.get_msg_type() == MessageType::MsgSnapshot),
            "the compacted log forces a snapshot: {sent:?}"
        );
        drive(&mut transport).await;
        let learner = handle
            .replication()
            .peers
            .into_iter()
            .find(|peer| peer.node_id == 9)
            .expect("learner progress");
        assert_eq!(
            learner.state,
            ReplicationState::Probe,
            "a failed snapshot returns the learner to Probe, to be re-sent"
        );
    }

    #[test]
    fn a_send_deadline_grows_with_the_message() {
        assert_eq!(send_deadline(0), RAFT_SEND_TIMEOUT);
        let production = 18 * 1024 * 1024;
        assert_eq!(
            send_deadline(production),
            RAFT_SEND_TIMEOUT + StdDuration::from_secs(144),
            "18 MiB at the 1 Mbit/s floor"
        );
    }

    /// A size refusal from either end is told apart from a broken channel and
    /// from any other refusal: only a broken channel is re-dialed, and only an
    /// oversized message is held back.
    #[test]
    fn send_failures_are_classified_by_what_retrying_can_change() {
        use crate::transport::TransportError;
        let of = |status: tonic::Status| SendFailure::of(TransportError::Status(status));
        assert!(matches!(
            of(tonic::Status::out_of_range(
                "Error, decoded message length too large: found 5726623 bytes, the limit is: \
                 4194304 bytes"
            )),
            SendFailure::Oversized(_)
        ));
        assert!(matches!(
            of(tonic::Status::resource_exhausted(
                "grpc: received message larger than max"
            )),
            SendFailure::Oversized(_)
        ));
        assert!(matches!(
            of(tonic::Status::unavailable("connection reset")),
            SendFailure::Connection(_)
        ));
        assert!(matches!(
            of(tonic::Status::not_found("zone")),
            SendFailure::Refused(_)
        ));
        assert!(matches!(
            SendFailure::of(TransportError::Rpc("step refused".into())),
            SendFailure::Refused(_)
        ));
        assert!(matches!(
            SendFailure::of(TransportError::Connection("refused".into())),
            SendFailure::Connection(_)
        ));
    }

    /// An oversized append is not re-sent each time raft-rs regenerates it:
    /// the same payload is held back with a doubling backoff, while a
    /// different payload is sent and a delivered send releases the hold.
    #[tokio::test]
    async fn an_oversized_payload_is_held_back_and_retried_with_backoff() {
        let (_directory, _handle, mut transport) = membership_fixture(ConfState {
            voters: vec![1, 2],
            ..Default::default()
        });
        let append = |index: u64| {
            let mut message = raft::eraftpb::Message::default();
            message.set_msg_type(MessageType::MsgAppend);
            message.to = 2;
            message.index = index;
            message.set_entries(
                vec![raft::eraftpb::Entry {
                    index: index + 1,
                    ..Default::default()
                }]
                .into(),
            );
            message
        };
        let oversized = |index: u64| SendReport {
            peer_id: 2,
            payload: Payload::of(&append(index)),
            outcome: Some(Err(SendFailure::Oversized("too large".into()))),
        };
        let now = Instant::now();
        transport.apply_send_report(oversized(7), now);
        let held = transport.held_back.get(&2).expect("held back");
        assert_eq!(held.backoff, OVERSIZED_RETRY_FIRST);
        let retry_at = held.retry_at;

        transport.send_messages_fire_and_forget(vec![append(7)]);
        tokio::task::yield_now().await;
        assert!(
            transport.report_rx.try_recv().is_err(),
            "the same payload was not sent again"
        );
        assert_eq!(transport.held_back[&2].retry_at, retry_at);

        transport.apply_send_report(oversized(7), now);
        assert_eq!(transport.held_back[&2].backoff, OVERSIZED_RETRY_FIRST * 2);

        // Another payload is sent (and here fails on the unserved address).
        transport.send_messages_fire_and_forget(vec![append(9)]);
        let report = tokio::time::timeout(Duration::from_secs(10), transport.report_rx.recv())
            .await
            .expect("the other payload was sent")
            .unwrap();
        assert_eq!(report.payload, Payload::of(&append(9)));

        let mut heartbeat = raft::eraftpb::Message::default();
        heartbeat.set_msg_type(MessageType::MsgHeartbeat);
        heartbeat.to = 2;
        transport.apply_send_report(
            SendReport {
                peer_id: 2,
                payload: Payload::of(&heartbeat),
                outcome: Some(Ok(())),
            },
            now,
        );
        assert!(
            transport.held_back.contains_key(&2),
            "heartbeats arriving do not show the peer accepts the append"
        );

        transport.apply_send_report(
            SendReport {
                peer_id: 2,
                payload: Payload::of(&append(7)),
                outcome: Some(Ok(())),
            },
            now,
        );
        assert!(
            transport.held_back.is_empty(),
            "a delivered append releases it"
        );
    }

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

#[cfg(test)]
mod quorum_health_tests {
    use super::{QuorumHealth, VOTER_RECOVERED_AFTER, VOTER_UNREACHABLE_WARN_AFTER};
    use std::time::{Duration, Instant};

    /// Drive `QuorumHealth` the way the transport loop does — a dead voter
    /// generates a send failure every second — and count total WARNs emitted
    /// over `secs`. Synthetic `now` values, so no real sleeps.
    fn run(voters: &[u64], failing_peer: u64, is_leader: bool, secs: u64) -> usize {
        let t0 = Instant::now();
        let mut qh = QuorumHealth::default();
        let mut warns = 0;
        for s in 0..=secs {
            let now = t0 + Duration::from_secs(s);
            qh.note_failure(failing_peer, now);
            warns += qh.newly_at_risk(voters, is_leader, now).len();
        }
        warns
    }

    #[test]
    fn warns_once_when_a_dead_voter_blocks_quorum() {
        // 2-voter zone, peer 2 dead → reachable {1} < quorum 2 → exactly ONE
        // WARN once it has been failing past the threshold (not per tick).
        assert_eq!(run(&[1, 2], 2, true, 8), 1);
    }

    #[test]
    fn silent_below_the_threshold() {
        let secs = VOTER_UNREACHABLE_WARN_AFTER.as_secs().saturating_sub(1);
        assert_eq!(run(&[1, 2], 2, true, secs), 0);
    }

    #[test]
    fn silent_when_quorum_still_holds() {
        // 3-voter zone, one dead → reachable {1,2} == quorum 2 → not a deadlock.
        assert_eq!(run(&[1, 2, 3], 3, true, 8), 0);
    }

    #[test]
    fn silent_on_a_follower() {
        assert_eq!(run(&[1, 2], 2, false, 8), 0);
    }

    #[test]
    fn re_arms_after_recovery() {
        let t0 = Instant::now();
        let mut qh = QuorumHealth::default();
        let voters = [1u64, 2u64];
        let mut warns = 0;
        for s in 0..=6 {
            let now = t0 + Duration::from_secs(s);
            qh.note_failure(2, now);
            warns += qh.newly_at_risk(&voters, true, now).len();
        }
        assert_eq!(warns, 1, "episode 1: one WARN");
        // No failures for > RECOVERED_AFTER → episode state GC'd (voter recovered).
        let recovered_at =
            t0 + Duration::from_secs(6) + VOTER_RECOVERED_AFTER + Duration::from_secs(1);
        assert!(qh.newly_at_risk(&voters, true, recovered_at).is_empty());
        // A fresh failure episode re-arms a new WARN.
        let t1 = recovered_at + Duration::from_secs(1);
        let mut warns2 = 0;
        for s in 0..=6 {
            let now = t1 + Duration::from_secs(s);
            qh.note_failure(2, now);
            warns2 += qh.newly_at_risk(&voters, true, now).len();
        }
        assert_eq!(warns2, 1, "a new episode after recovery re-arms the WARN");
    }
}
