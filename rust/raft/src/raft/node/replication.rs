//! What this node can observe about replication progress, in memory only.
//!
//! raft-rs keeps each peer's `Progress` on the leader and nothing on a
//! follower about its own lag: a follower's heartbeats carry
//! `min(leader commit, matched)`, so a replica the leader has stopped feeding
//! sees a perfectly current commit index. Two observations close that gap:
//!
//! * the leader times every peer's `Progress` — how long it has held its
//!   state (`Probe` / `Replicate` / `Snapshot`) and how long `matched` has
//!   stood still behind the commit index;
//! * a follower or learner asks the leader for its commit index with a
//!   periodic ReadIndex (the commit probe), and times its own applied index
//!   against the answer;
//! * the transport records each peer's run of failed sends, so a peer that
//!   cannot be reached — or cannot accept what it is sent — is named with the
//!   reason instead of being retried in silence.
//!
//! Every value here is an observation of the running process. None of it is
//! persisted: a restart rebuilds `Progress` from scratch, and so does this.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use raft::ProgressState;

use super::read_index::ReadContext;

/// How long an index may stand still behind the commit index, or a peer hold
/// `Probe` / `Snapshot` behind it, before it counts as stalled rather than in
/// flight. The one threshold for `doctor --live` alarms and the logs.
pub const REPLICATION_STALL: Duration = Duration::from_secs(30);

/// How often a follower asks the leader for its commit index.
pub(super) const COMMIT_PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// A probe unanswered for this long is abandoned and replaced: raft-rs drops a
/// ReadIndex silently when there is no leader, or when the leader has not yet
/// committed an entry in its term.
const COMMIT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// A peer's raft-rs `Progress` state, as reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationState {
    /// The leader is probing for the peer's last matching index; at most one
    /// append in flight.
    Probe,
    /// Steady state: appends are pipelined.
    Replicate,
    /// A snapshot was sent; nothing else is sent until it is reported or
    /// answered.
    Snapshot,
}

impl From<ProgressState> for ReplicationState {
    fn from(state: ProgressState) -> Self {
        match state {
            ProgressState::Probe => Self::Probe,
            ProgressState::Replicate => Self::Replicate,
            ProgressState::Snapshot => Self::Snapshot,
        }
    }
}

/// The leader's view of one other member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerReplication {
    pub node_id: u64,
    pub learner: bool,
    pub state: ReplicationState,
    /// Highest index known to be replicated on the peer.
    pub matched: u64,
    /// Next index the leader will send.
    pub next_index: u64,
    /// How long the peer has held `state`.
    pub in_state_for: Duration,
    /// How long `matched` has stood still while behind the leader's commit
    /// index; zero when caught up.
    pub stalled_for: Duration,
    /// Consecutive messages to the peer that did not reach it; zero once one
    /// does.
    pub send_failures: u64,
    /// How long those failures have run.
    pub send_failing_for: Duration,
    /// Why the latest of them failed.
    pub last_send_error: Option<String>,
}

/// The leader's commit index as a commit probe last reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaderCommit {
    pub index: u64,
    /// Time since the leader answered.
    pub observed_ago: Duration,
}

/// What this node observes about replication. The leader fills `peers`; a
/// follower or learner fills `leader_commit` and `stalled_for`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicationStatus {
    pub peers: Vec<PeerReplication>,
    pub leader_commit: Option<LeaderCommit>,
    /// How long this replica's applied index has stood still while behind
    /// `leader_commit`; zero when caught up.
    pub stalled_for: Duration,
}

/// An index and the instant it last changed.
#[derive(Debug, Clone, Copy)]
struct IndexClock {
    index: u64,
    /// When a target was first seen above `index`, since `index` last moved.
    /// A stall is time spent behind: an index that stood still while nothing
    /// was ahead of it (an idle zone) is caught up, however long the gap.
    behind_since: Option<Instant>,
}

impl IndexClock {
    fn new(index: u64) -> Self {
        Self {
            index,
            behind_since: None,
        }
    }

    /// A moved index starts over: any stall it had is over.
    fn observe(&mut self, index: u64) {
        if index != self.index {
            *self = Self::new(index);
        }
    }

    /// Record the index this one should reach: the commit index for a peer's
    /// `matched`, the leader's commit for a replica's `applied`.
    fn observe_target(&mut self, target: u64, now: Instant) {
        if self.index < target {
            self.behind_since.get_or_insert(now);
        } else {
            self.behind_since = None;
        }
    }

    /// How long the index has stood still while below `target`, counted from
    /// when it was first seen behind.
    fn stalled_behind(&self, target: u64, now: Instant) -> Duration {
        match self.behind_since {
            Some(since) if self.index < target => now.saturating_duration_since(since),
            _ => Duration::ZERO,
        }
    }
}

/// A peer's current run of failed sends of one kind.
#[derive(Debug, Clone)]
struct FailingSends {
    kind: &'static str,
    count: u64,
    since: Instant,
    last_error: String,
}

#[derive(Debug, Clone, Copy)]
struct PeerWatch {
    learner: bool,
    state: ProgressState,
    state_since: Instant,
    matched: IndexClock,
    next_index: u64,
    /// The observation that last saw this member in the tracker.
    round: u64,
}

/// Observations shared between the driver (writer) and the handle (reader).
#[derive(Debug, Default)]
pub(super) struct ReplicationView {
    /// Leader only: commit index and each other member's progress.
    leader: Option<(u64, HashMap<u64, PeerWatch>)>,
    /// Counts leader observations, to sweep members that left the tracker.
    round: u64,
    /// Follower only: the last probe answer and when it arrived.
    leader_commit: Option<(u64, Instant)>,
    applied: Option<IndexClock>,
    /// Any role: peers whose latest sends of a class failed, keyed by
    /// `(peer, carries_log)`. A delivered send of the same class removes the
    /// entry, so the map holds only runs currently failing.
    failing_sends: HashMap<(u64, bool), FailingSends>,
}

impl ReplicationView {
    /// Record the leader's tracker. Called by the driver after every ready.
    pub(super) fn observe_leader(
        &mut self,
        commit: u64,
        progress: impl Iterator<Item = (u64, ProgressState, u64, u64, bool)>,
        now: Instant,
    ) {
        self.leader_commit = None;
        self.applied = None;
        self.round = self.round.wrapping_add(1);
        let round = self.round;
        let (stored_commit, peers) = self.leader.get_or_insert_with(Default::default);
        *stored_commit = commit;
        let mut seen = 0usize;
        for (id, state, matched, next_index, learner) in progress {
            seen += 1;
            let watch = peers.entry(id).or_insert(PeerWatch {
                learner,
                state,
                state_since: now,
                matched: IndexClock::new(matched),
                next_index,
                round,
            });
            if watch.state != state {
                watch.state = state;
                watch.state_since = now;
            }
            watch.learner = learner;
            watch.matched.observe(matched);
            watch.matched.observe_target(commit, now);
            watch.next_index = next_index;
            watch.round = round;
        }
        if peers.len() > seen {
            peers.retain(|_, watch| watch.round == round);
        }
    }

    /// Drop leader-only state: this node no longer leads.
    pub(super) fn observe_follower(&mut self, applied: u64) {
        self.leader = None;
        match self.applied.as_mut() {
            Some(clock) => clock.observe(applied),
            None => self.applied = Some(IndexClock::new(applied)),
        }
    }

    pub(super) fn record_leader_commit(&mut self, index: u64, now: Instant) {
        self.leader_commit = Some((index, now));
        if let Some(applied) = self.applied.as_mut() {
            applied.observe_target(index, now);
        }
    }

    /// Record one send to `peer`: `failure` is its `(kind, description)`,
    /// `None` that it arrived. `carries_log` separates messages that feed the
    /// peer's log (appends, snapshots) from control messages (heartbeats,
    /// votes): a peer whose heartbeats arrive while every append is refused
    /// is still not being fed, so one class's success never ends the other's
    /// run. A failure of another kind starts a new run — it is a new problem.
    /// Returns the run of failures this send extends, or the run a delivered
    /// send ends (zero when none was running).
    pub(super) fn record_send(
        &mut self,
        peer: u64,
        carries_log: bool,
        failure: Option<(&'static str, &str)>,
        now: Instant,
    ) -> u64 {
        let key = (peer, carries_log);
        let Some((kind, description)) = failure else {
            return self
                .failing_sends
                .remove(&key)
                .map_or(0, |failing| failing.count);
        };
        let failing = self
            .failing_sends
            .entry(key)
            .and_modify(|failing| {
                if failing.kind != kind {
                    failing.kind = kind;
                    failing.count = 0;
                    failing.since = now;
                }
            })
            .or_insert_with(|| FailingSends {
                kind,
                count: 0,
                since: now,
                last_error: String::new(),
            });
        failing.count += 1;
        description.clone_into(&mut failing.last_error);
        failing.count
    }

    /// Point-in-time status, durations measured at `now`.
    pub(super) fn status(&self, now: Instant) -> ReplicationStatus {
        let mut status = ReplicationStatus::default();
        if let Some((commit, peers)) = &self.leader {
            status.peers = peers
                .iter()
                .map(|(id, watch)| {
                    // The log-carrying run is the one that says the peer is
                    // not fed; a control run says it is not reached at all.
                    let failing = self
                        .failing_sends
                        .get(&(*id, true))
                        .or_else(|| self.failing_sends.get(&(*id, false)));
                    PeerReplication {
                        node_id: *id,
                        learner: watch.learner,
                        state: watch.state.into(),
                        matched: watch.matched.index,
                        next_index: watch.next_index,
                        in_state_for: now.saturating_duration_since(watch.state_since),
                        stalled_for: watch.matched.stalled_behind(*commit, now),
                        send_failures: failing.map_or(0, |failing| failing.count),
                        send_failing_for: failing.map_or(Duration::ZERO, |failing| {
                            now.saturating_duration_since(failing.since)
                        }),
                        last_send_error: failing.map(|failing| failing.last_error.clone()),
                    }
                })
                .collect();
            status.peers.sort_unstable_by_key(|peer| peer.node_id);
        }
        if let Some((index, at)) = self.leader_commit {
            status.leader_commit = Some(LeaderCommit {
                index,
                observed_ago: now.saturating_duration_since(at),
            });
            if let Some(applied) = self.applied {
                status.stalled_for = applied.stalled_behind(index, now);
            }
        }
        status
    }
}

/// The follower's outstanding commit probe.
#[derive(Debug, Default)]
pub(super) struct CommitProbe {
    in_flight: Option<(ReadContext, Instant)>,
    last_sent: Option<Instant>,
}

impl CommitProbe {
    /// Whether a new probe is due at `now`.
    pub(super) fn due(&self, now: Instant) -> bool {
        let interval_elapsed = self
            .last_sent
            .is_none_or(|sent| now.saturating_duration_since(sent) >= COMMIT_PROBE_INTERVAL);
        let unanswered = self
            .in_flight
            .is_some_and(|(_, sent)| now.saturating_duration_since(sent) < COMMIT_PROBE_TIMEOUT);
        interval_elapsed && !unanswered
    }

    pub(super) fn sent(&mut self, context: ReadContext, now: Instant) {
        self.in_flight = Some((context, now));
        self.last_sent = Some(now);
    }

    /// Whether `context` answers the outstanding probe; consumes it if so.
    pub(super) fn answers(&mut self, context: &ReadContext) -> bool {
        let matched = self
            .in_flight
            .is_some_and(|(outstanding, _)| outstanding == *context);
        if matched {
            self.in_flight = None;
        }
        matched
    }

    /// This node leads now, or has no leader to ask.
    pub(super) fn reset(&mut self) {
        self.in_flight = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: u64, state: ProgressState, matched: u64) -> (u64, ProgressState, u64, u64, bool) {
        (id, state, matched, matched + 1, true)
    }

    #[test]
    fn a_peer_held_in_snapshot_accumulates_time_in_state_and_stall() {
        let t0 = Instant::now();
        let mut view = ReplicationView::default();
        view.observe_leader(100, [peer(7, ProgressState::Replicate, 90)].into_iter(), t0);
        let t1 = t0 + Duration::from_secs(1);
        view.observe_leader(110, [peer(7, ProgressState::Snapshot, 90)].into_iter(), t1);
        let t2 = t0 + Duration::from_secs(61);
        view.observe_leader(110, [peer(7, ProgressState::Snapshot, 90)].into_iter(), t2);

        let status = view.status(t2);
        let watched = &status.peers[0];
        assert_eq!(watched.state, ReplicationState::Snapshot);
        assert_eq!(watched.in_state_for, Duration::from_secs(60));
        assert_eq!(
            watched.stalled_for,
            Duration::from_secs(61),
            "matched has not moved since it was first seen behind the commit"
        );

        view.observe_leader(
            110,
            [peer(7, ProgressState::Replicate, 110)].into_iter(),
            t2,
        );
        let caught_up = view.status(t2 + Duration::from_secs(5));
        assert_eq!(caught_up.peers[0].stalled_for, Duration::ZERO);
        assert_eq!(caught_up.peers[0].in_state_for, Duration::from_secs(5));
    }

    #[test]
    fn a_run_of_failed_sends_is_reported_until_one_arrives() {
        let t0 = Instant::now();
        let mut view = ReplicationView::default();
        view.observe_leader(9, [peer(7, ProgressState::Probe, 3)].into_iter(), t0);
        assert_eq!(
            view.record_send(7, true, Some(("connection", "down")), t0),
            1
        );
        assert_eq!(
            view.record_send(7, true, Some(("message too large", "too large")), t0),
            1,
            "another kind of failure starts a new run"
        );
        let t5 = t0 + Duration::from_secs(5);
        assert_eq!(
            view.record_send(7, false, None, t5),
            0,
            "a heartbeat arriving does not end the append run"
        );
        assert_eq!(
            view.record_send(
                7,
                true,
                Some(("message too large", "message too large: 5 MB")),
                t5
            ),
            2
        );
        let watched = &view.status(t5).peers[0];
        assert_eq!(watched.send_failures, 2);
        assert_eq!(watched.send_failing_for, Duration::from_secs(5));
        assert_eq!(
            watched.last_send_error.as_deref(),
            Some("message too large: 5 MB")
        );

        assert_eq!(view.record_send(7, true, None, t5), 2, "the run that ended");
        assert_eq!(view.record_send(7, true, None, t5), 0);
        let healthy = &view.status(t5).peers[0];
        assert_eq!(healthy.send_failures, 0);
        assert_eq!(healthy.last_send_error, None);
    }

    /// An index that stood still because nothing was ahead of it — an idle zone
    /// — is caught up. When the next entry commits, the stall is counted from
    /// then, not from the last time the index moved, so the first entry after a
    /// long idle gap is not a long stall.
    #[test]
    fn an_idle_gap_is_not_a_stall() {
        let t0 = Instant::now();
        let mut view = ReplicationView::default();
        view.observe_follower(50);
        view.record_leader_commit(50, t0);
        let t100 = t0 + Duration::from_secs(100);
        view.observe_follower(50);
        view.record_leader_commit(51, t100);
        let status = view.status(t100 + Duration::from_secs(1));
        assert_eq!(status.stalled_for, Duration::from_secs(1));

        let mut leader = ReplicationView::default();
        leader.observe_leader(50, [peer(7, ProgressState::Replicate, 50)].into_iter(), t0);
        leader.observe_leader(
            51,
            [peer(7, ProgressState::Replicate, 50)].into_iter(),
            t100,
        );
        let watched = &leader.status(t100 + Duration::from_secs(1)).peers[0];
        assert_eq!(watched.stalled_for, Duration::from_secs(1));
    }

    #[test]
    fn a_departed_member_is_no_longer_reported() {
        let now = Instant::now();
        let mut view = ReplicationView::default();
        view.observe_leader(
            5,
            [
                peer(2, ProgressState::Replicate, 5),
                peer(3, ProgressState::Probe, 1),
            ]
            .into_iter(),
            now,
        );
        view.observe_leader(5, [peer(2, ProgressState::Replicate, 5)].into_iter(), now);
        let ids: Vec<u64> = view.status(now).peers.iter().map(|p| p.node_id).collect();
        assert_eq!(ids, vec![2]);
    }

    #[test]
    fn a_follower_behind_the_probed_commit_reports_how_long_it_stood_still() {
        let t0 = Instant::now();
        let mut view = ReplicationView::default();
        view.observe_follower(40);
        view.record_leader_commit(60, t0 + Duration::from_secs(1));
        let t9 = t0 + Duration::from_secs(9);
        view.observe_follower(40);
        let status = view.status(t9);
        assert_eq!(
            status.leader_commit,
            Some(LeaderCommit {
                index: 60,
                observed_ago: Duration::from_secs(8)
            })
        );
        assert_eq!(
            status.stalled_for,
            Duration::from_secs(8),
            "behind since the probe first answered ahead of it"
        );

        view.observe_follower(60);
        assert_eq!(view.status(t9).stalled_for, Duration::ZERO);
        assert!(view.status(t9).peers.is_empty());
    }

    #[test]
    fn the_probe_is_paced_and_replaced_only_after_its_timeout() {
        let t0 = Instant::now();
        let mut probe = CommitProbe::default();
        assert!(probe.due(t0));
        probe.sent([1; 32], t0);
        assert!(!probe.due(t0 + COMMIT_PROBE_INTERVAL), "still outstanding");
        assert!(
            probe.due(t0 + COMMIT_PROBE_TIMEOUT),
            "abandoned and replaced"
        );
        assert!(!probe.answers(&[2; 32]), "another context answers nothing");
        assert!(probe.answers(&[1; 32]));
        assert!(!probe.due(t0 + Duration::from_millis(10)), "paced");
        assert!(probe.due(t0 + COMMIT_PROBE_INTERVAL));
    }
}
