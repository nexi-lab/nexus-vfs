//! What a leader's compaction keeps for its peers: the log after an
//! in-flight snapshot, the log a progressing peer continues from, nothing
//! for a peer silent past the progress window, and never more than the
//! retained-log bound.

use super::*;
use raft::eraftpb::{Message, MessageType};

const THRESHOLD: u64 = 8;
const LEARNER: u64 = 2;

async fn drive(driver: &mut ZoneConsensusDriver<FullStateMachine>) -> Vec<Message> {
    driver.process_messages();
    driver.advance().await.expect("advance")
}

/// Commit `count` writes, returning every message the leader emitted.
async fn write(
    handle: &ZoneConsensus<FullStateMachine>,
    driver: &mut ZoneConsensusDriver<FullStateMachine>,
    prefix: &str,
    count: u64,
) -> Vec<Message> {
    let mut emitted = Vec::new();
    for i in 0..count {
        let caller = handle.clone();
        let key = format!("/{prefix}/{i}");
        let proposal = tokio::spawn(async move {
            caller
                .propose(Command::SetMetadata {
                    key,
                    value: vec![1],
                })
                .await
        });
        while !proposal.is_finished() {
            emitted.extend(drive(driver).await);
            tokio::task::yield_now().await;
        }
        proposal.await.unwrap().expect("write commits");
    }
    emitted.extend(drive(driver).await);
    emitted
}

fn from_learner(handle: &ZoneConsensus<FullStateMachine>, msg_type: MessageType) -> Message {
    let mut message = Message::default();
    message.set_msg_type(msg_type);
    message.from = LEARNER;
    message.to = 1;
    message.term = handle.term();
    message
}

fn snapshots_to_learner(messages: &[Message]) -> Vec<u64> {
    messages
        .iter()
        .filter(|m| m.to == LEARNER && m.get_msg_type() == MessageType::MsgSnapshot)
        .map(|m| m.get_snapshot().get_metadata().index)
        .collect()
}

/// A single-voter leader whose learner was given up and compacted past,
/// and has just been sent a snapshot on answering a heartbeat; returns that
/// snapshot's index. The progress window is the production one from here.
async fn leader_sending_a_snapshot() -> (
    ZoneConsensus<FullStateMachine>,
    ZoneConsensusDriver<FullStateMachine>,
    TempDir,
    u64,
) {
    let (handle, mut driver, dir) = leader_1voter().await;
    driver.set_snapshot_threshold(THRESHOLD);
    // The learner never answers: with no window it is given up at once.
    driver.set_progress_window(Duration::ZERO);
    let add = ConfChange {
        change_type: ConfChangeType::AddLearnerNode,
        node_id: LEARNER,
        ..Default::default()
    };
    driver.raw_node.propose_conf_change(vec![], add).unwrap();
    advance_until_membership(&mut driver, |m| m.learners == vec![LEARNER]).await;
    let emitted = write(&handle, &mut driver, "before", 3 * THRESHOLD).await;
    assert!(
        snapshots_to_learner(&emitted).is_empty(),
        "a learner that never answered is sent nothing but probes"
    );
    driver.set_progress_window(PROGRESS_WINDOW);

    // The learner answers a heartbeat: its next entry is compacted away, so
    // raft-rs sends it the stored snapshot.
    driver
        .raw_node
        .step(from_learner(&handle, MessageType::MsgHeartbeatResponse))
        .unwrap();
    let sent = snapshots_to_learner(&drive(&mut driver).await);
    assert_eq!(sent.len(), 1, "the compacted log forces one snapshot");
    let index = sent[0];
    assert_eq!(
        first_index(&driver),
        index + 1,
        "a silent peer held nothing back"
    );
    (handle, driver, dir, index)
}

fn first_index(driver: &ZoneConsensusDriver<FullStateMachine>) -> u64 {
    driver.raw_node.store().first_index_impl().unwrap()
}

fn stored_snapshot_index(driver: &ZoneConsensusDriver<FullStateMachine>) -> u64 {
    driver
        .raw_node
        .store()
        .snapshot(0, 0)
        .expect("stored snapshot")
        .get_metadata()
        .index
}

/// The learner reports its log through `index`: a snapshot installed there,
/// or entries appended up to it.
fn learner_reaches(
    handle: &ZoneConsensus<FullStateMachine>,
    driver: &mut ZoneConsensusDriver<FullStateMachine>,
    index: u64,
) {
    let mut response = from_learner(handle, MessageType::MsgAppendResponse);
    response.index = index;
    driver.raw_node.step(response).unwrap();
}

/// The learner answers heartbeats and acknowledges every append it is sent
/// until it holds the whole log; returns everything the leader emitted on
/// the way.
async fn learner_catches_up(
    handle: &ZoneConsensus<FullStateMachine>,
    driver: &mut ZoneConsensusDriver<FullStateMachine>,
) -> Vec<Message> {
    let mut emitted = drive(driver).await;
    for _ in 0..512 {
        let matched = progress_matched(&driver.raw_node, LEARNER);
        if matched == driver.raw_node.raft.raft_log.last_index() {
            break;
        }
        // Everything sent so far: seen here, or pipelined before.
        let pipelined = driver.raw_node.raft.prs().get(LEARNER).unwrap().next_idx - 1;
        let received = emitted
            .iter()
            .filter(|m| m.to == LEARNER && m.get_msg_type() == MessageType::MsgAppend)
            .filter_map(|m| m.get_entries().last().map(|entry| entry.index))
            .max()
            .map_or(pipelined, |seen| seen.max(pipelined));
        if received > matched {
            learner_reaches(handle, driver, received);
        } else {
            driver
                .raw_node
                .step(from_learner(handle, MessageType::MsgHeartbeatResponse))
                .unwrap();
        }
        let next = drive(driver).await;
        emitted.extend(next);
    }
    emitted
}

/// The previous index of the first append the leader sent the learner.
fn first_append(emitted: &[Message]) -> u64 {
    emitted
        .iter()
        .find(|m| m.to == LEARNER && m.get_msg_type() == MessageType::MsgAppend)
        .expect("an append follows")
        .index
}

/// Compactions while the snapshot is in flight keep every entry after it,
/// so the peer continues by appends once it installs: no second snapshot.
#[tokio::test]
async fn compaction_during_a_snapshot_keeps_the_log_the_peer_continues_from() {
    let (handle, mut driver, _dir, index) = leader_sending_a_snapshot().await;
    assert!(driver.awaits_snapshot(LEARNER, index));
    assert!(
        !driver.awaits_snapshot(LEARNER, index + 1),
        "another snapshot"
    );
    assert!(!driver.awaits_snapshot(7, index), "not a member");

    let emitted = write(&handle, &mut driver, "during", 4 * THRESHOLD).await;
    assert!(
        snapshots_to_learner(&emitted).is_empty(),
        "nothing more is generated for a peer awaiting its snapshot"
    );
    let applied = handle.applied_index();
    assert!(
        stored_snapshot_index(&driver) >= index + 3 * THRESHOLD,
        "the leader snapshotted and compacted again during the transfer"
    );
    assert_eq!(
        first_index(&driver),
        index + 1,
        "every entry after the in-flight snapshot is still in the log"
    );
    driver
        .raw_node
        .store()
        .term(index)
        .expect("the snapshot's own term stays answerable for the next append");

    learner_reaches(&handle, &mut driver, index);
    let emitted = learner_catches_up(&handle, &mut driver).await;
    assert!(
        !driver.awaits_snapshot(LEARNER, index),
        "the peer's own answer settled the snapshot"
    );
    assert!(
        snapshots_to_learner(&emitted).is_empty(),
        "the peer continues by appends: {emitted:?}"
    );
    assert_eq!(first_append(&emitted), index, "starting right after it");
    assert_eq!(progress_matched(&driver.raw_node, LEARNER), applied);
}

/// The snapshot was reported delivered and the peer has not yet answered
/// for it: its `Progress` is `Probe` with the `matched` it had before. A
/// compaction in that moment keeps the log, and the peer continues by
/// appends when its answer arrives.
#[tokio::test]
async fn compaction_right_after_a_delivered_snapshot_keeps_the_log() {
    let (handle, mut driver, _dir, index) = leader_sending_a_snapshot().await;
    driver.report_snapshot(LEARNER, raft::SnapshotStatus::Finish);
    assert!(!driver.awaits_snapshot(LEARNER, index));
    assert!(progress_matched(&driver.raw_node, LEARNER) < index);

    let emitted = write(&handle, &mut driver, "after", 3 * THRESHOLD).await;
    assert!(stored_snapshot_index(&driver) >= index + 2 * THRESHOLD);
    assert_eq!(
        first_index(&driver),
        index + 1,
        "the log the peer is about to continue from is still there"
    );
    assert!(snapshots_to_learner(&emitted).is_empty());

    learner_reaches(&handle, &mut driver, index);
    let emitted = learner_catches_up(&handle, &mut driver).await;
    assert!(
        snapshots_to_learner(&emitted).is_empty(),
        "no second snapshot: {emitted:?}"
    );
    assert_eq!(first_append(&emitted), index);
    assert_eq!(
        progress_matched(&driver.raw_node, LEARNER),
        handle.applied_index()
    );
}

/// A peer that installed its snapshot and is acknowledging appends keeps
/// the log from where it stands, many thresholds behind the leader.
#[tokio::test]
async fn a_peer_catching_up_by_appends_keeps_the_log_however_far_behind() {
    let (handle, mut driver, _dir, index) = leader_sending_a_snapshot().await;
    write(&handle, &mut driver, "during", 2 * THRESHOLD).await;
    learner_reaches(&handle, &mut driver, index);
    drive(&mut driver).await;
    // It has the snapshot and nothing after it; the leader moves on.
    let emitted = write(&handle, &mut driver, "meanwhile", 3 * THRESHOLD).await;
    assert_eq!(progress_matched(&driver.raw_node, LEARNER), index);
    assert!(handle.applied_index() - index >= 5 * THRESHOLD);
    assert!(stored_snapshot_index(&driver) >= index + 4 * THRESHOLD);
    assert_eq!(first_index(&driver), index + 1);
    assert!(snapshots_to_learner(&emitted).is_empty());

    let emitted = learner_catches_up(&handle, &mut driver).await;
    assert!(
        snapshots_to_learner(&emitted).is_empty(),
        "it catches up by appends: {emitted:?}"
    );
    assert_eq!(
        progress_matched(&driver.raw_node, LEARNER),
        handle.applied_index()
    );
    // Caught up, it holds back one threshold behind what it acknowledged.
    write(&handle, &mut driver, "after", 2 * THRESHOLD).await;
    learner_catches_up(&handle, &mut driver).await;
    let acknowledged = progress_matched(&driver.raw_node, LEARNER);
    write(&handle, &mut driver, "later", 2 * THRESHOLD).await;
    assert_eq!(progress_matched(&driver.raw_node, LEARNER), acknowledged);
    assert_eq!(first_index(&driver), acknowledged + 1 - THRESHOLD);
}

/// raft-rs, probing, takes a rejection for the entry before the one it is
/// about to send at its word and sends again from the rejection's hint —
/// also when the rejection predates acknowledgements that have since moved
/// `matched` past it, as happens when a burst of appends arrives out of
/// order. The entries before `matched` are still in the log, so that is a
/// re-send the peer acknowledges, not a snapshot.
#[tokio::test]
async fn a_late_rejection_costs_a_resend_not_a_snapshot() {
    let (handle, mut driver, _dir, index) = leader_sending_a_snapshot().await;
    learner_reaches(&handle, &mut driver, index);
    learner_catches_up(&handle, &mut driver).await;
    write(&handle, &mut driver, "acknowledged", 2 * THRESHOLD).await;
    learner_catches_up(&handle, &mut driver).await;
    let acknowledged = progress_matched(&driver.raw_node, LEARNER);
    assert_eq!(acknowledged, handle.applied_index());
    let hint = acknowledged - THRESHOLD / 2;
    let hint_term = driver.raw_node.store().term(hint).expect("learner's term");

    // The leader moves on and compacts; the peer is found unreachable and
    // probed from what it acknowledged.
    write(&handle, &mut driver, "meanwhile", 2 * THRESHOLD).await;
    assert!(
        stored_snapshot_index(&driver) > acknowledged,
        "compacted since"
    );
    driver.report_unreachable(LEARNER);
    driver
        .raw_node
        .step(from_learner(&handle, MessageType::MsgHeartbeatResponse))
        .unwrap();
    let probe = drive(&mut driver).await;
    assert_eq!(first_append(&probe), acknowledged, "probing from `matched`");

    // A rejection from before those acknowledgements arrives: the peer, it
    // says, has nothing after an index it has long since passed.
    let mut late = from_learner(&handle, MessageType::MsgAppendResponse);
    late.reject = true;
    late.index = acknowledged;
    late.reject_hint = hint;
    late.log_term = hint_term;
    driver.raw_node.step(late).unwrap();
    let mut emitted = drive(&mut driver).await;
    assert!(
        snapshots_to_learner(&emitted).is_empty(),
        "the entries after the hint are in the log: {emitted:?}"
    );
    assert_eq!(first_append(&emitted), hint, "sent again from the hint");

    emitted.extend(learner_catches_up(&handle, &mut driver).await);
    assert!(snapshots_to_learner(&emitted).is_empty());
    assert_eq!(
        progress_matched(&driver.raw_node, LEARNER),
        handle.applied_index()
    );
}

/// A peer whose snapshot failed is probing again and keeps the log while
/// it may still answer; silent for the whole progress window, it is given
/// up and compaction proceeds past it.
#[tokio::test]
async fn a_peer_silent_past_the_window_is_released() {
    let (handle, mut driver, _dir, index) = leader_sending_a_snapshot().await;
    driver.report_snapshot(LEARNER, raft::SnapshotStatus::Failure);
    assert!(!driver.awaits_snapshot(LEARNER, index));
    write(&handle, &mut driver, "within", 2 * THRESHOLD).await;
    assert_eq!(first_index(&driver), index + 1, "within the window");

    let window = Duration::from_millis(40);
    driver.set_progress_window(window);
    tokio::time::sleep(2 * window).await;
    write(&handle, &mut driver, "past", 2 * THRESHOLD).await;
    assert_eq!(
        first_index(&driver),
        stored_snapshot_index(&driver) + 1,
        "the whole applied log is compacted once the peer is given up"
    );
    assert!(first_index(&driver) > index + 3 * THRESHOLD);
}

/// However its peers stand, a leader keeps at most the retained-log bound
/// behind its applied index: a snapshot that takes longer than that many
/// entries to cross is followed by another.
#[tokio::test]
async fn the_retained_log_is_bounded_whatever_a_peer_needs() {
    let (handle, mut driver, _dir, index) = leader_sending_a_snapshot().await;
    let bound = RETAINED_LOG_THRESHOLDS * THRESHOLD;
    write(&handle, &mut driver, "within", bound - THRESHOLD).await;
    assert_eq!(first_index(&driver), index + 1, "within the bound");

    write(&handle, &mut driver, "beyond", 3 * THRESHOLD).await;
    assert!(driver.awaits_snapshot(LEARNER, index), "still in flight");
    let stored = stored_snapshot_index(&driver);
    assert_eq!(
        stored + 1 - first_index(&driver),
        bound,
        "exactly the bound is kept behind the last compaction (snapshot {stored})"
    );
    assert!(first_index(&driver) > index + 1);
}

/// A follower awaits nothing: only the leader's `Progress` is in force.
#[tokio::test]
async fn a_node_that_stopped_leading_awaits_no_snapshot() {
    let (handle, mut driver, _dir, index) = leader_sending_a_snapshot().await;
    let mut newer_leader = from_learner(&handle, MessageType::MsgHeartbeat);
    newer_leader.from = 9;
    newer_leader.term = handle.term() + 1;
    driver.raw_node.step(newer_leader).unwrap();
    drive(&mut driver).await;
    assert!(!handle.is_leader());
    assert!(!driver.awaits_snapshot(LEARNER, index));
}
