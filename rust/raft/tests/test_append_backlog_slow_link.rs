//! A replica behind a backlog of entries catches up over a link too slow to
//! carry a megabyte inside one call's deadline.
//!
//! An append is one call under one deadline, like a snapshot slice, and a
//! backlog is whatever accumulated while the replica was away. Sent as few
//! large appends it outlasts each deadline on a slow link and is re-sent
//! from its first entry forever; the replica's `matched` never moves. The
//! leader therefore batches at most `CALL_PAYLOAD_BYTES` of entries per
//! append, the size of a snapshot slice, and the backlog crosses call by
//! call.
//!
//! Appends that cross together share the link, and each has its own
//! deadline. A leader that pipelines a backlog larger than the link carries
//! in one deadline has every call time out; so once an append fails to
//! reach a peer, the peer is fed one append at a time, each as soon as the
//! one before it is delivered, and the backlog crosses at the link's rate.
//!
//! Topology: a founder (sole voter, leader) and a learner that joined by
//! snapshot, behind a [`ThrottledLink`] in front of a [`LossyLink`] that
//! passes everything and records the largest raft message and the snapshot
//! transfers it forwards. One test takes the link down while the leader
//! writes the backlog and brings it back slow; the other keeps a slow link
//! up while the leader writes far more than it carries in one deadline.

#![cfg(all(feature = "grpc", has_protos))]

mod common;
#[path = "common/lossy_link.rs"]
mod lossy_link;
#[path = "common/throttled_link.rs"]
mod throttled_link;
#[path = "common/zone_cluster.rs"]
mod zone_cluster;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use lossy_link::LossyLink;
use nexus_raft::prelude::Command;
use nexus_raft::raft::message_bound::CALL_PAYLOAD_BYTES;
use nexus_raft::raft::ReplicationState;
use nexus_raft::ZoneManager;
use throttled_link::ThrottledLink;
use zone_cluster::{consensus, eventually, found, has_key, join_as_learner, stop, write, Node};

/// Both tests' backlogs stay inside what the leader retains for a peer, and
/// inside the one threshold it keeps behind what the peer acknowledged.
const SNAPSHOT_THRESHOLD: u64 = 128;
/// Bytes per second toward the learner once the link is back.
const RATE: u64 = 24 * 1024;
/// The backlog: 300 KiB of entries, well inside what the leader retains.
const BACKLOG_ENTRIES: u64 = 75;
const ENTRY_VALUE_BYTES: usize = 4 * 1024;

// One megabyte in one call is allowed 30 s plus 8 s at the transport's floor
// rate; this link needs longer for it.
const _: () = assert!(1024 * 1024 / RATE > 30 + 8);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backlog_crosses_a_slow_link_as_small_appends() {
    // This binary's own process: no other test reads the variable.
    std::env::set_var(
        "NEXUS_SC_SNAPSHOT_THRESHOLD",
        SNAPSHOT_THRESHOLD.to_string(),
    );

    let leader_node = Node::new();
    let leader = found(&leader_node, vec![]).await;
    for i in 0..(SNAPSHOT_THRESHOLD + 8) {
        write(&leader, &format!("/before/{i}")).await;
    }

    let learner_node = Node::new();
    let counting_addr = common::node_bind_socket_addr();
    let counting = LossyLink::start(counting_addr, &learner_node.bind).await;
    let link = ThrottledLink::start(&counting_addr.to_string(), 0).await;
    let learner = ZoneManager::with_node_id(
        "learner",
        learner_node.id,
        learner_node.dir.path().to_str().unwrap(),
        vec![],
        &learner_node.bind,
        None,
        Some(link.address().to_string()),
        None,
    )
    .expect("learner");
    join_as_learner(&learner, &learner_node, &leader_node, &link.endpoint()).await;
    eventually("the learner installs the snapshot it joined by", || async {
        counting.snapshots_forwarded.load(Ordering::SeqCst) == 1
            && consensus(&learner).applied_index() >= consensus(&leader).commit_index()
    })
    .await;

    // The learner is away while the backlog is written.
    link.set_down(true);
    for i in 0..BACKLOG_ENTRIES {
        consensus(&leader)
            .propose(Command::SetMetadata {
                key: format!("/backlog/{i}"),
                value: vec![i as u8; ENTRY_VALUE_BYTES],
            })
            .await
            .expect("write backlog");
    }
    let newest = format!("/backlog/{}", BACKLOG_ENTRIES - 1);
    assert!(!has_key(&learner, &newest).await);
    let before = counting.largest_forwarded.swap(0, Ordering::SeqCst);
    assert!(before < CALL_PAYLOAD_BYTES, "only small messages so far");

    link.set_rate(RATE);
    link.set_down(false);
    let deadline = Instant::now() + Duration::from_secs(120);
    while consensus(&learner).applied_index() < consensus(&leader).commit_index() {
        assert!(
            Instant::now() < deadline,
            "the learner catches up over the slow link (applied {}, leader commit {})",
            consensus(&learner).applied_index(),
            consensus(&leader).commit_index()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        has_key(&learner, &newest).await,
        "{newest} reached the learner"
    );
    assert_eq!(
        counting.snapshots_forwarded.load(Ordering::SeqCst),
        1,
        "the backlog arrived by appends, with no further snapshot"
    );
    let largest = counting.largest_forwarded.load(Ordering::SeqCst);
    assert!(
        largest > CALL_PAYLOAD_BYTES / 2,
        "entries were batched (largest append {largest} bytes)"
    );
    assert!(
        largest <= CALL_PAYLOAD_BYTES + ENTRY_VALUE_BYTES,
        "no append carried more than one call's payload (largest {largest} bytes)"
    );

    stop(learner).await;
    stop(leader).await;
}

/// Bytes per second toward the learner while the pipelined backlog crosses.
const PIPELINED_RATE: u64 = 64 * 1024;
/// The deadline of a call carrying `CALL_PAYLOAD_BYTES`: 30 s plus one
/// second at the transport's floor rate.
const CALL_DEADLINE: Duration = Duration::from_secs(31);
/// What the link carries inside one call deadline, in appends.
const APPENDS_PER_DEADLINE: u64 =
    PIPELINED_RATE * CALL_DEADLINE.as_secs() / CALL_PAYLOAD_BYTES as u64;
/// The pipelined backlog: 6 MiB, three times what the link carries inside
/// one call deadline, as 96 appends of one entry each.
const PIPELINED_ENTRIES: u64 = 96;
const PIPELINED_VALUE_BYTES: usize = 64 * 1024;
const PIPELINED_BYTES: u64 = PIPELINED_ENTRIES * PIPELINED_VALUE_BYTES as u64;
const PIPELINED_APPENDS: u64 = PIPELINED_BYTES / CALL_PAYLOAD_BYTES as u64;
/// The link's own time for the backlog.
const CROSSING: Duration = Duration::from_secs(PIPELINED_BYTES / PIPELINED_RATE);
/// The longest the catch-up may take once the backlog is written: the burst
/// the leader pipelined runs into its deadlines, then the backlog crosses
/// one append behind another, allowed one and a half times the link's own
/// time for it, since the heartbeats share the link.
const CATCH_UP_BOUND: Duration = Duration::from_secs(31 + 96 + 48);

// Were the leader to pipeline again after every acknowledged append, each
// burst larger than the link carries inside one deadline would time out
// whole, and only the append that was acknowledged before it would count:
// one append per deadline until the remainder fits. That is far outside the
// bound, so meeting the bound shows the backlog crossed at the link's rate.
const _: () = assert!(PIPELINED_APPENDS >= 3 * APPENDS_PER_DEADLINE);

// A pipelined burst arrives out of order, and a rejection from it can reach
// the leader after the acknowledgements that followed it; raft-rs then sends
// again from the rejection's hint. The hint is the learner's last entry at
// that moment, so it is at most the whole burst behind what the learner has
// acknowledged, and the leader keeps one threshold of entries behind that:
// with the burst shorter than the threshold, the entries are always in the
// log and the learner is never owed a second snapshot.
const _: () = assert!(PIPELINED_ENTRIES < SNAPSHOT_THRESHOLD);
const _: () =
    assert!(2 * CATCH_UP_BOUND.as_secs() == 2 * CALL_DEADLINE.as_secs() + 3 * CROSSING.as_secs());
const _: () = assert!(
    (PIPELINED_APPENDS - APPENDS_PER_DEADLINE) * CALL_DEADLINE.as_secs()
        > 10 * CATCH_UP_BOUND.as_secs()
);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pipelined_backlog_crosses_a_slow_link_one_append_at_a_time() {
    // This binary's own process: no other test reads the variable.
    std::env::set_var(
        "NEXUS_SC_SNAPSHOT_THRESHOLD",
        SNAPSHOT_THRESHOLD.to_string(),
    );

    let leader_node = Node::new();
    let leader = found(&leader_node, vec![]).await;
    for i in 0..(SNAPSHOT_THRESHOLD + 8) {
        write(&leader, &format!("/before/{i}")).await;
    }

    let learner_node = Node::new();
    let counting_addr = common::node_bind_socket_addr();
    let counting = LossyLink::start(counting_addr, &learner_node.bind).await;
    let link = ThrottledLink::start(&counting_addr.to_string(), 0).await;
    let learner = ZoneManager::with_node_id(
        "learner",
        learner_node.id,
        learner_node.dir.path().to_str().unwrap(),
        vec![],
        &learner_node.bind,
        None,
        Some(link.address().to_string()),
        None,
    )
    .expect("learner");
    join_as_learner(&learner, &learner_node, &leader_node, &link.endpoint()).await;
    let learner_progress = || {
        consensus(&leader)
            .replication()
            .peers
            .into_iter()
            .find(|peer| peer.node_id == learner_node.id)
            .expect("learner progress")
    };
    eventually("the learner installs the snapshot it joined by", || async {
        counting.snapshots_forwarded.load(Ordering::SeqCst) == 1
            && consensus(&learner).applied_index() >= consensus(&leader).commit_index()
    })
    .await;
    // An acknowledged append moves the learner from probing to `Replicate`.
    write(&leader, "/joined").await;
    eventually("the learner replicates, pipelined", || async {
        consensus(&learner).applied_index() >= consensus(&leader).commit_index()
            && learner_progress().state == ReplicationState::Replicate
    })
    .await;

    // The link turns slow and stays up; the leader writes the backlog and
    // pipelines it to the learner as it is written.
    link.set_rate(PIPELINED_RATE);
    counting.largest_forwarded.store(0, Ordering::SeqCst);
    for i in 0..PIPELINED_ENTRIES {
        consensus(&leader)
            .propose(Command::SetMetadata {
                key: format!("/pipelined/{i}"),
                value: vec![i as u8; PIPELINED_VALUE_BYTES],
            })
            .await
            .expect("write backlog");
    }
    let written = Instant::now();
    let newest = format!("/pipelined/{}", PIPELINED_ENTRIES - 1);

    // Every call of the pipelined burst has ended one deadline after the
    // last write, and every heartbeat that queued behind the burst on the
    // link one deadline after that; from then on no call to the learner may
    // run into its deadline.
    let burst_over = written + 2 * CALL_DEADLINE + Duration::from_secs(15);
    while consensus(&learner).applied_index() < consensus(&leader).commit_index() {
        assert!(
            written.elapsed() < CATCH_UP_BOUND,
            "the learner catches up within {CATCH_UP_BOUND:?} of the backlog being written \
             (applied {}, leader commit {})",
            consensus(&learner).applied_index(),
            consensus(&leader).commit_index()
        );
        if Instant::now() > burst_over {
            let failing = learner_progress().last_send_error;
            assert!(
                !failing
                    .as_deref()
                    .is_some_and(|error| error.contains("no answer within")),
                "a call ran into its deadline {:?} after the backlog was written: {failing:?}",
                written.elapsed()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        has_key(&learner, &newest).await,
        "{newest} reached the learner"
    );
    assert_eq!(
        counting.snapshots_forwarded.load(Ordering::SeqCst),
        1,
        "the backlog arrived by appends, with no further snapshot"
    );
    let largest = counting.largest_forwarded.load(Ordering::SeqCst);
    assert!(
        largest <= CALL_PAYLOAD_BYTES + PIPELINED_VALUE_BYTES,
        "no append carried more than one call's payload (largest {largest} bytes)"
    );

    stop(learner).await;
    stop(leader).await;
}
