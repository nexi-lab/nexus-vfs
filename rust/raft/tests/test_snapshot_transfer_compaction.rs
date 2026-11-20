//! A leader that keeps writing — and compacting — while a snapshot crosses a
//! slow link does not strand the peer receiving it.
//!
//! A snapshot of a few megabytes takes seconds to minutes on a slow link.
//! The leader's log moves on meanwhile, and every `threshold` entries it
//! snapshots and compacts again. A compaction through the applied index
//! would put the entries after the in-flight snapshot below `first_index`:
//! the peer would install it, ask for the next entry, and be owed another
//! snapshot — for as long as the zone is written faster than a snapshot
//! crosses. While a peer's `Progress` is `Snapshot`, the leader keeps its log
//! from the entry after that snapshot, and once the peer installs it and
//! acknowledges appends, from wherever the peer stands — so the peer
//! continues by appends, however many entries behind the snapshot left it.
//!
//! Topology: a founder (sole voter, leader) and a learner that joins after
//! the log was compacted, so it needs a snapshot. The learner advertises a
//! [`ThrottledLink`] — a rate-capped TCP forwarder — in front of a
//! [`LossyLink`] that passes everything and counts the snapshot transfers
//! completed through it. Everything the leader sends the learner, heartbeats
//! included, crosses both.

#![cfg(all(feature = "grpc", has_protos))]

mod common;
#[path = "common/lossy_link.rs"]
mod lossy_link;
#[path = "common/throttled_link.rs"]
mod throttled_link;
#[path = "common/zone_cluster.rs"]
mod zone_cluster;

use std::sync::atomic::Ordering;
use std::time::Duration;

use lossy_link::LossyLink;
use nexus_raft::prelude::Command;
use nexus_raft::raft::{PeerReplication, RaftStorage, ReplicationState};
use nexus_raft::ZoneManager;
use throttled_link::ThrottledLink;
use zone_cluster::{
    consensus, eventually, first_retained_index, found, has_key, join_as_learner, stop, write, Node,
};

const SNAPSHOT_THRESHOLD: u64 = 16;
/// The value of each entry written during the transfer: 768 KiB of backlog
/// in all, about three seconds on the link.
const BACKLOG_VALUE_BYTES: usize = 16 * 1024;
/// Bytes per second toward the learner.
const RATE: u64 = 256 * 1024;
/// The zone's state before the learner joins: 3 MiB, about twelve seconds on
/// the link.
const VALUES: u64 = 48;
const VALUE_BYTES: usize = 64 * 1024;

fn learner_progress(leader: &ZoneManager, learner_id: u64) -> Option<PeerReplication> {
    consensus(leader)
        .replication()
        .peers
        .into_iter()
        .find(|peer| peer.node_id == learner_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compaction_during_a_snapshot_transfer_does_not_strand_the_peer() {
    // This binary's own process: no other test reads the variable.
    std::env::set_var(
        "NEXUS_SC_SNAPSHOT_THRESHOLD",
        SNAPSHOT_THRESHOLD.to_string(),
    );

    let leader_node = Node::new();
    let leader = found(&leader_node, vec![]).await;
    for i in 0..VALUES {
        consensus(&leader)
            .propose(Command::SetMetadata {
                key: format!("/state/{i}"),
                value: vec![i as u8; VALUE_BYTES],
            })
            .await
            .expect("write state");
    }

    let learner_node = Node::new();
    let counting_addr = common::node_bind_socket_addr();
    let counting = LossyLink::start(counting_addr, &learner_node.bind).await;
    let link = ThrottledLink::start(&counting_addr.to_string(), RATE).await;
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

    eventually("the leader sends the learner a snapshot", || async {
        learner_progress(&leader, learner_node.id)
            .is_some_and(|peer| peer.state == ReplicationState::Snapshot)
    })
    .await;

    // The leader writes three thresholds of entries while the snapshot is in
    // flight, compacting as it goes: a backlog that takes the link seconds.
    for i in 0..(3 * SNAPSHOT_THRESHOLD) {
        consensus(&leader)
            .propose(Command::SetMetadata {
                key: format!("/during/{i}"),
                value: vec![i as u8; BACKLOG_VALUE_BYTES],
            })
            .await
            .expect("write during the transfer");
    }
    let in_flight = learner_progress(&leader, learner_node.id).expect("learner progress");
    assert_eq!(
        in_flight.state,
        ReplicationState::Snapshot,
        "the transfer outlasted the writes"
    );
    assert_eq!(counting.snapshots_forwarded.load(Ordering::SeqCst), 0);
    // Heartbeats share the link with the transfer and are not held up by it.
    let contact = consensus(&learner).leader_contact_age();
    assert!(
        contact.is_some_and(|age| age < Duration::from_secs(3)),
        "the learner last heard its leader {contact:?} ago, mid-transfer"
    );

    // The snapshot lands. The learner is three thresholds behind it and
    // catching up by appends while the leader writes and compacts on.
    eventually("the learner installs the snapshot", || async {
        counting.snapshots_forwarded.load(Ordering::SeqCst) == 1
    })
    .await;
    for i in 0..(2 * SNAPSHOT_THRESHOLD) {
        write(&leader, &format!("/after/{i}")).await;
    }
    let newest = format!("/after/{}", 2 * SNAPSHOT_THRESHOLD - 1);
    let catching_up = learner_progress(&leader, learner_node.id).expect("learner progress");
    let behind = consensus(&leader).commit_index() - catching_up.matched;
    assert!(
        behind > SNAPSHOT_THRESHOLD,
        "the leader compacted again with the learner {behind} entries behind"
    );

    eventually("the learner catches up", || async {
        consensus(&learner).applied_index() >= consensus(&leader).commit_index()
    })
    .await;
    assert!(
        has_key(&learner, &newest).await,
        "{newest} reached the learner"
    );
    assert!(has_key(&learner, "/state/0").await);
    assert_eq!(
        counting.snapshots_forwarded.load(Ordering::SeqCst),
        1,
        "one snapshot, then appends: the entries written during the transfer were still in \
         the leader's log"
    );
    eventually("the leader sees the learner replicating", || async {
        learner_progress(&leader, learner_node.id).is_some_and(|peer| {
            peer.state == ReplicationState::Replicate
                && peer.matched == consensus(&leader).commit_index()
        })
    })
    .await;

    let transferred = counting.last_snapshot_index.load(Ordering::SeqCst);
    stop(learner).await;
    stop(leader).await;

    // The leader did snapshot and compact while the snapshot crossed and
    // while the learner caught up, and never past what the learner needed.
    let storage = RaftStorage::open(leader_node.raft_dir()).expect("reopen leader log");
    let stored = raft::Storage::snapshot(&storage, 0, 0)
        .expect("stored snapshot")
        .get_metadata()
        .index;
    drop(storage);
    assert!(
        stored >= transferred + 4 * SNAPSHOT_THRESHOLD,
        "the leader's snapshot moved from {transferred} to {stored} meanwhile"
    );
    assert!(first_retained_index(&leader_node.raft_dir()) > transferred);
}
