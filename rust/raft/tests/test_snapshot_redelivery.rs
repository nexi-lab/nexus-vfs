//! A learner that misses the snapshot it needs converges without a restart.
//!
//! The leader compacts its log past a learner that is a few entries behind,
//! so the only way to catch the learner up is a snapshot — and that snapshot
//! is lost after the transport reported it delivered (the receiver accepted
//! the RPC and never installed it). raft-rs holds the learner's `Progress` in
//! `Snapshot`, where nothing but heartbeats is sent, until the application
//! reports the snapshot's outcome; without a `Finish` report the learner
//! waits forever. Heartbeats keep flowing and carry
//! `min(leader commit, matched)`, so the learner's own view looks healthy.
//!
//! Topology: a founder (sole voter, leader) and a learner whose advertised
//! address is a [`LossyLink`] in front of its real server, so every message
//! the leader sends the learner crosses the link; the learner reaches the
//! leader directly. The link starves the learner of entries and snapshots
//! while passing heartbeats, then swallows the next snapshot.
//!
//! What the test holds the system to:
//!   1. while starved, the lag is visible on both sides (leader per-peer
//!      progress; learner commit probe), a write submitted through the
//!      learner reports that it committed but is not visible there, and a
//!      read there reports the lag instead of answering stale;
//!   2. after the link heals but swallows the first snapshot, the learner
//!      converges within a bounded time with no restart, which requires the
//!      leader to send a SECOND snapshot;
//!   3. afterwards the learner's own write is visible to its reads and the
//!      leader sees the learner replicating again.

#![cfg(all(feature = "grpc", has_protos))]

mod common;
#[path = "common/lossy_link.rs"]
mod lossy_link;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use lossy_link::{LossyLink, STARVE, SWALLOW_NEXT_SNAPSHOT};
use nexus_raft::prelude::{Command, FullStateMachine, RaftError, ZoneConsensus};
use nexus_raft::raft::ReplicationState;
use nexus_raft::transport::call_join_zone_rpc;
use nexus_raft::ZoneManager;
use tempfile::TempDir;

const ZONE: &str = "sharedzone";
const SNAPSHOT_THRESHOLD: u64 = 16;
const BUDGET: Duration = Duration::from_secs(30);

fn node_dir() -> (TempDir, u64) {
    let dir = TempDir::new().expect("node dir");
    let id = loop {
        let id = rand::random::<u64>();
        if id != 0 {
            break id;
        }
    };
    std::fs::write(dir.path().join(".node_id"), id.to_be_bytes()).expect("write .node_id");
    (dir, id)
}

async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + BUDGET;
    while !done() {
        assert!(Instant::now() < deadline, "{what} within {BUDGET:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn write(node: &ZoneConsensus<FullStateMachine>, key: &str) {
    node.propose(Command::SetMetadata {
        key: key.to_string(),
        value: key.as_bytes().to_vec(),
    })
    .await
    .unwrap_or_else(|error| panic!("write {key}: {error}"));
}

async fn has(node: &ZoneConsensus<FullStateMachine>, key: &str) -> bool {
    let key = key.to_string();
    node.with_state_machine(move |sm| sm.get_metadata(&key))
        .await
        .ok()
        .flatten()
        .is_some()
}

fn learner_progress(
    leader: &ZoneConsensus<FullStateMachine>,
    learner_id: u64,
) -> Option<nexus_raft::raft::PeerReplication> {
    leader
        .replication()
        .peers
        .into_iter()
        .find(|peer| peer.node_id == learner_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_learner_that_misses_its_catch_up_snapshot_converges_without_restart() {
    // This binary's own process: no other test reads the variable.
    std::env::set_var(
        "NEXUS_SC_SNAPSHOT_THRESHOLD",
        SNAPSHOT_THRESHOLD.to_string(),
    );

    let (leader_dir, leader_id) = node_dir();
    let leader_bind = common::node_bind_addr();
    let leader_zm = ZoneManager::with_node_id(
        "leader",
        leader_id,
        leader_dir.path().to_str().unwrap(),
        vec![],
        &leader_bind,
        None,
        Some(leader_bind.clone()),
        None,
    )
    .expect("leader");
    let leader = leader_zm
        .create_zone(ZONE)
        .expect("create zone")
        .consensus_node();
    eventually("the founder elects itself", || leader.is_leader()).await;

    let (learner_dir, learner_id) = node_dir();
    let learner_bind = common::node_bind_addr();
    let link_addr = common::node_bind_socket_addr();
    let link = LossyLink::start(link_addr, &learner_bind).await;
    let learner_zm = ZoneManager::with_node_id(
        "learner",
        learner_id,
        learner_dir.path().to_str().unwrap(),
        vec![],
        &learner_bind,
        None,
        Some(link_addr.to_string()),
        None,
    )
    .expect("learner");
    let learner = learner_zm
        .join_zone(ZONE, true)
        .expect("learner join_zone")
        .consensus_node();
    let joined = call_join_zone_rpc(
        &format!("http://{leader_bind}"),
        ZONE,
        learner_id,
        &format!("http://{link_addr}"),
        true,
        None,
        30,
    )
    .await
    .expect("JoinZone RPC");
    assert!(joined.success, "JoinZone: {:?}", joined.error);

    for i in 0..4 {
        write(&leader, &format!("/before/{i}")).await;
    }
    eventually("the learner replicates through the link", || {
        learner.applied_index() >= leader.applied_index()
    })
    .await;

    // ── Starved: heartbeats only, while the leader compacts past it. ──
    link.set(STARVE);
    let behind = learner.applied_index();
    for i in 0..(4 * SNAPSHOT_THRESHOLD) {
        write(&leader, &format!("/during/{i}")).await;
    }
    let newest = format!("/during/{}", 4 * SNAPSHOT_THRESHOLD - 1);
    eventually("the leader catches the learner up only by snapshot", || {
        link.snapshots_refused.load(Ordering::SeqCst) > 0
    })
    .await;

    eventually(
        "the leader sees the learner stalled behind its commit",
        || {
            learner_progress(&leader, learner_id).is_some_and(|peer| {
                peer.matched < leader.commit_index()
                    && peer.state != ReplicationState::Replicate
                    && peer.stalled_for >= Duration::from_secs(1)
            })
        },
    )
    .await;
    eventually("the learner learns the leader's real commit index", || {
        let status = learner.replication();
        status
            .leader_commit
            .is_some_and(|commit| commit.index > learner.applied_index())
            && status.stalled_for >= Duration::from_secs(1)
    })
    .await;
    assert_eq!(
        learner.commit_index(),
        learner.applied_index(),
        "heartbeats cannot tell the learner it lags: commit = applied, as in production"
    );
    assert_eq!(learner.applied_index(), behind);

    let via_learner = "/written/through/the/learner";
    let committed = match learner
        .propose(Command::SetMetadata {
            key: via_learner.into(),
            value: b"v".to_vec(),
        })
        .await
    {
        Err(RaftError::CommittedNotVisible { index, applied, .. }) => {
            let index = index.expect("a current leader reports the index it applied at");
            assert!(applied < index, "lag reported: applied {applied} < {index}");
            index
        }
        other => panic!("a write the learner cannot see must say so, got {other:?}"),
    };
    assert!(
        has(&leader, via_learner).await,
        "the write committed on the leader"
    );
    match learner.own_writes_visible().await {
        Err(RaftError::ReplicaBehind { required, applied }) => {
            assert!(required >= committed, "the floor covers the write");
            assert!(applied < committed);
        }
        other => panic!("a read after the learner's own write must report the lag, got {other:?}"),
    }

    // A caller already waiting for the write is released by the catch-up,
    // whichever of snapshot install or entry apply brings it.
    let parked = tokio::spawn({
        let learner = learner.clone();
        async move {
            learner
                .await_applied(committed, tokio::time::Instant::now() + BUDGET)
                .await
        }
    });

    // ── Healed, but the first snapshot after healing is lost. ──
    link.set(SWALLOW_NEXT_SNAPSHOT);
    eventually("the learner converges without a restart", || {
        learner.applied_index() >= leader.commit_index()
    })
    .await;
    assert_eq!(link.snapshots_swallowed.load(Ordering::SeqCst), 1);
    assert!(
        link.snapshots_forwarded.load(Ordering::SeqCst) >= 1,
        "converging required the leader to send another snapshot"
    );
    assert!(has(&learner, &newest).await, "{newest} reached the learner");
    tokio::time::timeout(Duration::from_secs(1), parked)
        .await
        .expect("the parked wait is released by the catch-up")
        .expect("wait task")
        .expect("applied through the learner's write");

    learner
        .own_writes_visible()
        .await
        .expect("the learner's own write is visible to its reads now");
    assert!(has(&learner, via_learner).await);
    write(&leader, "/after").await;
    eventually("the leader sees the learner replicating again", || {
        learner_progress(&leader, learner_id).is_some_and(|peer| {
            peer.state == ReplicationState::Replicate
                && peer.matched == leader.commit_index()
                && peer.stalled_for == Duration::ZERO
        })
    })
    .await;
    eventually("the learner's lag closes", || {
        learner.replication().stalled_for == Duration::ZERO
            && learner
                .replication()
                .leader_commit
                .is_some_and(|commit| commit.index <= learner.applied_index())
    })
    .await;

    learner_zm.shutdown();
    leader_zm.shutdown();
}
