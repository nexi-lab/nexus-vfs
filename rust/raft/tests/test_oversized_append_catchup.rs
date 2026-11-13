//! A learner behind a backlog of appends larger than tonic's 4 MiB default
//! catches up without a restart, and an entry beyond the raft entry bound is
//! refused before it enters the log.
//!
//! The production stall: a learner fell behind, and the leader's appends to
//! it reached 5.46 MB while the learner's raft transport still decoded at
//! tonic's 4 MiB default — no endpoint applied the bound its configuration
//! named. The learner refused every append, raft-rs regenerated the same one
//! on every heartbeat response, and the learner never advanced: 16,681
//! failed sends in 19 minutes, no snapshot involved.
//!
//! Here the learner is starved behind a [`LossyLink`] while the leader writes
//! entries of 6 MiB and one exactly at `MAX_ENTRY_BYTES`; once healed, it must
//! catch up through appends far above 4 MiB, with no restart.

#![cfg(all(feature = "grpc", has_protos))]

mod common;
#[path = "common/lossy_link.rs"]
mod lossy_link;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use lossy_link::{LossyLink, PASS, STARVE};
use nexus_raft::prelude::{Command, FullStateMachine, RaftError, ZoneConsensus};
use nexus_raft::raft::message_bound::MAX_ENTRY_BYTES;
use nexus_raft::raft::ReplicationState;
use nexus_raft::transport::call_join_zone_rpc;
use nexus_raft::ZoneManager;
use tempfile::TempDir;

const ZONE: &str = "sharedzone";
const BUDGET: Duration = Duration::from_secs(90);
const TONIC_DEFAULT_LIMIT: usize = 4 * 1024 * 1024;

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

fn set(key: &str, value_len: usize) -> Command {
    Command::SetMetadata {
        key: key.to_string(),
        value: vec![0x5a; value_len],
    }
}

/// A command whose log entry (8-byte proposal id + bincode) is `entry_bytes`.
fn entry_of(key: &str, entry_bytes: usize) -> Command {
    let overhead = 8 + bincode::serialized_size(&set(key, 0)).unwrap() as usize;
    let command = set(key, entry_bytes - overhead);
    assert_eq!(
        8 + bincode::serialized_size(&command).unwrap() as usize,
        entry_bytes
    );
    command
}

async fn value_len(node: &ZoneConsensus<FullStateMachine>, key: &str) -> Option<usize> {
    let key = key.to_string();
    node.with_state_machine(move |sm| sm.get_metadata(&key))
        .await
        .ok()
        .flatten()
        .map(|value| value.len())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_learner_behind_appends_beyond_four_mib_catches_up_and_an_over_bound_entry_is_refused() {
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
    leader.propose(set("/before", 16)).await.expect("write");
    eventually("the learner replicates through the link", || {
        learner.applied_index() >= leader.applied_index()
    })
    .await;

    // ── The learner falls behind a backlog of large entries. ──
    link.set(STARVE);
    for i in 0..3 {
        leader
            .propose(set(&format!("/big/{i}"), 6 * 1024 * 1024))
            .await
            .expect("6 MiB entry");
    }
    leader
        .propose(entry_of("/at-the-bound", MAX_ENTRY_BYTES))
        .await
        .expect("an entry exactly at the bound is admitted");

    // One byte more can never be replicated: refused before the log, on the
    // leader and on the learner (which must not forward it).
    let over = entry_of("/over-the-bound", MAX_ENTRY_BYTES + 1);
    for node in [&leader, &learner] {
        match node.propose(over.clone()).await {
            Err(RaftError::EntryTooLarge { bytes, limit }) => {
                assert_eq!((bytes, limit), (MAX_ENTRY_BYTES + 1, MAX_ENTRY_BYTES));
            }
            other => panic!("an over-bound entry must be refused, got {other:?}"),
        }
    }
    assert_eq!(value_len(&leader, "/over-the-bound").await, None);

    // ── Healed: the catch-up carries appends far above tonic's default. ──
    link.set(PASS);
    eventually("the learner catches up without a restart", || {
        learner.applied_index() >= leader.commit_index()
    })
    .await;
    assert!(
        link.largest_forwarded.load(Ordering::SeqCst) > MAX_ENTRY_BYTES,
        "the catch-up delivered the at-bound entry in one append"
    );
    assert!(link.largest_forwarded.load(Ordering::SeqCst) > TONIC_DEFAULT_LIMIT);
    for i in 0..3 {
        assert_eq!(
            value_len(&learner, &format!("/big/{i}")).await,
            Some(6 * 1024 * 1024)
        );
    }
    assert_eq!(
        value_len(&learner, "/at-the-bound").await,
        value_len(&leader, "/at-the-bound").await
    );
    assert_eq!(value_len(&learner, "/over-the-bound").await, None);

    leader.propose(set("/after", 16)).await.expect("write");
    eventually(
        "the leader sees the learner replicating, sends healthy",
        || {
            leader
                .replication()
                .peers
                .iter()
                .find(|peer| peer.node_id == learner_id)
                .is_some_and(|peer| {
                    peer.state == ReplicationState::Replicate
                        && peer.matched == leader.commit_index()
                        && peer.send_failures == 0
                })
        },
    )
    .await;

    learner_zm.shutdown();
    leader_zm.shutdown();
}
