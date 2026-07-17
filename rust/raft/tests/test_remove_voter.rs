//! Integration coverage for `ZoneApiService::RemoveVoter` — the
//! operator-facing prune of a stale voter/learner from a zone's
//! ConfState.  Escape hatch for S3 Phase C voter wipe-rejoin.
//!
//! Contract to pin:
//!
//! 1. `call_remove_voter_rpc` against a leader that carries the target
//!    id in its `ConfState.voters` (or `learners`) commits a `RemoveNode`
//!    ConfChange — post-call `cluster_status` reflects the smaller
//!    voter set.
//!
//! 2. `call_remove_voter_rpc` against an unknown id is idempotent —
//!    raft-rs's `Changer::remove` no-ops when the id is not in the
//!    conf, and the RPC surfaces `success=true`.
//!
//! 3. `call_remove_voter_rpc` against a follower returns
//!    `success=false` + `leader_address` set to the leader's advertise
//!    address, matching the JoinZone follower-redirect pattern.

#![cfg(all(feature = "grpc", has_protos))]

use std::time::Duration;

use nexus_raft::transport::{call_join_zone_rpc, call_remove_voter_rpc};
use nexus_raft::ZoneManager;
use tempfile::TempDir;

const NODE_ID_FILE: &str = ".node_id";

fn mint_random_id() -> u64 {
    let id = rand::random::<u64>();
    if id == 0 {
        1
    } else {
        id
    }
}

fn write_node_id(dir: &std::path::Path, id: u64) {
    std::fs::create_dir_all(dir).expect("create dir");
    std::fs::write(dir.join(NODE_ID_FILE), id.to_be_bytes()).expect("write .node_id");
}

async fn make_node(node_id: u64, dir: &std::path::Path) -> (std::sync::Arc<ZoneManager>, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    let bind_str = format!("{}", addr);

    let zm = ZoneManager::with_node_id(
        "test-host",
        node_id,
        dir.to_str().expect("utf-8"),
        vec![],
        &bind_str,
        None,
        Some(format!("http://{bind_str}")),
        None,
    )
    .expect("ZoneManager");
    (zm, bind_str)
}

async fn wait_leader(zm: &std::sync::Arc<ZoneManager>, zone_id: &str) {
    let zone = zm.get_zone(zone_id).expect("zone loaded");
    for _ in 0..100 {
        if zone.is_leader() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("zone {zone_id} did not elect within timeout");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_voter_prunes_learner_from_conf_state() {
    // Owner (voter) + joiner (learner) — RemoveVoter against the
    // learner id shrinks ConfState.  Learners are the safer case for
    // this test because dropping one never affects quorum.
    let dir_owner = TempDir::new().expect("owner dir");
    let dir_joiner = TempDir::new().expect("joiner dir");
    let id_owner = mint_random_id();
    let id_joiner = mint_random_id();
    assert_ne!(id_owner, id_joiner);
    write_node_id(dir_owner.path(), id_owner);
    write_node_id(dir_joiner.path(), id_joiner);

    let (zm_owner, bind_owner) = make_node(id_owner, dir_owner.path()).await;
    let (zm_joiner, bind_joiner) = make_node(id_joiner, dir_joiner.path()).await;

    zm_owner
        .create_zone("sharedzone", vec![format!("{id_owner}@{bind_owner}")])
        .expect("create sharedzone");
    wait_leader(&zm_owner, "sharedzone").await;

    let endpoint_owner = format!("http://{bind_owner}");
    let endpoint_joiner = format!("http://{bind_joiner}");
    zm_joiner
        .join_zone(
            "sharedzone",
            vec![format!("{id_owner}@{bind_owner}")],
            /* learner */ true,
        )
        .expect("local join");
    let r = call_join_zone_rpc(
        &endpoint_owner,
        "sharedzone",
        id_joiner,
        &endpoint_joiner,
        /* as_learner */ true,
        None,
        30,
    )
    .await
    .expect("JoinZone");
    assert!(r.success, "JoinZone must succeed: {:?}", r.error);

    // Wait for the joiner to appear in the owner's peer set (an
    // upper bound on the AddLearnerNode apply).
    let mut saw_joiner = false;
    for _ in 0..50 {
        let peers = zm_owner
            .registry()
            .get_peers("sharedzone")
            .unwrap_or_default();
        if peers.contains_key(&id_joiner) {
            saw_joiner = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(saw_joiner, "AddLearnerNode did not apply on owner");

    // Prune the learner.
    let result = call_remove_voter_rpc(&endpoint_owner, "sharedzone", id_joiner, None, 15)
        .await
        .expect("RemoveVoter RPC");
    assert!(
        result.success,
        "RemoveVoter must succeed: error={:?}",
        result.error,
    );

    // Wait for the learner to disappear from the owner's peer set.
    let mut pruned = false;
    for _ in 0..50 {
        let peers = zm_owner
            .registry()
            .get_peers("sharedzone")
            .unwrap_or_default();
        if !peers.contains_key(&id_joiner) {
            pruned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(pruned, "RemoveNode did not apply on owner");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remove_voter_is_idempotent_on_unknown_id() {
    // Removing an id that was never in the ConfState succeeds
    // (raft-rs's Changer::remove is a no-op on unknown ids).  This is
    // the operator-safe pattern — running the CLI twice against the
    // same ghost id is fine.
    let dir_owner = TempDir::new().expect("owner dir");
    let id_owner = mint_random_id();
    write_node_id(dir_owner.path(), id_owner);
    let (zm_owner, bind_owner) = make_node(id_owner, dir_owner.path()).await;
    zm_owner
        .create_zone("sharedzone", vec![format!("{id_owner}@{bind_owner}")])
        .expect("create");
    wait_leader(&zm_owner, "sharedzone").await;

    let endpoint = format!("http://{bind_owner}");
    let never_existed_id: u64 = 424242;
    let result = call_remove_voter_rpc(&endpoint, "sharedzone", never_existed_id, None, 15)
        .await
        .expect("RemoveVoter RPC");
    assert!(
        result.success,
        "unknown id must be a no-op success: error={:?}",
        result.error,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_voter_on_follower_returns_leader_address() {
    // Send RemoveVoter to a follower — must surface success=false +
    // leader_address so the operator (or the CLI's redirect-once
    // logic) can retry against the leader.
    let dir_owner = TempDir::new().expect("owner dir");
    let dir_joiner = TempDir::new().expect("joiner dir");
    let id_owner = mint_random_id();
    let id_joiner = mint_random_id();
    write_node_id(dir_owner.path(), id_owner);
    write_node_id(dir_joiner.path(), id_joiner);

    let (zm_owner, bind_owner) = make_node(id_owner, dir_owner.path()).await;
    let (zm_joiner, bind_joiner) = make_node(id_joiner, dir_joiner.path()).await;

    zm_owner
        .create_zone("sharedzone", vec![format!("{id_owner}@{bind_owner}")])
        .expect("create");
    wait_leader(&zm_owner, "sharedzone").await;

    let endpoint_owner = format!("http://{bind_owner}");
    let endpoint_joiner = format!("http://{bind_joiner}");
    zm_joiner
        .join_zone(
            "sharedzone",
            vec![format!("{id_owner}@{bind_owner}")],
            /* learner */ true,
        )
        .expect("local join");
    let r = call_join_zone_rpc(
        &endpoint_owner,
        "sharedzone",
        id_joiner,
        &endpoint_joiner,
        true,
        None,
        30,
    )
    .await
    .expect("JoinZone");
    assert!(r.success);

    // Wait for the ConfChange to apply on the joiner so it's actually
    // a proper follower of the sharedzone group.
    for _ in 0..50 {
        if zm_joiner.get_zone("sharedzone").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // RemoveVoter on the joiner (the follower) must redirect.  The
    // learner has no leader hint of its own until AppendEntries fills
    // its peer map — poll briefly to give that a chance.
    let mut redirect_seen = false;
    for _ in 0..40 {
        let result = call_remove_voter_rpc(&endpoint_joiner, "sharedzone", id_owner, None, 15)
            .await
            .expect("RemoveVoter RPC");
        if !result.success && result.leader_address.is_some() {
            redirect_seen = true;
            let leader_addr = result.leader_address.as_deref().unwrap_or("");
            assert!(
                leader_addr.contains(&bind_owner),
                "leader_address should include owner's endpoint: {leader_addr}",
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        redirect_seen,
        "follower must eventually return not-leader with leader_address"
    );
}
