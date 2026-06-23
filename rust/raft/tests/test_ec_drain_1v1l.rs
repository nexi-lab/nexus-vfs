//! Regression pin for nexi-lab/nexus-vfs#64 — EC drain in 1V+1L.
//!
//! Topology:
//!   * Founder bootstraps a 1-voter `sharedzone` and self-elects leader.
//!   * Joiner enters the zone as a Learner via JoinZone RPC.
//!
//! The pre-fix `replicate_ec_entries` computed `total_voters` from
//! `peer_snapshot.len() + 1`, which over-counted the single learner as
//! if it were a voter and required a learner ack for the EC watermark
//! to advance.  The learner's `acked_seq` stayed 0 in its EC backoff
//! window, the watermark could never advance, and subsequent
//! founder-side EC writes ceased reaching the learner's state machine
//! within any reasonable test budget.
//!
//! This test:
//!   1. propose_ec_local() a small payload on the founder.
//!   2. propose_ec_local() a larger payload (forces a real WAL drain
//!      across the wire — the case the original docker E2E caught).
//!   3. assert both keys appear in the learner's local state machine
//!      within 5 s.
//!
//! Must fail pre-fix (learner never receives either write), pass
//! post-fix (voter-only watermark + fire-and-forget drain + lower
//! backoff cap working in concert).

#![cfg(all(feature = "grpc", has_protos))]

use std::time::Duration;

use nexus_raft::prelude::Command;
use nexus_raft::transport::call_join_zone_rpc;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_ec_drain_1v1l_learner_receives_propose_ec_local() {
    let dir_owner = TempDir::new().expect("dir-owner");
    let dir_learner = TempDir::new().expect("dir-learner");

    let id_owner = mint_random_id();
    let id_learner = mint_random_id();
    assert_ne!(id_owner, id_learner, "two random mints must differ");
    write_node_id(dir_owner.path(), id_owner);
    write_node_id(dir_learner.path(), id_learner);

    let (zm_owner, bind_owner) = make_node(id_owner, dir_owner.path()).await;
    let (zm_learner, bind_learner) = make_node(id_learner, dir_learner.path()).await;

    // Owner: create 1-voter sharedzone.  Self-elects (quorum=1).
    let zone_owner = zm_owner
        .create_zone("sharedzone", vec![format!("{id_owner}@{bind_owner}")])
        .expect("create sharedzone on owner");
    for _ in 0..100 {
        if zone_owner.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        zone_owner.is_leader(),
        "owner must self-elect on 1-voter create"
    );

    let endpoint_owner = format!("http://{bind_owner}");
    let endpoint_learner = format!("http://{bind_learner}");

    // Learner registers locally with `learner=true`, then JoinZone(learner).
    let _zone_learner = zm_learner
        .join_zone(
            "sharedzone",
            vec![format!("{id_owner}@{bind_owner}")],
            /* learner */ true,
        )
        .expect("local join_zone(learner) on learner");

    let join_resp = call_join_zone_rpc(
        &endpoint_owner,
        "sharedzone",
        id_learner,
        &endpoint_learner,
        /* as_learner */ true,
        30,
    )
    .await
    .expect("JoinZone RPC");
    assert!(
        join_resp.success,
        "JoinZone(learner) must succeed: {:?}",
        join_resp.error
    );

    // Wait for the learner to be visible in the owner's peer view.
    // Without this, propose_ec_local races the AddLearnerNode commit.
    for _ in 0..50 {
        let status = zm_owner.cluster_status("sharedzone");
        if status.applied_index >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Small payload — the pre-fix bug already manifests here in 1V+1L
    // because total_voters is computed as `peer_snapshot.len() + 1 = 2`
    // and the watermark needs a learner ack to advance.
    let owner_consensus = zone_owner.consensus_node();
    let small_cmd = Command::SetMetadata {
        key: "/ec-drain-1v1l/small".into(),
        value: b"small".to_vec(),
    };
    owner_consensus
        .propose_ec_local(small_cmd)
        .await
        .expect("propose_ec_local(small) on owner");

    // Large payload — forces a wire drain that exceeded the cold-gRPC
    // EC_SEND_TIMEOUT window in the original repro.  16 KiB is well
    // under EC_MAX_ENTRIES_PER_BATCH-bound replication-cycle memory
    // but big enough that the WAL frame is non-trivial.
    let large_value = vec![0xABu8; 16 * 1024];
    let large_cmd = Command::SetMetadata {
        key: "/ec-drain-1v1l/large".into(),
        value: large_value.clone(),
    };
    owner_consensus
        .propose_ec_local(large_cmd)
        .await
        .expect("propose_ec_local(large) on owner");

    // Learner ZoneHandle (returned by `join_zone` above as the second
    // binding — we kept `_zone_learner` only to keep the local raft
    // node alive; re-fetch via `get_zone` for the read-side handle).
    let zone_learner_handle = zm_learner
        .get_zone("sharedzone")
        .expect("learner must have a ZoneHandle for sharedzone");
    let learner_consensus = zone_learner_handle.consensus_node();

    // Poll the learner's local state machine for both keys.  Budget
    // 5 s — pre-fix this loop times out (the learner's state machine
    // never sees the writes); post-fix it should resolve in well under
    // a second on a healthy localhost transport.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut both_seen = false;
    let mut last_small: Option<Vec<u8>> = None;
    let mut last_large: Option<Vec<u8>> = None;
    while std::time::Instant::now() < deadline {
        let (small, large) = learner_consensus
            .with_state_machine(|sm| {
                let s = sm.get_metadata("/ec-drain-1v1l/small").ok().flatten();
                let l = sm.get_metadata("/ec-drain-1v1l/large").ok().flatten();
                (s, l)
            })
            .await;
        last_small = small.clone();
        last_large = large.clone();
        if small.as_deref() == Some(b"small".as_ref()) && large.as_deref() == Some(&large_value[..])
        {
            both_seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        both_seen,
        "learner must apply both EC writes within 5s — \
         small={:?} large_present={:?}",
        last_small.as_deref().map(|v| v.len()),
        last_large.as_deref().map(|v| v.len()),
    );
}
