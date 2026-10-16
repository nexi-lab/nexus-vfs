//! A follower's successful management write is visible on that same replica.
#![cfg(all(feature = "grpc", has_protos))]

mod common;

use nexus_raft::{
    control_state_store::ControlStateStore, transport::call_join_zone_rpc, ZoneManager,
};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follower_put_and_revoke_return_after_local_apply() {
    let founder_dir = tempfile::tempdir().unwrap();
    let follower_dir = tempfile::tempdir().unwrap();
    let founder_addr = common::node_bind_addr();
    let follower_addr = common::node_bind_addr();
    let make_node = |id, dir: &std::path::Path, addr: &str| {
        ZoneManager::with_node_id(
            "visibility-test",
            id,
            dir.to_str().unwrap(),
            vec![],
            addr,
            None,
            Some(format!("http://{addr}")),
            None,
        )
        .unwrap()
    };
    let founder = make_node(1, founder_dir.path(), &founder_addr);
    let follower = make_node(2, follower_dir.path(), &follower_addr);
    let leader_zone = founder
        .create_zone("sharedzone", vec![format!("1@{founder_addr}")])
        .unwrap();
    leader_zone.consensus_node().campaign().await.unwrap();
    let follower_zone = follower
        .join_zone("sharedzone", vec![format!("1@{founder_addr}")], true)
        .unwrap();
    let joined = call_join_zone_rpc(
        &format!("http://{founder_addr}"),
        "sharedzone",
        2,
        &format!("http://{follower_addr}"),
        true,
        None,
        30,
    )
    .await
    .unwrap();
    assert!(joined.success, "{:?}", joined.error);
    let consensus = follower_zone.consensus_node();
    let store = ControlStateStore::new(
        consensus.clone(),
        follower_zone.runtime_handle(),
        "visibility-test",
    );
    // No caller-side retry, polling or sleep between a write and its read.
    // Alternate values so an earlier committed value cannot satisfy the check.
    tokio::task::spawn_blocking(move || {
        for generation in 0..16u64 {
            let value = generation.to_be_bytes();
            store.put("grant", &value).unwrap();
            assert_eq!(
                store.get("grant").unwrap().as_deref(),
                Some(value.as_slice())
            );
            assert!(store.delete("grant").unwrap());
            assert_eq!(store.get("grant").unwrap(), None);
        }
    })
    .await
    .unwrap();
    let node = leader_zone.consensus_node();
    let observed = tokio::time::timeout(
        Duration::from_secs(10),
        node.read_linearizable(|sm| sm.get_control_state("visibility-test", "grant")),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(observed, None);
}

/// A replica that LOSES a `put_if_absent` CAS race must see the winner's
/// record when it reads back immediately: the losing branch barriers
/// before returning `Ok(false)`, so the caller that reads the record back
/// right away (the journal's `begin` does) sees the winner instead of a
/// stale miss. Built on a same-replica double insert — the deterministic
/// shape of "lost the CAS, now read back" (a forwarded follower CAS does
/// not currently surface the leader's refusal as `Ok(false)`, which is a
/// transport-semantic gap outside this test's scope).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cas_loss_reads_back_the_winners_value() {
    let dir = tempfile::tempdir().unwrap();
    let addr = common::node_bind_addr();
    let zm = ZoneManager::with_node_id(
        "cas-visibility-test",
        1,
        dir.path().to_str().unwrap(),
        vec![],
        &addr,
        None,
        Some(format!("http://{addr}")),
        None,
    )
    .unwrap();
    let zone = zm
        .create_zone("sharedzone", vec![format!("1@{addr}")])
        .unwrap();
    for _ in 0..100 {
        if zone.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(zone.is_leader(), "solo node must self-elect");

    let store = ControlStateStore::new(
        zone.consensus_node(),
        zone.runtime_handle(),
        "cas-visibility-test",
    );

    tokio::task::spawn_blocking(move || {
        let winner = b"winner".to_vec();
        let loser = b"loser".to_vec();
        assert!(
            store.put_if_absent("cas-key", &winner).unwrap(),
            "the first insert wins"
        );
        assert!(
            !store.put_if_absent("cas-key", &loser).unwrap(),
            "the second insert loses the CAS"
        );
        let observed = store.get("cas-key").unwrap().expect(
            "the losing branch must barrier: the winner's record is committed, so a \
             read-back miss here would be a stale-apply artifact",
        );
        assert_eq!(observed, winner);
    })
    .await
    .unwrap();
}

/// The FORWARDED shape of [`cas_loss_reads_back_the_winners_value`]: the
/// loser's `put_if_absent` runs on a FOLLOWER, so its propose is forwarded
/// to the leader and the refusal travels back through the transport as the
/// inner `RaftResponse{success:false}` of the forwarded reply. The decoder
/// must surface it as `Ok(false)` — the zone-op journal's single-executor
/// grant rides on this: a follower that decoded the leader's refusal as
/// `Success` would believe IT won the insert and become a second executor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwarded_cas_loss_reports_the_loss() {
    let founder_dir = tempfile::tempdir().unwrap();
    let follower_dir = tempfile::tempdir().unwrap();
    let founder_addr = common::node_bind_addr();
    let follower_addr = common::node_bind_addr();
    let make_node = |id, dir: &std::path::Path, addr: &str| {
        ZoneManager::with_node_id(
            "forwarded-cas-test",
            id,
            dir.to_str().unwrap(),
            vec![],
            addr,
            None,
            Some(format!("http://{addr}")),
            None,
        )
        .unwrap()
    };
    let founder = make_node(1, founder_dir.path(), &founder_addr);
    let follower = make_node(2, follower_dir.path(), &follower_addr);
    let leader_zone = founder
        .create_zone("sharedzone", vec![format!("1@{founder_addr}")])
        .unwrap();
    leader_zone.consensus_node().campaign().await.unwrap();
    let follower_zone = follower
        .join_zone("sharedzone", vec![format!("1@{founder_addr}")], true)
        .unwrap();
    let joined = call_join_zone_rpc(
        &format!("http://{founder_addr}"),
        "sharedzone",
        2,
        &format!("http://{follower_addr}"),
        true,
        None,
        30,
    )
    .await
    .unwrap();
    assert!(joined.success, "{:?}", joined.error);

    let founder_store = ControlStateStore::new(
        leader_zone.consensus_node(),
        leader_zone.runtime_handle(),
        "forwarded-cas-test",
    );
    let follower_store = ControlStateStore::new(
        follower_zone.consensus_node(),
        follower_zone.runtime_handle(),
        "forwarded-cas-test",
    );

    // The winner inserts from the leader itself; the loser's CAS is
    // FORWARDED from the follower to the leader and must come back a loss.
    let winner = b"winner".to_vec();
    let loser = b"loser".to_vec();
    let expected = winner.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        assert!(
            founder_store.put_if_absent("cas-key", &winner).unwrap(),
            "the leader-side insert wins"
        );
        let lost = follower_store
            .put_if_absent("cas-key", &loser)
            .expect("the forwarded propose itself succeeds (the leader applies it)");
        let observed = follower_store.get("cas-key").unwrap().expect(
            "the losing branch must barrier: the winner's record is committed, so a \
             read-back miss here would be a stale-apply artifact",
        );
        (lost, observed)
    })
    .await
    .unwrap();
    assert!(
        !outcome.0,
        "a follower whose forwarded CAS loses must be told it lost — decoding the \
         leader's refusal as Success would crown a second executor"
    );
    assert_eq!(outcome.1, expected);
}
