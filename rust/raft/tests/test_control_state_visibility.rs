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
