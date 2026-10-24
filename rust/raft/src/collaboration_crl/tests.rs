use super::*;
use crate::raft::ZoneRaftRegistry;
use crate::transport::{generate_crl, generate_zone_ca};

async fn ready(node: &ZoneConsensus<FullStateMachine>) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !node.is_leader() || node.applied_index() < node.last_index() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("current-term entry must apply before ReadIndex");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_crl_replay_and_restart_cannot_unrevoke_an_observed_serial() {
    let private = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::new(private.path().to_path_buf(), 1);
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node, runtime.clone(), 60).unwrap();
    let (ca, key) = generate_zone_ca("original").unwrap();
    let (other_ca, other_key) = generate_zone_ca("same-name-independent-key").unwrap();
    let serial = [0x80, 1];
    assert!(matches!(
        store.check_serial(&ca, &serial),
        Err(CrlStateError::Unavailable(_))
    ));
    let original = generate_crl(&[], 0, &ca, &key).unwrap();
    store.publish(&ca, &original).unwrap();
    store.check_serial(&ca, &serial).unwrap();
    let current = generate_crl(&[serial.to_vec()], 1, &ca, &key).unwrap();
    store.publish(&ca, &current).unwrap();
    assert_eq!(
        store.check_serial(&ca, &serial),
        Err(CrlStateError::Revoked)
    );
    assert_eq!(
        store.check_serial(&ca, &[0, 0x80, 1]),
        Err(CrlStateError::Revoked)
    );
    store.check_serial(&ca, &[0x80, 2]).unwrap();
    // The legacy issuer's count-based number can decrease after pruning.
    // Signed older/empty data must not erase an observed certificate revoke.
    store.publish(&ca, &original).unwrap();
    assert_eq!(
        store.check_serial(&ca, &serial),
        Err(CrlStateError::Revoked)
    );
    store
        .publish(
            &other_ca,
            &generate_crl(&[], 0, &other_ca, &other_key).unwrap(),
        )
        .unwrap();
    store.check_serial(&other_ca, &serial).unwrap();
    assert!(matches!(
        store.publish(&other_ca, &current),
        Err(CrlStateError::Refused(_))
    ));
    drop(store);
    registry.shutdown_all();
    drop(registry);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let registry = ZoneRaftRegistry::new(private.path().to_path_buf(), 1);
    let node = registry
        .open_persisted_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node, runtime, 60).unwrap();
    assert_eq!(
        store.check_serial(&ca, &serial),
        Err(CrlStateError::Revoked)
    );
    store.check_serial(&other_ca, &serial).unwrap();
    registry.shutdown_all();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn freshness_is_checked_on_every_admission_and_corrupt_state_refuses() {
    let private = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::new(private.path().to_path_buf(), 1);
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node, runtime, 10).unwrap();
    let (ca, key) = generate_zone_ca("original").unwrap();
    let bytes = generate_crl(&[], 0, &ca, &key).unwrap();
    let receipt = store.publish(&ca, &bytes).unwrap();
    assert_eq!(
        receipt.snapshot_sha256,
        <[u8; 32]>::from(Sha256::digest(&bytes))
    );
    store.check_at(&ca, &[1], receipt.this_update + 10).unwrap();
    assert!(matches!(
        store.check_at(&ca, &[1], receipt.this_update + 11),
        Err(CrlStateError::Unavailable(_))
    ));
    assert!(matches!(
        store.check_at(&ca, &[1], receipt.this_update - 1),
        Err(CrlStateError::Unavailable(_))
    ));
    assert!(matches!(
        store.check_serial(&ca, &[]),
        Err(CrlStateError::Unavailable(_))
    ));
    store
        .inner
        .put(
            &snapshot_key(&receipt.authority),
            b"corrupt signed snapshot",
        )
        .unwrap();
    assert!(matches!(
        store.check_serial(&ca, &[1]),
        Err(CrlStateError::Unavailable(_))
    ));
    registry.shutdown_all();
}
