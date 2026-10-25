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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registered_admission_requires_exact_current_issuer_and_unambiguous_scope() {
    use crate::foreign_ca_store::RaftForeignCaStore;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let private = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::new(private.path().to_path_buf(), 1);
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let issuers = RaftForeignCaStore::new(node.clone(), runtime.clone());
    let crls = RaftCollaborationCrlStore::new(node, runtime, 60).unwrap();
    let (local, _) = generate_zone_ca("local").unwrap();
    let (foreign, key) = generate_zone_ca("edge").unwrap();
    let anchor = ForeignCaAnchor::from_pem("edge", &foreign)
        .unwrap()
        .collaboration_only();
    let authority = lib::transport_primitives::ca_spki_sha256(&foreign).unwrap();
    let check = || {
        crls.check_registered_serial(
            &local,
            &authority,
            &anchor.fingerprint(),
            Some("edge"),
            &[7],
        )
    };
    crls.publish(&foreign, &generate_crl(&[], 0, &foreign, &key).unwrap())
        .unwrap();
    assert!(
        matches!(check(), Err(CrlStateError::Unavailable(_))),
        "fresh CRL does not preserve removed trust"
    );
    issuers.register(&anchor).unwrap();
    check().unwrap();
    assert!(matches!(
        crls.check_registered_serial(&local, &authority, &[0; 32], Some("edge"), &[7]),
        Err(CrlStateError::Unavailable(_))
    ));
    assert!(matches!(
        crls.check_registered_serial(
            &local,
            &authority,
            &anchor.fingerprint(),
            Some("other"),
            &[7]
        ),
        Err(CrlStateError::Unavailable(_))
    ));

    // Same SPKI under another certificate/domain must refuse rather than pick
    // registry iteration order. A same-domain legacy alias is also too broad.
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_after = rcgen::date_time_ymd(2045, 1, 1);
    let key = KeyPair::from_pem(std::str::from_utf8(&key).unwrap()).unwrap();
    let alias_der = params.self_signed(&key).unwrap().der().to_vec();
    let alias = ForeignCaAnchor::new("other", alias_der.clone()).collaboration_only();
    issuers.register(&alias).unwrap();
    assert!(matches!(check(), Err(CrlStateError::Unavailable(_))));
    issuers.unregister(&alias.fingerprint_hex()).unwrap();
    check().unwrap();
    let legacy = ForeignCaAnchor::new("edge", alias_der);
    issuers.register(&legacy).unwrap();
    assert!(matches!(check(), Err(CrlStateError::Unavailable(_))));
    issuers.unregister(&legacy.fingerprint_hex()).unwrap();
    check().unwrap();
    issuers.unregister(&anchor.fingerprint_hex()).unwrap();
    assert!(matches!(check(), Err(CrlStateError::Unavailable(_))));
    registry.shutdown_all();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_admission_also_requires_fresh_crl_and_rejects_foreign_alias() {
    use crate::foreign_ca_store::RaftForeignCaStore;

    let private = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::new(private.path().to_path_buf(), 1);
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let issuers = RaftForeignCaStore::new(node.clone(), runtime.clone());
    let crls = RaftCollaborationCrlStore::new(node, runtime, 60).unwrap();
    let (local, key) = generate_zone_ca("local").unwrap();
    let anchor = ForeignCaAnchor::from_pem("not-local", &local)
        .unwrap()
        .collaboration_only();
    let authority = lib::transport_primitives::ca_spki_sha256(&local).unwrap();
    let check =
        || crls.check_registered_serial(&local, &authority, &anchor.fingerprint(), None, &[7]);
    assert!(matches!(check(), Err(CrlStateError::Unavailable(_))));
    crls.publish(&local, &generate_crl(&[], 0, &local, &key).unwrap())
        .unwrap();
    check().unwrap();
    issuers.register(&anchor).unwrap();
    assert!(matches!(check(), Err(CrlStateError::Unavailable(_))));
    issuers.unregister(&anchor.fingerprint_hex()).unwrap();
    check().unwrap();
    crls.publish(&local, &generate_crl(&[vec![7]], 1, &local, &key).unwrap())
        .unwrap();
    assert_eq!(check(), Err(CrlStateError::Revoked));
    registry.shutdown_all();
}
