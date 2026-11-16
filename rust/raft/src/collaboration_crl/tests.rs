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
        .create_zone(contracts::CONTROL_ZONE_ID, &runtime)
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
    registry.shutdown().released().await;
    drop(registry);
    let registry = ZoneRaftRegistry::new(private.path().to_path_buf(), 1);
    let node = registry
        .open_persisted_zone(contracts::CONTROL_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node, runtime, 60).unwrap();
    assert_eq!(
        store.check_serial(&ca, &serial),
        Err(CrlStateError::Revoked)
    );
    store.check_serial(&other_ca, &serial).unwrap();
    registry.shutdown().released().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn freshness_is_checked_on_every_admission_and_corrupt_state_refuses() {
    let private = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::new(private.path().to_path_buf(), 1);
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, &runtime)
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
    registry.shutdown().released().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registered_admission_requires_exact_current_issuer_and_unambiguous_scope() {
    use crate::foreign_ca_store::RaftForeignCaStore;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let private = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::new(private.path().to_path_buf(), 1);
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, &runtime)
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
    registry.shutdown().released().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_admission_also_requires_fresh_crl_and_rejects_foreign_alias() {
    use crate::foreign_ca_store::RaftForeignCaStore;

    let private = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    // Native current-issuer admission is qualified on its supported FixedLocal
    // store. The separate Managed case below must still refuse missing authority.
    let registry = ZoneRaftRegistry::isolated_root(private.path().to_path_buf(), 1);
    let node = registry
        .create_zone(contracts::ROOT_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let issuers = RaftForeignCaStore::new(node.clone(), runtime.clone());
    let crls = RaftCollaborationCrlStore::new(node, runtime, 60).unwrap();
    let (local, key) = generate_zone_ca("local").unwrap();
    use contracts::crl_control::{
        CrlControlChange, CrlControlOutcome, CrlControlRequest, CrlIssuerSelection,
    };
    assert!(matches!(
        crls.apply_control(&CrlControlRequest {
            operation_id: "local-admission-issuer".into(),
            change: CrlControlChange::LocalIssuer {
                expected_revision: None,
                ca_pem: Some(local.clone()),
            },
        })
        .unwrap(),
        CrlControlOutcome::LocalIssuerChanged(_)
    ));
    let publish = |operation: &str, revoked: &[Vec<u8>], number: u64| {
        assert!(matches!(
            crls.apply_control(&CrlControlRequest {
                operation_id: operation.into(),
                change: CrlControlChange::Install {
                    issuer: CrlIssuerSelection::Local { revision: 1 },
                    crl_pem: generate_crl(revoked, number, &local, &key).unwrap(),
                    observed_unix_s: now().unwrap(),
                    maximum_age_secs: 60,
                },
            })
            .unwrap(),
            CrlControlOutcome::Installed { .. }
        ));
    };
    let anchor = ForeignCaAnchor::from_pem("not-local", &local)
        .unwrap()
        .collaboration_only();
    let authority = lib::transport_primitives::ca_spki_sha256(&local).unwrap();
    let check =
        || crls.check_registered_serial(&local, &authority, &anchor.fingerprint(), None, &[7]);
    assert!(matches!(check(), Err(CrlStateError::Unavailable(_))));
    publish("local-admission-initial-crl", &[], 0);
    check().unwrap();
    issuers.register(&anchor).unwrap();
    assert!(matches!(check(), Err(CrlStateError::Unavailable(_))));
    issuers.unregister(&anchor.fingerprint_hex()).unwrap();
    check().unwrap();
    publish("local-admission-revoked-crl", &[vec![7]], 1);
    assert_eq!(check(), Err(CrlStateError::Revoked));
    registry.shutdown().released().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_local_admission_refuses_fresh_legacy_crl_without_durable_issuer() {
    let private = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::new(private.path().into(), 1);
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node.clone(), runtime, 60).unwrap();
    let (ca, key) = generate_zone_ca("unbound-local").unwrap();
    store
        .publish(&ca, &generate_crl(&[], 1, &ca, &key).unwrap())
        .unwrap();
    // A genuine fresh CRL is present; missing durable authority is the refusal.
    store.check_serial(&ca, &[7]).unwrap();
    assert_eq!(store.current_local_issuer().unwrap(), None);
    let authority = lib::transport_primitives::ca_spki_sha256(&ca).unwrap();
    let fingerprint = ForeignCaAnchor::from_pem("local", &ca)
        .unwrap()
        .fingerprint();
    let before = node.last_index();
    assert!(
        matches!(
            store.check_registered_serial(&ca, &authority, &fingerprint, None, &[7]),
            Err(CrlStateError::Unavailable(_))
        ),
        "fresh legacy CRL must not grant an unbound local issuer"
    );
    assert_eq!(
        node.last_index(),
        before,
        "admission must not install authority"
    );
    registry.shutdown().released().await;
}
