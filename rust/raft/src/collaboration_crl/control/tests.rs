use super::*;
use crate::prelude::{FullStateMachine, ZoneConsensus};
use crate::raft::ZoneRaftRegistry;
use crate::transport::{generate_crl, generate_zone_ca};
use contracts::crl_control::{CrlControlChange, CrlIssuerSelection};

async fn ready(node: &ZoneConsensus<FullStateMachine>) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !node.is_leader() || node.applied_index() < node.last_index() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("current-term entry must apply before ReadIndex");
}

fn issuer(operation_id: &str, revision: Option<u64>, ca: Option<&[u8]>) -> CrlControlRequest {
    CrlControlRequest {
        operation_id: operation_id.into(),
        change: CrlControlChange::LocalIssuer {
            expected_revision: revision,
            ca_pem: ca.map(<[u8]>::to_vec),
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_crl_roundtrip_retains_original_receipt_after_withdrawal_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    // This is a real FixedLocal foundation. It does not qualify a Managed
    // control zone or enable the typed protocol on a user tenant.
    let registry = ZoneRaftRegistry::isolated_root(directory.path().into(), 1);
    let node = registry
        .create_zone(contracts::ROOT_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node, runtime.clone(), 60).unwrap();
    let (ca, key) = generate_zone_ca("original-control-issuer").unwrap();
    let original = issuer("original-issuer", None, Some(&ca));
    assert_eq!(store.current_local_issuer().unwrap(), None);
    assert_eq!(store.reconcile_control(&original).unwrap(), None);
    let enrolled = store.apply_control(&original).unwrap();
    assert_eq!(
        enrolled,
        CrlControlOutcome::LocalIssuerChanged(LocalCrlIssuer {
            revision: 1,
            ca_pem: Some(ca.clone()),
        })
    );
    let crl = generate_crl(&[vec![0x80, 1]], 1, &ca, &key).unwrap();
    let install = CrlControlRequest {
        operation_id: "original-signed-crl".into(),
        change: CrlControlChange::Install {
            issuer: CrlIssuerSelection::Local { revision: 1 },
            crl_pem: crl,
            observed_unix_s: crate::collaboration_crl::now().unwrap(),
            maximum_age_secs: 60,
        },
    };
    let installed = store.apply_control(&install).unwrap();
    assert!(matches!(installed, CrlControlOutcome::Installed { .. }));
    assert_eq!(
        store.reconcile_control(&install).unwrap(),
        Some(installed.clone())
    );
    let withdrawn = LocalCrlIssuer {
        revision: 2,
        ca_pem: None,
    };
    assert_eq!(
        store
            .apply_control(&issuer("withdraw-local", Some(1), None))
            .unwrap(),
        CrlControlOutcome::LocalIssuerChanged(withdrawn.clone())
    );
    assert_eq!(
        store.reconcile_control(&original).unwrap(),
        Some(enrolled.clone())
    );
    assert_eq!(
        store.reconcile_control(&install).unwrap(),
        Some(installed.clone())
    );
    assert_eq!(
        store.current_local_issuer().unwrap(),
        Some(withdrawn.clone())
    );
    let changed = issuer("original-issuer", Some(2), Some(&ca));
    assert_eq!(
        store.reconcile_control(&changed).unwrap(),
        Some(CrlControlOutcome::OperationMismatch)
    );
    assert_eq!(
        store.current_local_issuer().unwrap(),
        Some(withdrawn.clone())
    );
    let mut later = install.clone();
    later.operation_id = "new-operation-with-retired-selection".into();
    assert!(matches!(
        store.apply_control(&later).unwrap(),
        CrlControlOutcome::Refused(_)
    ));
    drop(store);
    registry.shutdown().released().await;
    drop(registry);

    let registry = ZoneRaftRegistry::isolated_root(directory.path().into(), 1);
    let node = registry
        .open_persisted_zone(contracts::ROOT_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node, runtime, 60).unwrap();
    assert_eq!(
        store.reconcile_control(&original).unwrap(),
        Some(enrolled.clone())
    );
    assert_eq!(store.reconcile_control(&install).unwrap(), Some(installed));
    assert_eq!(
        store.current_local_issuer().unwrap(),
        Some(withdrawn.clone())
    );
    // Even an explicit original retry returns history without reinstating it.
    assert_eq!(store.apply_control(&original).unwrap(), enrolled);
    assert_eq!(store.current_local_issuer().unwrap(), Some(withdrawn));
    registry.shutdown().released().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_crl_control_refuses_before_any_submission() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::new(directory.path().into(), 1);
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node.clone(), runtime, 60).unwrap();
    let (ca, _) = generate_zone_ca("managed-control").unwrap();
    let request = issuer("managed-initial-issuer", None, Some(&ca));
    let before = node.last_index();
    assert!(matches!(
        store.apply_control(&request),
        Err(CrlStateError::Refused(_))
    ));
    assert_eq!(store.reconcile_control(&request).unwrap(), None);
    assert_eq!(store.current_local_issuer().unwrap(), None);
    assert_eq!(
        node.last_index(),
        before,
        "unsupported admission must not enqueue a log entry"
    );
    registry.shutdown().released().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_admission_observes_withdrawal_replacement_and_restart() {
    use crate::foreign_ca_store::RaftForeignCaStore;
    use lib::transport_primitives::{ca_spki_sha256, ForeignCaAnchor};
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::isolated_root(directory.path().into(), 1);
    let node = registry
        .create_zone(contracts::ROOT_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node.clone(), runtime.clone(), 60).unwrap();
    let (ca, key) = generate_zone_ca("local-admission-original").unwrap();
    let authority = ca_spki_sha256(&ca).unwrap();
    let fingerprint = ForeignCaAnchor::from_pem("local", &ca)
        .unwrap()
        .fingerprint();
    let original = issuer("admission-original", None, Some(&ca));
    let enrolled = store.apply_control(&original).unwrap();
    assert!(matches!(enrolled, CrlControlOutcome::LocalIssuerChanged(_)));
    let original_crl = CrlControlRequest {
        operation_id: "admission-crl-original".into(),
        change: CrlControlChange::Install {
            issuer: CrlIssuerSelection::Local { revision: 1 },
            crl_pem: generate_crl(&[], 1, &ca, &key).unwrap(),
            observed_unix_s: crate::collaboration_crl::now().unwrap(),
            maximum_age_secs: 60,
        },
    };
    assert!(matches!(
        store.apply_control(&original_crl).unwrap(),
        CrlControlOutcome::Installed { .. }
    ));
    store
        .check_registered_serial(&ca, &authority, &fingerprint, None, &[7])
        .unwrap();
    let withdrawn = store
        .apply_control(&issuer("admission-withdraw", Some(1), None))
        .unwrap();
    assert_eq!(
        withdrawn,
        CrlControlOutcome::LocalIssuerChanged(LocalCrlIssuer {
            revision: 2,
            ca_pem: None
        })
    );
    store.check_serial(&ca, &[7]).unwrap();
    assert!(
        matches!(
            store.check_registered_serial(&ca, &authority, &fingerprint, None, &[7]),
            Err(CrlStateError::Unavailable(_))
        ),
        "withdrawn local issuer must refuse despite a still-fresh CRL"
    );
    assert_eq!(
        store.reconcile_control(&original).unwrap(),
        Some(enrolled.clone())
    );
    assert_eq!(store.apply_control(&original).unwrap(), enrolled);
    assert!(store
        .check_registered_serial(&ca, &authority, &fingerprint, None, &[7])
        .is_err());
    drop(store);
    registry.shutdown().released().await;
    drop(registry);

    let registry = ZoneRaftRegistry::isolated_root(directory.path().into(), 1);
    let node = registry
        .open_persisted_zone(contracts::ROOT_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node.clone(), runtime.clone(), 60).unwrap();
    assert!(store
        .check_registered_serial(&ca, &authority, &fingerprint, None, &[7])
        .is_err());
    // Reuse the original key under a different CA certificate. Matching SPKI
    // alone must not admit the TLS anchor retained before replacement.
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut subject = DistinguishedName::new();
    subject.push(DnType::OrganizationName, "Nexus");
    subject.push(DnType::CommonName, "nexus-zone-local-admission-original-ca");
    params.distinguished_name = subject;
    params.not_after = rcgen::date_time_ymd(2045, 1, 1);
    let same_key = KeyPair::from_pem(std::str::from_utf8(&key).unwrap()).unwrap();
    let replacement = params.self_signed(&same_key).unwrap().pem().into_bytes();
    let replacement_fingerprint = ForeignCaAnchor::from_pem("local", &replacement)
        .unwrap()
        .fingerprint();
    assert_eq!(ca_spki_sha256(&replacement).unwrap(), authority);
    assert_ne!(replacement_fingerprint, fingerprint);
    let CrlControlChange::Install { crl_pem, .. } = &original_crl.change else {
        panic!("original request must retain its signed CRL");
    };
    // Isolate full certificate identity from signature, issuer-name and key
    // usage refusal: the original CRL is valid under both certificates.
    lib::transport_primitives::verify_signed_crl(crl_pem, &replacement).unwrap();
    assert!(matches!(
        store
            .apply_control(&issuer(
                "admission-replacement",
                Some(2),
                Some(&replacement)
            ))
            .unwrap(),
        CrlControlOutcome::LocalIssuerChanged(_)
    ));
    store.check_serial(&ca, &[7]).unwrap();
    assert!(
        matches!(
            store.check_registered_serial(&ca, &authority, &fingerprint, None, &[7]),
            Err(CrlStateError::Unavailable(_))
        ),
        "a same-key replacement must refuse the original TLS CA certificate"
    );
    let replacement_crl = CrlControlRequest {
        operation_id: "admission-crl-replacement".into(),
        change: CrlControlChange::Install {
            issuer: CrlIssuerSelection::Local { revision: 3 },
            crl_pem: generate_crl(&[], 2, &replacement, &key).unwrap(),
            observed_unix_s: crate::collaboration_crl::now().unwrap(),
            maximum_age_secs: 60,
        },
    };
    assert!(matches!(
        store.apply_control(&replacement_crl).unwrap(),
        CrlControlOutcome::Installed { .. }
    ));
    store
        .check_registered_serial(
            &replacement,
            &authority,
            &replacement_fingerprint,
            None,
            &[7],
        )
        .unwrap();
    // The ordinary foreign-registration API is unchanged by local admission.
    let foreign = RaftForeignCaStore::new(node, runtime);
    let alias = ForeignCaAnchor::from_pem("foreign-alias", &replacement)
        .unwrap()
        .collaboration_only();
    foreign.register(&alias).unwrap();
    assert!(store
        .check_registered_serial(
            &replacement,
            &authority,
            &replacement_fingerprint,
            None,
            &[7]
        )
        .is_err());
    foreign.unregister(&alias.fingerprint_hex()).unwrap();
    store
        .check_registered_serial(
            &replacement,
            &authority,
            &replacement_fingerprint,
            None,
            &[7],
        )
        .unwrap();
    registry.shutdown().released().await;
}
