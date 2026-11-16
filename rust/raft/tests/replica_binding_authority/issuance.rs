//! Actual CSR signing, Raft publication, competing retirement and cold recovery.
use super::*;
use contracts::replica_credential::{
    ReplicaCertificateIntent, ReplicaIssuanceChange, ReplicaIssuanceOutcome,
    ReplicaIssuanceRejection, ReplicaIssuanceRequest,
};
use nexus_raft::transport::{
    generate_zone_ca, prepare_replica_csr_intent, sign_committed_replica_intent,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

fn issue(operation: &str, change: ReplicaIssuanceChange) -> ReplicaIssuanceRequest {
    ReplicaIssuanceRequest {
        operation_id: operation.into(),
        change,
    }
}

fn credential_fixture(
    store: &RaftReplicaBindingStore,
) -> (
    ReplicaIssuanceRequest,
    ReplicaIssuanceRequest,
    ReplicaCertificateIntent,
    Vec<u8>,
) {
    let ReplicaBindingOutcome::Applied(binding) =
        store.apply(&request("replica-allocation", 801)).unwrap()
    else {
        panic!("allocation");
    };
    let (ca, key) = generate_zone_ca("actual-replica-issuer").unwrap();
    let der = pem::parse(&ca).unwrap();
    let admit = issue(
        "admit-ca",
        ReplicaIssuanceChange::Authority {
            expected_revision: None,
            issuer_sha256: Some(Sha256::digest(der.contents()).into()),
        },
    );
    let ReplicaIssuanceOutcome::AuthorityChanged(authority) = store.issue(&admit).unwrap() else {
        panic!("authority");
    };
    let holder = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&holder)
        .unwrap()
        .pem()
        .unwrap();
    let intent = prepare_replica_csr_intent(
        &binding,
        &authority,
        "session-replica",
        300,
        csr.as_bytes(),
        &ca,
    )
    .unwrap();
    let prepare = issue(
        "prepare-credential",
        ReplicaIssuanceChange::Prepare {
            intent: Box::new(intent.clone()),
            renews: None,
        },
    );
    assert!(matches!(
        store.issue(&prepare).unwrap(),
        ReplicaIssuanceOutcome::Prepared { .. }
    ));
    let signed = sign_committed_replica_intent(&intent, &ca, &key).unwrap();
    let publish = issue(
        "publish-credential",
        ReplicaIssuanceChange::Publish {
            credential_id: prepare.operation_id.clone(),
            certificate: signed,
        },
    );
    (prepare, publish, intent, ca)
}

#[test]
fn actual_replica_certificate_and_original_receipts_survive_restart_and_revocation() {
    let directory = tempfile::tempdir().unwrap();
    let (prepare, publish, intent, ca, original) = {
        let runtime = LocalAuthority::open(directory.path());
        let (prepare, publish, intent, ca) = credential_fixture(&runtime.store);
        let result = runtime.store.issue(&publish).unwrap();
        assert!(matches!(result, ReplicaIssuanceOutcome::Published { .. }));
        (prepare, publish, intent, ca, result)
    };
    let runtime = LocalAuthority::open(directory.path());
    assert_eq!(
        runtime.store.reconcile_issuance(&publish).unwrap(),
        Some(original.clone())
    );
    assert_eq!(runtime.store.issue(&publish).unwrap(), original);
    let observed = runtime
        .store
        .credential(&prepare.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(observed.intent, intent);
    assert!(!observed.revoked);
    let certificate = observed.certificate_der.unwrap();
    let (_, certificate) = X509Certificate::from_der(&certificate).unwrap();
    let ca = pem::parse(ca).unwrap();
    let (_, ca) = X509Certificate::from_der(ca.contents()).unwrap();
    certificate.verify_signature(Some(ca.public_key())).unwrap();
    assert_eq!(
        lib::transport_primitives::replica_node_id_from_x509(&certificate).unwrap(),
        Some(intent.binding.replica_id)
    );
    let revoke = issue(
        "revoke-leaf",
        ReplicaIssuanceChange::Revoke {
            credential_id: prepare.operation_id.clone(),
        },
    );
    assert!(matches!(
        runtime.store.issue(&revoke).unwrap(),
        ReplicaIssuanceOutcome::Revoked { .. }
    ));
    drop(runtime);
    let runtime = LocalAuthority::open(directory.path());
    assert_eq!(runtime.store.issue(&publish).unwrap(), original);
    assert!(
        runtime
            .store
            .credential(&prepare.operation_id)
            .unwrap()
            .unwrap()
            .revoked
    );
    let mut fresh = publish.clone();
    fresh.operation_id = "new-publication-after-revocation".into();
    assert_eq!(
        runtime.store.issue(&fresh).unwrap(),
        ReplicaIssuanceOutcome::Rejected(ReplicaIssuanceRejection::CredentialRevoked)
    );
    let mut changed = prepare;
    if let ReplicaIssuanceChange::Prepare { intent, .. } = &mut changed.change {
        intent.subject_name = "different-actor".into();
    }
    assert_eq!(
        runtime.store.issue(&changed).unwrap(),
        ReplicaIssuanceOutcome::OperationMismatch
    );
}

#[test]
fn publication_races_allocation_retirement_and_current_ca_rotation_in_real_raft() {
    for rotate in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let runtime = LocalAuthority::open(directory.path());
        let (prepare, publish, intent, _) = credential_fixture(&runtime.store);
        let gate = Arc::new(Barrier::new(2));
        let worker = {
            let store = runtime.store.clone();
            let publish = publish.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                store.issue(&publish).unwrap()
            })
        };
        gate.wait();
        if rotate {
            assert!(matches!(
                runtime
                    .store
                    .issue(&issue(
                        "rotate-ca",
                        ReplicaIssuanceChange::Authority {
                            expected_revision: Some(1),
                            issuer_sha256: Some([5; 32])
                        }
                    ))
                    .unwrap(),
                ReplicaIssuanceOutcome::AuthorityChanged(_)
            ));
        } else {
            assert!(matches!(
                runtime
                    .store
                    .apply(&ReplicaBindingRequest {
                        operation_id: "retire-allocation".into(),
                        allocation: intent.binding.allocation.clone(),
                        change: ReplicaBindingChange::Retire {
                            expected_revision: intent.binding.revision
                        },
                    })
                    .unwrap(),
                ReplicaBindingOutcome::Applied(_)
            ));
        }
        let result = worker.join().unwrap();
        let reason = if rotate {
            ReplicaIssuanceRejection::AuthorityChanged
        } else {
            ReplicaIssuanceRejection::BindingChanged
        };
        assert!(
            matches!(&result, ReplicaIssuanceOutcome::Published { .. })
                || result == ReplicaIssuanceOutcome::Rejected(reason.clone())
        );
        let observed = runtime
            .store
            .credential(&prepare.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(observed.authority_denial, Some(reason.clone()));
        assert_eq!(
            observed.certificate_der.is_some(),
            matches!(result, ReplicaIssuanceOutcome::Published { .. })
        );
        assert_eq!(
            runtime.store.reconcile_issuance(&publish).unwrap(),
            Some(result.clone())
        );
        assert_eq!(runtime.store.issue(&publish).unwrap(), result);
        let mut fresh = publish;
        fresh.operation_id = "publication-after-revocation-boundary".into();
        assert_eq!(
            runtime.store.issue(&fresh).unwrap(),
            ReplicaIssuanceOutcome::Rejected(reason)
        );
    }
}
