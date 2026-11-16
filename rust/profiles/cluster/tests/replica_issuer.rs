//! Real persistent Raft, native CA signing and original-operation readback.
#![cfg(feature = "experimental-managed-agent-csr")]

use contracts::replica_binding::{
    ReplicaAllocation, ReplicaBinding, ReplicaBindingChange, ReplicaBindingOutcome,
    ReplicaBindingRequest, ReplicaStorage,
};
use contracts::replica_credential::{
    ReplicaIssuanceChange, ReplicaIssuanceRequest, ReplicaIssuerAuthority,
};
use nexus_cluster::replica_control::{ReplicaControlError, ReplicaController};
use nexus_cluster::replica_issuer::{ReplicaIssue, ReplicaIssuer, ReplicaIssuerError};
use nexus_raft::transport::{
    add_revoked_serial, generate_agent_cert, generate_node_cert, generate_zone_ca,
    prepare_replica_csr_intent, replica_renewal_message, ReplicaRenewalProof,
};
use nexus_raft::{
    replica_binding_store::{RaftReplicaBindingStore, ReplicaBindingError},
    ZoneManager,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use x509_parser::prelude::{FromDer, X509Certificate};

#[test]
fn current_node_reconciles_original_issuer_operation_after_ca_rotation() {
    let f = Fixture::open();
    let original = ReplicaIssuanceRequest {
        operation_id: "admit-ca".into(),
        change: ReplicaIssuanceChange::Authority {
            expected_revision: None,
            issuer_sha256: f.admitted.issuer_sha256,
        },
    };
    let prior = f
        .controller()
        .reconcile_issuer_control(&f.caller, &original)
        .unwrap();
    assert!(prior.is_some());
    let (ca, key) = generate_zone_ca("root").unwrap();
    let der = pem::parse(&ca).unwrap().into_contents();
    let (node, _) = generate_node_cert(3, "root", &ca, &key, &[], None).unwrap();
    let caller = pem::parse(node).unwrap().into_contents();
    let controller = ReplicaController::new(&f.authority.store, &der, &f.revocations);
    let rotation = ReplicaIssuanceRequest {
        operation_id: "rotate-original-issuer".into(),
        change: ReplicaIssuanceChange::Authority {
            expected_revision: Some(1),
            issuer_sha256: Some(lib::transport_primitives::cert_fingerprint(&der)),
        },
    };
    controller.apply_issuer_control(&caller, &rotation).unwrap();
    let current = controller.current_issuer(&caller).unwrap().unwrap();
    assert_eq!(current.revision, 2);
    assert_ne!(current.issuer_sha256, f.admitted.issuer_sha256);
    assert_eq!(
        controller
            .reconcile_issuer_control(&caller, &original)
            .unwrap(),
        prior
    );
    assert!(controller.apply_issuer_control(&caller, &original).is_err());
    assert!(controller
        .reconcile_issuer_control(&f.caller, &original)
        .is_err());
    assert_eq!(controller.current_issuer(&caller).unwrap(), Some(current));
}

#[test]
fn controller_binding_lifecycle_preserves_original_receipts_and_current_generation() {
    use contracts::replica_binding::ReplicaBindingState;

    let f = Fixture::open();
    let controller = f.controller();
    let original = ReplicaBindingRequest {
        operation_id: "register-secondary".into(),
        allocation: ReplicaAllocation {
            owner_id: "owner-a".into(),
            allocation_id: "secondary".into(),
        },
        change: ReplicaBindingChange::Register {
            storage: ReplicaStorage {
                authority: "storage-a".into(),
                uid: "pvc-first".into(),
            },
            replica_id: 87,
        },
    };
    assert_eq!(
        controller
            .current_binding(&f.caller, &original.allocation)
            .unwrap(),
        None
    );
    assert_eq!(
        controller.reconcile_binding(&f.caller, &original).unwrap(),
        None
    );
    let applied = controller.apply_binding(&f.caller, &original).unwrap();
    let ReplicaBindingOutcome::Applied(first) = &applied else {
        panic!("registration must commit")
    };
    assert_eq!(first.generation, 1);
    assert_eq!(
        controller.apply_binding(&f.caller, &original).unwrap(),
        applied
    );
    let mut changed = original.clone();
    changed.change = ReplicaBindingChange::Register {
        storage: ReplicaStorage {
            authority: "storage-a".into(),
            uid: "pvc-reused-name".into(),
        },
        replica_id: 88,
    };
    assert_eq!(
        controller.apply_binding(&f.caller, &changed).unwrap(),
        ReplicaBindingOutcome::OperationMismatch
    );
    assert_eq!(
        controller
            .current_binding(&f.caller, &original.allocation)
            .unwrap(),
        Some(first.clone())
    );
    let retire = ReplicaBindingRequest {
        operation_id: "retire-secondary".into(),
        allocation: original.allocation.clone(),
        change: ReplicaBindingChange::Retire {
            expected_revision: first.revision,
        },
    };
    let ReplicaBindingOutcome::Applied(retired) =
        controller.apply_binding(&f.caller, &retire).unwrap()
    else {
        panic!("retirement must commit")
    };
    assert_eq!(retired.state, ReplicaBindingState::Retired);
    let replacement = ReplicaBindingRequest {
        operation_id: "replace-secondary".into(),
        allocation: original.allocation.clone(),
        change: ReplicaBindingChange::Replace {
            expected_revision: retired.revision,
            storage: ReplicaStorage {
                authority: "storage-a".into(),
                uid: "pvc-reused-name".into(),
            },
            replica_id: 88,
        },
    };
    let ReplicaBindingOutcome::Applied(current) =
        controller.apply_binding(&f.caller, &replacement).unwrap()
    else {
        panic!("replacement must commit")
    };
    assert_eq!(current.generation, 2);
    assert_eq!(current.storage.uid, "pvc-reused-name");
    assert_eq!(
        controller.reconcile_binding(&f.caller, &original).unwrap(),
        Some(applied.clone())
    );
    assert_eq!(
        controller.apply_binding(&f.caller, &original).unwrap(),
        applied
    );
    assert_eq!(
        controller
            .current_binding(&f.caller, &original.allocation)
            .unwrap(),
        Some(current)
    );
    assert_eq!(f.authority.store.current_for_replica(87).unwrap(), None);
}

#[test]
fn controller_requires_current_local_node_before_lifecycle_reads_and_writes() {
    let f = Fixture::open();
    let controller = f.controller();
    let retire = ReplicaBindingRequest {
        operation_id: "denied-retirement".into(),
        allocation: f.binding.allocation.clone(),
        change: ReplicaBindingChange::Retire {
            expected_revision: f.binding.revision,
        },
    };
    let (agent, _) = generate_agent_cert("agent", &f.ca, &f.key).unwrap();
    let (replica, _) = nexus_raft::transport::generate_user_replica_cert(
        "replica", "owner-a", 47, 300, &f.ca, &f.key,
    )
    .unwrap();
    let (foreign_ca, foreign_key) = generate_zone_ca("foreign").unwrap();
    let (foreign, _) =
        generate_node_cert(2, "foreign", &foreign_ca, &foreign_key, &[], None).unwrap();
    for denied in [agent, replica, foreign] {
        let caller = pem::parse(denied).unwrap().into_contents();
        assert!(matches!(
            controller.apply_binding(&caller, &retire),
            Err(ReplicaControlError::Refused(_))
        ));
        assert!(controller
            .current_binding(&caller, &f.binding.allocation)
            .is_err());
        assert!(controller.reconcile_binding(&caller, &retire).is_err());
    }
    assert_eq!(
        controller
            .current_binding(&f.caller, &f.binding.allocation)
            .unwrap(),
        Some(f.binding.clone())
    );
    let (_, node) = X509Certificate::from_der(&f.caller).unwrap();
    add_revoked_serial(&f.revocations, node.raw_serial()).unwrap();
    assert!(controller.apply_binding(&f.caller, &retire).is_err());
    assert!(controller
        .current_binding(&f.caller, &f.binding.allocation)
        .is_err());
    assert!(controller.reconcile_binding(&f.caller, &retire).is_err());
    assert_eq!(
        f.authority.store.current(&f.binding.allocation).unwrap(),
        Some(f.binding.clone())
    );
    assert_eq!(f.authority.store.reconcile(&retire).unwrap(), None);
}

#[test]
fn controller_issuer_control_cannot_bypass_csr_preparation_or_admit_another_ca() {
    let f = Fixture::open();
    let controller = f.controller();
    let (prepare, _, _) = f.request("forbidden-preparation", None, 300);
    assert!(controller
        .apply_issuer_control(&f.caller, &prepare)
        .is_err());
    assert!(controller
        .reconcile_issuer_control(&f.caller, &prepare)
        .is_err());
    assert_eq!(
        f.authority
            .store
            .credential("forbidden-preparation")
            .unwrap(),
        None
    );
    assert_eq!(
        f.authority.store.reconcile_issuance(&prepare).unwrap(),
        None
    );
    let ReplicaIssuanceChange::Prepare { intent, .. } = &prepare.change else {
        panic!("prepared CSR intent")
    };
    let publish = ReplicaIssuanceRequest {
        operation_id: "forbidden-publication".into(),
        change: ReplicaIssuanceChange::Publish {
            credential_id: prepare.operation_id.clone(),
            certificate: nexus_raft::transport::sign_committed_replica_intent(
                intent, &f.ca, &f.key,
            )
            .unwrap(),
        },
    };
    assert!(controller
        .apply_issuer_control(&f.caller, &publish)
        .is_err());
    assert!(controller
        .reconcile_issuer_control(&f.caller, &publish)
        .is_err());
    assert_eq!(
        f.authority.store.reconcile_issuance(&publish).unwrap(),
        None
    );
    let foreign = ReplicaIssuanceRequest {
        operation_id: "wrong-local-ca".into(),
        change: ReplicaIssuanceChange::Authority {
            expected_revision: Some(1),
            issuer_sha256: Some([9; 32]),
        },
    };
    assert!(controller
        .apply_issuer_control(&f.caller, &foreign)
        .is_err());
    assert_eq!(
        f.authority.store.reconcile_issuance(&foreign).unwrap(),
        None
    );
    assert_eq!(
        controller.current_issuer(&f.caller).unwrap(),
        Some(f.admitted.clone())
    );
    let disabled = ReplicaIssuanceRequest {
        operation_id: "disable-local-issuer".into(),
        change: ReplicaIssuanceChange::Authority {
            expected_revision: Some(1),
            issuer_sha256: None,
        },
    };
    let outcome = controller
        .apply_issuer_control(&f.caller, &disabled)
        .unwrap();
    assert_eq!(
        controller
            .reconcile_issuer_control(&f.caller, &disabled)
            .unwrap(),
        Some(outcome)
    );
    assert_eq!(
        controller.current_issuer(&f.caller).unwrap(),
        Some(ReplicaIssuerAuthority {
            revision: 2,
            issuer_sha256: None
        })
    );
}

#[test]
fn controller_revocation_preserves_the_published_certificate_and_original_operation() {
    let f = Fixture::open();
    let (original, csr, _) = f.request("revoke-published", None, 300);
    let published = f
        .issuer()
        .issue(
            &f.caller,
            &ReplicaIssue {
                preparation: &original,
                publication_operation_id: "publish-before-revoke",
                csr_pem: csr.as_bytes(),
                renewal: None,
            },
        )
        .unwrap();
    let request = ReplicaIssuanceRequest {
        operation_id: "original-revocation".into(),
        change: ReplicaIssuanceChange::Revoke {
            credential_id: original.operation_id.clone(),
        },
    };
    let controller = f.controller();
    let outcome = controller
        .apply_issuer_control(&f.caller, &request)
        .unwrap();
    assert!(
        matches!(&outcome, contracts::replica_credential::ReplicaIssuanceOutcome::Revoked { credential_id } if credential_id == &original.operation_id)
    );
    assert_eq!(
        controller
            .apply_issuer_control(&f.caller, &request)
            .unwrap(),
        outcome
    );
    assert_eq!(
        controller
            .reconcile_issuer_control(&f.caller, &request)
            .unwrap(),
        Some(outcome)
    );
    let retained = f
        .authority
        .store
        .credential(&original.operation_id)
        .unwrap()
        .unwrap();
    assert!(retained.revoked);
    assert_eq!(retained.certificate_der, published.certificate_der);
    assert!(f.issuer().query(&f.caller, &original).is_err());
}

struct Authority {
    manager: Arc<ZoneManager>,
    store: RaftReplicaBindingStore,
}

impl Authority {
    fn open(path: &Path) -> Self {
        let manager = ZoneManager::isolated(path.to_str().unwrap()).unwrap();
        let root = manager.create_zone("root").unwrap();
        assert!(root.wait_for_leader(Duration::from_secs(5)));
        let node = root.consensus_node();
        let runtime = manager.runtime_handle();
        runtime.block_on(node.read_linearizable(|_| ())).unwrap();
        Self {
            manager,
            store: RaftReplicaBindingStore::new(node, runtime),
        }
    }
}

impl Drop for Authority {
    fn drop(&mut self) {
        self.manager.shutdown();
    }
}

struct Fixture {
    authority: Authority,
    root: tempfile::TempDir,
    ca: Vec<u8>,
    ca_der: Vec<u8>,
    key: Vec<u8>,
    caller: Vec<u8>,
    binding: ReplicaBinding,
    admitted: ReplicaIssuerAuthority,
    revocations: PathBuf,
}

impl Fixture {
    fn controller(&self) -> ReplicaController<'_> {
        ReplicaController::new(&self.authority.store, &self.ca_der, &self.revocations)
    }

    fn open() -> Self {
        let root = tempfile::tempdir().unwrap();
        let authority = Authority::open(&root.path().join("raft"));
        let (ca, key) = generate_zone_ca("root").unwrap();
        let ca_der = pem::parse(&ca).unwrap().into_contents();
        let (node, _) = generate_node_cert(1, "root", &ca, &key, &[], None).unwrap();
        let caller = pem::parse(node).unwrap().into_contents();
        let ReplicaBindingOutcome::Applied(binding) = authority
            .store
            .apply(&ReplicaBindingRequest {
                operation_id: "original-allocation".into(),
                allocation: ReplicaAllocation {
                    owner_id: "owner-a".into(),
                    allocation_id: "primary".into(),
                },
                change: ReplicaBindingChange::Register {
                    storage: ReplicaStorage {
                        authority: "storage-a".into(),
                        uid: "pvc-a".into(),
                    },
                    replica_id: 47,
                },
            })
            .unwrap()
        else {
            panic!("allocation")
        };
        let admitted = ReplicaIssuerAuthority {
            revision: 1,
            issuer_sha256: Some(Sha256::digest(&ca_der).into()),
        };
        authority
            .store
            .issue(&ReplicaIssuanceRequest {
                operation_id: "admit-ca".into(),
                change: ReplicaIssuanceChange::Authority {
                    expected_revision: None,
                    issuer_sha256: admitted.issuer_sha256,
                },
            })
            .unwrap();
        let revocations = root.path().join("revocations");
        Self {
            authority,
            root,
            ca,
            ca_der,
            key,
            caller,
            binding,
            admitted,
            revocations,
        }
    }

    fn issuer(&self) -> ReplicaIssuer<'_> {
        ReplicaIssuer::new(
            &self.authority.store,
            &self.ca_der,
            &self.ca,
            &self.key,
            &self.revocations,
        )
        .unwrap()
    }

    fn request(
        &self,
        id: &str,
        renews: Option<&str>,
        seconds: u64,
    ) -> (ReplicaIssuanceRequest, String, KeyPair) {
        let holder = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let csr = CertificateParams::default()
            .serialize_request(&holder)
            .unwrap()
            .pem()
            .unwrap();
        let intent = prepare_replica_csr_intent(
            &self.binding,
            &self.admitted,
            "replica-runtime",
            seconds,
            csr.as_bytes(),
            &self.ca,
        )
        .unwrap();
        (
            ReplicaIssuanceRequest {
                operation_id: id.into(),
                change: ReplicaIssuanceChange::Prepare {
                    intent: Box::new(intent),
                    renews: renews.map(Into::into),
                },
            },
            csr,
            holder,
        )
    }
}

fn issue<'a>(request: &'a ReplicaIssuanceRequest, csr: &'a str) -> ReplicaIssue<'a> {
    ReplicaIssue {
        preparation: request,
        publication_operation_id: "original-publication",
        csr_pem: csr.as_bytes(),
        renewal: None,
    }
}

#[test]
fn publication_replay_and_restart_keep_the_original_certificate() {
    let fixture = Fixture::open();
    let (request, csr, _) = fixture.request("original-credential", None, 300);
    let published = fixture
        .issuer()
        .issue(&fixture.caller, &issue(&request, &csr))
        .unwrap();
    assert!(published.certificate_der.is_some());
    assert_eq!(
        fixture
            .issuer()
            .issue(&fixture.caller, &issue(&request, &csr))
            .unwrap(),
        published
    );
    assert_eq!(
        fixture.issuer().query(&fixture.caller, &request).unwrap(),
        Some(published.clone())
    );
    drop(fixture.authority);
    let authority = Authority::open(&fixture.root.path().join("raft"));
    let restored = ReplicaIssuer::new(
        &authority.store,
        &fixture.ca_der,
        &fixture.ca,
        &fixture.key,
        &fixture.revocations,
    )
    .unwrap();
    assert_eq!(
        restored.query(&fixture.caller, &request).unwrap(),
        Some(published)
    );
}

#[test]
fn agent_foreign_node_and_revoked_controller_cannot_prepare() {
    let fixture = Fixture::open();
    let (request, csr, _) = fixture.request("controller-refusal", None, 300);
    let (agent, _) = generate_agent_cert("atlas-moss", &fixture.ca, &fixture.key).unwrap();
    let (foreign_ca, foreign_key) = generate_zone_ca("foreign").unwrap();
    let (foreign, _) = generate_node_cert(1, "root", &foreign_ca, &foreign_key, &[], None).unwrap();
    for pem in [agent, foreign] {
        let der = pem::parse(pem).unwrap().into_contents();
        assert!(matches!(
            fixture.issuer().issue(&der, &issue(&request, &csr)),
            Err(ReplicaIssuerError::Refused(_))
        ));
        assert_eq!(
            fixture
                .authority
                .store
                .credential(&request.operation_id)
                .unwrap(),
            None
        );
    }
    let (_, node) = X509Certificate::from_der(&fixture.caller).unwrap();
    add_revoked_serial(&fixture.revocations, node.raw_serial()).unwrap();
    assert!(matches!(
        fixture
            .issuer()
            .issue(&fixture.caller, &issue(&request, &csr)),
        Err(ReplicaIssuerError::Refused(_))
    ));
    assert_eq!(
        fixture
            .authority
            .store
            .credential(&request.operation_id)
            .unwrap(),
        None
    );
}

#[test]
fn invalid_possession_or_certificate_profile_has_no_preparation_effect() {
    let fixture = Fixture::open();
    let (request, csr, _) = fixture.request("csr-refusal", None, 300);
    let (_, wrong_csr, _) = fixture.request("other-holder", None, 300);
    assert!(matches!(
        fixture
            .issuer()
            .issue(&fixture.caller, &issue(&request, &wrong_csr)),
        Err(ReplicaIssuerError::Refused(_))
    ));
    let mut changed = request.clone();
    let ReplicaIssuanceChange::Prepare { intent, .. } = &mut changed.change else {
        unreachable!()
    };
    intent.subject_name = "different-subject-with-original-tbs".into();
    assert!(matches!(
        fixture
            .issuer()
            .issue(&fixture.caller, &issue(&changed, &csr)),
        Err(ReplicaIssuerError::Refused(_))
    ));
    assert_eq!(
        fixture
            .authority
            .store
            .credential(&request.operation_id)
            .unwrap(),
        None
    );
    assert!(fixture
        .issuer()
        .issue(&fixture.caller, &issue(&request, &csr))
        .unwrap()
        .certificate_der
        .is_some());
}

#[test]
fn signing_failure_preserves_original_preparation_for_readback() {
    let fixture = Fixture::open();
    let (request, csr, _) = fixture.request("signing-failure", None, 300);
    let (_, wrong_key) = generate_zone_ca("wrong-key").unwrap();
    let issuer = ReplicaIssuer::new(
        &fixture.authority.store,
        &fixture.ca_der,
        &fixture.ca,
        &wrong_key,
        &fixture.revocations,
    )
    .unwrap();
    assert!(matches!(
        issuer.issue(&fixture.caller, &issue(&request, &csr)),
        Err(ReplicaIssuerError::Store(ReplicaBindingError::Unknown(_)))
    ));
    let observed = fixture
        .issuer()
        .query(&fixture.caller, &request)
        .unwrap()
        .unwrap();
    assert!(observed.certificate_der.is_none());
    let ReplicaIssuanceChange::Prepare { intent, .. } = &request.change else {
        unreachable!()
    };
    assert_eq!(&observed.intent, intent.as_ref());
    // Query itself cannot sign or publish even though the corrected key exists.
    assert_eq!(
        fixture.issuer().query(&fixture.caller, &request).unwrap(),
        Some(observed)
    );
}

#[test]
fn retired_allocation_does_not_reactivate_from_a_published_receipt() {
    let fixture = Fixture::open();
    let (request, csr, _) = fixture.request("retired-credential", None, 300);
    fixture
        .issuer()
        .issue(&fixture.caller, &issue(&request, &csr))
        .unwrap();
    fixture
        .authority
        .store
        .apply(&ReplicaBindingRequest {
            operation_id: "retire-original-storage".into(),
            allocation: fixture.binding.allocation.clone(),
            change: ReplicaBindingChange::Retire {
                expected_revision: fixture.binding.revision,
            },
        })
        .unwrap();
    assert!(fixture.issuer().query(&fixture.caller, &request).is_err());
    assert!(fixture
        .issuer()
        .issue(&fixture.caller, &issue(&request, &csr))
        .is_err());
    assert!(fixture
        .authority
        .store
        .credential(&request.operation_id)
        .unwrap()
        .unwrap()
        .authority_denial
        .is_some());
}

#[test]
fn renewal_requires_original_holder_and_publishes_only_the_same_binding() {
    use lib::transport_primitives::authorship::sign;
    let fixture = Fixture::open();
    let (previous, csr, holder) = fixture.request("predecessor", None, 300);
    let published = fixture
        .issuer()
        .issue(&fixture.caller, &issue(&previous, &csr))
        .unwrap();
    let (request, csr, wrong_holder) = fixture.request("renewal", Some("predecessor"), 120);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let message = replica_renewal_message(
        &request,
        published.certificate_der.as_ref().unwrap(),
        &fixture.caller,
        now,
    )
    .unwrap();
    let wrong = sign(&message, wrong_holder.serialize_pem().as_bytes()).unwrap();
    let mut attempt = issue(&request, &csr);
    attempt.publication_operation_id = "renewal-publication";
    attempt.renewal = Some(ReplicaRenewalProof {
        issued_at_unix_ms: now,
        signature: &wrong,
    });
    assert!(fixture.issuer().issue(&fixture.caller, &attempt).is_err());
    assert_eq!(fixture.authority.store.credential("renewal").unwrap(), None);
    let proof = sign(&message, holder.serialize_pem().as_bytes()).unwrap();
    attempt.renewal = Some(ReplicaRenewalProof {
        issued_at_unix_ms: now,
        signature: &proof,
    });
    let renewed = fixture.issuer().issue(&fixture.caller, &attempt).unwrap();
    assert_eq!(renewed.intent.binding, fixture.binding);
    assert_eq!(renewed.renews.as_deref(), Some("predecessor"));
    assert!(renewed.certificate_der.is_some());
}

#[test]
fn concurrent_original_operation_returns_one_published_certificate() {
    let fixture = Fixture::open();
    let (request, csr, _) = fixture.request("concurrent-original", None, 300);
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let work = || {
            barrier.wait();
            fixture
                .issuer()
                .issue(&fixture.caller, &issue(&request, &csr))
                .unwrap()
        };
        let first = scope.spawn(work);
        let second = scope.spawn(work);
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!(results.0, results.1);
    assert!(results.0.certificate_der.is_some());
    assert_eq!(
        fixture.issuer().query(&fixture.caller, &request).unwrap(),
        Some(results.0)
    );
}
