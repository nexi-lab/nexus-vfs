use super::*;
use crate::{
    raft::{Command, MembershipPolicy, StateMachine},
    storage::RedbStore,
};
use contracts::{
    credential_intent::CertificateIntent,
    replica_binding::{
        ReplicaAllocation, ReplicaBindingChange, ReplicaBindingOutcome, ReplicaBindingRequest,
        ReplicaStorage,
    },
    SignedAgentCertificate,
};

fn fixture() -> (RedbStore, FullStateMachine, ReplicaCertificateIntent) {
    let store = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    let binding = ReplicaBindingRequest {
        operation_id: "allocate".into(),
        allocation: ReplicaAllocation {
            owner_id: "owner-a".into(),
            allocation_id: "primary".into(),
        },
        change: ReplicaBindingChange::Register {
            storage: ReplicaStorage {
                authority: "storage-a".into(),
                uid: "pvc-a".into(),
            },
            replica_id: 71,
        },
    };
    let CommandResult::Value(bytes) = state
        .apply(1, &Command::ApplyReplicaBinding(Box::new(binding)))
        .unwrap()
    else {
        panic!("binding");
    };
    let ReplicaBindingOutcome::Applied(binding) = bincode::deserialize(&bytes).unwrap() else {
        panic!("active");
    };
    apply(
        &mut state,
        "admit-ca",
        ReplicaIssuanceChange::Authority {
            expected_revision: None,
            issuer_sha256: Some([4; 32]),
        },
    );
    let intent = ReplicaCertificateIntent {
        version: 1,
        binding,
        issuer_revision: 1,
        subject_name: "replica-runtime".into(),
        certificate: CertificateIntent {
            issuer_sha256: [4; 32],
            subject_public_key_info_der: vec![3],
            serial: vec![5],
            not_before_unix_s: 100,
            not_after_unix_s: 400,
            tbs_certificate_der: vec![7],
        },
    };
    (store, state, intent)
}

fn apply(
    state: &mut FullStateMachine,
    operation: &str,
    change: ReplicaIssuanceChange,
) -> ReplicaIssuanceOutcome {
    let request = ReplicaIssuanceRequest {
        operation_id: operation.into(),
        change,
    };
    let CommandResult::Value(bytes) = state
        .apply(
            state.last_applied_index() + 1,
            &Command::ApplyReplicaIssuance(Box::new(request)),
        )
        .unwrap()
    else {
        panic!("issuance receipt");
    };
    bincode::deserialize(&bytes).unwrap()
}

fn prepare(intent: &ReplicaCertificateIntent, renews: Option<&str>) -> ReplicaIssuanceChange {
    ReplicaIssuanceChange::Prepare {
        intent: Box::new(intent.clone()),
        renews: renews.map(Into::into),
    }
}

fn publish(id: &str, intent: &ReplicaCertificateIntent) -> ReplicaIssuanceChange {
    ReplicaIssuanceChange::Publish {
        credential_id: id.into(),
        certificate: SignedAgentCertificate {
            certificate_der: vec![9],
            tbs_certificate_der: intent.certificate.tbs_certificate_der.clone(),
            serial: intent.certificate.serial.clone(),
        },
    }
}

#[test]
fn issuer_commit_abort_preserves_receipts_format_and_last_applied() {
    let store = RedbStore::open_temporary().unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    let request = ReplicaIssuanceRequest {
        operation_id: "first-ca".into(),
        change: ReplicaIssuanceChange::Authority {
            expected_revision: None,
            issuer_sha256: Some([1; 32]),
        },
    };
    let txn = state.control_state.raw_db().begin_write().unwrap();
    state.apply_replica_issuance(&txn, &request).unwrap();
    txn.abort().unwrap();
    assert!(state.list_control_state(NAMESPACE).unwrap().is_empty());
    assert!(state
        .list_control_state("content-version-v1")
        .unwrap()
        .is_empty());
    assert_eq!(state.last_applied_index(), 0);
    assert_eq!(state.replica_issuance_receipt(&request).unwrap(), None);
}

#[test]
fn publication_retirement_and_issuer_rotation_share_one_order() {
    for rotate in [false, true] {
        let (_store, mut state, intent) = fixture();
        assert!(matches!(
            apply(&mut state, "prepare", prepare(&intent, None)),
            ReplicaIssuanceOutcome::Prepared { .. }
        ));
        if rotate {
            assert!(matches!(
                apply(
                    &mut state,
                    "rotate",
                    ReplicaIssuanceChange::Authority {
                        expected_revision: Some(1),
                        issuer_sha256: Some([8; 32])
                    }
                ),
                ReplicaIssuanceOutcome::AuthorityChanged(_)
            ));
        } else {
            let request = ReplicaBindingRequest {
                operation_id: "retire".into(),
                allocation: intent.binding.allocation.clone(),
                change: ReplicaBindingChange::Retire {
                    expected_revision: intent.binding.revision,
                },
            };
            state
                .apply(
                    state.last_applied_index() + 1,
                    &Command::ApplyReplicaBinding(Box::new(request)),
                )
                .unwrap();
        }
        let expected = if rotate {
            ReplicaIssuanceRejection::AuthorityChanged
        } else {
            ReplicaIssuanceRejection::BindingChanged
        };
        assert_eq!(
            apply(&mut state, "publish", publish("prepare", &intent)),
            ReplicaIssuanceOutcome::Rejected(expected)
        );
        assert!(state
            .replica_credential("prepare")
            .unwrap()
            .unwrap()
            .certificate_der
            .is_none());
    }
}

#[test]
fn original_publication_and_revocation_survive_snapshot_without_reactivation() {
    let (_store, mut state, intent) = fixture();
    let prepared = apply(&mut state, "prepare", prepare(&intent, None));
    let published = apply(&mut state, "publish", publish("prepare", &intent));
    assert!(matches!(
        published,
        ReplicaIssuanceOutcome::Published { .. }
    ));
    apply(
        &mut state,
        "revoke",
        ReplicaIssuanceChange::Revoke {
            credential_id: "prepare".into(),
        },
    );
    assert_eq!(
        apply(&mut state, "prepare", prepare(&intent, None)),
        prepared
    );
    assert_eq!(
        apply(&mut state, "publish", publish("prepare", &intent)),
        published
    );
    assert!(
        state
            .replica_credential("prepare")
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        apply(&mut state, "new-publication", publish("prepare", &intent)),
        ReplicaIssuanceOutcome::Rejected(ReplicaIssuanceRejection::CredentialRevoked)
    );
    let snapshot = state.snapshot().unwrap();
    let target = RedbStore::open_temporary().unwrap();
    let mut restored = FullStateMachine::new(&target).unwrap();
    restored.restore_snapshot(&snapshot).unwrap();
    assert_eq!(restored.last_applied_index(), state.last_applied_index());
    assert_eq!(
        restored.replica_credential("prepare").unwrap(),
        state.replica_credential("prepare").unwrap()
    );
    assert_eq!(
        apply(&mut restored, "publish", publish("prepare", &intent)),
        published
    );
    assert!(
        restored
            .replica_credential("prepare")
            .unwrap()
            .unwrap()
            .revoked
    );
    assert!(restored
        .validate_membership_policy(MembershipPolicy::Managed)
        .is_err());
    assert!(restored
        .validate_membership_policy(MembershipPolicy::FixedLocal)
        .is_ok());
}

#[test]
fn renewal_preserves_identity_and_rechecks_predecessor_revocation_at_publication() {
    let (_store, mut state, intent) = fixture();
    apply(&mut state, "prepare", prepare(&intent, None));
    apply(&mut state, "publish", publish("prepare", &intent));
    let mut renewal = intent.clone();
    renewal.certificate.serial = vec![6];
    renewal.certificate.tbs_certificate_der = vec![8];
    // The controller verifies the predecessor's possession proof and the
    // new CSR. Renewal may rotate the holder key while retaining identity.
    renewal.certificate.subject_public_key_info_der = vec![77];
    assert!(matches!(
        apply(&mut state, "renew", prepare(&renewal, Some("prepare"))),
        ReplicaIssuanceOutcome::Prepared { .. }
    ));
    let observed = state.replica_credential("renew").unwrap().unwrap();
    assert_eq!(observed.renews.as_deref(), Some("prepare"));
    let mut wrong_subject = renewal.clone();
    wrong_subject.subject_name = "different-subject".into();
    assert_eq!(
        apply(
            &mut state,
            "wrong-subject",
            prepare(&wrong_subject, Some("prepare"))
        ),
        ReplicaIssuanceOutcome::Rejected(ReplicaIssuanceRejection::RenewalMismatch)
    );
    apply(
        &mut state,
        "revoke",
        ReplicaIssuanceChange::Revoke {
            credential_id: "prepare".into(),
        },
    );
    assert_eq!(
        apply(&mut state, "publish-renewal", publish("renew", &renewal)),
        ReplicaIssuanceOutcome::Rejected(ReplicaIssuanceRejection::CredentialRevoked)
    );
}

#[test]
fn exact_publication_is_immutable_and_changed_retries_preserve_original_receipts() {
    let (_store, mut state, intent) = fixture();
    apply(&mut state, "prepare", prepare(&intent, None));
    let mut changed = intent.clone();
    changed.certificate.serial = vec![6];
    assert_eq!(
        apply(&mut state, "prepare", prepare(&changed, None)),
        ReplicaIssuanceOutcome::OperationMismatch
    );
    assert_eq!(
        apply(&mut state, "wrong-cert", publish("prepare", &changed)),
        ReplicaIssuanceOutcome::Rejected(ReplicaIssuanceRejection::CertificateMismatch)
    );
    let original = apply(&mut state, "publish", publish("prepare", &intent));
    assert!(matches!(original, ReplicaIssuanceOutcome::Published { .. }));
    assert_eq!(
        apply(&mut state, "another-publish", publish("prepare", &intent)),
        ReplicaIssuanceOutcome::Rejected(ReplicaIssuanceRejection::AlreadyPublished)
    );
    assert_eq!(
        state
            .replica_credential("prepare")
            .unwrap()
            .unwrap()
            .certificate_der,
        Some(vec![9])
    );
    assert_eq!(
        apply(&mut state, "publish", publish("prepare", &intent)),
        original
    );
}

#[test]
fn authority_only_state_retains_floor_and_refuses_generic_mutations() {
    let store = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    let change = ReplicaIssuanceChange::Authority {
        expected_revision: None,
        issuer_sha256: Some([1; 32]),
    };
    apply(&mut state, "admit", change.clone());
    assert_eq!(
        state
            .get_control_state("content-version-v1", "requires:protected-records-v1")
            .unwrap()
            .as_deref(),
        Some(b"replica-issuance-v1".as_slice())
    );
    assert!(state
        .validate_membership_policy(MembershipPolicy::Managed)
        .is_err());
    assert_eq!(
        apply(&mut state, "another-admit", change),
        ReplicaIssuanceOutcome::Rejected(ReplicaIssuanceRejection::AuthorityChanged)
    );
    let disabled = apply(
        &mut state,
        "disable",
        ReplicaIssuanceChange::Authority {
            expected_revision: Some(1),
            issuer_sha256: None,
        },
    );
    assert_eq!(
        disabled,
        ReplicaIssuanceOutcome::AuthorityChanged(ReplicaIssuerAuthority {
            revision: 2,
            issuer_sha256: None
        })
    );
    let before = state.replica_issuer_authority().unwrap();
    for command in [
        Command::PutControlState {
            namespace: NAMESPACE.into(),
            key: "issuer:current".into(),
            value: vec![0],
            if_absent: false,
        },
        Command::DeleteControlState {
            namespace: NAMESPACE.into(),
            key: "issuer:current".into(),
        },
    ] {
        assert!(state.apply_local(&command).is_err());
        assert!(matches!(
            state
                .apply(state.last_applied_index() + 1, &command)
                .unwrap(),
            CommandResult::Error(_)
        ));
    }
    assert_eq!(state.replica_issuer_authority().unwrap(), before);
}
