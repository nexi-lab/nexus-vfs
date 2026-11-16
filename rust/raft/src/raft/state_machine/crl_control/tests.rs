use super::*;
use crate::raft::state_machine::assert_snapshots_equal;
use crate::transport::{generate_crl, generate_zone_ca};
use crate::{
    raft::{Command, MembershipPolicy, StateMachine},
    storage::RedbStore,
};
use lib::transport_primitives::{ca_spki_sha256, verify_signed_crl, ForeignCaAnchor};

fn request(operation: &str, change: CrlControlChange) -> CrlControlRequest {
    CrlControlRequest {
        operation_id: operation.into(),
        change,
    }
}

fn local(operation: &str, revision: Option<u64>, ca: Option<&[u8]>) -> CrlControlRequest {
    request(
        operation,
        CrlControlChange::LocalIssuer {
            expected_revision: revision,
            ca_pem: ca.map(<[u8]>::to_vec),
        },
    )
}

fn install(operation: &str, revision: u64, crl: &[u8], ca: &[u8]) -> CrlControlRequest {
    request(
        operation,
        CrlControlChange::Install {
            issuer: CrlIssuerSelection::Local { revision },
            crl_pem: crl.to_vec(),
            observed_unix_s: verify_signed_crl(crl, ca).unwrap().this_update(),
            maximum_age_secs: 60,
        },
    )
}

fn apply(state: &mut FullStateMachine, request: &CrlControlRequest) -> CrlControlOutcome {
    let CommandResult::Value(bytes) = state
        .apply(
            state.last_applied_index() + 1,
            &Command::ApplyCrlControl(Box::new(request.clone())),
        )
        .unwrap()
    else {
        panic!("original typed result");
    };
    bincode::deserialize(&bytes).unwrap()
}

fn refused(outcome: CrlControlOutcome, text: &str) {
    let CrlControlOutcome::Refused(message) = outcome else {
        panic!("expected refusal, got {outcome:?}");
    };
    assert!(message.contains(text), "unexpected refusal: {message}");
}

fn enrolled(state: &mut FullStateMachine, ca: &[u8]) {
    assert!(matches!(
        apply(state, &local("initial-ca", None, Some(ca))),
        CrlControlOutcome::LocalIssuerChanged(LocalCrlIssuer { revision: 1, .. })
    ));
}

#[test]
fn original_receipt_does_not_reactivate_a_withdrawn_issuer() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.redb");
    let db = RedbStore::open(&path).unwrap();
    let mut state = FullStateMachine::new(&db).unwrap();
    let (ca, signer) = generate_zone_ca("original").unwrap();
    let initial = local("original-issuer", None, Some(&ca));
    assert_eq!(state.local_crl_issuer().unwrap(), None);
    assert_eq!(state.crl_control_receipt(&initial).unwrap(), None);
    let issued = apply(&mut state, &initial);
    let crl = generate_crl(&[], 1, &ca, &signer).unwrap();
    let publication = install("original-crl", 1, &crl, &ca);
    let installed = apply(&mut state, &publication);
    apply(&mut state, &local("withdraw", Some(1), None));
    let before = state.snapshot().unwrap();
    let withdrawn = Some(LocalCrlIssuer {
        revision: 2,
        ca_pem: None,
    });
    assert_eq!(state.local_crl_issuer().unwrap(), withdrawn);
    assert_eq!(state.crl_control_receipt(&initial).unwrap(), Some(issued));
    assert_eq!(
        state.crl_control_receipt(&publication).unwrap(),
        Some(installed)
    );
    let changed = local("original-issuer", Some(2), Some(&ca));
    assert_eq!(
        state.crl_control_receipt(&changed).unwrap(),
        Some(CrlControlOutcome::OperationMismatch)
    );
    let mut invalid = publication;
    invalid.operation_id.clear();
    assert!(state.crl_control_receipt(&invalid).is_err());
    assert_snapshots_equal(&state.snapshot().unwrap(), &before);
    drop(state);
    drop(db);
    let db = RedbStore::open(&path).unwrap();
    let reopened = FullStateMachine::new(&db).unwrap();
    assert_eq!(reopened.local_crl_issuer().unwrap(), withdrawn);
    assert_eq!(
        reopened.crl_control_receipt(&changed).unwrap(),
        Some(CrlControlOutcome::OperationMismatch)
    );
    assert_snapshots_equal(&reopened.snapshot().unwrap(), &before);
}

#[test]
fn abort_leaves_no_snapshot_revocations_receipt_floor_or_applied_index() {
    let db = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&db).unwrap();
    let (ca, signer) = generate_zone_ca("original").unwrap();
    let original = local("initial-ca", None, Some(&ca));
    let txn = state.control_state.raw_db().begin_write().unwrap();
    state.apply_crl_control(&txn, &original).unwrap();
    txn.abort().unwrap();
    assert!(state.list_control_state(NAMESPACE).unwrap().is_empty());
    assert!(state
        .control_state
        .get(&super::super::storage_admission::requirement_key())
        .unwrap()
        .is_none());
    assert_eq!(state.last_applied_index(), 0);
    enrolled(&mut state, &ca);
    let before = state.snapshot().unwrap();
    let crl = generate_crl(&[vec![0x80, 1]], 2, &ca, &signer).unwrap();
    let original = install("snapshot", 1, &crl, &ca);
    let txn = state.control_state.raw_db().begin_write().unwrap();
    state.apply_crl_control(&txn, &original).unwrap();
    txn.abort().unwrap();
    assert_snapshots_equal(&state.snapshot().unwrap(), &before);
    assert!(matches!(
        apply(&mut state, &original),
        CrlControlOutcome::Installed { .. }
    ));
    let authority = hex(&ca_spki_sha256(&ca).unwrap());
    assert_eq!(
        state
            .control_state
            .get(&key("snapshot", &authority))
            .unwrap(),
        Some(crl)
    );
    assert_eq!(
        state
            .control_state
            .get(&key("revoked", &format!("{authority}:8001")))
            .unwrap(),
        Some(b"revoked-v1".to_vec())
    );
    assert!(state
        .control_state
        .get(&key("operation", "snapshot"))
        .unwrap()
        .is_some());
    assert_eq!(state.last_applied_index(), 2);
}

#[test]
fn late_lower_and_conflicting_equal_numbers_cannot_replace_committed_snapshot() {
    let db = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&db).unwrap();
    let (ca, signer) = generate_zone_ca("original").unwrap();
    enrolled(&mut state, &ca);
    let older = generate_crl(&[], 3, &ca, &signer).unwrap();
    let current = generate_crl(&[vec![7]], 4, &ca, &signer).unwrap();
    // Both requests can be prepared before either proposal is committed.
    let delayed = install("delayed-lower", 1, &older, &ca);
    let winner = install("current", 1, &current, &ca);
    let original_outcome = apply(&mut state, &winner);
    assert!(matches!(
        original_outcome,
        CrlControlOutcome::Installed { .. }
    ));
    refused(apply(&mut state, &delayed), "number");
    let conflicting = generate_crl(&[vec![9]], 4, &ca, &signer).unwrap();
    refused(
        apply(
            &mut state,
            &install("conflicting-equal", 1, &conflicting, &ca),
        ),
        "another signed snapshot",
    );
    let authority = hex(&ca_spki_sha256(&ca).unwrap());
    assert_eq!(
        state
            .control_state
            .get(&key("snapshot", &authority))
            .unwrap(),
        Some(current.clone())
    );
    assert!(state
        .control_state
        .get(&key("revoked", &format!("{authority}:09")))
        .unwrap()
        .is_none());
    assert_eq!(apply(&mut state, &winner), original_outcome);
    let mut changed = winner.clone();
    changed.change = delayed.change;
    assert_eq!(
        apply(&mut state, &changed),
        CrlControlOutcome::OperationMismatch
    );
    apply(&mut state, &local("withdraw", Some(1), None));
    // Historical success is immutable and does not restore current authority.
    assert_eq!(apply(&mut state, &winner), original_outcome);
    refused(
        apply(&mut state, &install("after-withdraw", 1, &current, &ca)),
        "revision changed",
    );
    let current_issuer: LocalCrlIssuer = bincode::deserialize(
        &state
            .control_state
            .get(&key("issuer", "local"))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        current_issuer,
        LocalCrlIssuer {
            revision: 2,
            ca_pem: None
        }
    );
}

#[test]
fn pruning_restart_and_snapshot_keep_revocations_and_order_floor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.redb");
    let (ca, signer) = generate_zone_ca("original").unwrap();
    let original = generate_crl(&[vec![0, 0x80, 1]], 2, &ca, &signer).unwrap();
    let pruned = generate_crl(&[], 3, &ca, &signer).unwrap();
    let db = RedbStore::open(&path).unwrap();
    let mut state = FullStateMachine::new(&db).unwrap();
    enrolled(&mut state, &ca);
    apply(&mut state, &install("original", 1, &original, &ca));
    apply(&mut state, &install("pruned", 1, &pruned, &ca));
    let snapshot = state.snapshot().unwrap();
    assert_eq!(state.last_applied_index(), 3);
    drop(state);
    drop(db);
    let db = RedbStore::open(&path).unwrap();
    let mut state = FullStateMachine::new(&db).unwrap();
    assert_snapshots_equal(&state.snapshot().unwrap(), &snapshot);
    let authority = hex(&ca_spki_sha256(&ca).unwrap());
    assert!(state
        .control_state
        .get(&key("revoked", &format!("{authority}:8001")))
        .unwrap()
        .is_some());
    refused(
        apply(
            &mut state,
            &install("after-restart-lower", 1, &original, &ca),
        ),
        "number",
    );
    state
        .validate_membership_policy(MembershipPolicy::FixedLocal)
        .unwrap();
    assert!(state
        .validate_membership_policy(MembershipPolicy::Managed)
        .is_err());
    assert!(state
        .validate_snapshot_membership(&snapshot, MembershipPolicy::Managed)
        .is_err());
    assert_eq!(
        state
            .control_state
            .get(&super::super::storage_admission::requirement_key())
            .unwrap()
            .as_deref(),
        Some(b"signed-crl-control-v1".as_slice())
    );
}

#[test]
fn issuer_reinstallation_fences_a_prepared_request_even_with_identical_ca() {
    let db = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&db).unwrap();
    let (ca, signer) = generate_zone_ca("original").unwrap();
    enrolled(&mut state, &ca);
    let crl = generate_crl(&[], 2, &ca, &signer).unwrap();
    let prepared = install("old-installation", 1, &crl, &ca);
    assert!(matches!(
        apply(&mut state, &local("reinstall", Some(1), Some(&ca))),
        CrlControlOutcome::LocalIssuerChanged(LocalCrlIssuer { revision: 2, .. })
    ));
    refused(apply(&mut state, &prepared), "revision changed");
    assert!(matches!(
        apply(&mut state, &install("current-installation", 2, &crl, &ca)),
        CrlControlOutcome::Installed { .. }
    ));
}

#[test]
fn foreign_installation_uses_existing_exact_current_registration() {
    let db = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&db).unwrap();
    let (ca, signer) = generate_zone_ca("foreign").unwrap();
    let anchor = ForeignCaAnchor::from_pem("foreign-domain", &ca)
        .unwrap()
        .collaboration_only();
    let registration = anchor.encode().unwrap();
    let crl = generate_crl(&[vec![1]], 1, &ca, &signer).unwrap();
    let mut prepared = install("foreign-install", 1, &crl, &ca);
    if let CrlControlChange::Install { issuer, .. } = &mut prepared.change {
        *issuer = CrlIssuerSelection::Foreign {
            registration: registration.clone(),
        };
    }
    refused(apply(&mut state, &prepared), "registration changed");
    state
        .apply(
            state.last_applied_index() + 1,
            &Command::PutControlState {
                namespace: contracts::CONTROL_NS_FOREIGN_CA.into(),
                key: anchor.fingerprint_hex(),
                value: registration,
                if_absent: true,
            },
        )
        .unwrap();
    prepared.operation_id = "foreign-current".into();
    assert!(matches!(
        apply(&mut state, &prepared),
        CrlControlOutcome::Installed { .. }
    ));
    state
        .apply(
            state.last_applied_index() + 1,
            &Command::DeleteControlState {
                namespace: contracts::CONTROL_NS_FOREIGN_CA.into(),
                key: anchor.fingerprint_hex(),
            },
        )
        .unwrap();
    prepared.operation_id = "foreign-after-withdraw".into();
    refused(apply(&mut state, &prepared), "registration changed");
}

#[test]
fn untyped_and_eventual_writers_cannot_modify_signed_crl_state() {
    let db = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&db).unwrap();
    let (ca, _) = generate_zone_ca("original").unwrap();
    let original = local("initial-ca", None, Some(&ca));
    assert!(state
        .apply_local(&Command::ApplyCrlControl(Box::new(original.clone())))
        .is_err());
    enrolled(&mut state, &ca);
    let original_bytes = state.control_state.get(&key("issuer", "local")).unwrap();
    for command in [
        Command::PutControlState {
            namespace: NAMESPACE.into(),
            key: "issuer:local".into(),
            value: vec![],
            if_absent: false,
        },
        Command::DeleteControlState {
            namespace: NAMESPACE.into(),
            key: "issuer:local".into(),
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
    assert_eq!(
        state.control_state.get(&key("issuer", "local")).unwrap(),
        original_bytes
    );
}
