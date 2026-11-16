use super::*;
use crate::raft::{Command, CommandResult, StateMachine, WitnessStateMachineInMemory};
use crate::storage::RedbStore;

fn activate(state: &mut FullStateMachine, index: u64) {
    assert!(matches!(
        state
            .apply(
                index,
                &Command::ActivateReplicaControl {
                    operation_id: "original".into(),
                }
            )
            .unwrap(),
        CommandResult::Value(_)
    ));
}

#[test]
fn managed_reader_admits_only_the_exact_replica_domain_and_format_key() {
    let store = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    activate(&mut state, 1);
    state
        .apply(
            2,
            &Command::PutControlState {
                namespace: format!("{}-other", conditional_metadata::NAMESPACE),
                key: "ordinary".into(),
                value: b"ordinary data".to_vec(),
                if_absent: false,
            },
        )
        .unwrap();
    state
        .validate_storage_reader(MembershipPolicy::Managed, true)
        .unwrap();
    let image = state.snapshot().unwrap();
    state
        .validate_snapshot_reader(&image, MembershipPolicy::Managed, true)
        .unwrap();
    assert!(state
        .validate_storage_reader(MembershipPolicy::Managed, false)
        .is_err());
    assert!(state
        .validate_snapshot_reader(&image, MembershipPolicy::Managed, false)
        .is_err());

    state
        .apply(
            3,
            &Command::SetMetadata {
                key: "/private".into(),
                value: b"original".to_vec(),
            },
        )
        .unwrap();
    state
        .apply(
            4,
            &Command::AdoptProtectedMetadata {
                key: "/private".into(),
                expected_image: Some(b"original".to_vec()),
                incarnation: [4; 16],
            },
        )
        .unwrap();
    let version = state
        .get_versioned_metadata("/private")
        .unwrap()
        .version
        .unwrap();
    // The highest reader format remains present while lower-domain records are
    // added. Its ordinal must not grant conditional or record-lifetime access.
    for index in [5, 6] {
        assert_eq!(
            state
                .control_state
                .get(&requirement_key())
                .unwrap()
                .as_deref(),
            Some(StorageFormat::ReplicaControlActive.bytes())
        );
        let image = state.snapshot().unwrap();
        assert!(state
            .validate_storage_reader(MembershipPolicy::Managed, true)
            .is_err());
        assert!(state
            .validate_snapshot_reader(&image, MembershipPolicy::Managed, true)
            .is_err());
        state
            .validate_storage_reader(MembershipPolicy::FixedLocal, false)
            .unwrap();
        assert!(matches!(
            state
                .apply(
                    index,
                    &Command::AdmitRecordIoOwner {
                        key: "/private".into(),
                        expected_version: version.clone(),
                    }
                )
                .unwrap(),
            CommandResult::Success
        ));
    }
}

#[test]
fn witness_checks_replica_snapshot_reader_without_storing_business_activation() {
    let store = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    let witness = WitnessStateMachineInMemory::new();
    let ordinary = state.snapshot().unwrap();
    witness
        .validate_snapshot_reader(&ordinary, MembershipPolicy::Managed, false)
        .unwrap();
    activate(&mut state, 1);
    let image = state.snapshot().unwrap();
    assert!(witness
        .validate_snapshot_reader(&image, MembershipPolicy::Managed, false)
        .is_err());
    witness
        .validate_snapshot_reader(&image, MembershipPolicy::Managed, true)
        .unwrap();
    assert!(witness.replica_control_activation().unwrap().is_none());
    assert!(witness.snapshot().unwrap().is_empty());
}
