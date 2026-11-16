use super::*;
use crate::{
    raft::{Command, MembershipPolicy, StateMachine},
    storage::RedbStore,
};

fn command(operation: &str) -> Command {
    Command::ActivateReplicaControl {
        operation_id: operation.into(),
    }
}

fn applied(state: &mut FullStateMachine, index: u64, operation: &str) -> ReplicaControlActivation {
    match state.apply(index, &command(operation)).unwrap() {
        CommandResult::Value(bytes) => bincode::deserialize(&bytes).unwrap(),
        other => panic!("unexpected activation result: {other:?}"),
    }
}

#[test]
fn aborted_transaction_publishes_neither_reader_floor_nor_activation() {
    let store = RedbStore::open_temporary().unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    let transaction = store.raw().begin_write().unwrap();
    assert!(matches!(
        state
            .activate_replica_control_in_txn(&transaction, "aborted")
            .unwrap(),
        CommandResult::Value(_)
    ));
    transaction.abort().unwrap();
    assert_eq!(state.replica_control_activation().unwrap(), None);
    assert!(state
        .control_state
        .get(&requirement_key())
        .unwrap()
        .is_none());
    assert!(state
        .control_state
        .get(&activation_key())
        .unwrap()
        .is_none());
    assert_eq!(state.last_applied_index(), 0);
}

#[test]
fn original_activation_survives_retry_restart_and_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let store = RedbStore::open(directory.path().join("state")).unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    let original = applied(&mut state, 1, "original");
    assert_eq!(original.operation_id, "original");
    assert_eq!(applied(&mut state, 2, "original"), original);
    assert_eq!(applied(&mut state, 3, "another-operation"), original);
    assert_eq!(
        state.replica_control_activation().unwrap(),
        Some(original.clone())
    );
    assert_eq!(state.last_applied_index(), 3);
    let snapshot = state.snapshot().unwrap();
    drop((state, store));
    let store = RedbStore::open(directory.path().join("state")).unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    assert_eq!(
        state.replica_control_activation().unwrap(),
        Some(original.clone())
    );
    assert_eq!(state.last_applied_index(), 3);
    let target = RedbStore::open_temporary().unwrap();
    let mut restored = FullStateMachine::new(&target).unwrap();
    restored.restore_snapshot(&snapshot).unwrap();
    assert_eq!(
        restored.replica_control_activation().unwrap(),
        Some(original)
    );
    assert_eq!(restored.last_applied_index(), 3);
    for machine in [&state, &restored] {
        machine
            .validate_membership_policy(MembershipPolicy::FixedLocal)
            .unwrap();
        assert!(machine
            .validate_membership_policy(MembershipPolicy::Managed)
            .is_err());
        assert!(machine
            .validate_snapshot_membership(&snapshot, MembershipPolicy::Managed)
            .is_err());
    }
}

#[test]
fn generic_writes_and_ec_cannot_replace_or_erase_activation() {
    let store = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    assert!(state.apply_local(&command("ec")).is_err());
    let original = applied(&mut state, 1, "original");
    let writes = [
        Command::PutControlState {
            namespace: NAMESPACE.into(),
            key: "protocol:replica-control-v2".into(),
            value: vec![],
            if_absent: false,
        },
        Command::DeleteControlState {
            namespace: NAMESPACE.into(),
            key: "protocol:replica-control-v2".into(),
        },
    ];
    for (index, write) in writes.into_iter().enumerate() {
        assert!(state.apply_local(&write).is_err());
        assert!(matches!(
            state.apply(index as u64 + 2, &write).unwrap(),
            CommandResult::Error(_)
        ));
        assert_eq!(
            state.replica_control_activation().unwrap(),
            Some(original.clone())
        );
    }
}

#[test]
fn missing_original_fact_cannot_reactivate_from_the_reader_floor() {
    let store = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    applied(&mut state, 1, "original");
    // Model retained storage corruption through the raw test store. The generic
    // mutation APIs refuse this deletion in the separate ordinary-write case.
    state.control_state.delete(&activation_key()).unwrap();
    assert!(state.replica_control_activation().is_err());
    let fatal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.apply(2, &command("replacement"))
    }))
    .expect_err("committed storage corruption must stop apply");
    let message = fatal
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| fatal.downcast_ref::<&str>().copied())
        .expect("fatal apply error describes the corruption");
    assert!(message.contains("Fatal: storage error applying committed entry at index 2"));
    assert!(message.contains("reader requirement is missing its activation"));
    assert_eq!(state.last_applied_index(), 1);
    for policy in [MembershipPolicy::FixedLocal, MembershipPolicy::Managed] {
        assert!(state.validate_membership_policy(policy).is_err());
        assert!(state
            .validate_snapshot_membership(&state.snapshot().unwrap(), policy)
            .is_err());
    }
    let target = RedbStore::open_temporary().unwrap();
    let mut restored = FullStateMachine::new(&target).unwrap();
    assert!(restored
        .validate_snapshot_membership(&state.snapshot().unwrap(), MembershipPolicy::FixedLocal)
        .is_err());
    assert!(restored
        .restore_snapshot(&state.snapshot().unwrap())
        .is_err());
    assert_eq!(restored.last_applied_index(), 0);
}

#[test]
fn activation_requires_a_matching_reader_floor_and_valid_original_operation() {
    let store = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    for (index, operation) in ["".to_owned(), "a\nb".to_owned(), "x".repeat(257)]
        .iter()
        .enumerate()
    {
        assert!(matches!(
            state.apply(index as u64 + 1, &command(operation)).unwrap(),
            CommandResult::Error(_)
        ));
        assert_eq!(state.replica_control_activation().unwrap(), None);
        assert!(state
            .control_state
            .get(&requirement_key())
            .unwrap()
            .is_none());
    }
    let original = applied(&mut state, 4, "valid");
    state.control_state.delete(&requirement_key()).unwrap();
    assert!(state.replica_control_activation().is_err());
    assert_eq!(
        state.control_state.get(&activation_key()).unwrap(),
        Some(bincode::serialize(&original).unwrap())
    );
    assert!(state
        .validate_membership_policy(MembershipPolicy::FixedLocal)
        .is_err());
}

#[test]
fn older_writers_preserve_activation_and_its_reader_requirement() {
    let store = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    let original = applied(&mut state, 1, "original");
    let floor = state
        .control_state
        .get(&requirement_key())
        .unwrap()
        .unwrap();
    let transaction = store.raw().begin_write().unwrap();
    state
        .require_storage_format_in_txn(&transaction, StorageFormat::ReplicaIssuance)
        .unwrap();
    transaction.commit().unwrap();
    assert_eq!(
        state.control_state.get(&requirement_key()).unwrap(),
        Some(floor)
    );
    assert_eq!(state.replica_control_activation().unwrap(), Some(original));
}

#[test]
fn snapshot_cannot_erase_or_replace_the_original_activation() {
    let store = RedbStore::open_temporary().unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    let original = applied(&mut state, 1, "original");
    state
        .apply(
            2,
            &Command::SetMetadata {
                key: "/saved".into(),
                value: b"original data".to_vec(),
            },
        )
        .unwrap();
    for other in [None, Some("different-operation")] {
        let other_store = RedbStore::open_temporary().unwrap();
        let mut incoming = FullStateMachine::new(&other_store).unwrap();
        if let Some(operation) = other {
            applied(&mut incoming, 1, operation);
        }
        incoming.apply(100, &Command::Noop).unwrap();
        let snapshot = incoming.snapshot().unwrap();
        assert!(state
            .validate_snapshot_membership(&snapshot, MembershipPolicy::FixedLocal)
            .is_err());
        assert!(state.restore_snapshot(&snapshot).is_err());
        assert_eq!(
            state.replica_control_activation().unwrap(),
            Some(original.clone())
        );
        assert_eq!(state.last_applied_index(), 2);
        assert_eq!(
            state.get_metadata("/saved").unwrap(),
            Some(b"original data".to_vec())
        );
    }
    let other_store = RedbStore::open_temporary().unwrap();
    let mut incoming = FullStateMachine::new(&other_store).unwrap();
    applied(&mut incoming, 1, "original");
    incoming
        .apply(
            100,
            &Command::SetMetadata {
                key: "/later".into(),
                value: b"same authority".to_vec(),
            },
        )
        .unwrap();
    let snapshot = incoming.snapshot().unwrap();
    state.restore_snapshot(&snapshot).unwrap();
    assert_eq!(state.replica_control_activation().unwrap(), Some(original));
    assert_eq!(state.last_applied_index(), 100);
    assert_eq!(
        state.get_metadata("/later").unwrap(),
        Some(b"same authority".to_vec())
    );
}
