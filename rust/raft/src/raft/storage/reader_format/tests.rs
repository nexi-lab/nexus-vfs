use super::*;
use raft::GetEntriesContext;

fn entries(start: u64, end: u64) -> Vec<Entry> {
    (start..end)
        .map(|index| Entry {
            index,
            term: 2,
            ..Default::default()
        })
        .collect()
}

fn snapshot(index: u64) -> Snapshot {
    let mut result = Snapshot::default();
    result.mut_metadata().index = index;
    result.mut_metadata().term = 2;
    result.mut_metadata().mut_conf_state().voters = vec![1, 2];
    result
}

fn rows(tree: &RedbTree) -> Vec<(Vec<u8>, Vec<u8>)> {
    tree.iter().map(|row| row.unwrap()).collect()
}

#[test]
fn upgrade_and_reopen_preserve_log_membership_and_hard_state() {
    let directory = tempfile::tempdir().unwrap();
    let storage = RaftStorage::open(directory.path()).unwrap();
    storage.append(&entries(1, 4)).unwrap();
    storage
        .set_hard_state(&HardState {
            term: 2,
            vote: 1,
            commit: 2,
            ..Default::default()
        })
        .unwrap();
    storage
        .set_conf_state(&snapshot(2).take_metadata().take_conf_state())
        .unwrap();
    let original_state = storage.initial_state_impl().unwrap();
    let original_log = rows(&storage.entries);
    assert!(!storage.replica_control_reader_required().unwrap());
    assert_eq!(
        storage.state.get(KEY_FIRST_INDEX).unwrap().unwrap(),
        1u64.to_be_bytes()
    );
    storage.prepare_replica_control_reader().unwrap();
    let upgraded = rows(&storage.state);
    storage.prepare_replica_control_reader().unwrap();
    assert_eq!(
        rows(&storage.state),
        upgraded,
        "preparation must be idempotent"
    );
    drop(storage);

    let reopened = RaftStorage::open(directory.path()).unwrap();
    assert!(reopened.replica_control_reader_required().unwrap());
    assert_eq!(reopened.first_index_impl().unwrap(), 1);
    assert_eq!(reopened.last_index_impl().unwrap(), 3);
    let state = reopened.initial_state_impl().unwrap();
    assert_eq!(state.hard_state, original_state.hard_state);
    assert_eq!(state.conf_state, original_state.conf_state);
    assert_eq!(rows(&reopened.entries), original_log);
    assert_eq!(rows(&reopened.state), upgraded);
}

#[test]
fn replacement_compaction_and_snapshots_preserve_reader_requirement() {
    let directory = tempfile::tempdir().unwrap();
    let storage = RaftStorage::open(directory.path()).unwrap();
    storage.prepare_replica_control_reader().unwrap();
    storage.append(&entries(1, 7)).unwrap();
    storage
        .set_hard_state(&HardState {
            term: 2,
            vote: 1,
            commit: 3,
            ..Default::default()
        })
        .unwrap();
    storage.append(&entries(4, 6)).unwrap();
    assert_eq!(storage.last_index_impl().unwrap(), 5);
    storage.store_snapshot(&snapshot(3)).unwrap();
    storage.compact(4).unwrap();
    assert!(storage.replica_control_reader_required().unwrap());
    assert_eq!(storage.first_index_impl().unwrap(), 4);
    assert_eq!(
        storage
            .entries(4, 6, None, GetEntriesContext::empty(false))
            .unwrap(),
        entries(4, 6)
    );
    storage.apply_snapshot(&snapshot(8)).unwrap();
    storage.append(&entries(9, 11)).unwrap();
    assert_eq!(storage.first_index_impl().unwrap(), 9);
    assert_eq!(storage.last_index_impl().unwrap(), 10);
    let expected_state = storage.initial_state_impl().unwrap();
    assert_eq!(expected_state.hard_state.commit, 8);
    assert_eq!(expected_state.hard_state.vote, 1);
    drop(storage);

    let reopened = RaftStorage::open(directory.path()).unwrap();
    assert!(reopened.replica_control_reader_required().unwrap());
    assert_eq!(reopened.first_index_impl().unwrap(), 9);
    let state = reopened.initial_state_impl().unwrap();
    assert_eq!(state.hard_state, expected_state.hard_state);
    assert_eq!(state.conf_state, expected_state.conf_state);
    assert_eq!(reopened.snapshot(0, 1).unwrap(), snapshot(8));
}

#[test]
fn ordinary_snapshot_and_compaction_keep_the_original_index_encoding() {
    let directory = tempfile::tempdir().unwrap();
    let storage = RaftStorage::open(directory.path()).unwrap();
    storage.append(&entries(1, 4)).unwrap();
    storage.store_snapshot(&snapshot(2)).unwrap();
    storage.compact(3).unwrap();
    assert_eq!(
        storage.state.get(KEY_FIRST_INDEX).unwrap().unwrap(),
        3u64.to_be_bytes()
    );
    storage.apply_snapshot(&snapshot(8)).unwrap();
    assert_eq!(
        storage.state.get(KEY_FIRST_INDEX).unwrap().unwrap(),
        9u64.to_be_bytes()
    );
    assert!(!storage.replica_control_reader_required().unwrap());
}

#[test]
fn unknown_reader_format_cannot_be_reopened_or_replaced_by_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let storage = RaftStorage::open(directory.path()).unwrap();
    storage.append(&entries(1, 4)).unwrap();
    let unknown = [b"NXRIDX02".as_slice(), &1u64.to_be_bytes()].concat();
    storage.state.set(KEY_FIRST_INDEX, &unknown).unwrap();
    let before = (rows(&storage.state), rows(&storage.entries));
    for result in [
        storage.prepare_replica_control_reader(),
        storage.apply_snapshot(&snapshot(8)),
        storage.compact(3),
    ] {
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported Raft log-boundary format"));
        assert_eq!((rows(&storage.state), rows(&storage.entries)), before);
    }
    drop(storage);
    let error = match RaftStorage::open(directory.path()) {
        Ok(_) => panic!("an unknown reader format was admitted"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("unsupported Raft log-boundary format"));
    let store = RedbStore::open(directory.path().join("raft.redb")).unwrap();
    assert_eq!(
        (
            rows(&store.tree(TREE_STATE).unwrap()),
            rows(&store.tree(TREE_ENTRIES).unwrap())
        ),
        before
    );
}
