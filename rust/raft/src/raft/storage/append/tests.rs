use super::*;
use raft::{Config, GetEntriesContext, RawNode};

fn entry(index: u64, term: u64) -> Entry {
    Entry {
        index,
        term,
        data: format!("{term}:{index}").into_bytes().into(),
        ..Default::default()
    }
}

fn history(storage: &RaftStorage) -> Vec<Entry> {
    storage
        .entries(
            storage.first_index_impl().unwrap(),
            storage.last_index_impl().unwrap() + 1,
            None,
            GetEntriesContext::empty(false),
        )
        .unwrap()
}

#[test]
fn shorter_replacement_removes_durable_tail_and_preserves_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let storage = RaftStorage::open(directory.path()).unwrap();
    storage
        .append(&(1..=7).map(|i| entry(i, 1)).collect::<Vec<_>>())
        .unwrap();
    storage
        .set_hard_state(&HardState {
            term: 1,
            commit: 2,
            ..Default::default()
        })
        .unwrap();
    storage.append(&[entry(3, 2), entry(4, 2)]).unwrap();
    let expected = vec![entry(1, 1), entry(2, 1), entry(3, 2), entry(4, 2)];
    assert_eq!(history(&storage), expected);
    assert_eq!(storage.last_index_impl().unwrap(), 4);
    drop(storage);
    let storage = RaftStorage::open(directory.path()).unwrap();
    assert_eq!(history(&storage), expected);
    assert_eq!(storage.initial_state_impl().unwrap().hard_state.commit, 2);
    storage.append(&[entry(5, 2)]).unwrap();
    assert_eq!(storage.last_index_impl().unwrap(), 5);
}

#[test]
fn invalid_replacement_leaves_original_log_and_hard_state() {
    let directory = tempfile::tempdir().unwrap();
    let storage = RaftStorage::open(directory.path()).unwrap();
    let original: Vec<_> = (1..=5).map(|i| entry(i, 1)).collect();
    storage.append(&original).unwrap();
    let hard = HardState {
        term: 2,
        commit: 3,
        ..Default::default()
    };
    storage.set_hard_state(&hard).unwrap();
    for invalid in [
        vec![entry(7, 2)],
        vec![entry(4, 2), entry(6, 2)],
        vec![entry(2, 2), entry(3, 2)],
        vec![entry(1, 1), entry(2, 1)],
    ] {
        assert!(storage.append(&invalid).is_err());
        assert_eq!(history(&storage), original);
        assert_eq!(storage.initial_state_impl().unwrap().hard_state, hard);
    }
    storage.append(&[]).unwrap();
    assert_eq!(history(&storage), original);
    storage.append(&original).unwrap();
    assert_eq!(history(&storage), original);
}

#[test]
fn compacted_prefix_stays_absent_across_overlapping_append() {
    let directory = tempfile::tempdir().unwrap();
    let storage = RaftStorage::open(directory.path()).unwrap();
    storage
        .append(&(1..=5).map(|i| entry(i, 1)).collect::<Vec<_>>())
        .unwrap();
    let mut snapshot = Snapshot::default();
    snapshot.mut_metadata().index = 3;
    snapshot.mut_metadata().term = 1;
    snapshot.mut_metadata().mut_conf_state().voters = vec![1];
    storage.store_snapshot(&snapshot).unwrap();
    storage.compact(4).unwrap();
    assert!(storage
        .append(&(1..=6).map(|i| entry(i, 1)).collect::<Vec<_>>())
        .is_err());
    storage.append(&[entry(6, 1)]).unwrap();
    assert_eq!(storage.first_index_impl().unwrap(), 4);
    assert_eq!(
        history(&storage),
        (4..=6).map(|i| entry(i, 1)).collect::<Vec<_>>()
    );
    assert!(storage.entries.get(&1u64.to_be_bytes()).unwrap().is_none());
    assert!(storage.append(&[entry(1, 1), entry(2, 1)]).is_err());
    assert_eq!(storage.last_index_impl().unwrap(), 6);
    assert_eq!(storage.term(3).unwrap(), 1);
}

#[test]
fn real_follower_restart_uses_the_new_leaders_shorter_log() {
    let directory = tempfile::tempdir().unwrap();
    let storage = RaftStorage::open(directory.path()).unwrap();
    storage
        .set_conf_state(&ConfState {
            voters: vec![1, 2],
            ..Default::default()
        })
        .unwrap();
    storage
        .append(&(1..=7).map(|i| entry(i, 1)).collect::<Vec<_>>())
        .unwrap();
    storage
        .set_hard_state(&HardState {
            term: 1,
            commit: 2,
            ..Default::default()
        })
        .unwrap();
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let config = Config {
        id: 2,
        applied: 2,
        ..Default::default()
    };
    let mut node = RawNode::new(&config, storage, &logger).unwrap();
    let mut append = raft::eraftpb::Message {
        from: 1,
        to: 2,
        term: 2,
        index: 2,
        log_term: 1,
        commit: 4,
        ..Default::default()
    };
    append.set_msg_type(raft::eraftpb::MessageType::MsgAppend);
    append.entries = vec![entry(3, 2), entry(4, 2)].into();
    node.step(append).unwrap();
    assert_eq!(node.raft.raft_log.last_index(), 4);
    assert!(node.has_ready());
    let ready = node.ready();
    node.mut_store().append(ready.entries()).unwrap();
    if let Some(hard) = ready.hs() {
        node.mut_store().set_hard_state(hard).unwrap();
    }
    let _ = node.advance(ready);
    drop(node);
    let storage = RaftStorage::open(directory.path()).unwrap();
    assert_eq!(storage.last_index_impl().unwrap(), 4);
    assert_eq!(
        history(&storage),
        vec![entry(1, 1), entry(2, 1), entry(3, 2), entry(4, 2)]
    );
    let restarted = RawNode::new(
        &Config {
            applied: 4,
            ..config
        },
        storage,
        &logger,
    )
    .unwrap();
    assert_eq!(restarted.raft.raft_log.last_index(), 4);
    assert_eq!(restarted.raft.raft_log.committed, 4);
}
