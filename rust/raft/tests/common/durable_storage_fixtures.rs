//! Persistent format fixtures shared by the current native producers.

use super::{FullStateMachine, RaftStorage, RedbStore, StateMachine, ZonePersistence};
use raft::{eraftpb::Snapshot, Storage};
use std::path::Path;

pub(crate) fn saved_image(path: &Path, compact: bool) -> Snapshot {
    let persistence = ZonePersistence::open(path, "root").unwrap();
    let store = RedbStore::open(persistence.sm_path()).unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    let storage = RaftStorage::open(persistence.raft_path()).unwrap();
    let index = state.last_applied_index();
    assert_eq!(index, storage.last_index_impl().unwrap());
    let mut snapshot = Snapshot::default();
    snapshot.data = state.snapshot().unwrap().into();
    snapshot.mut_metadata().index = index;
    snapshot.mut_metadata().term = storage.term(index).unwrap();
    snapshot
        .mut_metadata()
        .set_conf_state(storage.conf_state().unwrap());
    if compact {
        storage.store_snapshot(&snapshot).unwrap();
        storage.compact(index + 1).unwrap();
        assert_eq!(storage.first_index_impl().unwrap(), index + 1);
    }
    snapshot
}

pub(crate) fn install_snapshot(source: &Path, target: &Path, snapshot: &Snapshot) {
    std::fs::create_dir_all(target).unwrap();
    // Local root identity is durable and independent of the network replica ID.
    std::fs::copy(source.join(".node_id"), target.join(".node_id")).unwrap();
    let mut persistence = ZonePersistence::create(target, "root").unwrap();
    let storage = RaftStorage::open(persistence.raft_path()).unwrap();
    storage.apply_snapshot(snapshot).unwrap();
    let store = RedbStore::open(persistence.sm_path()).unwrap();
    FullStateMachine::new(&store).unwrap();
    persistence.commit();
}
