//! Compiled against the pinned previous reader by storage-format-compatibility.py.
#![cfg(all(feature = "grpc", has_protos))]

use nexus_raft::{
    raft::{
        FullStateMachine, RaftConfig, RaftStorage, StateMachine, WitnessStateMachine,
        ZoneConsensus, ZonePersistence,
    },
    storage::RedbStore,
    ZoneManager,
};
use std::{path::Path, time::Duration};

fn durable_contents(path: &Path) -> (u64, Vec<(String, Vec<u8>)>) {
    let persistence = ZonePersistence::open(path, "root").unwrap();
    let store = RedbStore::open(persistence.sm_path()).unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    let mut records = state.list_control_state("replica-binding").unwrap();
    records.extend(state.list_control_state("content-version-v1").unwrap());
    records.sort();
    (state.last_applied_index(), records)
}

#[test]
fn previous_reader_refuses_applied_compacted_and_snapshot_replica_formats() {
    let fixtures = std::path::PathBuf::from(
        std::env::var_os("NEXUS_REPLICA_FORMAT_FIXTURES").expect("fixture directory"),
    );
    for fixture in [
        "applied",
        "compacted",
        "snapshot",
        "node-applied",
        "node-compacted",
        "node-snapshot",
        "issuer-applied",
        "issuer-compacted",
        "issuer-snapshot",
    ] {
        let path = fixtures.join(fixture);
        let id = {
            let persistence = ZonePersistence::open(&path, "root").unwrap();
            let storage = RaftStorage::open(persistence.raft_path()).unwrap();
            storage.conf_state().unwrap().voters[0]
        };
        let before = durable_contents(&path);
        if fixture.ends_with("snapshot") {
            assert_eq!(before, (0, vec![]));
        } else {
            assert!(before.0 > 0 && !before.1.is_empty());
        }
        for fixed_local in [false, true] {
            let result = if fixed_local {
                ZoneManager::isolated(path.to_str().unwrap())
            } else {
                ZoneManager::with_node_id(
                    "previous-reader",
                    id,
                    path.to_str().unwrap(),
                    vec![],
                    "127.0.0.1:0",
                    None,
                    None,
                    None,
                )
            };
            match result {
                Err(error) => assert!(
                    error
                        .to_string()
                        .contains("unsupported protected-record storage format"),
                    "{fixture} fixed_local={fixed_local}: {error}"
                ),
                Ok(manager) => {
                    manager.shutdown();
                    panic!("previous reader admitted {fixture} fixed_local={fixed_local}");
                }
            }
            assert_eq!(durable_contents(&path), before);
        }
    }
    // An ordinary root still opens with this exact previous binary.
    let directory = tempfile::tempdir().unwrap();
    let runtime = ZoneManager::isolated(directory.path().to_str().unwrap()).unwrap();
    let root = runtime.create_zone("root", vec![]).unwrap();
    assert!(root.wait_for_leader(Duration::from_secs(5)));
    runtime.shutdown();
    refuse_versioned_raft_storage(&fixtures);
}

fn raft_contents(path: &Path) -> Vec<Vec<(Vec<u8>, Vec<u8>)>> {
    let store = RedbStore::open(path.join("raft.redb")).unwrap();
    ["raft_entries", "raft_state"]
        .into_iter()
        .map(|name| {
            store
                .tree(name)
                .unwrap()
                .iter()
                .map(|row| row.unwrap())
                .collect()
        })
        .collect()
}

fn refuse_versioned_raft_storage(fixtures: &Path) {
    for name in ["reader-prepared", "reader-compacted", "reader-snapshot"] {
        let path = fixtures.join(name);
        let before = raft_contents(&path);
        for witness in [false, true] {
            let storage = RaftStorage::open(&path).unwrap();
            let config = RaftConfig {
                id: 1,
                is_witness: witness,
                skip_bootstrap: true,
                ..Default::default()
            };
            let state_store =
                RedbStore::open(path.join(if witness { "witness.redb" } else { "full.redb" }))
                    .unwrap();
            let result = if witness {
                ZoneConsensus::new(
                    config,
                    storage,
                    WitnessStateMachine::new(&state_store).unwrap(),
                    None,
                )
                .map(|_| ())
            } else {
                ZoneConsensus::new(
                    config,
                    storage,
                    FullStateMachine::new(&state_store).unwrap(),
                    None,
                )
                .map(|_| ())
            };
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("invalid first_index"),
                "{name} witness={witness}"
            );
            assert_eq!(
                raft_contents(&path),
                before,
                "refused boot must preserve {name}"
            );
        }
    }
    // The identical old witness path admits an ordinary store.
    let directory = tempfile::tempdir().unwrap();
    let storage = RaftStorage::open(directory.path()).unwrap();
    let store = RedbStore::open(directory.path().join("witness.redb")).unwrap();
    let state = WitnessStateMachine::new(&store).unwrap();
    let (node, _driver) =
        ZoneConsensus::new(RaftConfig::witness(1, vec![]), storage, state, None).unwrap();
    assert!(node.is_witness());
}
