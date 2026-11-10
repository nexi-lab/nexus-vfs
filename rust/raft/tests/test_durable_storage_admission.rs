//! Real proposals, compacted history and snapshot-only recovery keep the same
//! storage admission boundary, including tombstones and retired allocations.
#![cfg(all(feature = "grpc", has_protos))]

use contracts::replica_binding::{
    ReplicaAllocation, ReplicaBindingChange, ReplicaBindingOutcome, ReplicaBindingRequest,
    ReplicaStorage,
};
use kernel::meta_store::{ConditionalMetadataResult, FileMetadata, MetaStore};
use nexus_raft::{
    raft::{
        FullStateMachine, RaftConfig, RaftStorage, StateMachine, ZoneConsensus, ZonePersistence,
    },
    replica_binding_store::RaftReplicaBindingStore,
    storage::RedbStore,
    zone_meta_store::ZoneMetaStore,
    ZoneManager,
};
use raft::{
    eraftpb::{Message, MessageType, Snapshot},
    Storage,
};
use std::{path::Path, sync::Arc, time::Duration};

const PATH: &str = "/__managed_content_v1__/session";

#[derive(Clone, Copy, Debug)]
enum Case {
    Content,
    ContentDeleted,
    Replica,
    ReplicaRetired,
}

const CASES: [Case; 4] = [
    Case::Content,
    Case::ContentDeleted,
    Case::Replica,
    Case::ReplicaRetired,
];

impl Case {
    fn namespace(self) -> &'static str {
        match self {
            Self::Content | Self::ContentDeleted => "content-version-v1",
            Self::Replica | Self::ReplicaRetired => contracts::constants::CONTROL_NS_REPLICA,
        }
    }
}

struct Runtime(Arc<ZoneManager>);

impl Runtime {
    fn open(path: &Path) -> Self {
        let manager = ZoneManager::isolated(path.to_str().unwrap()).unwrap();
        let root = manager.create_zone("root", vec![]).unwrap();
        assert!(root.wait_for_leader(Duration::from_secs(5)));
        Self(manager)
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

fn populate(path: &Path, case: Case) -> u64 {
    let runtime = Runtime::open(path);
    let node = runtime.0.get_zone("root").unwrap().consensus_node().clone();
    match case {
        Case::Content | Case::ContentDeleted => {
            let store = ZoneMetaStore::new_with_subtree(
                node.clone(),
                runtime.0.runtime_handle(),
                "/".into(),
                "/".into(),
            );
            assert!(matches!(
                store
                    .as_conditional_metadata()
                    .unwrap()
                    .replace_if_version(
                        PATH,
                        FileMetadata {
                            content_id: Some("durable-content".into()),
                            ..Default::default()
                        },
                        None,
                    )
                    .unwrap(),
                ConditionalMetadataResult::Committed { .. }
            ));
            if matches!(case, Case::ContentDeleted) {
                store.delete(PATH).unwrap();
            }
        }
        Case::Replica | Case::ReplicaRetired => {
            let store = RaftReplicaBindingStore::new(node.clone(), runtime.0.runtime_handle());
            let request = ReplicaBindingRequest {
                operation_id: "original".into(),
                allocation: ReplicaAllocation {
                    owner_id: "owner".into(),
                    allocation_id: "primary".into(),
                },
                change: ReplicaBindingChange::Register {
                    storage: ReplicaStorage {
                        authority: "cluster".into(),
                        uid: "pvc-incarnation".into(),
                    },
                    replica_id: 51,
                },
            };
            let ReplicaBindingOutcome::Applied(binding) = store.apply(&request).unwrap() else {
                panic!("binding was not committed");
            };
            if matches!(case, Case::ReplicaRetired) {
                assert!(matches!(
                    store
                        .apply(&ReplicaBindingRequest {
                            operation_id: "retirement".into(),
                            allocation: request.allocation,
                            change: ReplicaBindingChange::Retire {
                                expected_revision: binding.revision
                            },
                        })
                        .unwrap(),
                    ReplicaBindingOutcome::Applied(_)
                ));
            }
        }
    }
    runtime
        .0
        .runtime_handle()
        .block_on(node.read_linearizable(|_| ()))
        .unwrap();
    runtime.0.node_id()
}

fn saved_image(path: &Path, compact: bool) -> Snapshot {
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

fn install_snapshot(source: &Path, target: &Path, snapshot: &Snapshot) {
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

#[test]
fn replica_format_fixtures_for_previous_reader() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = std::env::var_os("NEXUS_REPLICA_FORMAT_FIXTURES")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_owned());
    for (name, case, compact) in [
        ("applied", Case::Replica, false),
        ("compacted", Case::ReplicaRetired, true),
    ] {
        let path = destination.join(name);
        std::fs::create_dir_all(&path).unwrap();
        populate(&path, case);
        let snapshot = saved_image(&path, compact);
        let persistence = ZonePersistence::open(&path, "root").unwrap();
        let db = RedbStore::open(persistence.sm_path()).unwrap();
        let state = FullStateMachine::new(&db).unwrap();
        assert_eq!(
            state
                .get_control_state("content-version-v1", "requires:protected-records-v1")
                .unwrap()
                .as_deref(),
            Some(b"replica-binding-v1".as_slice())
        );
        if compact {
            install_snapshot(&path, &destination.join("snapshot"), &snapshot);
        }
    }
}

fn refuse_managed(path: &Path, id: u64, case: Case) {
    match ZoneManager::with_node_id(
        "unqualified-mode-change",
        id,
        path.to_str().unwrap(),
        vec![],
        "127.0.0.1:0",
        None,
        None,
        None,
    ) {
        Err(error) => assert!(
            error.to_string().contains(case.namespace()),
            "{case:?}: {error}"
        ),
        Ok(manager) => {
            manager.shutdown();
            panic!("managed startup admitted {case:?}");
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DurableContents {
    control: Vec<(String, Vec<u8>)>,
    metadata: Option<Vec<u8>>,
}

fn contents(path: &Path, case: Case) -> DurableContents {
    let persistence = ZonePersistence::open(path, "root").unwrap();
    let store = RedbStore::open(persistence.sm_path()).unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    let mut control = state.list_control_state(case.namespace()).unwrap();
    control.sort();
    DurableContents {
        control,
        metadata: state.get_metadata(PATH).unwrap(),
    }
}

#[test]
fn applied_and_compacted_records_refuse_mode_changes_and_remain_recoverable() {
    for case in CASES {
        for compact in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let id = populate(directory.path(), case);
            saved_image(directory.path(), compact);
            let before = contents(directory.path(), case);
            assert!(!before.control.is_empty());
            refuse_managed(directory.path(), id, case);
            assert_eq!(contents(directory.path(), case), before);
            {
                let runtime = Runtime::open(directory.path());
                assert_eq!(runtime.0.node_id(), id);
            }
            assert_eq!(contents(directory.path(), case), before);
        }
    }
}

#[test]
fn snapshot_only_restart_refuses_before_restoring_into_an_empty_store() {
    for case in CASES {
        let source = tempfile::tempdir().unwrap();
        let id = populate(source.path(), case);
        let snapshot = saved_image(source.path(), false);
        let expected = contents(source.path(), case);
        let target = tempfile::tempdir().unwrap();
        install_snapshot(source.path(), target.path(), &snapshot);
        let empty = contents(target.path(), case);
        assert!(empty.control.is_empty());
        refuse_managed(target.path(), id, case);
        assert_eq!(contents(target.path(), case), empty);
        // The production local-root constructor admits and restores this image.
        {
            let runtime = Runtime(
                ZoneManager::with_local_root(
                    "qualified-local-root",
                    id,
                    target.path().to_str().unwrap(),
                    vec![],
                    "127.0.0.1:0",
                    None,
                    None,
                    None,
                )
                .unwrap(),
            );
            let root = runtime.0.create_zone("root", vec![]).unwrap();
            assert!(root.wait_for_leader(Duration::from_secs(5)));
            assert!(
                runtime
                    .0
                    .runtime_handle()
                    .block_on(
                        root.consensus_node()
                            .read_linearizable(|state| state.last_applied_index())
                    )
                    .unwrap()
                    >= snapshot.get_metadata().index
            );
        }
        assert_eq!(contents(target.path(), case), expected);
    }
}

#[tokio::test]
async fn managed_snapshot_ingress_rejects_durable_namespaces_before_enqueue() {
    for case in CASES {
        let snapshot = std::thread::spawn(move || {
            let source = tempfile::tempdir().unwrap();
            populate(source.path(), case);
            saved_image(source.path(), false)
        })
        .join()
        .unwrap();
        let target = tempfile::tempdir().unwrap();
        let storage = RaftStorage::open(target.path().join("raft")).unwrap();
        let store = RedbStore::open(target.path().join("state")).unwrap();
        let state = FullStateMachine::new(&store).unwrap();
        let (node, _driver) =
            ZoneConsensus::new(RaftConfig::default(), storage, state, None).unwrap();
        let before = node.last_index();
        let mut message = Message::default();
        message.set_msg_type(MessageType::MsgSnapshot);
        message.from = 2;
        message.to = 1;
        message.set_snapshot(snapshot);
        assert!(node
            .step(message)
            .await
            .unwrap_err()
            .to_string()
            .contains(case.namespace()));
        assert_eq!(node.last_index(), before);
        assert!(node
            .with_state_machine(|state| state.list_control_state(case.namespace()).unwrap())
            .await
            .is_empty());
    }
}
