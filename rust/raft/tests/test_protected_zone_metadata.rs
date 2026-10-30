//! Stable-path adoption through the actual Raft actor and persistent redb store.
#![cfg(all(feature = "grpc", has_protos))]

use kernel::meta_store::{
    ConditionalMetadataResult, FileMetadata, MetaStore, RecordProtection, RecordProtectionResult,
};
use nexus_raft::prelude::{Command, CommandResult, FullStateMachine, StateMachine};
use nexus_raft::raft::{RaftConfig, RaftStorage, ZoneConsensus, ZonePersistence};
use nexus_raft::storage::RedbStore;
use nexus_raft::zone_meta_store::ZoneMetaStore;
use nexus_raft::ZoneManager;
use raft::eraftpb::{Entry, Message, MessageType};
use std::sync::Arc;
use std::time::Duration;

const PATH: &str = "/conversations/stable-cid/readers/agent-a";

struct Runtime(Arc<ZoneManager>);

impl Runtime {
    fn open(directory: &std::path::Path) -> Self {
        let manager = ZoneManager::isolated(directory.to_str().unwrap()).unwrap();
        let zone = manager.create_zone("root", vec![]).unwrap();
        assert!(zone.wait_for_leader(Duration::from_secs(10)));
        Self(manager)
    }

    fn store(&self, mount: &str, subtree: &str) -> ZoneMetaStore {
        let zone = self.0.get_zone("root").unwrap();
        ZoneMetaStore::new_with_subtree(
            zone.consensus_node().clone(),
            self.0.runtime_handle(),
            mount.into(),
            subtree.into(),
        )
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

fn image(content: &str) -> FileMetadata {
    FileMetadata {
        content_id: Some(content.into()),
        size: 41,
        owner_id: Some("agent-owner".into()),
        ..Default::default()
    }
}

fn protected(store: &ZoneMetaStore, path: &str) -> Option<kernel::meta_store::MetadataSnapshot> {
    match store.protect_record(path, &|_| Ok(())).unwrap() {
        RecordProtectionResult::Protected => store
            .as_conditional_metadata()
            .unwrap()
            .read_versioned(path)
            .unwrap(),
        RecordProtectionResult::Conflict => panic!("quiescent adoption must commit"),
    }
}

#[test]
fn qualification_and_adoption_compare_the_same_legacy_image() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let alias = runtime.store("/alias", "/conversations/stable-cid/readers");
    store.put(PATH, image("qualified-image")).unwrap();
    let outcome = store
        .protect_record(PATH, &|metadata| {
            assert_eq!(metadata.path, PATH);
            assert_eq!(metadata.content_id.as_deref(), Some("qualified-image"));
            alias.put("/alias/agent-a", image("concurrent-image"))
        })
        .unwrap();
    assert_eq!(outcome, RecordProtectionResult::Conflict);
    assert_eq!(
        store.get(PATH).unwrap().unwrap().content_id.as_deref(),
        Some("concurrent-image")
    );
    assert!(store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(PATH)
        .is_err());
    // A conflicted admission has committed neither a policy nor a revision.
    store.put(PATH, image("still-ordinary")).unwrap();
    protected(&store, PATH).unwrap();
    assert!(store.put(PATH, image("now-refused")).is_err());
}

#[test]
fn failed_qualification_preserves_the_ordinary_record_and_its_policy() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    store.put(PATH, image("unqualified-content")).unwrap();
    assert!(store
        .protect_record(PATH, &|_| {
            Err(kernel::meta_store::MetaStoreError::IOError(
                "immutable object is unavailable".into(),
            ))
        })
        .is_err());
    assert_eq!(
        store.get(PATH).unwrap().unwrap().content_id.as_deref(),
        Some("unqualified-content")
    );
    store.put(PATH, image("ordinary-repair")).unwrap();
    assert!(store.delete(PATH).unwrap());
    store
        .put(
            PATH,
            FileMetadata {
                entry_type: kernel::meta_store::DT_DIR,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(matches!(
        store.protect_record(PATH, &|_| panic!("directories have no record content")),
        Err(kernel::meta_store::ConditionalMetadataError::Unsupported)
    ));
    assert!(store.delete(PATH).unwrap());
}

#[test]
fn protected_rename_refuses_before_publishing_a_destination() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    store.put(PATH, image("reader-position-41")).unwrap();
    let before = protected(&store, PATH).unwrap();
    let destination = "/conversations/stable-cid/readers/renamed-agent";
    assert!(store.rename_path(PATH, destination, false).is_err());
    assert!(
        store.get(destination).unwrap().is_none(),
        "rejected rename must not publish a destination"
    );
    let after = store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(PATH)
        .unwrap()
        .unwrap();
    assert_eq!(after.version, before.version);
    assert_eq!(after.metadata.content_id, before.metadata.content_id);
}

#[test]
fn deferred_alias_rename_uses_the_resolved_nodes_atomic_policy() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    store.put(PATH, image("reader-position-41")).unwrap();
    let before = protected(&store, PATH).unwrap();
    let alias = ZoneMetaStore::deferred_arc(
        runtime.0.registry(),
        "root",
        runtime.0.runtime_handle(),
        "/alias".into(),
        "/conversations/stable-cid/readers".into(),
    );
    assert!(alias
        .rename_path("/alias/agent-a", "/alias/renamed-agent", false)
        .is_err());
    assert!(alias.get("/alias/renamed-agent").unwrap().is_none());
    let after = store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(PATH)
        .unwrap()
        .unwrap();
    assert_eq!(after.version, before.version);
    assert_eq!(after.metadata.content_id, before.metadata.content_id);
    store
        .put("/ordinary/source", image("ordinary-content"))
        .unwrap();
    let ordinary_alias = ZoneMetaStore::deferred_arc(
        runtime.0.registry(),
        "root",
        runtime.0.runtime_handle(),
        "/ordinary-alias".into(),
        "/ordinary".into(),
    );
    ordinary_alias
        .rename_path("/ordinary-alias/source", "/ordinary-alias/target", false)
        .unwrap();
    assert!(store.get("/ordinary/source").unwrap().is_none());
    assert_eq!(
        store
            .get("/ordinary/target")
            .unwrap()
            .unwrap()
            .content_id
            .as_deref(),
        Some("ordinary-content")
    );
}

#[test]
fn rename_refreshes_conditional_revisions_for_both_paths() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let operation = store.as_conditional_metadata().unwrap();
    let source = "/__managed_content_v1__/source";
    let destination = "/__managed_content_v1__/target";
    for path in [source, destination] {
        assert!(matches!(
            operation
                .replace_if_version(path, image(path), None)
                .unwrap(),
            ConditionalMetadataResult::Committed { .. }
        ));
    }
    let old_source = operation.read_versioned(source).unwrap().unwrap();
    let old_target = operation.read_versioned(destination).unwrap().unwrap();
    store.rename_path(source, destination, false).unwrap();
    assert!(operation.read_versioned(source).unwrap().is_none());
    let after = operation.read_versioned(destination).unwrap().unwrap();
    assert_ne!(after.version, old_source.version);
    assert_ne!(after.version, old_target.version);
    assert_eq!(after.metadata.content_id, old_source.metadata.content_id);
    for (path, version) in [
        (source, old_source.version),
        (destination, old_target.version),
    ] {
        assert!(matches!(
            operation
                .replace_if_version(path, image("stale"), Some(&version))
                .unwrap(),
            ConditionalMetadataResult::Conflict { .. }
        ));
    }
    assert!(operation.read_versioned(source).unwrap().is_none());
    assert_eq!(
        operation
            .read_versioned(destination)
            .unwrap()
            .unwrap()
            .version,
        after.version
    );
}

#[test]
fn a_moved_subtree_carries_existing_revision_eligibility_to_new_paths() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/view", "/__managed_content_v1__");
    let operation = store.as_conditional_metadata().unwrap();
    store
        .put(
            "/view/source",
            FileMetadata {
                entry_type: kernel::meta_store::DT_DIR,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(matches!(
        operation
            .replace_if_version("/view/source/tracked", image("qualified-source"), None)
            .unwrap(),
        ConditionalMetadataResult::Committed { .. }
    ));
    let original = operation
        .read_versioned("/view/source/tracked")
        .unwrap()
        .unwrap();
    store
        .put("/view/source/legacy", image("ordinary-source"))
        .unwrap();
    store
        .rename_path("/view/source", "/view/destination", false)
        .unwrap();
    assert!(operation
        .read_versioned("/view/source/tracked")
        .unwrap()
        .is_none());
    let moved = operation
        .read_versioned("/view/destination/tracked")
        .unwrap()
        .unwrap();
    assert_ne!(moved.version, original.version);
    assert_eq!(moved.metadata.content_id, original.metadata.content_id);
    assert_eq!(moved.metadata.path, "/view/destination/tracked");
    assert!(matches!(
        operation
            .replace_if_version(
                "/view/destination/tracked",
                image("stale-source-token"),
                Some(&original.version)
            )
            .unwrap(),
        ConditionalMetadataResult::Conflict { .. }
    ));
    // An unrelated ordinary child remains outside conditional admission.
    assert!(matches!(
        operation.read_versioned("/view/destination/legacy"),
        Err(kernel::meta_store::ConditionalMetadataError::Unsupported)
    ));
    assert_eq!(
        store
            .get("/view/destination/legacy")
            .unwrap()
            .unwrap()
            .content_id
            .as_deref(),
        Some("ordinary-source")
    );
}

#[test]
fn malformed_subtree_rename_refuses_without_partial_effects_and_actor_keeps_serving() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    store.put("/source/a", image("valid")).unwrap();
    let node = runtime.0.get_zone("root").unwrap().consensus_node().clone();
    runtime
        .0
        .runtime_handle()
        .block_on(node.propose(Command::SetMetadata {
            key: "/source/b".into(),
            value: vec![0xff],
        }))
        .unwrap();
    assert!(store.rename_path("/source", "/target", false).is_err());
    assert_eq!(
        store
            .get("/source/a")
            .unwrap()
            .unwrap()
            .content_id
            .as_deref(),
        Some("valid")
    );
    assert!(store.get("/target/a").unwrap().is_none());
    store
        .put("/after-refusal", image("actor-still-serving"))
        .unwrap();
    assert_eq!(
        store
            .get("/after-refusal")
            .unwrap()
            .unwrap()
            .content_id
            .as_deref(),
        Some("actor-still-serving")
    );
}

#[test]
fn subtree_rename_preserves_raw_fields_and_updates_every_cached_view() {
    use nexus_raft::transport::proto::nexus::core::FileMetadata as Proto;
    use prost::Message as _;

    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/left", "/records");
    let alias = runtime.store("/right", "/records");
    let node = runtime.0.get_zone("root").unwrap().consensus_node().clone();
    let original = Proto {
        path: "/records/source".into(),
        content_id: "source-content".into(),
        owner_id: "owner".into(),
        ttl_seconds: 57.0,
        created_at: "2026-10-30T00:00:00Z".into(),
        modified_at: "2026-10-30T01:00:00Z".into(),
        ..Default::default()
    };
    runtime
        .0
        .runtime_handle()
        .block_on(node.propose(Command::SetMetadata {
            key: original.path.clone(),
            value: original.encode_to_vec(),
        }))
        .unwrap();
    store
        .put("/left/source/child", image("child-content"))
        .unwrap();
    store
        .put("/left/source-neighbor", image("neighbor-content"))
        .unwrap();
    store.put("/left/target", image("previous-target")).unwrap();
    assert!(alias.get("/right/source").unwrap().is_some());
    assert!(alias.get("/right/source/child").unwrap().is_some());
    assert_eq!(
        alias
            .get("/right/target")
            .unwrap()
            .unwrap()
            .content_id
            .as_deref(),
        Some("previous-target")
    );
    store
        .rename_path("/left/source", "/left/target", false)
        .unwrap();
    assert!(alias.get("/right/source").unwrap().is_none());
    assert!(alias.get("/right/source/child").unwrap().is_none());
    assert_eq!(
        alias
            .get("/right/target")
            .unwrap()
            .unwrap()
            .content_id
            .as_deref(),
        Some("source-content")
    );
    let child = alias.get("/right/target/child").unwrap().unwrap();
    assert_eq!(child.path, "/right/target/child");
    assert_eq!(child.content_id.as_deref(), Some("child-content"));
    assert_eq!(
        store
            .get("/left/source-neighbor")
            .unwrap()
            .unwrap()
            .content_id
            .as_deref(),
        Some("neighbor-content")
    );
    let raw = runtime.0.runtime_handle().block_on(
        node.with_state_machine(|state| state.get_metadata("/records/target").unwrap().unwrap()),
    );
    let renamed = Proto::decode(raw.as_slice()).unwrap();
    assert_eq!(renamed.path, "/records/target");
    assert_eq!(renamed.ttl_seconds, original.ttl_seconds);
    assert_eq!(renamed.created_at, original.created_at);
    assert_eq!(renamed.modified_at, original.modified_at);
    assert_eq!(renamed.owner_id, original.owner_id);
    drop(node);
    drop(alias);
    drop(store);
    drop(runtime);
    let restarted = Runtime::open(directory.path());
    let store = restarted.store("/restored", "/records");
    assert!(store.get("/restored/source").unwrap().is_none());
    assert_eq!(
        store
            .get("/restored/target/child")
            .unwrap()
            .unwrap()
            .content_id
            .as_deref(),
        Some("child-content")
    );
}

#[test]
fn protected_descendant_and_destination_keep_the_entire_rename_unchanged() {
    for protection in ["/source/b", "/target/b"] {
        let directory = tempfile::tempdir().unwrap();
        let runtime = Runtime::open(directory.path());
        let store = runtime.store("/", "/");
        for (path, content) in [
            ("/source/a", "a"),
            ("/source/b", "b"),
            ("/target", "existing"),
        ] {
            store.put(path, image(content)).unwrap();
        }
        protected(&store, protection);
        let node = runtime.0.get_zone("root").unwrap().consensus_node().clone();
        let before = runtime
            .0
            .runtime_handle()
            .block_on(node.with_state_machine(|state| state.list_metadata("/").unwrap()));
        assert!(store.rename_path("/source", "/target", false).is_err());
        let after = runtime
            .0
            .runtime_handle()
            .block_on(node.with_state_machine(|state| state.list_metadata("/").unwrap()));
        assert_eq!(
            after, before,
            "protected entry {protection} must abort every mutation"
        );
        assert_eq!(
            store.get("/target").unwrap().unwrap().content_id.as_deref(),
            Some("existing")
        );
        assert!(store.get("/target/a").unwrap().is_none());
    }
}

#[test]
fn pas_rename_keeps_relative_content_paths_consistent_across_subtree_views() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/visible", "/namespace/root");
    let alias = runtime.store("/alias", "/namespace/root");
    store.put("/visible/source/a", image("source/a")).unwrap();
    store
        .put("/visible/source/b", image("opaque:connector-id"))
        .unwrap();
    store
        .rename_path("/visible/source", "/visible/target", true)
        .unwrap();
    assert_eq!(
        alias
            .get("/alias/target/a")
            .unwrap()
            .unwrap()
            .content_id
            .as_deref(),
        Some("target/a")
    );
    assert_eq!(
        alias
            .get("/alias/target/b")
            .unwrap()
            .unwrap()
            .content_id
            .as_deref(),
        Some("opaque:connector-id")
    );
    assert!(alias.get("/alias/source/a").unwrap().is_none());
}

#[test]
fn namespace_rename_preserves_service_owned_endpoints_and_mounts() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    for entry_type in [2, 3, 4, 5] {
        let source = format!("/source-{entry_type}");
        let destination = format!("/target-{entry_type}");
        let endpoint = FileMetadata {
            entry_type,
            ..image("endpoint")
        };
        store.put(&source, endpoint.clone()).unwrap();
        assert!(store.rename_path(&source, &destination, false).is_err());
        assert!(store.get(&source).unwrap().is_some());
        assert!(store.get(&destination).unwrap().is_none());
        store.put(&destination, endpoint).unwrap();
        store.put(&source, image("ordinary")).unwrap();
        assert!(store.rename_path(&source, &destination, false).is_err());
        assert_eq!(
            store.get(&source).unwrap().unwrap().content_id.as_deref(),
            Some("ordinary")
        );
        assert_eq!(
            store.get(&destination).unwrap().unwrap().entry_type,
            entry_type
        );
    }
}

#[test]
fn adoption_retains_the_path_and_image_and_fences_ordinary_writes_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let version;
    {
        let runtime = Runtime::open(directory.path());
        let store = runtime.store("/", "/");
        store.put(PATH, image("legacy-offset-41")).unwrap();
        let legacy = store.get(PATH).unwrap().unwrap();
        let node = runtime.0.get_zone("root").unwrap().consensus_node().clone();
        let raw_before = runtime
            .0
            .runtime_handle()
            .block_on(node.with_state_machine(|state| state.get_metadata(PATH).unwrap()));
        assert!(store
            .as_conditional_metadata()
            .unwrap()
            .read_versioned(PATH)
            .is_err());
        let snapshot = protected(&store, PATH).unwrap();
        assert_eq!(
            runtime
                .0
                .runtime_handle()
                .block_on(node.with_state_machine(|state| state.get_metadata(PATH).unwrap()),),
            raw_before,
            "adoption must preserve every serialized field of the legacy image",
        );
        assert_eq!(snapshot.metadata.path, PATH);
        assert_eq!(snapshot.metadata.content_id, legacy.content_id);
        assert_eq!(snapshot.metadata.owner_id, legacy.owner_id);
        assert_eq!(snapshot.metadata.size, legacy.size);
        let operation = store.as_conditional_metadata().unwrap();
        version = match operation
            .replace_if_version(PATH, image("accepted-offset-82"), Some(&snapshot.version))
            .unwrap()
        {
            ConditionalMetadataResult::Committed { version } => version,
            result => panic!("current holder must commit: {result:?}"),
        };
        assert!(store.put(PATH, image("late-offset-0")).is_err());
        assert!(store.delete(PATH).is_err());
        assert_eq!(protected(&store, PATH).unwrap().version, version);
        assert_eq!(
            operation
                .read_versioned(PATH)
                .unwrap()
                .unwrap()
                .metadata
                .content_id
                .as_deref(),
            Some("accepted-offset-82")
        );
    }
    {
        let runtime = Runtime::open(directory.path());
        let store = runtime.store("/", "/");
        assert!(store.put(PATH, image("restart-offset-0")).is_err());
        let snapshot = store
            .as_conditional_metadata()
            .unwrap()
            .read_versioned(PATH)
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.version, version);
        assert_eq!(
            snapshot.metadata.content_id.as_deref(),
            Some("accepted-offset-82")
        );
    }
}

#[test]
fn a_reserved_absent_path_excludes_legacy_creates_and_aliases_share_its_policy() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let alias = runtime.store("/alias", "/conversations/stable-cid/readers");
    assert!(protected(&store, PATH).is_none());
    assert!(store.put(PATH, image("legacy-create")).is_err());
    assert!(alias.put("/alias/agent-a", image("alias-create")).is_err());
    let operation = alias.as_conditional_metadata().unwrap();
    assert!(matches!(
        operation
            .replace_if_version("/alias/agent-a", image("first-accepted-position"), None)
            .unwrap(),
        ConditionalMetadataResult::Committed { .. }
    ));
    assert_eq!(
        store.get(PATH).unwrap().unwrap().content_id.as_deref(),
        Some("first-accepted-position")
    );
    assert!(alias.delete("/alias/agent-a").is_err());
}

#[test]
fn ec_origin_peer_ingress_and_export_preserve_the_adopted_image() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    store.put(PATH, image("durable-position")).unwrap();
    let snapshot = protected(&store, PATH).unwrap();
    let node = runtime.0.get_zone("root").unwrap().consensus_node().clone();
    let before = node.ec_wal_bounds().unwrap();
    for mutation in [
        Command::SetMetadata {
            key: PATH.into(),
            value: b"stale".to_vec(),
        },
        Command::CasSetMetadata {
            key: PATH.into(),
            value: b"stale".to_vec(),
            expected_version: 0,
        },
        Command::DeleteMetadata { key: PATH.into() },
        Command::AdjustCounter {
            key: PATH.into(),
            delta: 1,
        },
    ] {
        assert!(runtime
            .0
            .runtime_handle()
            .block_on(node.propose_ec_local(mutation.clone()))
            .is_err());
        assert!(matches!(
            runtime
                .0
                .runtime_handle()
                .block_on(node.apply_ec_from_peer(mutation.clone(), u64::MAX))
                .unwrap(),
            CommandResult::Success
        ));
        assert!(matches!(
            runtime
                .0
                .runtime_handle()
                .block_on(node.propose(mutation))
                .unwrap(),
            CommandResult::Error(_)
        ));
    }
    assert_eq!(node.ec_wal_bounds().unwrap(), before);
    assert_eq!(
        store
            .as_conditional_metadata()
            .unwrap()
            .read_versioned(PATH)
            .unwrap()
            .unwrap()
            .version,
        snapshot.version
    );
    let exported = runtime
        .0
        .runtime_handle()
        .block_on(node.with_state_machine(|state| state.ec_state_snapshot()))
        .unwrap();
    assert!(exported
        .iter()
        .all(|command| !matches!(command, Command::SetMetadata { key, .. } if key == PATH)));
}

#[test]
fn protected_storage_refuses_a_managed_reopen_without_changing_the_original_record() {
    let directory = tempfile::tempdir().unwrap();
    let (id, before) = {
        let runtime = Runtime::open(directory.path());
        let store = runtime.store("/", "/");
        store.put(PATH, image("committed-before-reopen")).unwrap();
        let before = protected(&store, PATH).unwrap();
        (runtime.0.node_id(), before)
    };
    {
        let result = ZoneManager::with_node_id(
            "unsupported-protected-reopen",
            id,
            directory.path().to_str().unwrap(),
            vec![],
            "127.0.0.1:0",
            None,
            None,
            None,
        );
        match result {
            Err(error) => assert!(error.to_string().contains("protected records require")),
            Ok(manager) => {
                manager.shutdown();
                panic!("managed startup admitted protected storage");
            }
        }
    }
    {
        let persistence = ZonePersistence::open(directory.path(), "root").unwrap();
        let storage = RaftStorage::open(persistence.raft_path()).unwrap();
        let store = RedbStore::open(persistence.sm_path()).unwrap();
        let state = FullStateMachine::new(&store).unwrap();
        let result = ZoneConsensus::new(
            RaftConfig {
                id,
                ..Default::default()
            },
            storage,
            state,
            None,
        );
        assert!(matches!(
            result,
            Err(nexus_raft::raft::RaftError::Config(_))
        ));
    }
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let after = store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(PATH)
        .unwrap()
        .unwrap();
    assert_eq!(after.version, before.version);
    assert_eq!(after.metadata.content_id, before.metadata.content_id);
    assert!(store.put(PATH, image("reopened-stale-writer")).is_err());
}

fn adoption_entry(index: u64, term: u64) -> Entry {
    let command = Command::AdoptProtectedMetadata {
        key: PATH.into(),
        expected_image: None,
        incarnation: [7; 16],
    };
    let mut bytes = 123_u64.to_be_bytes().to_vec();
    bytes.extend(bincode::serialize(&command).unwrap());
    Entry {
        index,
        term,
        data: bytes.into(),
        ..Default::default()
    }
}

#[test]
fn managed_startup_refuses_an_unapplied_protection_in_the_retained_log() {
    let directory = tempfile::tempdir().unwrap();
    let id = {
        let runtime = Runtime::open(directory.path());
        runtime.0.node_id()
    };
    let persistence = ZonePersistence::open(directory.path(), "root").unwrap();
    let storage = RaftStorage::open(persistence.raft_path()).unwrap();
    let last = storage.last_index_impl().unwrap();
    let term = storage.initial_state_impl().unwrap().hard_state.term;
    storage.append(&[adoption_entry(last + 1, term)]).unwrap();
    let store = RedbStore::open(persistence.sm_path()).unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    let result = ZoneConsensus::new(
        RaftConfig {
            id,
            ..Default::default()
        },
        storage,
        state,
        None,
    );
    assert!(matches!(
        result,
        Err(nexus_raft::raft::RaftError::Config(_))
    ));
    let storage = RaftStorage::open(persistence.raft_path()).unwrap();
    assert_eq!(storage.last_index_impl().unwrap(), last + 1);
}

#[tokio::test]
async fn managed_peer_ingress_refuses_protected_snapshots_and_log_entries_before_enqueue() {
    let protected_directory = tempfile::tempdir().unwrap();
    let protected_snapshot = std::thread::spawn(move || {
        let runtime = Runtime::open(protected_directory.path());
        let store = runtime.store("/", "/");
        store.put(PATH, image("source-private-progress")).unwrap();
        protected(&store, PATH);
        let node = runtime.0.get_zone("root").unwrap().consensus_node().clone();
        runtime
            .0
            .runtime_handle()
            .block_on(node.with_state_machine(|state| state.snapshot().unwrap()))
    })
    .join()
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let storage = RaftStorage::open(directory.path().join("raft")).unwrap();
    let store = RedbStore::open(directory.path().join("state")).unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    let (node, _driver) = ZoneConsensus::new(RaftConfig::default(), storage, state, None).unwrap();
    let before = node.last_index();
    let mut snapshot = Message::default();
    snapshot.set_msg_type(MessageType::MsgSnapshot);
    snapshot.from = 2;
    snapshot.to = 1;
    snapshot.mut_snapshot().data = protected_snapshot.into();
    assert!(node.step(snapshot).await.is_err());
    let mut append = Message::default();
    append.set_msg_type(MessageType::MsgAppend);
    append.from = 2;
    append.to = 1;
    append.entries.push(adoption_entry(before + 1, 1));
    assert!(node.step(append).await.is_err());
    assert_eq!(node.last_index(), before);
    assert!(node
        .with_state_machine(|state| state.get_metadata(PATH).unwrap())
        .await
        .is_none());
    let mut heartbeat = Message::default();
    heartbeat.set_msg_type(MessageType::MsgHeartbeat);
    heartbeat.from = 2;
    heartbeat.to = 1;
    node.step(heartbeat).await.unwrap();
    let mut query = Message::default();
    query.set_msg_type(MessageType::MsgReadIndex);
    query.from = 2;
    query.to = 1;
    query.entries.push(Entry {
        data: b"opaque-read-context".to_vec().into(),
        ..Default::default()
    });
    node.step(query).await.unwrap();
}

#[test]
fn an_unreadable_protection_policy_fails_ec_export_instead_of_returning_an_empty_image() {
    let directory = tempfile::tempdir().unwrap();
    let store = RedbStore::open(directory.path().join("state")).unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    state
        .apply(
            1,
            &Command::SetMetadata {
                key: "/ordinary/durable".into(),
                value: b"must-still-replicate".to_vec(),
            },
        )
        .unwrap();
    assert_eq!(state.ec_state_snapshot().unwrap().len(), 1);
    // Corrupt the synthetic store through its physical redb layer: the public
    // control command correctly refuses writes to this owned namespace.
    let control = store.tree("sm_control_state").unwrap();
    let key = format!("content-version-v1\0protected:{PATH}");
    control.set(key.as_bytes(), b"corrupt-policy").unwrap();
    assert!(state.ec_state_snapshot().is_err());
    assert_eq!(
        state.get_metadata("/ordinary/durable").unwrap().as_deref(),
        Some(b"must-still-replicate".as_slice())
    );
}
