//! Exercise conditional metadata through the real isolated Raft actor and redb.
#![cfg(all(feature = "grpc", has_protos))]

mod common;

use std::sync::{Arc, Barrier};
use std::time::Duration;

use kernel::meta_store::{
    ConditionalMetadataError, ConditionalMetadataResult, FileMetadata, LocalMetaStore, MetaStore,
};
use nexus_raft::zone_meta_store::ZoneMetaStore;
use nexus_raft::ZoneManager;
use tempfile::TempDir;

const MANAGED: &str = "/__managed_content_v1__";

struct Runtime(Arc<ZoneManager>);

impl Runtime {
    fn open(dir: &TempDir) -> Self {
        Self(ZoneManager::isolated(dir.path().to_str().unwrap()).unwrap())
    }

    fn store(&self, mount: &str, subtree: &str) -> Arc<dyn MetaStore> {
        let root = self.0.create_zone("root", vec![]).unwrap();
        assert!(root.wait_for_leader(Duration::from_secs(10)));
        Arc::new(ZoneMetaStore::new_with_subtree(
            root.consensus_node().clone(),
            self.0.runtime_handle(),
            mount.into(),
            subtree.into(),
        ))
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

fn image(content_id: &str) -> FileMetadata {
    FileMetadata {
        content_id: Some(content_id.into()),
        size: 17,
        ..Default::default()
    }
}

fn committed(result: ConditionalMetadataResult) -> Vec<u8> {
    match result {
        ConditionalMetadataResult::Committed { version } => version,
        result => panic!("expected committed replacement, got {result:?}"),
    }
}

#[test]
fn competing_alias_creates_publish_one_image_and_updates_evict_both_caches() {
    let dir = TempDir::new().unwrap();
    let runtime = Runtime::open(&dir);
    let a = runtime.store("/a", MANAGED);
    let b = runtime.store("/b", MANAGED);
    let barrier = Arc::new(Barrier::new(2));
    let writers: Vec<_> = [
        (a.clone(), "/a/cursor", "one"),
        (b.clone(), "/b/cursor", "two"),
    ]
    .into_iter()
    .map(|(store, path, content)| {
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            store
                .as_conditional_metadata()
                .unwrap()
                .replace_if_version(path, image(content), None)
                .unwrap()
        })
    })
    .collect();
    let results: Vec<_> = writers
        .into_iter()
        .map(|writer| writer.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, ConditionalMetadataResult::Committed { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(
                r,
                ConditionalMetadataResult::Conflict {
                    current_version: Some(_)
                }
            ))
            .count(),
        1
    );
    let current = a
        .as_conditional_metadata()
        .unwrap()
        .read_versioned("/a/cursor")
        .unwrap()
        .unwrap();
    assert_eq!(a.get("/a/cursor").unwrap().unwrap().path, "/a/cursor");
    assert_eq!(
        b.get("/b/cursor").unwrap().unwrap().content_id,
        current.metadata.content_id
    );
    committed(
        b.as_conditional_metadata()
            .unwrap()
            .replace_if_version("/b/cursor", image("updated"), Some(&current.version))
            .unwrap(),
    );
    for (store, path) in [(&a, "/a/cursor"), (&b, "/b/cursor")] {
        let read = store.get(path).unwrap().unwrap();
        assert_eq!(read.content_id.as_deref(), Some("updated"));
        assert_eq!(read.path, path);
    }
}

#[test]
fn unconditional_writes_and_delete_recreate_invalidate_old_tokens() {
    let dir = TempDir::new().unwrap();
    let runtime = Runtime::open(&dir);
    let store = runtime.store("/readers", MANAGED);
    let operation = store.as_conditional_metadata().unwrap();
    let path = "/readers/cursor";
    let first = committed(
        operation
            .replace_if_version(path, image("first"), None)
            .unwrap(),
    );
    store.put(path, image("ordinary")).unwrap();
    let ordinary = operation.read_versioned(path).unwrap().unwrap();
    assert_ne!(ordinary.version, first);
    assert_eq!(
        operation
            .replace_if_version(path, image("stale"), Some(&first))
            .unwrap(),
        ConditionalMetadataResult::Conflict {
            current_version: Some(ordinary.version.clone())
        }
    );
    assert_eq!(
        operation
            .read_versioned(path)
            .unwrap()
            .unwrap()
            .metadata
            .content_id
            .as_deref(),
        Some("ordinary")
    );
    assert!(store.delete(path).unwrap());
    assert!(operation.read_versioned(path).unwrap().is_none());
    assert_eq!(
        operation
            .replace_if_version(path, image("deleted-stale"), Some(&ordinary.version))
            .unwrap(),
        ConditionalMetadataResult::Conflict {
            current_version: None
        }
    );
    let recreated = committed(
        operation
            .replace_if_version(path, image("recreated"), None)
            .unwrap(),
    );
    assert_ne!(recreated, first);
    assert_ne!(recreated, ordinary.version);
}

#[test]
fn restart_preserves_tokens_and_new_roots_have_distinct_namespaces() {
    let dir = TempDir::new().unwrap();
    let first = {
        let runtime = Runtime::open(&dir);
        let store = runtime.store("/readers", MANAGED);
        committed(
            store
                .as_conditional_metadata()
                .unwrap()
                .replace_if_version("/readers/cursor", image("saved"), None)
                .unwrap(),
        )
    };
    {
        let runtime = Runtime::open(&dir);
        let store = runtime.store("/restored", MANAGED);
        let operation = store.as_conditional_metadata().unwrap();
        let saved = operation
            .read_versioned("/restored/cursor")
            .unwrap()
            .unwrap();
        assert_eq!(saved.version, first);
        assert_eq!(saved.metadata.path, "/restored/cursor");
        assert_eq!(saved.metadata.content_id.as_deref(), Some("saved"));
        assert_ne!(
            committed(
                operation
                    .replace_if_version("/restored/cursor", image("next"), Some(&first))
                    .unwrap()
            ),
            first
        );
    }
    let other_dir = TempDir::new().unwrap();
    let other_runtime = Runtime::open(&other_dir);
    let other = other_runtime.store("/readers", MANAGED);
    let version = committed(
        other
            .as_conditional_metadata()
            .unwrap()
            .replace_if_version("/readers/cursor", image("saved"), None)
            .unwrap(),
    );
    assert_ne!(version, first);
    assert_eq!(
        other
            .as_conditional_metadata()
            .unwrap()
            .replace_if_version("/readers/cursor", image("foreign"), Some(&first))
            .unwrap(),
        ConditionalMetadataResult::Conflict {
            current_version: Some(version)
        }
    );
}

#[test]
fn legacy_images_and_unsupported_namespaces_fail_without_replacement() {
    let dir = TempDir::new().unwrap();
    let runtime = Runtime::open(&dir);
    let store = runtime.store("/readers", MANAGED);
    store.put("/readers/legacy", image("legacy")).unwrap();
    let operation = store.as_conditional_metadata().unwrap();
    assert!(matches!(
        operation.read_versioned("/readers/legacy"),
        Err(ConditionalMetadataError::Unsupported)
    ));
    assert!(matches!(
        operation.replace_if_version("/readers/legacy", image("overwritten"), None),
        Err(ConditionalMetadataError::Unsupported)
    ));
    assert_eq!(
        store
            .get("/readers/legacy")
            .unwrap()
            .unwrap()
            .content_id
            .as_deref(),
        Some("legacy")
    );
    let ordinary = runtime.store("/ordinary", "/ordinary");
    assert!(matches!(
        ordinary
            .as_conditional_metadata()
            .unwrap()
            .read_versioned("/ordinary/file"),
        Err(ConditionalMetadataError::Unsupported)
    ));
    assert!(matches!(
        ordinary
            .as_conditional_metadata()
            .unwrap()
            .replace_if_version("/ordinary/file", image("unsupported"), None),
        Err(ConditionalMetadataError::Unsupported)
    ));
    assert!(ordinary.get("/ordinary/file").unwrap().is_none());
    assert!(LocalMetaStore::in_memory()
        .unwrap()
        .as_conditional_metadata()
        .is_none());
}

#[test]
fn managed_membership_keeps_the_optional_operations_closed() {
    let dir = TempDir::new().unwrap();
    let bind = common::node_bind_addr();
    let runtime = Runtime(
        ZoneManager::with_node_id(
            "conditional-managed-fixture",
            1,
            dir.path().to_str().unwrap(),
            vec![],
            &bind,
            None,
            Some(format!("http://{bind}")),
            None,
        )
        .unwrap(),
    );
    let root = runtime.0.create_zone("root", vec![]).unwrap();
    let store = ZoneMetaStore::new_with_subtree(
        root.consensus_node().clone(),
        runtime.0.runtime_handle(),
        "/readers".into(),
        MANAGED.into(),
    );
    assert!(store.as_conditional_metadata().is_none());
    assert!(matches!(
        kernel::meta_store::ConditionalMetadata::read_versioned(&store, "/readers/file"),
        Err(ConditionalMetadataError::Unsupported)
    ));
    assert!(matches!(
        kernel::meta_store::ConditionalMetadata::replace_if_version(
            &store,
            "/readers/file",
            image("refused"),
            None
        ),
        Err(ConditionalMetadataError::Unsupported)
    ));
    assert!(store.get("/readers/file").unwrap().is_none());
}

#[test]
fn isolated_metadata_adapter_keeps_generic_conditional_proposals_closed() {
    let dir = TempDir::new().unwrap();
    let runtime = Runtime::open(&dir);
    let root = runtime.0.create_zone("root", vec![]).unwrap();
    assert!(root.wait_for_leader(Duration::from_secs(10)));
    let node = root.consensus_node();
    runtime
        .0
        .runtime_handle()
        .block_on(node.read_linearizable(|_| ()))
        .unwrap();
    let before = root.last_log_index();
    let refused = runtime.0.runtime_handle().block_on(node.propose(
        nexus_raft::prelude::Command::WriteVersionedMetadata {
            key: format!("{MANAGED}/not-admitted"),
            value: vec![1],
            expected: None,
            incarnation: [1; 16],
        },
    ));
    assert!(refused.is_err());
    assert_eq!(root.last_log_index(), before);
    let store = runtime.store("/readers", MANAGED);
    assert!(store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned("/readers/not-admitted")
        .unwrap()
        .is_none());
}
