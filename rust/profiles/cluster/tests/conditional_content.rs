//! Qualify the kernel content boundary with the actual isolated actor and durable CAS.
#![cfg(all(feature = "driver-cas-local", target_os = "linux"))]

#[path = "conditional_content/rpc.rs"]
mod rpc;

#[path = "conditional_content/protection.rs"]
mod protection;

#[path = "conditional_content/rename.rs"]
mod rename;

use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use backends::storage::cas_local::CasLocalBackend;
use kernel::abc::object_store::ObjectStore;
use kernel::kernel::conditional_content::{ConditionalContentError, ConditionalContentResult};
use kernel::kernel::{Kernel, KernelError, OperationContext, WriteRequest};
use kernel::meta_store::{FileMetadata, MetaStore, DT_LINK};
use kernel::{HookContext, HookOutcome, NativeInterceptHook, Permission, PermissionProvider};
use nexus_raft::zone_meta_store::ZoneMetaStore;
use nexus_raft::ZoneManager;

const MANAGED: &str = "/__managed_content_v1__";

fn context() -> OperationContext {
    OperationContext::new("alice", "root", false, None, false)
}

struct Fixture {
    kernel: Arc<Kernel>,
    manager: Arc<ZoneManager>,
    backend: Arc<CasLocalBackend>,
    store: Arc<dyn MetaStore>,
    _root: Arc<tempfile::TempDir>,
}

impl Fixture {
    fn open() -> Self {
        Self::open_root(Arc::new(tempfile::tempdir().unwrap()))
    }

    fn open_root(root: Arc<tempfile::TempDir>) -> Self {
        Self::open_root_with_namespace(root, "/state", MANAGED)
    }

    fn open_root_with_namespace(
        root: Arc<tempfile::TempDir>,
        mount_point: &str,
        subtree: &str,
    ) -> Self {
        let manager = ZoneManager::isolated(root.path().join("raft").to_str().unwrap()).unwrap();
        let zone = manager.create_zone("root", vec![]).unwrap();
        assert!(zone.wait_for_leader(Duration::from_secs(10)));
        let kernel = Arc::new(Kernel::new());
        let backend = Arc::new(CasLocalBackend::new_durable(&root.path().join("cas")).unwrap());
        let store: Arc<dyn MetaStore> = Arc::new(ZoneMetaStore::new_with_subtree(
            zone.consensus_node().clone(),
            manager.runtime_handle(),
            mount_point.into(),
            subtree.into(),
        ));
        for mount in [mount_point, "/alias"] {
            let metadata: Arc<dyn MetaStore> = if mount == mount_point {
                store.clone()
            } else {
                Arc::new(ZoneMetaStore::new_with_subtree(
                    zone.consensus_node().clone(),
                    manager.runtime_handle(),
                    mount.into(),
                    subtree.into(),
                ))
            };
            kernel
                .vfs_router_arc()
                .add_mount(mount, "root", Some(backend.clone()), false);
            kernel.install_mount_metastore(Kernel::canonical_mount_key(mount, "root"), metadata);
        }
        Self {
            kernel,
            manager,
            backend,
            store,
            _root: root,
        }
    }

    fn replace(&self, path: &str, content: &[u8], version: Option<&[u8]>) -> Vec<u8> {
        committed(
            self.kernel
                .replace_content_if_version(path, &context(), content, version)
                .unwrap(),
        )
    }
}

#[test]
fn restart_preserves_the_token_and_delete_recreate_cannot_reuse_it() {
    let fixture = Fixture::open();
    let first = fixture.replace("/state/register", b"same bytes", None);
    let root = fixture._root.clone();
    drop(fixture);
    let fixture = Fixture::open_root(root);
    let restored = fixture
        .kernel
        .read_versioned_content("/alias/register", &context())
        .unwrap()
        .unwrap();
    assert_eq!(restored.version, first);
    assert_eq!(restored.content, b"same bytes");
    fixture.store.delete("/state/register").unwrap();
    assert!(fixture
        .kernel
        .read_versioned_content("/state/register", &context())
        .unwrap()
        .is_none());
    let recreated = fixture.replace("/state/register", b"same bytes", None);
    assert_ne!(recreated, first);
    assert!(
        matches!(fixture.kernel.replace_content_if_version("/state/register", &context(), b"stale", Some(&first)).unwrap(),
        ConditionalContentResult::Conflict { current_version: Some(version) } if version == recreated)
    );
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.kernel.release_metastores();
        self.manager.shutdown();
    }
}

fn committed(result: ConditionalContentResult) -> Vec<u8> {
    match result {
        ConditionalContentResult::Committed { version } => version,
        result => panic!("expected a committed replacement: {result:?}"),
    }
}

#[test]
fn competing_alias_replacements_publish_one_complete_image() {
    let fixture = Fixture::open();
    let kernel = &fixture.kernel;
    assert!(kernel
        .read_versioned_content("/state/register", &context())
        .unwrap()
        .is_none());
    let first = fixture.replace("/state/register", b"first", None);
    let barrier = Arc::new(Barrier::new(2));
    let writers: Vec<_> = [
        ("/state/register", b"second".as_slice()),
        ("/alias/register", b"third"),
    ]
    .into_iter()
    .map(|(path, content)| {
        let kernel = kernel.clone();
        let barrier = barrier.clone();
        let first = first.clone();
        std::thread::spawn(move || {
            barrier.wait();
            kernel
                .replace_content_if_version(path, &context(), content, Some(&first))
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
            .filter(|result| matches!(result, ConditionalContentResult::Committed { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                ConditionalContentResult::Conflict {
                    current_version: Some(_)
                }
            ))
            .count(),
        1
    );
    let image = kernel
        .read_versioned_content("/state/register", &context())
        .unwrap()
        .unwrap();
    let alias = kernel
        .read_versioned_content("/alias/register", &context())
        .unwrap()
        .unwrap();
    assert!(image.content == b"second" || image.content == b"third");
    assert_eq!(image.content, alias.content);
    assert_eq!(image.version, alias.version);
    assert_ne!(image.version, first);
    assert!(
        matches!(kernel.replace_content_if_version("/state/register", &context(), b"stale", Some(&first)).unwrap(),
        ConditionalContentResult::Conflict { current_version: Some(version) } if version == image.version)
    );
    assert_eq!(
        kernel
            .read_versioned_content("/state/register", &context())
            .unwrap()
            .unwrap()
            .content,
        image.content
    );
}

#[test]
fn ordinary_writes_invalidate_the_token_without_changing_the_content_contract() {
    let fixture = Fixture::open();
    let first = fixture.replace("/state/register", b"conditional", None);
    let result = fixture.kernel.sys_write(
        &[WriteRequest {
            path: "/alias/register".into(),
            content: b"ordinary".to_vec(),
            offset: 0,
        }],
        &context(),
    );
    assert!(result[0].as_ref().unwrap().hit);
    let current = fixture
        .kernel
        .read_versioned_content("/state/register", &context())
        .unwrap()
        .unwrap();
    assert_eq!(current.content, b"ordinary");
    assert_ne!(current.version, first);
    assert!(
        matches!(fixture.kernel.replace_content_if_version("/alias/register", &context(), b"lost", Some(&first)).unwrap(),
        ConditionalContentResult::Conflict { current_version: Some(version) } if version == current.version)
    );
    assert_eq!(
        fixture
            .kernel
            .read_versioned_content("/state/register", &context())
            .unwrap()
            .unwrap()
            .content,
        b"ordinary"
    );
}

#[test]
fn complete_json_contents_round_trip_even_when_they_name_a_chunk_manifest() {
    let fixture = Fixture::open();
    let content = br#"{"type":"chunked_manifest","total_size":0,"chunks":[]}"#;
    fixture.replace("/state/register", content, None);
    let snapshot = fixture
        .kernel
        .read_versioned_content("/state/register", &context())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.content, content);
}

#[test]
fn ordinary_partial_writes_keep_the_logical_size_of_escaped_json() {
    let fixture = Fixture::open();
    let content = br#"{"type":"chunked_manifest","total_size":0,"chunks":[]}"#;
    let first = fixture.replace("/state/register", content, None);
    let mut expected = content.to_vec();
    expected[1] = b' ';
    let result = fixture.kernel.sys_write(
        &[WriteRequest {
            path: "/state/register".into(),
            content: vec![b' '],
            offset: 1,
        }],
        &context(),
    );
    assert!(result[0].as_ref().unwrap().hit);
    let snapshot = fixture
        .kernel
        .read_versioned_content("/state/register", &context())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.content, expected);
    assert_ne!(snapshot.version, first);
}

#[test]
fn corrupt_and_missing_immutable_objects_are_failures_instead_of_absence() {
    let fixture = Fixture::open();
    fixture.replace("/state/register", b"uncorrupted", None);
    let metadata = fixture.store.get("/state/register").unwrap().unwrap();
    let object = fixture
        .backend
        .as_cas()
        .unwrap()
        .transport()
        .blob_path(metadata.content_id.as_ref().unwrap());
    std::fs::write(&object, b"corrupted").unwrap();
    assert!(matches!(
        fixture
            .kernel
            .read_versioned_content("/state/register", &context()),
        Err(ConditionalContentError::Failed(_))
    ));
    std::fs::remove_file(&object).unwrap();
    assert!(matches!(
        fixture
            .kernel
            .read_versioned_content("/state/register", &context()),
        Err(ConditionalContentError::Failed(_))
    ));
    assert!(fixture.store.get("/state/register").unwrap().is_some());
}

#[test]
fn file_only_cas_and_local_metadata_refuse_both_operations_before_publication() {
    let fixture = Fixture::open();
    let root = tempfile::tempdir().unwrap();
    let file_only = Arc::new(CasLocalBackend::new(root.path(), true).unwrap());
    let kernel = Kernel::new();
    kernel
        .vfs_router_arc()
        .add_mount("/", "root", Some(file_only.clone()), false);
    for kernel in [&kernel, &*fixture.kernel] {
        let path = if std::ptr::eq(kernel, &*fixture.kernel) {
            "/alias/untracked"
        } else {
            "/untracked"
        };
        if path.starts_with("/alias") {
            kernel.install_mount_metastore(
                Kernel::canonical_mount_key("/alias", "root"),
                Arc::new(
                    kernel::meta_store::LocalMetaStore::open(&root.path().join("local.redb"))
                        .unwrap(),
                ),
            );
        }
        assert!(matches!(
            kernel.read_versioned_content(path, &context()),
            Err(ConditionalContentError::Unsupported)
        ));
        assert!(matches!(
            kernel.replace_content_if_version(path, &context(), b"refused", None),
            Err(ConditionalContentError::Unsupported)
        ));
    }
    for backend in [file_only.as_ref(), fixture.backend.as_ref()] {
        assert!(!backend
            .as_cas()
            .unwrap()
            .content_exists(&lib::hash::hash_content(b"refused")));
    }
}

struct DenyTarget;

struct RewriteHook(Arc<Mutex<Vec<String>>>);

impl NativeInterceptHook for RewriteHook {
    fn name(&self) -> &str {
        "conditional-content-rewrite"
    }

    fn mutating_path_suffixes(&self) -> &'static [&'static str] {
        &["/register"]
    }

    fn on_pre(&self, context: &HookContext) -> Result<HookOutcome, String> {
        if let HookContext::Write(write) = context {
            assert_eq!(write.identity.user_id, "alice");
            return Ok(HookOutcome::Replace(b"policy replacement".to_vec()));
        }
        Ok(HookOutcome::Pass)
    }

    fn on_post(&self, context: &HookContext) {
        if let HookContext::Write(write) = context {
            self.0.lock().unwrap().push(write.path.clone());
        }
    }
}

#[test]
fn conditional_writes_keep_native_replacements_and_notify_only_after_commit() {
    let fixture = Fixture::open();
    let committed_paths = Arc::new(Mutex::new(Vec::new()));
    let service = fixture
        .kernel
        .enlist_hook_only_service("conditional-content-fixture")
        .unwrap();
    fixture
        .kernel
        .register_service_hook(&service, Box::new(RewriteHook(committed_paths.clone())));
    let version = fixture.replace("/state/register", b"caller bytes", None);
    assert_eq!(
        fixture
            .kernel
            .read_versioned_content("/state/register", &context())
            .unwrap()
            .unwrap()
            .content,
        b"policy replacement"
    );
    assert!(matches!(
        fixture
            .kernel
            .replace_content_if_version("/alias/register", &context(), b"caller bytes", None)
            .unwrap(),
        ConditionalContentResult::Conflict { .. }
    ));
    assert_eq!(*committed_paths.lock().unwrap(), ["/state/register"]);
    assert_eq!(
        fixture
            .kernel
            .read_versioned_content("/alias/register", &context())
            .unwrap()
            .unwrap()
            .version,
        version
    );
}

#[test]
fn concurrent_readers_keep_the_bytes_associated_with_each_committed_revision() {
    let fixture = Fixture::open();
    let first = fixture.replace("/state/register", b"initial", None);
    let kernel = fixture.kernel.clone();
    let barrier = Arc::new(Barrier::new(2));
    let writer_barrier = barrier.clone();
    let writer = std::thread::spawn(move || {
        let mut versions = vec![(first, b"initial".to_vec())];
        writer_barrier.wait();
        for index in 0..32_u8 {
            let payload = vec![index; 8192];
            let version = committed(
                kernel
                    .replace_content_if_version(
                        "/state/register",
                        &context(),
                        &payload,
                        Some(&versions.last().unwrap().0),
                    )
                    .unwrap(),
            );
            versions.push((version, payload));
        }
        versions
    });
    barrier.wait();
    let reads: Vec<_> = (0..64)
        .map(|_| {
            fixture
                .kernel
                .read_versioned_content("/alias/register", &context())
                .unwrap()
                .unwrap()
        })
        .collect();
    let versions = writer.join().unwrap();
    for read in reads {
        let expected = versions
            .iter()
            .find(|(version, _)| *version == read.version)
            .unwrap();
        assert_eq!(read.content, expected.1);
    }
}

impl PermissionProvider for DenyTarget {
    fn check(
        &self,
        path: &str,
        _route: Option<&kernel::vfs_router::RouteResult>,
        _permission: Permission,
        _ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        if path.starts_with("/alias/") {
            Err(KernelError::PermissionDenied("target is private".into()))
        } else {
            Ok(())
        }
    }
}

#[test]
fn directory_aliases_recheck_the_target_permission_for_the_original_identity() {
    let fixture = Fixture::open();
    fixture
        .store
        .put(
            "/state/shortcut",
            FileMetadata {
                path: "/state/shortcut".into(),
                entry_type: DT_LINK,
                link_target: Some("/alias/subdirectory".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let version = fixture.replace("/state/shortcut/register", b"private", None);
    assert_eq!(
        fixture
            .kernel
            .read_versioned_content("/alias/subdirectory/register", &context())
            .unwrap()
            .unwrap()
            .version,
        version
    );
    fixture
        .kernel
        .set_permission_provider(Arc::new(Box::new(DenyTarget)));
    assert!(matches!(
        fixture
            .kernel
            .read_versioned_content("/state/shortcut/register", &context()),
        Err(ConditionalContentError::Failed(
            KernelError::PermissionDenied(_)
        ))
    ));
    assert!(matches!(
        fixture.kernel.replace_content_if_version(
            "/state/shortcut/register",
            &context(),
            b"refused",
            Some(&version)
        ),
        Err(ConditionalContentError::Failed(
            KernelError::PermissionDenied(_)
        ))
    ));
    assert!(!fixture
        .backend
        .as_cas()
        .unwrap()
        .content_exists(&lib::hash::hash_content(b"refused")));
}
