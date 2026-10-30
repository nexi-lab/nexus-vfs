//! Admit the exact legacy file through the real Kernel, CAS and zone actor.

use kernel::abc::object_store::ObjectStore;
use kernel::kernel::conditional_content::ConditionalContentError;
use kernel::kernel::convenience::KernelConvenience;
use kernel::kernel::{KernelError, OperationContext, UnlinkRequest, WriteRequest};
use kernel::meta_store::{ConditionalMetadataError, FileMetadata, RecordProtectionResult, DT_LINK};
use std::sync::Arc;

use super::{context, Fixture};

#[test]
fn deferred_capability_probe_is_lazy_and_unavailable_zone_is_an_error() {
    let directory = tempfile::tempdir().unwrap();
    let manager = nexus_raft::ZoneManager::isolated(directory.path().to_str().unwrap()).unwrap();
    let registry = manager.registry();
    let before = registry.resident_zones();
    let store = nexus_raft::zone_meta_store::ZoneMetaStore::deferred_arc(
        registry.clone(),
        "unavailable-private-zone",
        manager.runtime_handle(),
        "/conversations".into(),
        "/conversations".into(),
    );
    let conditional = store.as_conditional_metadata().unwrap();
    let protection = store.as_record_protection().unwrap();
    assert_eq!(registry.resident_zones(), before);
    let path = "/conversations/pair/readers/owner";
    assert!(matches!(
        conditional.read_versioned(path),
        Err(ConditionalMetadataError::Failed(_))
    ));
    assert!(matches!(
        protection.protect_record(path, &|_| panic!("unavailable zone cannot qualify content")),
        Err(ConditionalMetadataError::Failed(_))
    ));
    assert_eq!(registry.resident_zones(), before);
    drop(store);
    manager.shutdown();
}

#[test]
fn reader_admission_keeps_the_canonical_conversation_path_across_restart() {
    for is_deferred in [false, true] {
        reader_admission_across_restart(is_deferred);
    }
}

fn reader_admission_across_restart(is_deferred: bool) {
    const PATH: &str = "/conversations/stable-cid/readers/agent-a";
    const ALIAS: &str = "/alias/stable-cid/readers/agent-a";
    const LEGACY: &[u8] =
        br#"{"epoch":1,"holder":"legacy-runtime","claim_id":"legacy","read_offset":41}"#;
    const CURRENT: &[u8] =
        br#"{"epoch":2,"holder":"current-runtime","claim_id":"current","read_offset":82}"#;
    let root = Arc::new(tempfile::tempdir().unwrap());
    let fixture = Fixture::open_root_with_binding(
        root.clone(),
        "/conversations",
        "/conversations",
        is_deferred,
    );
    KernelConvenience::mkdir(
        fixture.kernel.as_ref(),
        "/conversations/stable-cid/readers",
        &context(),
        true,
        true,
    )
    .unwrap();
    assert!(write(&fixture, PATH, LEGACY));
    assert!(matches!(
        fixture.kernel.read_versioned_content(PATH, &context()),
        Err(ConditionalContentError::Unsupported)
    ));
    assert_eq!(
        fixture
            .kernel
            .protect_record_content(PATH, &service())
            .unwrap(),
        RecordProtectionResult::Protected
    );
    let admitted = fixture
        .kernel
        .read_versioned_content(ALIAS, &context())
        .unwrap()
        .unwrap();
    assert_eq!(admitted.content, LEGACY);
    let current = fixture.replace(ALIAS, CURRENT, Some(&admitted.version));
    for spelling in [PATH, ALIAS] {
        assert!(!write(&fixture, spelling, LEGACY));
    }
    let destination = "/conversations/stable-cid/readers/renamed-agent";
    assert!(fixture
        .kernel
        .sys_rename(PATH, destination, &context())
        .is_err());
    assert!(fixture.store.get(destination).unwrap().is_none());
    let rows = fixture
        .store
        .list("/conversations/stable-cid/readers/")
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].path, PATH);
    drop(fixture);
    let restored =
        Fixture::open_root_with_binding(root, "/conversations", "/conversations", is_deferred);
    let after = restored
        .kernel
        .read_versioned_content(PATH, &context())
        .unwrap()
        .unwrap();
    assert_eq!(after.content, CURRENT);
    assert_eq!(after.version, current);
    assert!(!write(&restored, ALIAS, LEGACY));
    assert!(matches!(
        restored.kernel.replace_content_if_version(PATH, &context(), LEGACY, Some(&admitted.version)).unwrap(),
        kernel::kernel::conditional_content::ConditionalContentResult::Conflict { current_version: Some(version) } if version == current
    ));
}

fn service() -> OperationContext {
    OperationContext::new("alice", "root", true, None, false)
}

fn write(fixture: &Fixture, path: &str, content: &[u8]) -> bool {
    fixture.kernel.sys_write(
        &[WriteRequest {
            path: path.into(),
            content: content.to_vec(),
            offset: 0,
        }],
        &context(),
    )[0]
    .as_ref()
    .map(|result| result.hit)
    .unwrap_or(false)
}

#[test]
fn admission_preserves_legacy_content_and_fences_alias_writes_across_restart() {
    let fixture = Fixture::open();
    assert!(write(&fixture, "/state/reader", b"legacy-position"));
    assert!(fixture
        .kernel
        .read_versioned_content("/state/reader", &context())
        .is_err());
    assert_eq!(
        fixture
            .kernel
            .protect_record_content("/alias/reader", &service())
            .unwrap(),
        RecordProtectionResult::Protected
    );
    let snapshot = fixture
        .kernel
        .read_versioned_content("/state/reader", &context())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.content, b"legacy-position");
    assert!(!write(&fixture, "/state/reader", b"late-legacy-position"));
    assert!(fixture.kernel.sys_unlink(
        &[UnlinkRequest {
            path: "/alias/reader".into(),
            recursive: false,
        }],
        &context(),
    )[0]
    .is_err());
    let version = fixture.replace(
        "/alias/reader",
        b"accepted-position",
        Some(&snapshot.version),
    );
    assert_eq!(
        fixture
            .kernel
            .protect_record_content("/state/reader", &service())
            .unwrap(),
        RecordProtectionResult::Protected
    );
    let root = fixture._root.clone();
    drop(fixture);
    let restored = Fixture::open_root(root);
    let snapshot = restored
        .kernel
        .read_versioned_content("/alias/reader", &context())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.version, version);
    assert_eq!(snapshot.content, b"accepted-position");
    assert!(!write(
        &restored,
        "/alias/reader",
        b"restart-legacy-position"
    ));
}

#[test]
fn an_absent_protected_record_accepts_only_a_conditional_first_image() {
    let fixture = Fixture::open();
    assert_eq!(
        fixture
            .kernel
            .protect_record_content("/state/reader", &service())
            .unwrap(),
        RecordProtectionResult::Protected
    );
    assert!(fixture
        .kernel
        .read_versioned_content("/alias/reader", &context())
        .unwrap()
        .is_none());
    assert!(!write(&fixture, "/alias/reader", b"ordinary-first-image"));
    fixture.replace("/state/reader", b"conditional-first-image", None);
    assert_eq!(
        fixture
            .kernel
            .read_versioned_content("/alias/reader", &context())
            .unwrap()
            .unwrap()
            .content,
        b"conditional-first-image"
    );
}

#[test]
fn a_different_canonical_content_id_requires_conversion_before_admission() {
    let fixture = Fixture::open();
    let engine = fixture.backend.as_cas().unwrap();
    let content = b"legacy-position";
    let chunk = engine.transport().write_blob(content).unwrap();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "type": "chunked_manifest",
        "total_size": content.len(),
        "chunks": [{"chunk_hash":chunk, "offset":0, "length":content.len()}],
    }))
    .unwrap();
    let legacy = engine.transport().write_blob(&manifest).unwrap();
    fixture
        .store
        .put(
            "/state/reader",
            FileMetadata {
                content_id: Some(legacy.clone()),
                size: content.len() as u64,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(matches!(
        fixture
            .kernel
            .protect_record_content("/state/reader", &service()),
        Err(ConditionalContentError::Failed(_))
    ));
    assert_eq!(
        fixture
            .store
            .get("/state/reader")
            .unwrap()
            .unwrap()
            .content_id,
        Some(legacy.clone())
    );
    assert_eq!(engine.read_content(&legacy).unwrap(), content);
    // The service converts this ordinary representation before admission. Its
    // logical bytes stay the same; admission then preserves its exact pointer.
    assert!(write(&fixture, "/state/reader", content));
    assert_eq!(
        fixture
            .kernel
            .protect_record_content("/state/reader", &service())
            .unwrap(),
        RecordProtectionResult::Protected
    );
    assert_eq!(
        fixture
            .kernel
            .read_versioned_content("/alias/reader", &context())
            .unwrap()
            .unwrap()
            .content,
        content
    );
}

#[test]
fn missing_and_corrupt_legacy_content_leave_the_record_unprotected() {
    for missing in [false, true] {
        let fixture = Fixture::open();
        assert!(write(&fixture, "/state/reader", b"original"));
        let metadata = fixture.store.get("/state/reader").unwrap().unwrap();
        let object = fixture
            .backend
            .as_cas()
            .unwrap()
            .transport()
            .blob_path(metadata.content_id.as_ref().unwrap());
        if missing {
            std::fs::remove_file(&object).unwrap();
        } else {
            std::fs::write(&object, b"corrupt!").unwrap();
        }
        assert!(matches!(
            fixture
                .kernel
                .protect_record_content("/state/reader", &service()),
            Err(ConditionalContentError::Failed(_))
        ));
        assert!(write(&fixture, "/alias/reader", b"repaired"));
        assert!(fixture.store.delete("/state/reader").unwrap());
    }
}

#[test]
fn admission_requires_the_runtime_service_and_a_qualified_storage_path() {
    let fixture = Fixture::open();
    assert!(matches!(
        fixture
            .kernel
            .protect_record_content("/state/reader", &context()),
        Err(ConditionalContentError::Failed(
            KernelError::PermissionDenied(_)
        ))
    ));
    assert!(write(&fixture, "/state/reader", b"still-ordinary"));
    assert!(matches!(
        fixture
            .kernel
            .protect_record_content("/unmounted/reader", &service()),
        Err(ConditionalContentError::Unsupported)
    ));
}

#[test]
fn admission_rechecks_directory_link_permissions_without_changing_the_target() {
    let fixture = Fixture::open();
    fixture
        .store
        .put(
            "/state/shortcut",
            FileMetadata {
                path: "/state/shortcut".into(),
                entry_type: DT_LINK,
                link_target: Some("/alias/private".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(write(&fixture, "/alias/private/reader", b"private"));
    fixture
        .kernel
        .set_permission_provider(Arc::new(Box::new(super::DenyTarget)));
    assert!(matches!(
        fixture
            .kernel
            .protect_record_content("/state/shortcut/reader", &service()),
        Err(ConditionalContentError::Failed(
            KernelError::PermissionDenied(_)
        ))
    ));
    // The denied operation did not install a target policy.
    assert!(fixture.store.delete("/state/private/reader").unwrap());
}
