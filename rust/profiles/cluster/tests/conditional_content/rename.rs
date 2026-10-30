//! Public Kernel rename over the actual CAS, actor and aliased namespace.

use super::{context, Fixture};
use kernel::kernel::OperationContext;
use kernel::meta_store::RecordProtectionResult;

fn protect(fixture: &Fixture, path: &str) {
    let service = OperationContext::new("alice", "root", true, None, false);
    assert_eq!(
        fixture
            .kernel
            .protect_record_content(path, &service)
            .unwrap(),
        RecordProtectionResult::Protected
    );
}

#[test]
fn kernel_refuses_protected_source_without_publishing_a_second_content_path() {
    let fixture = Fixture::open();
    fixture.replace("/state/source", b"private reader position", None);
    protect(&fixture, "/state/source");
    let before = fixture
        .kernel
        .read_versioned_content("/state/source", &context())
        .unwrap()
        .unwrap();
    assert!(fixture
        .kernel
        .sys_rename("/state/source", "/state/target", &context())
        .is_err());
    assert!(fixture
        .kernel
        .read_versioned_content("/alias/target", &context())
        .unwrap()
        .is_none());
    let after = fixture
        .kernel
        .read_versioned_content("/alias/source", &context())
        .unwrap()
        .unwrap();
    assert_eq!(after.content, before.content);
    assert_eq!(after.version, before.version);
}

#[test]
fn kernel_refuses_protected_destination_and_preserves_both_content_images() {
    let fixture = Fixture::open();
    fixture.replace("/state/source", b"source bytes", None);
    fixture.replace("/state/target", b"protected destination bytes", None);
    protect(&fixture, "/state/target");
    let paths = ["/state/source", "/state/target"];
    let before = paths.map(|path| {
        fixture
            .kernel
            .read_versioned_content(path, &context())
            .unwrap()
            .unwrap()
    });
    assert!(fixture
        .kernel
        .sys_rename(paths[0], paths[1], &context())
        .is_err());
    for (path, previous) in paths.into_iter().zip(before) {
        let after = fixture
            .kernel
            .read_versioned_content(path, &context())
            .unwrap()
            .unwrap();
        assert_eq!(after.content, previous.content);
        assert_eq!(after.version, previous.version);
    }
}

#[test]
fn kernel_rename_updates_aliases_and_keeps_content_after_actor_restart() {
    let fixture = Fixture::open();
    let previous = fixture.replace("/state/source", b"durable renamed bytes", None);
    // Populate both aliases before the mutation so the test exercises cache
    // invalidation as well as the durable pointer update.
    fixture
        .kernel
        .read_versioned_content("/alias/source", &context())
        .unwrap()
        .unwrap();
    fixture
        .kernel
        .sys_rename("/state/source", "/state/target", &context())
        .unwrap();
    assert!(fixture
        .kernel
        .read_versioned_content("/alias/source", &context())
        .unwrap()
        .is_none());
    let moved = fixture
        .kernel
        .read_versioned_content("/alias/target", &context())
        .unwrap()
        .unwrap();
    assert_eq!(moved.content, b"durable renamed bytes");
    assert_ne!(moved.version, previous);
    let root = fixture._root.clone();
    drop(fixture);
    let restored = Fixture::open_root(root);
    assert!(restored
        .kernel
        .read_versioned_content("/state/source", &context())
        .unwrap()
        .is_none());
    let after = restored
        .kernel
        .read_versioned_content("/alias/target", &context())
        .unwrap()
        .unwrap();
    assert_eq!(after.content, moved.content);
    assert_eq!(after.version, moved.version);
}
