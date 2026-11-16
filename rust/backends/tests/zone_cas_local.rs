#![cfg(feature = "driver-cas-local")]

use backends::storage::zone_cas_local::ZoneCasLocalStores;
use std::io::ErrorKind;

#[test]
fn a_read_cannot_prepare_a_namespace() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("content");
    let stores = ZoneCasLocalStores::open(&root).unwrap();
    assert!(stores.get("agent-alice").unwrap().is_none());
    assert!(stores.get("../agent-alice").unwrap().is_none());
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
    for zone in ["root", "", "../agent-alice", "AGENT-ALICE"] {
        assert_eq!(
            stores.prepare(zone).err().unwrap().kind(),
            ErrorKind::InvalidInput
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn physical_namespaces_keep_private_objects_out_of_other_zone_reads_after_restart() {
    use kernel::kernel::OperationContext;
    use std::sync::Arc;

    let root = tempfile::tempdir().unwrap();
    let stores = ZoneCasLocalStores::open(root.path()).unwrap();
    let alice = stores.prepare("agent-alice").unwrap();
    let conversation = stores.prepare("conversation-alice-bob").unwrap();
    let charlie = stores.prepare("agent-charlie").unwrap();
    assert!(Arc::ptr_eq(&alice, &stores.prepare("agent-alice").unwrap()));
    let ctx = OperationContext::new("owner-alice", "agent-alice", false, Some("alice"), false);
    let secret = b"private memory, attachment and reader progress bytes";
    let hash = alice
        .backend()
        .write_content(secret, "", &ctx, 0)
        .unwrap()
        .content_id;
    assert_eq!(alice.read_blob(&hash).unwrap(), secret);
    assert_eq!(alice.read_file(&hash).unwrap(), secret);
    for unshared in [&conversation, &charlie] {
        assert_eq!(
            unshared.read_blob(&hash).unwrap_err().kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            std::fs::read_dir(root.path().join(unshared.zone_id()))
                .unwrap()
                .count(),
            0
        );
    }
    let public = b"only this bilateral conversation is shared";
    let shared = conversation
        .backend()
        .write_content(public, "", &ctx, 0)
        .unwrap()
        .content_id;
    assert_eq!(conversation.read_blob(&shared).unwrap(), public);
    drop((alice, conversation, charlie, stores));

    let restarted = ZoneCasLocalStores::open(root.path()).unwrap();
    assert!(restarted.get("agent-alice").unwrap().is_none());
    let private = restarted.prepare("agent-alice").unwrap();
    assert_eq!(private.read_blob(&hash).unwrap(), secret);
    let shared_zone = restarted.prepare("conversation-alice-bob").unwrap();
    assert_eq!(shared_zone.read_blob(&shared).unwrap(), public);
    assert_eq!(
        shared_zone.read_blob(&hash).unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_zone_directory_cannot_alias_another_namespace() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let stores = ZoneCasLocalStores::open(root.path()).unwrap();
    stores.prepare("agent-alice").unwrap();
    symlink(
        root.path().join("agent-alice"),
        root.path().join("agent-bob"),
    )
    .unwrap();
    assert_eq!(
        stores.prepare("agent-bob").err().unwrap().kind(),
        ErrorKind::PermissionDenied
    );
    assert!(stores.get("agent-bob").unwrap().is_none());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unqualified_durability_does_not_publish_a_namespace() {
    let root = tempfile::tempdir().unwrap();
    let stores = ZoneCasLocalStores::open(root.path()).unwrap();
    assert_eq!(
        stores.prepare("agent-alice").err().unwrap().kind(),
        ErrorKind::Unsupported
    );
    assert!(stores.get("agent-alice").unwrap().is_none());
}
