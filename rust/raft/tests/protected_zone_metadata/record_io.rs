//! Actual native I/O keeps its lifetime after request cancellation and reopen.

use super::record_guard::{admit, HISTORY, OWNER};
use super::*;
use kernel::meta_store::{ConditionalMetadata, ConditionalMetadataError};
use std::io::Write;
use std::sync::mpsc;

fn retire(store: &ZoneMetaStore, handle: &[u8]) -> Vec<u8> {
    match store
        .retire_record_guard(OWNER, image("deleted"), handle)
        .unwrap()
    {
        ConditionalMetadataResult::Committed { version } => version,
        result => panic!("expected terminal revision: {result:?}"),
    }
}

#[test]
fn enrolled_owner_qualification_shares_child_io_exclusion_and_cannot_revive() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let handle = admit(&store);
    assert!(store.begin_record_io(OWNER, &handle).is_err());
    store.admit_record_io_owner(OWNER, &handle).unwrap();
    assert!(store.begin_record_io("/unbound", &handle).is_err());
    let lifetime = store.begin_record_io(OWNER, &handle).unwrap();
    let terminal = retire(&store, &handle);
    let mut content =
        std::fs::File::create(directory.path().join("qualification-in-progress")).unwrap();
    content
        .write_all(b"real qualification work after retirement")
        .unwrap();
    content.sync_all().unwrap();
    assert!(store
        .try_exclude_retired_record_io(OWNER, &terminal)
        .unwrap()
        .is_none());
    assert!(store.begin_record_io(OWNER, &handle).is_err());
    assert!(store.begin_record_io(OWNER, &terminal).is_err());
    assert!(store
        .bind_record_guard("/late-child", None, OWNER, &handle)
        .is_err());
    drop(content);
    drop(lifetime);
    assert!(store
        .try_exclude_retired_record_io(OWNER, &terminal)
        .unwrap()
        .is_some());
}

#[test]
fn cancelled_reply_does_not_retire_real_io_and_finished_io_needs_no_process_exit() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = Arc::new(runtime.store("/", "/"));
    let alias = runtime.store("/view", "/sessions/session-a");
    let handle = admit(&store);
    assert!(matches!(
        store.begin_record_io(HISTORY, &handle),
        Err(ConditionalMetadataError::Unsupported)
    ));
    assert_eq!(
        store.read_versioned(OWNER).unwrap().unwrap().version,
        handle,
        "an I/O query cannot enroll an owner or advance its revision"
    );
    let node = runtime.0.get_zone("root").unwrap().consensus_node().clone();
    runtime
        .0
        .runtime_handle()
        .block_on(node.with_state_machine(|state| {
            assert_eq!(
                state
                    .get_control_state("content-version-v1", "requires:protected-records-v1")
                    .unwrap()
                    .as_deref(),
                Some(b"guarded-records-v1".as_slice())
            );
        }));
    store.admit_record_io_owner(OWNER, &handle).unwrap();
    store.admit_record_io_owner(OWNER, &handle).unwrap();
    assert_eq!(
        store.read_versioned(OWNER).unwrap().unwrap().version,
        handle
    );
    let payload = directory.path().join("owned-payload");
    let worker_payload = payload.clone();
    let worker_store = Arc::clone(&store);
    let worker_handle = handle.clone();
    let (admitted, admission) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let (response, caller) = mpsc::channel();
    let (finished, completion) = mpsc::channel();
    let (exit, alive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let lifetime = worker_store
            .begin_record_io(HISTORY, &worker_handle)
            .unwrap();
        admitted.send(()).unwrap();
        resumed.recv_timeout(Duration::from_secs(10)).unwrap();
        let mut file = std::fs::File::create(worker_payload).unwrap();
        file.write_all(b"actual bytes written after the deletion decision")
            .unwrap();
        file.sync_all().unwrap();
        assert!(worker_store
            .append_guarded_record(HISTORY, b"late-publication", &worker_handle)
            .is_err());
        assert!(
            response.send(()).is_err(),
            "the request caller has cancelled"
        );
        drop(file);
        drop(lifetime);
        finished.send(()).unwrap();
        alive.recv_timeout(Duration::from_secs(10)).unwrap();
    });
    admission.recv_timeout(Duration::from_secs(10)).unwrap();
    drop(caller);
    let terminal = retire(&store, &handle);
    assert!(store.begin_record_io(HISTORY, &handle).is_err());
    assert!(alias
        .try_exclude_retired_record_io("/view/lifetime", &terminal)
        .unwrap()
        .is_none());
    resume.send(()).unwrap();
    completion.recv_timeout(Duration::from_secs(10)).unwrap();
    let exclusion = alias
        .try_exclude_retired_record_io("/view/lifetime", &terminal)
        .unwrap()
        .unwrap();
    assert!(
        !worker.is_finished(),
        "the runtime worker remains alive while its I/O is retired"
    );
    assert_eq!(
        std::fs::read(&payload).unwrap(),
        b"actual bytes written after the deletion decision"
    );
    std::fs::remove_file(&payload).unwrap();
    assert!(!payload.exists());
    drop(exclusion);
    exit.send(()).unwrap();
    worker.join().unwrap();
    assert_eq!(
        store
            .read_versioned(OWNER)
            .unwrap()
            .unwrap()
            .metadata
            .content_id
            .as_deref(),
        Some("deleted")
    );
}

#[test]
fn reopening_the_authority_does_not_forget_an_outstanding_native_io_guard() {
    let directory = tempfile::tempdir().unwrap();
    let lifetime;
    let terminal;
    {
        let runtime = Runtime::open(directory.path());
        let store = runtime.store("/", "/");
        let handle = admit(&store);
        store.admit_record_io_owner(OWNER, &handle).unwrap();
        lifetime = store.begin_record_io(HISTORY, &handle).unwrap();
        terminal = retire(&store, &handle);
        assert!(protected(&store, "/later-adoption").is_none());
    }
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    assert!(store
        .try_exclude_retired_record_io(OWNER, &terminal)
        .unwrap()
        .is_none());
    drop(lifetime);
    let _exclusion = store
        .try_exclude_retired_record_io(OWNER, &terminal)
        .unwrap()
        .unwrap();
    let node = runtime.0.get_zone("root").unwrap().consensus_node().clone();
    runtime
        .0
        .runtime_handle()
        .block_on(node.with_state_machine(|state| {
            assert_eq!(
                state
                    .get_control_state("content-version-v1", "requires:protected-records-v1")
                    .unwrap()
                    .as_deref(),
                Some(b"guarded-record-io-v1".as_slice())
            );
        }));
}
