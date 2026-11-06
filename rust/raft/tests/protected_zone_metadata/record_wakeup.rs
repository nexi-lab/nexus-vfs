//! A real committed guarded append reaches a parked Kernel watch.

use super::record_guard::{admit, HISTORY, OWNER};
use super::*;
use kernel::core::stream::wal::wal_stream_prefix;
use kernel::kernel::Kernel;
use kernel::meta_store::ConditionalMetadata;
use nexus_raft::stream_wakeup::install_stream_wakeup_observer;
use std::sync::mpsc;
use std::time::Instant;

#[test]
fn guarded_append_wakes_an_actual_watch_after_durable_apply() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let handle = admit(&store);
    let kernel = Arc::new(Kernel::new());
    let zone = runtime.0.get_zone("root").unwrap();
    install_stream_wakeup_observer(&zone.consensus_node(), Arc::downgrade(&kernel), "root");
    // Reinstalling the keyed observer must remain safe.
    install_stream_wakeup_observer(&zone.consensus_node(), Arc::downgrade(&kernel), "root");
    let (result, received) = mpsc::channel();
    let watcher = {
        let kernel = Arc::clone(&kernel);
        std::thread::spawn(move || {
            result
                .send(kernel.sys_watch(HISTORY, 5_000).map(|event| event.path))
                .unwrap();
        })
    };
    // Repeated committed appends remove any assumption about thread scheduling
    // or when sys_watch registers. Only an actual delivered event can pass.
    let deadline = Instant::now() + Duration::from_secs(5);
    let observed = loop {
        let offset = store
            .append_guarded_record(HISTORY, b"durable-frame", &handle)
            .unwrap();
        assert_eq!(
            store
                .get_stream_entry(&format!("{}{offset}", wal_stream_prefix(HISTORY)))
                .unwrap()
                .unwrap(),
            b"durable-frame"
        );
        match received.recv_timeout(Duration::from_millis(20)) {
            Ok(event) => break event,
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
            Err(mpsc::RecvTimeoutError::Timeout) => break None,
            other => panic!("guarded append did not reach the parked Kernel watch: {other:?}"),
        }
    };
    watcher.join().unwrap();
    assert_eq!(observed.as_deref(), Some(HISTORY));
}

#[test]
fn refused_guarded_and_ordinary_appends_do_not_publish_watch_events() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let handle = admit(&store);
    let kernel = Arc::new(Kernel::new());
    let zone = runtime.0.get_zone("root").unwrap();
    install_stream_wakeup_observer(&zone.consensus_node(), Arc::downgrade(&kernel), "root");
    store
        .retire_record_guard(OWNER, image("deleted"), &handle)
        .unwrap();
    let watcher = {
        let kernel = Arc::clone(&kernel);
        std::thread::spawn(move || kernel.sys_watch(HISTORY, 1_000))
    };
    // Every proposal is rejected by the real apply transaction. Repeat across
    // the watch window so the check cannot miss a registration race.
    while !watcher.is_finished() {
        assert!(store
            .append_guarded_record(HISTORY, b"retired-writer", &handle)
            .is_err());
        assert!(store
            .append_stream_entry(&wal_stream_prefix(HISTORY), b"ordinary-bypass")
            .is_err());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(watcher.join().unwrap().is_none());
    assert_eq!(store.stream_tail(&wal_stream_prefix(HISTORY)).unwrap(), 0);
    assert_eq!(
        store
            .read_versioned(OWNER)
            .unwrap()
            .unwrap()
            .metadata
            .content_id,
        Some("deleted".into())
    );
}
