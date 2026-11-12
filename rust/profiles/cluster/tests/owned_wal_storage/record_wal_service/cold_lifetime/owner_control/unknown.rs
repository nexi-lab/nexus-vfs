//! Unknown readback keeps its real original store after an equal-revision remount.

use super::super::super::after_inode::{FailAfterInode, CUT};
use super::{retire, run_in_cold_child, service, snapshot, wait_for, ClonedStores, HISTORY, OWNER};
use kernel::core::stream::wal::wal_stream_prefix;
use kernel::kernel::conditional_content::ConditionalContentError;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::OperationContext;
use kernel::meta_store::{MetaStore, DT_STREAM};
use kernel::stream::StreamBackend;
use std::sync::{atomic::Ordering, Arc};

fn unknown_keeps_original_storage() {
    let stores = ClonedStores::open();
    let b = stores
        .b
        .kernel
        .create_record_wal_with_control(HISTORY, OWNER, &service(), &stores.version)
        .unwrap();
    assert_eq!(b.wal().write_sync(b"original B").unwrap(), 0);
    let fault = Arc::new(FailAfterInode::new(stores.a.store.clone()));
    stores
        .a
        .kernel
        .mount(
            "/",
            MountOptions::new(&service(), "local")
                .with_backend(stores.a_backend.clone())
                .with_metastore(fault.clone()),
        )
        .unwrap();
    let untrusted = OperationContext::new("other-agent", "root", false, None, false);
    let refused = match stores.a.kernel.create_record_wal_with_control(
        HISTORY,
        OWNER,
        &untrusted,
        &stores.version,
    ) {
        Err(error) => error,
        Ok(_) => panic!("an untrusted caller obtained an owned WAL"),
    };
    assert!(
        refused.recovery().is_none(),
        "pre-admission refusal minted a recovery capability"
    );
    assert!(matches!(
        refused.outcome(),
        ConditionalContentError::Failed(_)
    ));
    assert_eq!(fault.fault_count(), 0);
    let error = match stores.a.kernel.create_record_wal_with_control(
        HISTORY,
        OWNER,
        &service(),
        &stores.version,
    ) {
        Err(error) => error,
        Ok(_) => panic!("post-inode fault returned a ready pair"),
    };
    assert!(
        matches!(error.outcome(), ConditionalContentError::Unknown(message) if message.contains(CUT))
    );
    assert_eq!(fault.fault_count(), 1);
    let recovery = error
        .recovery()
        .expect("Unknown lost original readback authority")
        .clone();
    let committed_a = snapshot(&stores.a, HISTORY);
    assert_eq!(committed_a.metadata.entry_type, DT_STREAM);
    let prefix = wal_stream_prefix(HISTORY);
    assert_eq!(stores.a.store.stream_tail(&prefix).unwrap(), 0);

    stores
        .a
        .kernel
        .mount(
            "/",
            MountOptions::new(&service(), "local")
                .with_backend(stores.b_backend.clone())
                .with_metastore(stores.b.store.clone()),
        )
        .unwrap();
    let visible_b = stores
        .a
        .kernel
        .open_record_wal_with_control(HISTORY, OWNER, &service(), &stores.version)
        .unwrap();
    assert_eq!(
        visible_b.wal().read_at(0).unwrap(),
        Some(b"original B".to_vec())
    );
    let b_owner = snapshot(&stores.b, OWNER);
    let b_history = snapshot(&stores.b, HISTORY);
    let b_tail = stores.b.store.stream_tail(&prefix).unwrap();
    let b_floor = stores.b.store.stream_floor(&prefix).unwrap();
    let b_segments = stores.b.store.list_stream_segments(&prefix).unwrap();
    let b_reads = stores.b_backend.reads.load(Ordering::SeqCst);
    let b_staged = stores.b_backend.staged.lock().unwrap().clone();

    let original = recovery.open().unwrap();
    assert_eq!(
        original.wal().read_at(0).unwrap(),
        None,
        "Unknown recovery followed replacement B"
    );
    let initialization = b"original initialization operation";
    assert_eq!(original.wal().write_sync(initialization).unwrap(), 0);
    for index in 1..3 {
        assert_eq!(
            original
                .wal()
                .write_sync(format!("original A{index}").as_bytes())
                .unwrap(),
            index
        );
    }
    assert_eq!(
        StreamBackend::push(original.wal(), b"original A3").unwrap(),
        3
    );
    wait_for(|| stores.a.store.stream_floor(&prefix).unwrap() == 2);
    assert_eq!(
        recovery.open().unwrap().wal().read_at(0).unwrap(),
        Some(initialization.to_vec())
    );
    let after_a = snapshot(&stores.a, HISTORY);
    assert_eq!(after_a.metadata, committed_a.metadata);
    assert_eq!(after_a.version, committed_a.version);
    assert_eq!(stores.a.store.stream_tail(&prefix).unwrap(), 4);
    assert_eq!(stores.b.store.stream_tail(&prefix).unwrap(), b_tail);
    assert_eq!(stores.b.store.stream_floor(&prefix).unwrap(), b_floor);
    assert_eq!(
        stores.b.store.list_stream_segments(&prefix).unwrap(),
        b_segments
    );
    assert_eq!(snapshot(&stores.b, OWNER).metadata, b_owner.metadata);
    assert_eq!(snapshot(&stores.b, OWNER).version, b_owner.version);
    assert_eq!(snapshot(&stores.b, HISTORY).metadata, b_history.metadata);
    assert_eq!(snapshot(&stores.b, HISTORY).version, b_history.version);
    assert_eq!(stores.b_backend.reads.load(Ordering::SeqCst), b_reads);
    assert_eq!(*stores.b_backend.staged.lock().unwrap(), b_staged);

    let terminal = retire(recovery.owner(), &stores.version);
    assert!(recovery.owner().state().unwrap().is_retired);
    assert!(recovery.open().is_err());
    assert!(original.wal().write_sync(b"retired A").is_err());
    wait_for(|| {
        recovery
            .owner()
            .try_exclude_retired_io(&terminal)
            .unwrap()
            .is_some()
    });
    assert!(!b.owner().state().unwrap().is_retired);
    assert_eq!(b.wal().write_sync(b"B remains writable").unwrap(), 1);
}

#[test]
fn kernel_owned_wal_unknown_retains_original_pair_across_remount() {
    run_in_cold_child(
        "record_wal_service::cold_lifetime::owner_control::unknown::kernel_owned_wal_unknown_retains_original_pair_across_remount",
        unknown_keeps_original_storage,
    );
}
