//! Owned WAL operations retain actual native I/O across retirement.

use super::record_guard::{admit, HISTORY, OWNER};
use super::*;
use kernel::core::stream::wal::{wal_stream_prefix, ColdSegmentStore, SealPolicy, WalStreamCore};
use kernel::stream::StreamBackend;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{mpsc, Mutex};
use std::time::Instant;

fn enrolled(store: &ZoneMetaStore) -> Vec<u8> {
    let owner = admit(store);
    store.admit_record_io_owner(OWNER, &owner).unwrap();
    owner
}

fn retire(store: &ZoneMetaStore, owner: &[u8]) -> Vec<u8> {
    match store
        .retire_record_guard(OWNER, image("deleted"), owner)
        .unwrap()
    {
        ConditionalMetadataResult::Committed { version } => version,
        outcome => panic!("expected terminal revision: {outcome:?}"),
    }
}

fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "owned WAL work did not finish");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn owned_wal_rejects_stale_handles_after_retirement_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = Arc::new(runtime.store("/", "/"));
    let owner = enrolled(&store);
    let core = WalStreamCore::new(store.clone(), HISTORY.into())
        .with_record_owner(HISTORY, owner.clone())
        .unwrap();
    let second = WalStreamCore::new(store.clone(), HISTORY.into())
        .with_record_owner(HISTORY, owner.clone())
        .unwrap();
    assert_eq!(core.write_sync(b"first").unwrap(), 0);
    assert_eq!(second.write_sync(b"second").unwrap(), 1);
    assert_eq!(core.read_at(1).unwrap(), Some(b"second".to_vec()));
    let terminal = retire(&store, &owner);
    for handle in [&core, &second] {
        assert!(handle.write_sync(b"stale").is_err());
        assert!(handle.read_at(0).is_err());
        assert!(StreamBackend::push(handle, b"").is_err());
    }
    // Idle handles do not pin reclamation until their runtime exits.
    assert!(store
        .try_exclude_retired_record_io(OWNER, &terminal)
        .unwrap()
        .is_some());
    drop((core, second, store, runtime));

    let reopened = Runtime::open(directory.path());
    let store = Arc::new(reopened.store("/", "/"));
    for version in [owner, terminal] {
        assert!(WalStreamCore::new(store.clone(), HISTORY.into())
            .with_record_owner(HISTORY, version)
            .is_err());
    }
    assert_eq!(store.stream_tail(&wal_stream_prefix(HISTORY)).unwrap(), 2);
}

struct NativeCold {
    directory: PathBuf,
    pause: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}

impl ColdSegmentStore for NativeCold {
    fn self_origin(&self) -> Option<String> {
        None
    }

    fn write_segment(&self, _: &str, base: u64, bytes: &[u8]) -> Result<String, String> {
        let pause = self.pause.lock().unwrap().take();
        if let Some((entered, resume)) = pause {
            entered.send(()).map_err(|error| error.to_string())?;
            resume.recv().map_err(|error| error.to_string())?;
        }
        let id = format!("{base}.segment");
        let mut file =
            std::fs::File::create(self.directory.join(&id)).map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        Ok(id)
    }

    fn read_segment(&self, _: &str, id: &str, _: &str) -> Result<Vec<u8>, String> {
        std::fs::read(self.directory.join(id)).map_err(|error| error.to_string())
    }
}

#[test]
fn mounted_owner_paths_share_one_canonical_wal_and_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let cold_directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let root = Arc::new(runtime.store("/", "/"));
    let owner = enrolled(&root);
    let first_view = Arc::new(runtime.store("/view-a", "/sessions/session-a"));
    let second_view = Arc::new(runtime.store("/view-b", "/sessions/session-a"));
    let cold = Arc::new(NativeCold {
        directory: cold_directory.path().into(),
        pause: Mutex::new(None),
    });
    let policy = SealPolicy {
        hot_window: 2,
        seal_batch: 2,
    };
    // A caller path cannot authorize a different canonical stream identity.
    assert!(
        WalStreamCore::new(first_view.clone(), "/different/history".into())
            .with_record_owner("/view-a/history", owner.clone())
            .is_err()
    );
    let first =
        WalStreamCore::with_cold_tier(first_view.clone(), HISTORY.into(), cold.clone(), policy, 0)
            .with_record_owner("/view-a/history", owner.clone())
            .unwrap();
    let second =
        WalStreamCore::with_cold_tier(second_view.clone(), HISTORY.into(), cold.clone(), policy, 0)
            .with_record_owner("/view-b/history", owner.clone())
            .unwrap();
    assert_eq!(first.stream_id(), second.stream_id());
    assert_eq!(first.write_sync(b"from-a").unwrap(), 0);
    assert_eq!(second.write_sync(b"from-b").unwrap(), 1);
    assert_eq!(first.read_at(1).unwrap(), Some(b"from-b".to_vec()));
    assert_eq!(second.read_at(0).unwrap(), Some(b"from-a".to_vec()));
    for seq in 2..10 {
        assert_eq!(
            StreamBackend::push(&first, format!("m{seq}").as_bytes()).unwrap(),
            seq
        );
    }
    let prefix = wal_stream_prefix(HISTORY);
    wait_for(|| root.stream_floor(&prefix).unwrap() == 8);
    // Reads include real cold files and populate the second handle's cache.
    assert_eq!(second.read_at(0).unwrap(), Some(b"from-a".to_vec()));
    for seq in 2..10 {
        assert_eq!(
            second.read_at(seq).unwrap(),
            Some(format!("m{seq}").into_bytes())
        );
    }
    for alias in ["/view-a/history", "/view-b/history"] {
        assert_eq!(root.stream_tail(&wal_stream_prefix(alias)).unwrap(), 0);
    }
    let terminal = match second_view
        .retire_record_guard("/view-b/lifetime", image("deleted"), &owner)
        .unwrap()
    {
        ConditionalMetadataResult::Committed { version } => version,
        outcome => panic!("expected terminal revision: {outcome:?}"),
    };
    for handle in [&first, &second] {
        assert!(
            handle.read_at(0).is_err(),
            "cached content must remain fenced"
        );
        assert!(handle.write_sync(b"retired").is_err());
    }
    wait_for(|| {
        root.try_exclude_retired_record_io(OWNER, &terminal)
            .unwrap()
            .is_some()
    });
    drop((first, second, first_view, second_view, root, runtime));

    let reopened = Runtime::open(directory.path());
    let store = Arc::new(reopened.store("/view-b", "/sessions/session-a"));
    for version in [owner, terminal] {
        assert!(WalStreamCore::new(store.clone(), HISTORY.into())
            .with_record_owner("/view-b/history", version)
            .is_err());
    }
    assert_eq!(store.stream_tail(&prefix).unwrap(), 10);
}

#[test]
fn owned_wal_seals_and_trims_with_the_captured_owner() {
    let directory = tempfile::tempdir().unwrap();
    let cold_directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = Arc::new(runtime.store("/", "/"));
    let owner = enrolled(&store);
    let core = WalStreamCore::with_cold_tier(
        store.clone(),
        HISTORY.into(),
        Arc::new(NativeCold {
            directory: cold_directory.path().into(),
            pause: Mutex::new(None),
        }),
        SealPolicy {
            hot_window: 2,
            seal_batch: 2,
        },
        64,
    )
    .with_record_owner(HISTORY, owner.clone())
    .unwrap();
    for seq in 0..10 {
        assert_eq!(
            StreamBackend::push(&core, format!("m{seq}").as_bytes()).unwrap(),
            seq
        );
    }
    let prefix = wal_stream_prefix(HISTORY);
    wait_for(|| {
        // Four 28-byte segments leave exactly the last two under a 64-byte
        // budget. Floor8 alone can precede the final trim from earliest2 to4.
        store.stream_floor(&prefix).unwrap() == 8 && store.stream_earliest(&prefix).unwrap() == 4
    });
    let earliest = store.stream_earliest(&prefix).unwrap();
    assert!(matches!(
        StreamBackend::read_at(&core, 0),
        Err(kernel::stream::StreamError::Truncated(_, 0))
    ));
    for seq in earliest..10 {
        assert_eq!(
            core.read_at(seq).unwrap(),
            Some(format!("m{seq}").into_bytes())
        );
    }
    // Even a terminal token cannot authorize another seal or trim.
    let terminal = retire(&store, &owner);
    let segment = store.list_stream_segments(&prefix).unwrap().pop().unwrap();
    for version in [&owner, &terminal] {
        let records = store.as_guarded_records().unwrap();
        assert!(records
            .seal_guarded_record(HISTORY, &segment, version)
            .is_err());
        assert!(records
            .trim_guarded_record(HISTORY, 10, vec![], version)
            .is_err());
    }
    assert!(core.read_at(earliest).is_err());
    assert_eq!(store.stream_tail(&prefix).unwrap(), 10);
}

#[test]
fn background_seal_keeps_io_until_real_work_finishes_after_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let cold_directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = Arc::new(runtime.store("/", "/"));
    let owner = enrolled(&store);
    let (entered, entry) = mpsc::channel();
    let (resume, resumption) = mpsc::channel();
    let core = WalStreamCore::with_cold_tier(
        store.clone(),
        HISTORY.into(),
        Arc::new(NativeCold {
            directory: cold_directory.path().into(),
            pause: Mutex::new(Some((entered, resumption))),
        }),
        SealPolicy {
            hot_window: 1,
            seal_batch: 1,
        },
        0,
    )
    .with_record_owner(HISTORY, owner.clone())
    .unwrap();
    StreamBackend::push(&core, b"first").unwrap();
    StreamBackend::push(&core, b"second").unwrap();
    entry.recv_timeout(Duration::from_secs(10)).unwrap();
    let terminal = retire(&store, &owner);
    // The actual seal thread owns the handle, independent of the request/core.
    drop(core);
    assert!(store
        .try_exclude_retired_record_io(OWNER, &terminal)
        .unwrap()
        .is_none());
    resume.send(()).unwrap();
    wait_for(|| {
        store
            .try_exclude_retired_record_io(OWNER, &terminal)
            .unwrap()
            .is_some()
    });
    assert!(cold_directory.path().join("0.segment").is_file());
    let prefix = wal_stream_prefix(HISTORY);
    assert_eq!(store.stream_floor(&prefix).unwrap(), 0);
    assert!(store.list_stream_segments(&prefix).unwrap().is_empty());
    assert_eq!(store.stream_tail(&prefix).unwrap(), 2);
    // Staged content was not physically deleted without shared-reference proof.
}
