//! The lifecycle authority follows original I/O across replacement and cloning.

use super::{run_in_cold_child, service, wait_for, Cut, Fixture, PausedCas, HISTORY, OWNER};
use kernel::core::stream::wal::wal_stream_prefix;
use kernel::kernel::conditional_content::ConditionalContentResult;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::record_control::{RecordContentExclusion, RecordContentOwner};
use kernel::kernel::{OperationContext, RecordWalHandle};
use kernel::meta_store::{MetaStore, MetadataSnapshot};
use kernel::stream::StreamBackend;
use std::path::Path;
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;

fn copy_closed_fixture(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        assert!(
            !kind.is_symlink(),
            "the private store fixture contains a link"
        );
        if kind.is_dir() {
            copy_closed_fixture(&entry.path(), &destination.join(entry.file_name()));
        } else {
            std::fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
        }
    }
}

struct ClonedStores {
    a: Fixture,
    b: Fixture,
    a_backend: Arc<PausedCas>,
    b_backend: Arc<PausedCas>,
    version: Vec<u8>,
    _a_directory: tempfile::TempDir,
    _b_directory: tempfile::TempDir,
}

impl ClonedStores {
    fn open() -> Self {
        let a_directory = tempfile::tempdir().unwrap();
        let b_directory = tempfile::tempdir().unwrap();
        let seed = Fixture::open(a_directory.path(), true);
        let version = seed.enroll();
        // No WAL worker exists yet. Shutdown closes the original native store
        // before copying its committed owner and opaque revision to real B.
        drop(seed);
        copy_closed_fixture(a_directory.path(), b_directory.path());
        let a_backend = Arc::new(PausedCas::new(&a_directory.path().join("cas")));
        let b_backend = Arc::new(PausedCas::new(&b_directory.path().join("cas")));
        let a = Fixture::open_with_components(a_directory.path(), |s| s, a_backend.clone()).0;
        let b = Fixture::open_with_components(b_directory.path(), |s| s, b_backend.clone()).0;
        a.kernel.arm_stream_materializer();
        b.kernel.arm_stream_materializer();
        for fixture in [&a, &b] {
            let state = fixture
                .kernel
                .record_content_owner_state(OWNER, &service())
                .unwrap();
            assert!(!state.is_retired);
            assert_eq!(state.version, version, "copied opaque revision changed");
        }
        Self {
            a,
            b,
            a_backend,
            b_backend,
            version,
            _a_directory: a_directory,
            _b_directory: b_directory,
        }
    }
}

fn snapshot(fixture: &Fixture, path: &str) -> MetadataSnapshot {
    fixture
        .store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(path)
        .unwrap()
        .unwrap()
}

fn retire(owner: &RecordContentOwner, version: &[u8]) -> Vec<u8> {
    match owner.retire(version).unwrap() {
        ConditionalContentResult::Committed { version } => version,
        other => panic!("expected original owner's committed retirement: {other:?}"),
    }
}

fn independent_b_exclusion(
    b: &RecordWalHandle,
    a_owner: &RecordContentOwner,
    a_terminal: &[u8],
    original_version: &[u8],
) -> RecordContentExclusion {
    assert!(!b.owner().state().unwrap().is_retired);
    assert_eq!(b.wal().write_sync(b"B remains writable").unwrap(), 1);
    let b_terminal = retire(b.owner(), original_version);
    let b_exclusion = b
        .owner()
        .try_exclude_retired_io(&b_terminal)
        .unwrap()
        .expect("B has no admitted I/O");
    assert!(b.owner().owns_exclusion(&b_exclusion));
    assert!(
        !a_owner.owns_exclusion(&b_exclusion),
        "replacement B's exclusion authorized original A cleanup"
    );
    assert!(
        a_owner
            .try_exclude_retired_io(a_terminal)
            .unwrap()
            .is_none(),
        "B exclusion was mistaken for original A I/O drain"
    );
    b_exclusion
}

fn lifecycle_stays_with_original_io() {
    let stores = ClonedStores::open();
    let writer = stores
        .a
        .kernel
        .create_record_wal_with_control(HISTORY, OWNER, &service(), &stores.version)
        .unwrap();
    let b = stores
        .b
        .kernel
        .create_record_wal_with_control(HISTORY, OWNER, &service(), &stores.version)
        .unwrap();
    assert_eq!(b.wal().write_sync(b"original B").unwrap(), 0);
    assert_eq!(b.wal().read_at(0).unwrap(), Some(b"original B".to_vec()));
    assert_eq!(writer.owner().state().unwrap(), b.owner().state().unwrap());
    for index in 0..4 {
        assert_eq!(
            StreamBackend::push(writer.wal(), format!("original A{index}").as_bytes()).unwrap(),
            index
        );
    }
    let prefix = wal_stream_prefix(HISTORY);
    wait_for(|| stores.a.store.stream_floor(&prefix).unwrap() == 2);
    let segment = stores
        .a
        .store
        .list_stream_segments(&prefix)
        .unwrap()
        .remove(0);
    let reader = Arc::new(
        stores
            .a
            .kernel
            .open_record_wal_with_control(HISTORY, OWNER, &service(), &stores.version)
            .unwrap(),
    );
    let untrusted = OperationContext::new("agent-a", "root", false, None, false);
    assert!(stores
        .a
        .kernel
        .capture_record_content_owner(OWNER, &untrusted)
        .is_err());
    assert!(stores
        .a
        .kernel
        .capture_record_content_owner(HISTORY, &service())
        .is_err());
    let b_history = snapshot(&stores.b, HISTORY);
    let b_owner = snapshot(&stores.b, OWNER);
    let b_reads = stores.b_backend.reads.load(Ordering::SeqCst);
    let (entered, resume) = stores.a_backend.arm(Cut::Read(segment.content_id));
    let request = Arc::clone(&reader);
    let work = std::thread::spawn(move || request.wal().read_at(0));
    entered.recv_timeout(Duration::from_secs(10)).unwrap();
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
    // Both path and initial opaque revision match. Only the retained storage
    // capability distinguishes A's decision and native lifetime lock from B's.
    assert_eq!(reader.owner().state().unwrap().version, stores.version);
    let terminal = retire(reader.owner(), &stores.version);
    let retired = reader.owner().state().unwrap();
    assert!(
        retired.is_retired,
        "original A owner was not retired by its retained control"
    );
    assert_eq!(retired.version, terminal);
    assert!(
        !stores
            .a
            .kernel
            .record_content_owner_state(OWNER, &service())
            .unwrap()
            .is_retired
    );
    let unchanged_history = snapshot(&stores.b, HISTORY);
    let unchanged_owner = snapshot(&stores.b, OWNER);
    assert_eq!(unchanged_history.metadata, b_history.metadata);
    assert_eq!(unchanged_history.version, b_history.version);
    assert_eq!(unchanged_owner.metadata, b_owner.metadata);
    assert_eq!(unchanged_owner.version, b_owner.version);
    assert_eq!(stores.b.store.stream_tail(&prefix).unwrap(), 1);
    assert_eq!(stores.b.store.stream_floor(&prefix).unwrap(), 0);
    assert!(stores
        .b
        .store
        .list_stream_segments(&prefix)
        .unwrap()
        .is_empty());
    assert!(stores.b_backend.staged.lock().unwrap().is_empty());
    assert_eq!(stores.b_backend.reads.load(Ordering::SeqCst), b_reads);
    let b_exclusion = independent_b_exclusion(&b, reader.owner(), &terminal, &stores.version);
    resume.send(()).unwrap();
    assert_eq!(work.join().unwrap().unwrap(), Some(b"original A0".to_vec()));
    wait_for(|| {
        reader
            .owner()
            .try_exclude_retired_io(&terminal)
            .unwrap()
            .is_some()
    });
    let a_exclusion = reader
        .owner()
        .try_exclude_retired_io(&terminal)
        .unwrap()
        .unwrap();
    assert!(reader.owner().owns_exclusion(&a_exclusion));
    assert!(!b.owner().owns_exclusion(&a_exclusion));
    assert!(!reader.owner().owns_exclusion(&b_exclusion));
    assert!(reader.wal().write_sync(b"retired A").is_err());
    assert!(writer.wal().read_at(0).is_err());
}

#[test]
fn kernel_owned_wal_control_keeps_original_owner_across_equal_revision_remount() {
    run_in_cold_child(
        "record_wal_service::cold_lifetime::owner_control::kernel_owned_wal_control_keeps_original_owner_across_equal_revision_remount",
        lifecycle_stays_with_original_io,
    );
}

#[test]
fn kernel_owned_wal_reopen_pairs_only_its_actual_owner() {
    const OTHER_OWNER: &str = "/sessions/other-session/lifetime";
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(directory.path(), true);
    let original_version = fixture.enroll();
    let other_version = fixture.enroll_at(OTHER_OWNER, fixture.store.as_ref());
    let writer = fixture
        .kernel
        .create_record_wal_with_control(HISTORY, OWNER, &service(), &original_version)
        .unwrap();
    assert_eq!(
        writer.wal().write_sync(b"original owner payload").unwrap(),
        0
    );
    let other = fixture
        .kernel
        .capture_record_content_owner(OTHER_OWNER, &service())
        .unwrap();
    assert_eq!(other.state().unwrap().version, other_version);
    assert!(!other.state().unwrap().is_retired);
    let original_before = snapshot(&fixture, OWNER);
    let other_before = snapshot(&fixture, OTHER_OWNER);
    let history_before = snapshot(&fixture, HISTORY);
    let refusal = match fixture.kernel.open_record_wal_with_control(
        HISTORY,
        OTHER_OWNER,
        &service(),
        &original_version,
    ) {
        Err(error) => error,
        Ok(_) => panic!("WAL reopened with another valid owner's control"),
    };
    assert!(
        refusal
            .to_string()
            .contains("record binding does not match its control owner"),
        "unexpected setup or storage error: {refusal}"
    );
    for (path, before) in [
        (OWNER, original_before),
        (OTHER_OWNER, other_before),
        (HISTORY, history_before),
    ] {
        let after = snapshot(&fixture, path);
        assert_eq!(after.metadata, before.metadata);
        assert_eq!(after.version, before.version);
    }
    assert_eq!(
        fixture
            .store
            .stream_tail(&wal_stream_prefix(HISTORY))
            .unwrap(),
        1
    );
    let reopened = fixture
        .kernel
        .open_record_wal_with_control(HISTORY, OWNER, &service(), &original_version)
        .unwrap();
    assert_eq!(
        reopened.owner().state().unwrap(),
        writer.owner().state().unwrap()
    );
    assert_eq!(
        reopened.wal().read_at(0).unwrap(),
        Some(b"original owner payload".to_vec())
    );
    assert!(!other.state().unwrap().is_retired);
}
