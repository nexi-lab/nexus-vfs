//! Real Kernel cold-tier I/O outlives cancellation, with process-local policy.

use super::{service, Fixture, HISTORY, OWNER};
use backends::storage::cas_local::CasLocalBackend;
use kernel::abc::object_store::{ObjectStore, StorageError, WriteResult};
use kernel::cas_engine::CASEngine;
use kernel::core::stream::wal::wal_stream_prefix;
use kernel::kernel::conditional_content::ConditionalContentResult;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::OperationContext;
use kernel::meta_store::MetaStore;
use kernel::stream::StreamBackend;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

#[path = "cold_lifetime/owner_control.rs"]
mod owner_control;

enum Cut {
    Write,
    Read(String),
}

struct Pause {
    cut: Cut,
    entered: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
}

/// Preserve real durable CAS operations; pause only after their actual I/O.
struct PausedCas {
    inner: CasLocalBackend,
    pause: Mutex<Option<Pause>>,
    staged: Mutex<Vec<String>>,
    reads: AtomicUsize,
}

impl PausedCas {
    fn new(directory: &std::path::Path) -> Self {
        Self {
            inner: CasLocalBackend::new_durable(directory).unwrap(),
            pause: Mutex::new(None),
            staged: Mutex::new(Vec::new()),
            reads: AtomicUsize::new(0),
        }
    }

    fn arm(&self, cut: Cut) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered, entry) = mpsc::channel();
        let (resume, resumption) = mpsc::channel();
        let mut pause = self.pause.lock().unwrap();
        assert!(pause.is_none());
        *pause = Some(Pause {
            cut,
            entered,
            resume: resumption,
        });
        (entry, resume)
    }

    fn stop_after(&self, matches: impl FnOnce(&Cut) -> bool) {
        let mut pending = self.pause.lock().unwrap();
        let pause = if pending.as_ref().is_some_and(|pause| matches(&pause.cut)) {
            pending.take()
        } else {
            None
        };
        drop(pending);
        if let Some(pause) = pause {
            pause.entered.send(()).unwrap();
            pause.resume.recv().unwrap();
        }
    }
}

impl ObjectStore for PausedCas {
    fn name(&self) -> &str {
        self.inner.name()
    }

    #[allow(private_interfaces)]
    fn as_cas(&self) -> Option<&CASEngine> {
        self.inner.as_cas()
    }

    fn write_content(
        &self,
        content: &[u8],
        content_id: &str,
        ctx: &OperationContext,
        offset: u64,
    ) -> Result<WriteResult, StorageError> {
        let result = self.inner.write_content(content, content_id, ctx, offset)?;
        if content_id.starts_with("/__stream_segments__/") {
            self.staged.lock().unwrap().push(result.content_id.clone());
            self.stop_after(|cut| matches!(cut, Cut::Write));
        }
        Ok(result)
    }

    fn read_content(
        &self,
        content_id: &str,
        ctx: &OperationContext,
    ) -> Result<Vec<u8>, StorageError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let bytes = self.inner.read_content(content_id, ctx)?;
        self.stop_after(|cut| matches!(cut, Cut::Read(expected) if expected == content_id));
        Ok(bytes)
    }
}

fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "Kernel cold-tier I/O did not finish"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn retire(fixture: &Fixture, owner: &[u8]) -> Vec<u8> {
    match fixture
        .kernel
        .retire_record_content_owner(OWNER, &service(), owner)
        .unwrap()
    {
        ConditionalContentResult::Committed { version } => version,
        other => panic!("expected committed retirement: {other:?}"),
    }
}

fn cancelled_cold_read() {
    let directory = tempfile::tempdir().unwrap();
    let backend = Arc::new(PausedCas::new(&directory.path().join("cas")));
    let fixture = Fixture::open_with_components(directory.path(), |store| store, backend.clone()).0;
    fixture.kernel.arm_stream_materializer();
    let owner = fixture.enroll();
    let writer = fixture
        .kernel
        .create_record_wal(HISTORY, OWNER, &service(), &owner)
        .unwrap();
    for sequence in 0..4 {
        assert_eq!(
            StreamBackend::push(&writer, format!("m{sequence}").as_bytes()).unwrap(),
            sequence
        );
    }
    let prefix = wal_stream_prefix(HISTORY);
    wait_for(|| fixture.store.stream_floor(&prefix).unwrap() == 2);
    assert!(fixture
        .store
        .get_stream_entry(&format!("{prefix}0"))
        .unwrap()
        .is_none());
    let segment = fixture
        .store
        .list_stream_segments(&prefix)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!((segment.base, segment.end), (0, 2));

    let cached = fixture
        .kernel
        .open_record_wal(HISTORY, &service(), &owner)
        .unwrap();
    let before = backend.reads.load(Ordering::SeqCst);
    assert_eq!(cached.read_at(0).unwrap(), Some(b"m0".to_vec()));
    assert!(backend.reads.load(Ordering::SeqCst) > before);

    let reader = fixture
        .kernel
        .open_record_wal(HISTORY, &service(), &owner)
        .unwrap();
    let (entered, resume) = backend.arm(Cut::Read(segment.content_id.clone()));
    let (finished, completion) = mpsc::channel();
    let request = fixture._runtime.0.runtime_handle().spawn_blocking(move || {
        let result = reader.read_at(0);
        finished.send(result).unwrap();
    });
    entered.recv_timeout(Duration::from_secs(10)).unwrap();
    // Abort the actual waiting task; a running blocking worker still owns I/O.
    request.abort();
    drop(request);
    let terminal = retire(&fixture, &owner);
    assert!(fixture
        .kernel
        .try_exclude_retired_content_io(OWNER, &service(), &terminal)
        .unwrap()
        .is_none());
    assert!(
        cached.read_at(0).is_err(),
        "cached reads must recheck retirement"
    );
    assert!(writer.write_sync(b"retired writer").is_err());
    resume.send(()).unwrap();
    assert_eq!(
        completion
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap(),
        Some(b"m0".to_vec())
    );
    wait_for(|| {
        fixture
            .kernel
            .try_exclude_retired_content_io(OWNER, &service(), &terminal)
            .unwrap()
            .is_some()
    });
    assert_eq!(fixture.store.stream_tail(&prefix).unwrap(), 4);
    assert_eq!(fixture.store.stream_floor(&prefix).unwrap(), 2);
    assert_eq!(
        fixture.store.list_stream_segments(&prefix).unwrap().len(),
        1
    );
    // Retirement neither unlinks shared CAS bytes nor recreates an owned handle.
    assert!(backend
        .inner
        .read_content(&segment.content_id, &service())
        .is_ok());
    for version in [&owner, &terminal] {
        assert!(fixture
            .kernel
            .open_record_wal(HISTORY, &service(), version)
            .is_err());
    }
}

fn dropped_seal_handle() {
    let directory = tempfile::tempdir().unwrap();
    let backend = Arc::new(PausedCas::new(&directory.path().join("cas")));
    let fixture = Fixture::open_with_components(directory.path(), |store| store, backend.clone()).0;
    fixture.kernel.arm_stream_materializer();
    let owner = fixture.enroll();
    let core = fixture
        .kernel
        .create_record_wal(HISTORY, OWNER, &service(), &owner)
        .unwrap();
    let (entered, resume) = backend.arm(Cut::Write);
    for sequence in 0..4 {
        assert_eq!(
            StreamBackend::push(&core, format!("m{sequence}").as_bytes()).unwrap(),
            sequence
        );
    }
    entered.recv_timeout(Duration::from_secs(10)).unwrap();
    let staged = backend.staged.lock().unwrap().clone();
    assert_eq!(staged.len(), 1);
    assert!(backend.inner.read_content(&staged[0], &service()).is_ok());
    let terminal = retire(&fixture, &owner);
    drop(core);
    assert!(fixture
        .kernel
        .try_exclude_retired_content_io(OWNER, &service(), &terminal)
        .unwrap()
        .is_none());
    resume.send(()).unwrap();
    wait_for(|| {
        fixture
            .kernel
            .try_exclude_retired_content_io(OWNER, &service(), &terminal)
            .unwrap()
            .is_some()
    });
    let prefix = wal_stream_prefix(HISTORY);
    assert_eq!(fixture.store.stream_tail(&prefix).unwrap(), 4);
    assert_eq!(fixture.store.stream_floor(&prefix).unwrap(), 0);
    assert!(fixture
        .store
        .list_stream_segments(&prefix)
        .unwrap()
        .is_empty());
    assert!(backend.inner.read_content(&staged[0], &service()).is_ok());
    for version in [&owner, &terminal] {
        assert!(fixture
            .kernel
            .open_record_wal(HISTORY, &service(), version)
            .is_err());
    }
}

fn remounted_content_stays_with_its_admitted_store() {
    let first_directory = tempfile::tempdir().unwrap();
    let second_directory = tempfile::tempdir().unwrap();
    let first_backend = Arc::new(PausedCas::new(&first_directory.path().join("cas")));
    let second_backend = Arc::new(PausedCas::new(&second_directory.path().join("cas")));
    let first =
        Fixture::open_with_components(first_directory.path(), |store| store, first_backend.clone())
            .0;
    let second = Fixture::open_with_components(
        second_directory.path(),
        |store| store,
        second_backend.clone(),
    )
    .0;
    first.kernel.arm_stream_materializer();
    second.kernel.arm_stream_materializer();
    let first_owner = first.enroll();
    let second_owner = second.enroll();
    let first_writer = first
        .kernel
        .create_record_wal(HISTORY, OWNER, &service(), &first_owner)
        .unwrap();
    let second_writer = second
        .kernel
        .create_record_wal(HISTORY, OWNER, &service(), &second_owner)
        .unwrap();
    for sequence in 0..4 {
        assert_eq!(
            StreamBackend::push(&first_writer, format!("a{sequence}").as_bytes()).unwrap(),
            sequence
        );
        assert_eq!(
            StreamBackend::push(&second_writer, format!("b{sequence}").as_bytes()).unwrap(),
            sequence
        );
    }
    let prefix = wal_stream_prefix(HISTORY);
    wait_for(|| {
        first.store.stream_floor(&prefix).unwrap() == 2
            && second.store.stream_floor(&prefix).unwrap() == 2
    });
    assert_eq!(first_writer.read_at(0).unwrap(), Some(b"a0".to_vec()));
    assert_eq!(second_writer.read_at(0).unwrap(), Some(b"b0".to_vec()));
    let first_reader = first
        .kernel
        .open_record_wal(HISTORY, &service(), &first_owner)
        .unwrap();
    let first_sealer = first
        .kernel
        .open_record_wal(HISTORY, &service(), &first_owner)
        .unwrap();
    let second_image = second
        .store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(HISTORY)
        .unwrap()
        .unwrap();
    let second_owner_image = second
        .store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(OWNER)
        .unwrap()
        .unwrap();
    let second_segments = second.store.list_stream_segments(&prefix).unwrap();
    assert_eq!(second_segments.len(), 1);

    // Replace both real storage pillars at the same path and zone. Old handles
    // still name the first store; newly admitted handles use the second.
    first
        .kernel
        .mount(
            "/",
            MountOptions::new(&service(), "local")
                .with_backend(second_backend.clone())
                .with_metastore(second.store.clone()),
        )
        .unwrap();
    let current = first
        .kernel
        .open_record_wal(HISTORY, &service(), &second_owner)
        .unwrap();
    assert_eq!(current.read_at(0).unwrap(), Some(b"b0".to_vec()));
    let first_reads = first_backend.reads.load(Ordering::SeqCst);
    let second_reads = second_backend.reads.load(Ordering::SeqCst);
    let second_staged = second_backend.staged.lock().unwrap().clone();
    // This handle has an empty segment cache: a successful read must reach the
    // captured original backend, even when the current mount has another log.
    assert_eq!(first_reader.read_at(0).unwrap(), Some(b"a0".to_vec()));
    assert!(first_backend.reads.load(Ordering::SeqCst) > first_reads);
    assert_eq!(second_backend.reads.load(Ordering::SeqCst), second_reads);

    // Use a fresh captured handle for the trigger, so this check does not race
    // the first writer's previous background worker clearing its trigger flag.
    assert_eq!(first_writer.write_sync(b"a4").unwrap(), 4);
    assert_eq!(StreamBackend::push(&first_sealer, b"a5").unwrap(), 5);
    wait_for(|| first.store.stream_floor(&prefix).unwrap() == 4);
    assert_eq!(first_reader.read_at(2).unwrap(), Some(b"a2".to_vec()));
    let segment = first
        .store
        .list_stream_segments(&prefix)
        .unwrap()
        .into_iter()
        .find(|segment| segment.base == 2)
        .unwrap();
    assert!(first_backend
        .inner
        .read_content(&segment.content_id, &service())
        .is_ok());
    assert!(second_backend
        .inner
        .read_content(&segment.content_id, &service())
        .is_err());
    assert_eq!(
        second_backend.staged.lock().unwrap().as_slice(),
        second_staged.as_slice()
    );
    assert_eq!(second_backend.reads.load(Ordering::SeqCst), second_reads);
    assert_eq!(first.store.stream_tail(&prefix).unwrap(), 6);
    assert_eq!(second.store.stream_tail(&prefix).unwrap(), 4);
    assert_eq!(second.store.stream_floor(&prefix).unwrap(), 2);
    let unchanged = second
        .store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(HISTORY)
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.version, second_image.version);
    assert_eq!(unchanged.metadata, second_image.metadata);
    let unchanged_owner = second
        .store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(OWNER)
        .unwrap()
        .unwrap();
    assert_eq!(unchanged_owner.version, second_owner_image.version);
    assert_eq!(unchanged_owner.metadata, second_owner_image.metadata);
    let unchanged_segments = second.store.list_stream_segments(&prefix).unwrap();
    assert_eq!(unchanged_segments.len(), second_segments.len());
    assert_eq!(
        unchanged_segments[0].content_id,
        second_segments[0].content_id
    );

    first
        .kernel
        .mount(
            "/",
            MountOptions::new(&service(), "local")
                .with_backend(first_backend.clone())
                .with_metastore(first.store.clone()),
        )
        .unwrap();
    retire(&first, &first_owner);
    first
        .kernel
        .mount(
            "/",
            MountOptions::new(&service(), "local")
                .with_backend(second_backend.clone())
                .with_metastore(second.store.clone()),
        )
        .unwrap();
    for handle in [&first_reader, &first_writer, &first_sealer] {
        assert!(handle.read_at(0).is_err());
        assert!(handle.write_sync(b"retired first store writer").is_err());
    }
    assert_eq!(current.read_at(0).unwrap(), Some(b"b0".to_vec()));
    assert_eq!(current.write_sync(b"b4").unwrap(), 4);
    assert_eq!(first.store.stream_tail(&prefix).unwrap(), 6);
    assert_eq!(second.store.stream_tail(&prefix).unwrap(), 5);
}

fn run_in_cold_child(test_name: &str, case: impl FnOnce()) {
    const CHILD: &str = "NEXUS_Q1_KERNEL_COLD_CHILD";
    let completed = format!("Q1 Kernel cold-tier actual I/O case completed: {test_name}");
    if std::env::var_os(CHILD).is_none() {
        // Existing production knobs are scoped to this real test subprocess.
        // Parallel test cases and the user's shell retain their environment.
        let outcome = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD, test_name)
            .env("NEXUS_STREAM_HOT_WINDOW", "2")
            .env("NEXUS_STREAM_SEAL_BATCH", "2")
            .output()
            .unwrap();
        let stdout = String::from_utf8(outcome.stdout).unwrap();
        let stderr = String::from_utf8(outcome.stderr).unwrap();
        print!("{stdout}");
        eprint!("{stderr}");
        assert!(
            outcome.status.success(),
            "real Kernel cold-tier child failed: {}",
            outcome.status
        );
        assert!(
            stdout.contains(&completed),
            "child did not complete its real I/O cuts"
        );
        assert!(
            stdout.contains("test result: ok. 1 passed; 0 failed;"),
            "exact child selection did not execute one test"
        );
        return;
    }
    assert_eq!(std::env::var(CHILD).unwrap(), test_name);
    assert_eq!(std::env::var("NEXUS_STREAM_HOT_WINDOW").unwrap(), "2");
    assert_eq!(std::env::var("NEXUS_STREAM_SEAL_BATCH").unwrap(), "2");
    case();
    println!("{completed}");
}

#[test]
fn kernel_owned_wal_cold_reads_and_cancelled_seals_keep_actual_io() {
    run_in_cold_child(
        "record_wal_service::cold_lifetime::kernel_owned_wal_cold_reads_and_cancelled_seals_keep_actual_io",
        || {
            cancelled_cold_read();
            dropped_seal_handle();
        },
    );
}

#[test]
fn kernel_owned_wal_keeps_captured_content_across_remount() {
    run_in_cold_child(
        "record_wal_service::cold_lifetime::kernel_owned_wal_keeps_captured_content_across_remount",
        remounted_content_stays_with_its_admitted_store,
    );
}

fn fresh_admissions_during_mount_replacement() {
    use std::sync::atomic::AtomicBool;

    struct Replacer {
        stop: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<usize>>,
    }
    impl Drop for Replacer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a_backend = Arc::new(PausedCas::new(&a_dir.path().join("cas")));
    let b_backend = Arc::new(PausedCas::new(&b_dir.path().join("cas")));
    let a = Fixture::open_with_components(a_dir.path(), |store| store, a_backend.clone()).0;
    let b = Fixture::open_with_components(b_dir.path(), |store| store, b_backend.clone()).0;
    let a_owner = a.enroll();
    let b_owner = b.enroll();
    assert_ne!(a_owner, b_owner);
    // Each attempt owns a separate stream seeded synchronously below the seal
    // threshold. No initialization worker or earlier handle can seal its next
    // batch or consume its actual-I/O cut. Floor publication alone is not drain.
    for attempt in 0..24 {
        let history = format!("/sessions/service-session/admission-{attempt}");
        for (fixture, owner, label) in [(&a, &a_owner, "a"), (&b, &b_owner, "b")] {
            fixture.kernel.arm_stream_materializer();
            let writer = fixture
                .kernel
                .create_record_wal(&history, OWNER, &service(), owner)
                .unwrap();
            for index in 0..2 {
                assert_eq!(
                    writer
                        .write_sync(format!("{label}{index}").as_bytes())
                        .unwrap(),
                    index
                );
            }
            let prefix = wal_stream_prefix(&history);
            assert_eq!(fixture.store.stream_floor(&prefix).unwrap(), 0);
            assert_eq!(fixture.store.stream_tail(&prefix).unwrap(), 2);
            assert!(fixture
                .store
                .list_stream_segments(&prefix)
                .unwrap()
                .is_empty());
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(std::sync::Barrier::new(2));
    let worker = {
        let kernel = a.kernel.clone();
        let stores = [a.store.clone(), b.store.clone()];
        let backends = [a_backend.clone(), b_backend.clone()];
        let stop = stop.clone();
        let ready = ready.clone();
        std::thread::spawn(move || {
            ready.wait();
            let mut switches = 0;
            while !stop.load(Ordering::SeqCst) {
                let index = switches % 2;
                kernel
                    .mount(
                        "/",
                        MountOptions::new(&service(), "local")
                            .with_backend(backends[index].clone())
                            .with_metastore(stores[index].clone()),
                    )
                    .unwrap();
                switches += 1;
                std::thread::sleep(Duration::from_millis(1));
            }
            switches
        })
    };
    let mut replacer = Replacer {
        stop,
        worker: Some(worker),
    };
    ready.wait();
    let mut accepted = 0;
    let mut overlapped_seals = 0;
    for attempt in 0..24 {
        let history = format!("/sessions/service-session/admission-{attempt}");
        let prefix = wal_stream_prefix(&history);
        let (owner, label, own, other, own_backend, other_backend) = if attempt % 2 == 0 {
            (&a_owner, "a", &a, &b, &a_backend, &b_backend)
        } else {
            (&b_owner, "b", &b, &a, &b_backend, &a_backend)
        };
        let handle = match a.kernel.open_record_wal(&history, &service(), owner) {
            Ok(handle) => handle,
            Err(kernel::kernel::conditional_content::ConditionalContentError::Failed(
                kernel::kernel::KernelError::IOError(message),
            )) if message.contains("record owner handle is not live") => {
                // Only the known alternate owner revision may refuse an open.
                // Unsupported, Unknown, missing data and other I/O errors fail.
                continue;
            }
            Err(error) => panic!("unexpected fresh owning admission failure: {error:?}"),
        };
        accepted += 1;
        let other_tail = other.store.stream_tail(&prefix).unwrap();
        let other_floor = other.store.stream_floor(&prefix).unwrap();
        let other_segments = other.store.list_stream_segments(&prefix).unwrap();
        let other_staged = other_backend.staged.lock().unwrap().clone();
        let other_image = other
            .store
            .as_conditional_metadata()
            .unwrap()
            .read_versioned(&history)
            .unwrap()
            .unwrap();
        let other_owner = other
            .store
            .as_conditional_metadata()
            .unwrap()
            .read_versioned(OWNER)
            .unwrap()
            .unwrap();
        assert_eq!(
            handle.read_at(0).unwrap(),
            Some(format!("{label}0").into_bytes())
        );

        let next = own.store.stream_tail(&prefix).unwrap();
        let previous_floor = own.store.stream_floor(&prefix).unwrap();
        assert_eq!(next, previous_floor + 2);
        let expected_sealed = [previous_floor, previous_floor + 1]
            .map(|sequence| handle.read_at(sequence).unwrap().unwrap());
        let staged_before = own_backend.staged.lock().unwrap().len();
        let (entered, resume) = own_backend.arm(Cut::Write);
        // A synchronous first append cannot start a worker below the seal
        // threshold and race the second append's trigger flag.
        assert_eq!(
            handle
                .write_sync(format!("{label}-new-{attempt}-0").as_bytes())
                .unwrap(),
            next
        );
        assert_eq!(
            StreamBackend::push(&handle, format!("{label}-new-{attempt}-1").as_bytes()).unwrap(),
            (next + 1) as usize
        );
        entered.recv_timeout(Duration::from_secs(10)).unwrap();
        // The actual CAS write has completed and its background I/O guard is
        // still held. Acknowledged publication of two distinct pairs here
        // proves replacement inside that same admitted operation window.
        for (backend, store) in [(own_backend, &own.store), (other_backend, &other.store)] {
            a.kernel
                .mount(
                    "/",
                    MountOptions::new(&service(), "local")
                        .with_backend(backend.clone())
                        .with_metastore(store.clone()),
                )
                .unwrap();
        }
        assert_eq!(
            own.store.stream_floor(&prefix).unwrap(),
            previous_floor,
            "segment index published before the paused content operation returned"
        );
        resume.send(()).unwrap();
        let target_floor = previous_floor + 2;
        wait_for(|| own.store.stream_floor(&prefix).unwrap() == target_floor);
        assert!(
            target_floor > previous_floor,
            "accepted operation did not advance the cold floor"
        );
        let segment = own
            .store
            .find_stream_segment(&prefix, previous_floor)
            .unwrap()
            .unwrap();
        assert_eq!((segment.base, segment.end), (previous_floor, target_floor));
        assert_eq!(own.store.stream_tail(&prefix).unwrap(), next + 2);
        assert_eq!(own_backend.staged.lock().unwrap().len(), staged_before + 1);
        assert!(own_backend
            .inner
            .read_content(&segment.content_id, &service())
            .is_ok());
        assert!(other_backend
            .inner
            .read_content(&segment.content_id, &service())
            .is_err());
        let reads_before = own_backend.reads.load(Ordering::SeqCst);
        for (offset, expected) in expected_sealed.into_iter().enumerate() {
            assert_eq!(
                handle.read_at(previous_floor + offset as u64).unwrap(),
                Some(expected)
            );
        }
        assert!(
            own_backend.reads.load(Ordering::SeqCst) > reads_before,
            "new segment read did not reach the matching captured backend"
        );
        assert_eq!(other.store.stream_tail(&prefix).unwrap(), other_tail);
        assert_eq!(other.store.stream_floor(&prefix).unwrap(), other_floor);
        assert_eq!(
            other.store.list_stream_segments(&prefix).unwrap(),
            other_segments
        );
        assert_eq!(
            other_backend.staged.lock().unwrap().as_slice(),
            other_staged.as_slice()
        );
        let unchanged = other
            .store
            .as_conditional_metadata()
            .unwrap()
            .read_versioned(&history)
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.version, other_image.version);
        assert_eq!(unchanged.metadata, other_image.metadata);
        let unchanged_owner = other
            .store
            .as_conditional_metadata()
            .unwrap()
            .read_versioned(OWNER)
            .unwrap()
            .unwrap();
        assert_eq!(unchanged_owner.version, other_owner.version);
        assert_eq!(unchanged_owner.metadata, other_owner.metadata);
        overlapped_seals += 1;
    }
    replacer.stop.store(true, Ordering::SeqCst);
    let switches = replacer.worker.take().unwrap().join().unwrap();
    assert!(
        switches > 0,
        "actual concurrent mount replacement never ran"
    );
    assert!(
        accepted > 0,
        "no fresh owning admission overlapped mount replacement"
    );

    assert_eq!(
        overlapped_seals, accepted,
        "an accepted operation lacked a correlated new seal"
    );

    // Stable controls cover both owner identities after the concurrent phase,
    // including fresh unpublished create and its real cold publication.
    for (fixture, owner, label, backend, other) in [
        (&a, &a_owner, "a", &a_backend, &b),
        (&b, &b_owner, "b", &b_backend, &a),
    ] {
        a.kernel
            .mount(
                "/",
                MountOptions::new(&service(), "local")
                    .with_backend(backend.clone())
                    .with_metastore(fixture.store.clone()),
            )
            .unwrap();
        let path = format!("/sessions/service-session/fresh-{label}");
        let writer = a
            .kernel
            .create_record_wal(&path, OWNER, &service(), owner)
            .unwrap();
        for index in 0..4 {
            assert_eq!(
                StreamBackend::push(&writer, format!("{label}-fresh-{index}").as_bytes()).unwrap(),
                index
            );
        }
        wait_for(|| {
            fixture
                .store
                .stream_floor(&wal_stream_prefix(&path))
                .unwrap()
                == 2
        });
        assert_eq!(
            writer.read_at(0).unwrap(),
            Some(format!("{label}-fresh-0").into_bytes())
        );
        assert!(other.store.get(&path).unwrap().is_none());
        assert_eq!(
            other.store.stream_tail(&wal_stream_prefix(&path)).unwrap(),
            0
        );
    }
}

#[test]
fn kernel_owned_wal_fresh_admission_keeps_actual_storage_pairs_during_replacement() {
    run_in_cold_child(
        "record_wal_service::cold_lifetime::kernel_owned_wal_fresh_admission_keeps_actual_storage_pairs_during_replacement",
        fresh_admissions_during_mount_replacement,
    );
}
