//! Real-filesystem integrity, concurrent publication and failed-write regressions.

use std::io;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use kernel::core::cas::engine::{CASEngine, CASError};
use kernel::core::cas::transport::LocalCASTransport;

#[test]
fn cas_exists_survives_reopening_the_persistent_store() {
    let root = tempfile::tempdir().unwrap();
    let content = b"durable bytes from the earlier engine instance";
    let hash = {
        let engine = CASEngine::new(LocalCASTransport::new(root.path(), true).unwrap());
        let hash = engine.write_content(content).unwrap();
        assert!(engine.content_exists(&hash));
        hash
    };
    let reopened = CASEngine::new(LocalCASTransport::new(root.path(), true).unwrap());
    assert_eq!(reopened.read_content(&hash).unwrap(), content);
    assert!(
        reopened.content_exists(&hash),
        "existing persistent content must be discoverable after reopen"
    );
}

#[test]
fn cas_exists_observes_other_engines_using_the_same_store() {
    let root = tempfile::tempdir().unwrap();
    let observer = CASEngine::new(LocalCASTransport::new(root.path(), true).unwrap());
    let publisher = CASEngine::new(LocalCASTransport::new(root.path(), true).unwrap());
    let content = b"one immutable store shared by two engine views";
    let hash = publisher.write_content(content).unwrap();
    assert_eq!(observer.read_content(&hash).unwrap(), content);
    assert!(
        observer.content_exists(&hash),
        "a second engine must observe the published object"
    );
    publisher.delete_content(&hash).unwrap();
    assert!(!observer.content_exists(&hash));
}

#[test]
fn cas_exists_refuses_invalid_addresses_without_panicking() {
    let root = tempfile::tempdir().unwrap();
    let engine = CASEngine::new(LocalCASTransport::new(root.path(), true).unwrap());
    engine
        .write_content(b"initialize the physical CAS directories")
        .unwrap();
    for invalid in [
        String::new(),
        "x".into(),
        "abc".into(),
        "z".repeat(64),
        "\u{1f4be}".repeat(16),
        "/".repeat(64),
    ] {
        assert!(
            !engine.content_exists(&invalid),
            "invalid address: {invalid:?}"
        );
    }
}

fn interrupted_final_object() -> (tempfile::TempDir, LocalCASTransport, Vec<u8>, String) {
    let root = tempfile::tempdir().unwrap();
    let transport = LocalCASTransport::new(root.path(), true).unwrap();
    let complete = b"complete immutable object; the final bytes must all be present".to_vec();
    let hash = lib::hash::hash_content(&complete);
    let path = transport.blob_path(&hash);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    // Inject the on-disk result of termination after final-path creation and
    // before write_all completes. No mock replaces the actual transport or FS.
    std::fs::write(path, &complete[..9]).unwrap();
    (root, transport, complete, hash)
}

#[test]
fn a_partial_final_object_is_not_a_successful_deduplication_hit() {
    let (_root, transport, complete, hash) = interrupted_final_object();
    let result = transport.write_blob_tracked(&complete);
    assert!(
        result.is_err(),
        "partial final object must not be accepted as a dedup hit: {result:?}"
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        std::fs::read(transport.blob_path(&hash)).unwrap(),
        &complete[..9]
    );
}

#[test]
fn prehashed_writes_also_refuse_a_partial_final_object() {
    let (_root, transport, complete, hash) = interrupted_final_object();
    let result = transport.write_blob_with_hash(&complete, &hash);
    assert!(
        result.is_err(),
        "prehashed write must not accept a partial final object: {result:?}"
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        std::fs::read(transport.blob_path(&hash)).unwrap(),
        &complete[..9]
    );
}

fn assert_corruption(error: CASError) {
    match error {
        CASError::IOError(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
        other => panic!("expected an integrity failure, got {other:?}"),
    }
}

#[test]
fn corrupt_regular_content_is_refused_without_rewriting_it() {
    let root = tempfile::tempdir().unwrap();
    let engine = CASEngine::new(LocalCASTransport::new(root.path(), true).unwrap());
    let hash = engine.write_content(b"original durable register").unwrap();
    let path = engine.transport().blob_path(&hash);
    let corruption = b"different register bytes";
    std::fs::write(&path, corruption).unwrap();
    assert_corruption(engine.read_content(&hash).unwrap_err());
    assert_eq!(std::fs::read(path).unwrap(), corruption);
}

#[test]
fn corrupt_regular_content_cannot_seed_a_partial_write() {
    let root = tempfile::tempdir().unwrap();
    let engine = CASEngine::new(LocalCASTransport::new(root.path(), true).unwrap());
    let hash = engine.write_content(b"original durable register").unwrap();
    let path = engine.transport().blob_path(&hash);
    std::fs::write(&path, b"different register bytes").unwrap();
    assert_corruption(engine.write_partial(&hash, b"new", 4, &[]).unwrap_err());
    assert_eq!(std::fs::read(path).unwrap(), b"different register bytes");
}

fn substituted_manifest() -> (tempfile::TempDir, CASEngine, String, Vec<u8>) {
    let root = tempfile::tempdir().unwrap();
    let engine = CASEngine::new(LocalCASTransport::new(root.path(), true).unwrap());
    let hash = engine.write_content(&vec![b'a'; 17 * 1024 * 1024]).unwrap();
    assert!(engine.is_chunked(&hash));
    let path = engine.transport().blob_path(&hash);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let first = &mut manifest["chunks"][0];
    let length = first["length"].as_u64().unwrap() as usize;
    let replacement = engine.transport().write_blob(&vec![b'z'; length]).unwrap();
    first["chunk_hash"] = replacement.into();
    let substituted = serde_json::to_vec(&manifest).unwrap();
    std::fs::write(path, &substituted).unwrap();
    (root, engine, hash, substituted)
}

#[test]
fn corrupt_manifest_is_refused_before_full_reassembly() {
    let (_root, engine, hash, substituted) = substituted_manifest();
    assert_corruption(engine.read_content(&hash).unwrap_err());
    assert_eq!(
        std::fs::read(engine.transport().blob_path(&hash)).unwrap(),
        substituted
    );
}

#[test]
fn corrupt_manifest_is_refused_before_range_reassembly() {
    let (_root, engine, hash, _) = substituted_manifest();
    assert_corruption(engine.read_chunked_range(&hash, 0, 16).unwrap_err());
}

#[test]
fn corrupt_manifest_cannot_seed_a_partial_write() {
    let (_root, engine, hash, _) = substituted_manifest();
    assert_corruption(engine.write_partial(&hash, b"new", 4, &[]).unwrap_err());
}

#[test]
fn mismatched_prehashed_input_is_refused_before_creating_an_object() {
    let root = tempfile::tempdir().unwrap();
    let transport = LocalCASTransport::new(root.path(), true).unwrap();
    let claimed = lib::hash::hash_content(b"different bytes");
    let result = transport.write_blob_with_hash(b"actual bytes", &claimed);
    assert!(
        result.is_err(),
        "mismatched prehashed input must be refused: {result:?}"
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    assert!(!transport.blob_path(&claimed).exists());
}

const WORKER_ROLE: &str = "NEXUS_CAS_PUBLICATION_WORKER";
const WORKER_ROOT: &str = "NEXUS_CAS_PUBLICATION_ROOT";
const WORKER_ID: &str = "NEXUS_CAS_PUBLICATION_ID";
const DEADLINE: Duration = Duration::from_secs(30);

/// Kill only this test's child on an assertion or deadline failure.
struct Worker(Child);

impl Worker {
    fn spawn(root: &Path, role: &str, id: usize) -> Self {
        Self::spawn_with(root, role, id, |_| {})
    }

    fn spawn_with(
        root: &Path,
        role: &str,
        id: usize,
        configure: impl FnOnce(&mut Command),
    ) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "cas_process_worker", "--nocapture"])
            .env(WORKER_ROLE, role)
            .env(WORKER_ROOT, root)
            .env(WORKER_ID, id.to_string());
        configure(&mut command);
        Self(command.spawn().unwrap())
    }

    fn is_finished(&mut self) -> bool {
        match self.0.try_wait().unwrap() {
            Some(status) => {
                assert!(status.success(), "CAS worker failed: {status}");
                true
            }
            None => false,
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(start.elapsed() < DEADLINE, "CAS child process timed out");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn concurrent_content() -> Vec<u8> {
    (0..4 * 1024 * 1024).map(|index| index as u8).collect()
}

fn sidecar_content(id: usize) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "writer": id, "data": "x".repeat(128 * 1024) }))
        .unwrap()
}

fn start_writers(root: &Path, role: &str) -> Vec<Worker> {
    let mut workers: Vec<_> = (0..4).map(|id| Worker::spawn(root, role, id)).collect();
    wait_until(|| {
        // Surface early failures instead of waiting for an absent ready marker.
        for worker in &mut workers {
            assert!(!worker.is_finished(), "CAS writer exited before release");
        }
        (0..4).all(|id| root.join(format!("ready-{id}")).exists())
    });
    std::fs::write(root.join("start"), []).unwrap();
    workers
}

#[test]
fn concurrent_processes_publish_one_complete_blob() {
    concurrent_blob_publication("blob", false);
}

#[cfg(target_os = "linux")]
#[test]
fn concurrent_processes_publish_one_durable_blob() {
    concurrent_blob_publication("strong-blob", true);
}

fn concurrent_blob_publication(role: &str, durable: bool) {
    let root = tempfile::tempdir().unwrap();
    let transport = if durable {
        LocalCASTransport::new_durable(root.path()).unwrap()
    } else {
        LocalCASTransport::new(root.path(), true).unwrap()
    };
    assert_eq!(transport.has_durable_publication(), durable);
    let content = concurrent_content();
    let hash = lib::hash::hash_content(&content);
    let mut workers = start_writers(root.path(), role);
    let mut was_visible = false;
    wait_until(|| {
        match transport.read_blob(&hash) {
            Ok(bytes) => {
                assert_eq!(bytes, content, "reader observed an incomplete CAS object");
                was_visible = true;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && !was_visible => {}
            Err(error) => panic!("published CAS object became unreadable: {error}"),
        }
        workers.iter_mut().all(Worker::is_finished)
    });
    assert_eq!(transport.read_blob(&hash).unwrap(), content);
    let winners = (0..4)
        .filter(|id| {
            std::fs::read_to_string(root.path().join(format!("result-{id}"))).unwrap() == "true"
        })
        .count();
    assert_eq!(winners, 1, "exactly one process must publish the cold blob");
    let parent = transport.blob_path(&hash).parent().unwrap().to_path_buf();
    assert_eq!(std::fs::read_dir(parent).unwrap().count(), 1);
}

#[test]
fn concurrent_sidecar_replacement_preserves_complete_json() {
    let root = tempfile::tempdir().unwrap();
    let transport = LocalCASTransport::new(root.path(), true).unwrap();
    let hash = transport.write_blob(b"sidecar object").unwrap();
    let candidates: Vec<_> = (0..4).map(sidecar_content).collect();
    transport.write_meta(&hash, &candidates[0]).unwrap();
    let mut workers = start_writers(root.path(), "meta");
    wait_until(|| {
        let bytes = transport.read_meta(&hash).unwrap();
        assert!(
            candidates.contains(&bytes),
            "reader observed incomplete sidecar JSON"
        );
        workers.iter_mut().all(Worker::is_finished)
    });
    assert!(candidates.contains(&transport.read_meta(&hash).unwrap()));
    let parent = transport.blob_path(&hash).parent().unwrap().to_path_buf();
    assert_eq!(std::fs::read_dir(parent).unwrap().count(), 2);
}

#[test]
fn open_sidecar_reader_retains_its_snapshot_across_replacements() {
    use std::io::Read;

    let root = tempfile::tempdir().unwrap();
    let transport = LocalCASTransport::new(root.path(), true).unwrap();
    let hash = transport.write_blob(b"open sidecar reader").unwrap();
    let original = br#"{"generation":0}"#;
    transport.write_meta(&hash, original).unwrap();
    let mut reader =
        std::fs::File::open(transport.blob_path(&hash).with_extension("meta")).unwrap();
    for generation in 1..=2 {
        let replacement = format!("{{\"generation\":{generation}}}");
        transport.write_meta(&hash, replacement.as_bytes()).unwrap();
        assert_eq!(transport.read_meta(&hash).unwrap(), replacement.as_bytes());
    }
    let mut retained = Vec::new();
    reader.read_to_end(&mut retained).unwrap();
    assert_eq!(retained, original);
}

#[test]
fn cas_process_worker() {
    let Ok(role) = std::env::var(WORKER_ROLE) else {
        return;
    };
    let root = std::env::var_os(WORKER_ROOT).unwrap();
    let root = Path::new(&root);
    let id: usize = std::env::var(WORKER_ID).unwrap().parse().unwrap();
    #[cfg(target_os = "linux")]
    if let Some(mode) = role.strip_prefix("durable-") {
        durable_process_worker(root, mode);
        return;
    }
    let is_durable = role == "strong-blob";
    let transport = if is_durable {
        LocalCASTransport::new_durable(root).unwrap()
    } else {
        LocalCASTransport::new(root, true).unwrap()
    };
    if role == "blob" || role == "meta" || is_durable {
        let is_blob = role != "meta";
        let content = if is_blob {
            concurrent_content()
        } else {
            sidecar_content(id)
        };
        let hash = if is_blob {
            lib::hash::hash_content(&content)
        } else {
            lib::hash::hash_content(b"sidecar object")
        };
        std::fs::write(root.join(format!("ready-{id}")), []).unwrap();
        wait_until(|| root.join("start").exists());
        if is_blob {
            // Compete through both public entry points against the same object.
            let published = if id.is_multiple_of(2) {
                transport.write_blob_tracked(&content).unwrap().1
            } else {
                transport.write_blob_with_hash(&content, &hash).unwrap()
            };
            std::fs::write(root.join(format!("result-{id}")), published.to_string()).unwrap();
            assert!(!transport.write_blob_with_hash(&content, &hash).unwrap());
        } else {
            for _ in 0..8 {
                transport.write_meta(&hash, &content).unwrap();
            }
        }
        return;
    }

    #[cfg(target_os = "linux")]
    if let Some(mode) = role.strip_prefix("fail-") {
        // Keep the real EFBIG injection within the storage operation. Libtest
        // must regain its original file limit before reporting the result.
        let _limit = ScopedFileSizeLimit::new();
        let content = vec![42; 64 * 1024];
        let hash = lib::hash::hash_content(&content);
        let error = match mode {
            "tracked" => transport.write_blob_tracked(&content).unwrap_err(),
            "prehashed" => transport.write_blob_with_hash(&content, &hash).unwrap_err(),
            "meta" => transport.write_meta(&hash, &content).unwrap_err(),
            _ => panic!("unknown failure mode: {mode}"),
        };
        assert_eq!(error.raw_os_error(), Some(libc::EFBIG));
        return;
    }
    panic!("unknown CAS worker role: {role}");
}

#[cfg(target_os = "linux")]
struct ScopedFileSizeLimit {
    previous: libc::rlimit,
    previous_signal: libc::sighandler_t,
}

#[cfg(target_os = "linux")]
impl ScopedFileSizeLimit {
    fn new() -> Self {
        unsafe {
            let mut previous = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut previous), 0);
            assert!(previous.rlim_cur >= 4096);
            let previous_signal = libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            assert_ne!(previous_signal, libc::SIG_ERR);
            let guard = Self {
                previous,
                previous_signal,
            };
            let limit = libc::rlimit {
                rlim_cur: 4096,
                rlim_max: guard.previous.rlim_max,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
            guard
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ScopedFileSizeLimit {
    fn drop(&mut self) {
        unsafe {
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &self.previous), 0);
            assert_ne!(
                libc::signal(libc::SIGXFSZ, self.previous_signal),
                libc::SIG_ERR
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn failed_publication(mode: &str) {
    use std::io::Write;

    let root = tempfile::tempdir().unwrap();
    let transport = LocalCASTransport::new(root.path(), true).unwrap();
    let hash = lib::hash::hash_content(&vec![42; 64 * 1024]);
    let previous_meta = br#"{"size":65536,"is_chunked_manifest":true}"#;
    if mode == "meta" {
        transport.write_meta(&hash, previous_meta).unwrap();
    }
    let log_path = root.path().join("worker.log");
    let mut log = std::fs::File::create(&log_path).unwrap();
    // A regular stdout file already beyond the injected limit deterministically
    // exercises restoration before libtest emits its completion report.
    log.write_all(&[b' '; 8192]).unwrap();
    let mut worker = Worker::spawn_with(root.path(), &format!("fail-{mode}"), 0, |command| {
        command.stdout(log);
    });
    wait_until(|| worker.is_finished());
    assert!(std::fs::read_to_string(log_path)
        .unwrap()
        .contains("test result: ok. 1 passed;"));
    assert!(
        !transport.blob_path(&hash).exists(),
        "failed write published a partial blob"
    );
    if mode == "meta" {
        assert_eq!(transport.read_meta(&hash).unwrap(), previous_meta);
    }
    let parent = transport.blob_path(&hash).parent().unwrap().to_path_buf();
    assert_eq!(
        std::fs::read_dir(parent).unwrap().count(),
        usize::from(mode == "meta")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn failed_tracked_write_leaves_no_final_object() {
    failed_publication("tracked");
}

#[cfg(target_os = "linux")]
#[test]
fn failed_prehashed_write_leaves_no_final_object() {
    failed_publication("prehashed");
}

#[cfg(target_os = "linux")]
#[test]
fn failed_sidecar_replacement_preserves_previous_bytes() {
    failed_publication("meta");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unqualified_durability_is_refused_before_creating_storage() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("not-created");
    let result = LocalCASTransport::new_durable(&root);
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::Unsupported);
    assert!(!root.exists());
}

#[cfg(target_os = "linux")]
fn durable_process_worker(root: &Path, mode: &str) {
    use lib::file_durability::PublishedButNotDurable;

    let transport = LocalCASTransport::new_durable(root).unwrap();
    assert!(transport.has_durable_publication());
    let content = b"complete object acknowledged after file and namespace barriers";
    let hash = lib::hash::hash_content(content);
    if mode == "success" || mode == "kill-before" || mode == "kill-after" {
        assert_eq!(
            transport.write_blob_tracked(content).unwrap(),
            (hash.clone(), true)
        );
        if mode == "kill-after" {
            unsafe { libc::raise(libc::SIGKILL) };
            panic!("SIGKILL returned");
        }
        assert_eq!(transport.read_blob(&hash).unwrap(), content);
        return;
    }
    let error = if mode == "meta" {
        transport
            .write_meta(&hash, br#"{"complete":true}"#)
            .unwrap_err()
    } else {
        transport.write_blob_with_hash(content, &hash).unwrap_err()
    };
    if mode == "prepare" || mode == "file" {
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(!transport.blob_path(&hash).exists());
    } else {
        let state = error
            .get_ref()
            .unwrap()
            .downcast_ref::<PublishedButNotDurable>()
            .unwrap();
        assert_eq!(state.io_error().raw_os_error(), Some(libc::EIO));
        if mode == "meta" {
            assert_eq!(transport.read_meta(&hash).unwrap(), br#"{"complete":true}"#);
        } else {
            assert_eq!(transport.read_blob(&hash).unwrap(), content);
        }
    }
    // Recover the same transport after the injected OS barrier failure.
    std::env::remove_var("NEXUS_CAS_SYNC_FAULT");
    if mode == "meta" {
        transport
            .write_meta(&hash, br#"{"complete":true}"#)
            .unwrap();
    } else {
        let published = transport.write_blob_with_hash(content, &hash).unwrap();
        assert_eq!(published, mode == "prepare" || mode == "file");
    }
}

#[cfg(target_os = "linux")]
fn durability_fixture() -> tempfile::TempDir {
    let fixture = tempfile::tempdir().unwrap();
    let source = fixture.path().join("fault.c");
    std::fs::write(&source, include_str!("fixtures/cas_fsync_fault.c")).unwrap();
    let output = Command::new("cc")
        .args(["-shared", "-fPIC", "-O0", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(fixture.path().join("fault.so"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture
}

#[cfg(target_os = "linux")]
fn durable_child(
    root: &Path,
    target: &Path,
    fixture: &Path,
    trace: &Path,
    mode: &str,
    fault: &str,
) -> Worker {
    Worker::spawn_with(root, &format!("durable-{mode}"), 0, |command| {
        command
            .env("LD_PRELOAD", fixture.join("fault.so"))
            .env("NEXUS_CAS_SYNC_ROOT", root)
            .env("NEXUS_CAS_SYNC_TARGET", target)
            .env("NEXUS_CAS_SYNC_TRACE", trace)
            .env("NEXUS_CAS_SYNC_FAULT", fault)
            .env("NEXUS_CAS_SYNC_MARKER", root.join("paused"));
    })
}

#[cfg(target_os = "linux")]
#[test]
fn durable_publication_orders_file_and_directory_barriers() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("new/nested/storage");
    let hash =
        lib::hash::hash_content(b"complete object acknowledged after file and namespace barriers");
    let target = root.join(format!("cas/{}/{}/{hash}", &hash[..2], &hash[2..4]));
    let fixture = durability_fixture();
    let trace = parent.path().join("trace");
    let mut worker = durable_child(&root, &target, fixture.path(), &trace, "success", "");
    wait_until(|| worker.is_finished());
    let events = std::fs::read_to_string(trace).unwrap();
    let events: Vec<_> = events.lines().collect();
    let file = events
        .iter()
        .position(|line| line.starts_with("F|0|0|"))
        .unwrap();
    for directory in target.parent().unwrap().ancestors() {
        let event = format!("D|0|0|{}", directory.display());
        assert!(
            events[..file].contains(&event.as_str()),
            "missing prepublication barrier: {event}"
        );
    }
    let published = format!("D|1|0|{}", target.parent().unwrap().display());
    assert!(events[file + 1..].contains(&published.as_str()));
}

#[cfg(target_os = "linux")]
#[test]
fn durable_failures_preserve_publication_state_and_retry_barriers() {
    for (mode, fault) in [
        ("prepare", "prepare-dir"),
        ("file", "staged-file"),
        ("published", "published-dir"),
        ("dedup", "existing-file"),
        ("meta", "published-dir"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let content = b"complete object acknowledged after file and namespace barriers";
        let hash = lib::hash::hash_content(content);
        let transport = LocalCASTransport::new(root.path(), false).unwrap();
        let blob = transport.blob_path(&hash);
        if mode == "dedup" {
            transport.write_blob(content).unwrap();
        }
        let target = if mode == "meta" {
            blob.with_extension("meta")
        } else {
            blob
        };
        let fixture = durability_fixture();
        let trace = root.path().join("trace");
        let mut worker = durable_child(root.path(), &target, fixture.path(), &trace, mode, fault);
        wait_until(|| worker.is_finished());
        let events = std::fs::read_to_string(trace).unwrap();
        assert!(
            events
                .lines()
                .any(|line| line.split('|').nth(2) == Some("1")),
            "fault not exercised: {mode}"
        );
        let lines: Vec<_> = events.lines().collect();
        let failed = lines
            .iter()
            .position(|line| line.split('|').nth(2) == Some("1"))
            .unwrap();
        let acknowledged = format!("D|1|0|{}", target.parent().unwrap().display());
        assert!(
            lines[failed + 1..].contains(&acknowledged.as_str()),
            "retry acknowledged without a successful publication barrier: {mode}"
        );
        if mode == "dedup" {
            assert!(
                !events.contains(".cas-"),
                "dedup must synchronize the existing object"
            );
            let retry = format!("F|1|0|{}", target.display());
            assert!(events.lines().any(|line| line == retry));
        }
        if mode == "prepare" {
            let retry = format!("D|0|0|{}", target.parent().unwrap().display());
            assert!(
                events.lines().any(|line| line == retry),
                "failed parent preparation must be retried"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn killed_publishers_recover_before_and_after_acknowledgement() {
    use std::os::unix::process::ExitStatusExt;

    for mode in ["kill-before", "kill-after"] {
        let root = tempfile::tempdir().unwrap();
        let content = b"complete object acknowledged after file and namespace barriers";
        let hash = lib::hash::hash_content(content);
        let transport = LocalCASTransport::new(root.path(), false).unwrap();
        let target = transport.blob_path(&hash);
        let fixture = durability_fixture();
        let trace = root.path().join("trace");
        let fault = if mode == "kill-before" {
            "pause-file"
        } else {
            ""
        };
        let mut worker = durable_child(root.path(), &target, fixture.path(), &trace, mode, fault);
        if mode == "kill-before" {
            wait_until(|| {
                assert!(!worker.is_finished(), "publisher exited before pause");
                root.path().join("paused").exists()
            });
            worker.0.kill().unwrap();
        }
        let mut status = None;
        wait_until(|| {
            status = worker.0.try_wait().unwrap();
            status.is_some()
        });
        assert_eq!(status.unwrap().signal(), Some(libc::SIGKILL));
        let recovered = LocalCASTransport::new_durable(root.path()).unwrap();
        if mode == "kill-before" {
            assert_eq!(
                recovered.read_blob(&hash).unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
        } else {
            assert_eq!(recovered.read_blob(&hash).unwrap(), content);
        }
        assert_eq!(
            recovered.write_blob_tracked(content).unwrap(),
            (hash.clone(), mode == "kill-before")
        );
        assert_eq!(recovered.read_blob(&hash).unwrap(), content);
    }
}
