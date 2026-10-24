//! Real-filesystem integrity, concurrent publication and failed-write regressions.

use std::io;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use kernel::core::cas::transport::LocalCASTransport;

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
    assert_eq!(transport.read_blob(&hash).unwrap(), &complete[..9]);
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
    assert_eq!(transport.read_blob(&hash).unwrap(), &complete[..9]);
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
        Self(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cas_process_worker", "--nocapture"])
                .env(WORKER_ROLE, role)
                .env(WORKER_ROOT, root)
                .env(WORKER_ID, id.to_string())
                .spawn()
                .unwrap(),
        )
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
    let root = tempfile::tempdir().unwrap();
    let transport = LocalCASTransport::new(root.path(), true).unwrap();
    let content = concurrent_content();
    let hash = lib::hash::hash_content(&content);
    let mut workers = start_writers(root.path(), "blob");
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
    let transport = LocalCASTransport::new(root, true).unwrap();
    if role == "blob" || role == "meta" {
        let content = if role == "blob" {
            concurrent_content()
        } else {
            sidecar_content(id)
        };
        let hash = if role == "blob" {
            lib::hash::hash_content(&content)
        } else {
            lib::hash::hash_content(b"sidecar object")
        };
        std::fs::write(root.join(format!("ready-{id}")), []).unwrap();
        wait_until(|| root.join("start").exists());
        if role == "blob" {
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
        // Exercise a real short write followed by EFBIG, isolated to this child.
        // This never changes limits or signal handlers in the parent test runner.
        let limit = libc::rlimit {
            rlim_cur: 4096,
            rlim_max: 4096,
        };
        unsafe {
            assert_ne!(libc::signal(libc::SIGXFSZ, libc::SIG_IGN), libc::SIG_ERR);
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
        }
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
fn failed_publication(mode: &str) {
    let root = tempfile::tempdir().unwrap();
    let transport = LocalCASTransport::new(root.path(), true).unwrap();
    let hash = lib::hash::hash_content(&vec![42; 64 * 1024]);
    let previous_meta = br#"{"size":65536,"is_chunked_manifest":true}"#;
    if mode == "meta" {
        transport.write_meta(&hash, previous_meta).unwrap();
    }
    let mut worker = Worker::spawn(root.path(), &format!("fail-{mode}"), 0);
    wait_until(|| worker.is_finished());
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
