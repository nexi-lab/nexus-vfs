use super::*;
use redb::{backends::FileBackend, ReadableDatabase, StorageBackend, TableDefinition};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const FACTS: TableDefinition<&str, &str> = TableDefinition::new("facts");

fn builder() -> Builder {
    let mut builder = Database::builder();
    builder.set_cache_size(1024 * 1024);
    builder
}

fn record_fact(database: &Database) {
    let transaction = database.begin_write().unwrap();
    transaction
        .open_table(FACTS)
        .unwrap()
        .insert("key", "durable")
        .unwrap();
    transaction.commit().unwrap();
}

fn assert_fact(database: &Database) {
    let transaction = database.begin_read().unwrap();
    let table = transaction.open_table(FACTS).unwrap();
    assert_eq!(table.get("key").unwrap().unwrap().value(), "durable");
}

#[test]
fn creates_nested_path_preserves_facts_and_excludes_second_opener() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested/store.redb");
    let database = open_or_create(&path, &builder()).unwrap();
    record_fact(&database);
    assert!(matches!(
        open_or_create(&path, &builder()),
        Err(DatabaseError::DatabaseAlreadyOpen)
    ));
    drop(database);
    assert_fact(&open_or_create(&path, &builder()).unwrap());
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        1
    );
}

#[test]
fn invalid_existing_files_are_never_reinitialized() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    for bytes in [
        b"".as_slice(),
        b"incomplete header",
        b"existing non-database facts",
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert!(open_or_create(&path, &builder()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn concurrent_creators_never_overwrite_the_winner() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let builder = builder();
                open_or_create_with(&path, &builder, |file| {
                    let database = builder.create_file(file)?;
                    barrier.wait();
                    Ok(database)
                })
            })
        })
        .collect();
    // Keep both results alive: the winner retains its database lock while the
    // loser opens the canonical path, so exactly one creator can own the store.
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(DatabaseError::DatabaseAlreadyOpen)))
            .count(),
        1
    );
    record_fact(
        results
            .iter()
            .find_map(|result| result.as_ref().ok())
            .unwrap(),
    );
    drop(results);
    assert_fact(&open_or_create(&path, &builder()).unwrap());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn killed_bootstrap_never_publishes_partial_data_and_committed_facts_survive() {
    for phase in ["in-place", "partial", "initialized", "committed"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.redb");
        let ready = directory.path().join("ready");
        let mut child = OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "redb_storage::tests::bootstrap_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("NEXUS_REDB_BOOTSTRAP_TEST_PATH", &path)
                .env("NEXUS_REDB_BOOTSTRAP_TEST_PHASE", phase)
                .env("NEXUS_REDB_BOOTSTRAP_TEST_READY", &ready)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !ready.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "bootstrap child exited at {phase}"
            );
            assert!(Instant::now() < deadline, "bootstrap child missed {phase}");
            std::thread::sleep(Duration::from_millis(5));
        }
        if matches!(phase, "partial" | "initialized") {
            assert!(
                !path.exists(),
                "unpublished initialization became visible at {phase}"
            );
        }
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        if phase == "in-place" {
            // Control: redb's direct initialization really leaves an invalid
            // canonical file at this kill point. Do not repair it by deletion.
            let bytes = std::fs::read(&path).unwrap();
            assert!(!bytes.is_empty());
            assert!(open_or_create(&path, &builder()).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            continue;
        }
        let database = open_or_create(&path, &builder()).unwrap();
        if phase == "committed" {
            assert_fact(&database);
        } else {
            record_fact(&database);
            drop(database);
            assert_fact(&open_or_create(&path, &builder()).unwrap());
        }
    }
}

fn park_at(ready: &Path) -> ! {
    std::fs::write(ready, b"ready").unwrap();
    loop {
        std::thread::park();
    }
}

#[derive(Debug)]
struct InterruptedInitialization {
    backend: FileBackend,
    ready: std::path::PathBuf,
    first_write: AtomicBool,
}

impl StorageBackend for InterruptedInitialization {
    fn len(&self) -> io::Result<u64> {
        self.backend.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.backend.read(offset, out)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.backend.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.backend.sync_data()
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if self.first_write.swap(false, Ordering::SeqCst) {
            // Persist an actual incomplete header, then let the parent hard-kill
            // this process before redb can finish the first database creation.
            self.backend.write(offset, &data[..data.len().min(1)])?;
            self.backend.sync_data()?;
            park_at(&self.ready);
        }
        self.backend.write(offset, data)
    }
    fn close(&self) -> io::Result<()> {
        self.backend.close()
    }
}

#[test]
#[ignore = "subprocess entry point invoked by the hard-kill regression"]
fn bootstrap_child() {
    let path =
        std::path::PathBuf::from(std::env::var_os("NEXUS_REDB_BOOTSTRAP_TEST_PATH").unwrap());
    let ready =
        std::path::PathBuf::from(std::env::var_os("NEXUS_REDB_BOOTSTRAP_TEST_READY").unwrap());
    let phase = std::env::var("NEXUS_REDB_BOOTSTRAP_TEST_PHASE").unwrap();
    let builder = builder();
    let interrupted = |file| {
        builder.create_with_backend(InterruptedInitialization {
            backend: FileBackend::new(file)?,
            ready: ready.clone(),
            first_write: AtomicBool::new(true),
        })
    };
    if phase == "in-place" {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        interrupted(file).unwrap();
        panic!("the parent must kill the in-place initializer");
    }
    let database = open_or_create_with(&path, &builder, |file| {
        if phase == "partial" {
            interrupted(file)
        } else {
            let database = builder.create_file(file)?;
            if phase == "initialized" {
                park_at(&ready);
            }
            Ok(database)
        }
    })
    .unwrap();
    record_fact(&database);
    park_at(&ready);
}
