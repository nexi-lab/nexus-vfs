use super::*;
use crate::transport::crl::{
    add_revoked_serial, read_revoked_serials_checked, write_revoked_entries,
};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CASE: &str =
    "transport::crl::lock::tests::process_writers_share_exclusion_and_exit_releases_it";
const ROLE: &str = "NEXUS_CRL_LOCK_TEST_ROLE";
const DIRECTORY: &str = "NEXUS_CRL_LOCK_TEST_DIRECTORY";

struct TestChild(Child);

impl Drop for TestChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn child(directory: &Path, role: &str) -> TestChild {
    TestChild(
        Command::new(std::env::current_exe().unwrap())
            .args([CASE, "--exact", "--test-threads=1"])
            .env(ROLE, role)
            .env(DIRECTORY, directory)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

fn wait_for_marker(child: &mut TestChild, marker: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before marker"
        );
        assert!(Instant::now() < deadline, "child marker deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn process_writers_share_exclusion_and_exit_releases_it() {
    if let Ok(role) = std::env::var(ROLE) {
        let directory = std::path::PathBuf::from(std::env::var_os(DIRECTORY).unwrap());
        let path = directory.join("revoked-serials");
        if role == "writer" {
            let probe = File::options()
                .read(true)
                .write(true)
                .open(path.with_extension("lock"))
                .unwrap();
            assert!(
                matches!(probe.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
                "another process must observe the original revocation guard"
            );
            drop(probe);
            std::fs::write(directory.join("writer-observed-lock"), []).unwrap();
            add_revoked_serial(&path, b"child-revoked").unwrap();
            std::fs::write(directory.join("writer-complete"), []).unwrap();
        } else {
            assert_eq!(role, "holder");
            let _guard = RevocationGuard::acquire(&path).unwrap();
            std::fs::write(directory.join("holder-acquired"), []).unwrap();
            loop {
                std::thread::park();
            }
        }
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("revoked-serials");
    add_revoked_serial(&path, b"original").unwrap();
    let guard = RevocationGuard::acquire(&path).unwrap();
    let mut writer = child(directory.path(), "writer");
    wait_for_marker(&mut writer, &directory.path().join("writer-observed-lock"));
    assert!(!directory.path().join("writer-complete").exists());
    assert_eq!(
        read_revoked_serials_checked(&path).unwrap(),
        vec![b"original".to_vec()]
    );
    // Commit a competing writer's snapshot while the original guard is held.
    // The child must read this replacement after acquiring the same OS lock.
    write_revoked_entries(&path, &[]).unwrap();
    drop(guard);
    wait_for_marker(&mut writer, &directory.path().join("writer-complete"));
    assert!(writer.0.wait().unwrap().success());
    assert_eq!(
        read_revoked_serials_checked(&path).unwrap(),
        vec![b"child-revoked".to_vec()]
    );

    let mut holder = child(directory.path(), "holder");
    wait_for_marker(&mut holder, &directory.path().join("holder-acquired"));
    let probe = File::options()
        .read(true)
        .write(true)
        .open(path.with_extension("lock"))
        .unwrap();
    assert!(matches!(
        probe.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    holder.0.kill().unwrap();
    holder.0.wait().unwrap();
    probe.try_lock().expect("process exit releases its OS lock");
    probe.unlock().unwrap();
    add_revoked_serial(&path, b"after-exit").unwrap();
    assert_eq!(
        read_revoked_serials_checked(&path).unwrap(),
        vec![b"child-revoked".to_vec(), b"after-exit".to_vec()]
    );
}
