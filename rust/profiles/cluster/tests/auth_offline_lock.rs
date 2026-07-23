//! Black-box E2E: offline `auth` against a RUNNING daemon fails cleanly.
//!
//! The `auth` subcommand is offline by design — it opens the data dir's redb
//! directly, which a running daemon holds an exclusive lock on. That build a
//! ZoneManager owning a nested tokio runtime; when the open failed on an async
//! worker of the outer `#[tokio::main]`, dropping that runtime panicked
//! ("Cannot drop a runtime in a context where blocking is not allowed") — a
//! cryptic failure for the common operator slip of minting without stopping
//! the daemon. `run_auth` now runs the whole thing on the blocking pool, so
//! the lock contention surfaces as a normal, actionable error. This pins that:
//! a locked data dir FAILS LOUD, never panics.

mod common;

use std::time::Duration;

use common::{cli, free_port, Daemon};

const SECRET: &str = "e2e-offline-lock-secret";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_auth_against_a_running_daemon_fails_cleanly_not_panics() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    let data = data.to_string_lossy();
    let ident = tmp.path().join("id");
    let ident = ident.to_string_lossy();
    let env = [
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", ident.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_NO_TLS", "true"),
    ];

    // Daemon up → it holds the exclusive redb lock on the data dir.
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let mut d = Daemon::spawn(&["--bind-addr", &bind, "--no-tls"], &env);
    d.wait_tcp(port, Duration::from_secs(90))
        .await
        .expect("daemon serves (holds the data-dir lock)");

    // Offline `auth mint` against the SAME locked data dir must FAIL LOUD with
    // an actionable error — never the old "Cannot drop a runtime" panic.
    let (ok, _out, err) = cli(
        &env,
        &[
            "auth",
            "mint",
            "--subject-type",
            "agent",
            "--subject-id",
            "x",
            "--zone",
            "sharedzone:rw",
            "--name",
            "e2e",
        ],
    );
    assert!(
        !ok,
        "mint against a running daemon must fail, got success:\n{err}"
    );
    assert!(
        !err.to_lowercase().contains("panic"),
        "a locked data dir must fail cleanly, not panic:\n{err}"
    );
    assert!(
        err.contains("daemon is running") || err.to_lowercase().contains("lock"),
        "the error should point at the running daemon / exclusive lock:\n{err}"
    );
}
