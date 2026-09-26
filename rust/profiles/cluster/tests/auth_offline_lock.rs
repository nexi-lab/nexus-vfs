//! Black-box E2E: offline `auth` against a RUNNING daemon fails cleanly.
//!
//! The `auth` subcommand is offline by design — it opens the data dir's redb
//! directly, and a running daemon holds that lock. Minting without stopping the
//! daemon is the common operator slip, so what it produces has to be an actionable
//! error and never a panic: opening a data dir builds a ZoneManager owning a nested
//! tokio runtime, and a runtime dropped on an async worker mid-error panics over the
//! very message the operator needs (`lib::rt::OwnedRuntime` is what keeps that from
//! happening, wherever the open is attempted from).
//!
//! Sibling coverage: `share`'s half of the same contract lives in
//! `share_contract.rs`, which also pins the guidance text.

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
