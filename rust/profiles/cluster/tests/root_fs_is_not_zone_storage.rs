//! Black-box E2E: the namespace served at `/` is not a zone's storage directory.
//!
//! The default root mount used to be `<data_dir>/root`, which is where the ROOT ZONE's
//! raft storage lives (`<data_dir>/<zone_id>/`, and that zone's id is `root`). So a
//! default daemon served its own consensus files as the namespace: `readdir /` answered
//! `raft` and `sm`, `readdir /raft` answered `raft.redb`, and every federation mount
//! point showed its target zone's storage dir — because the same backend answers the
//! traversal.
//!
//! Two halves are pinned here, because either alone leaves the sharp edge: a fresh
//! daemon's `/` is clean, and a root mount that IS a zone storage dir is refused at
//! boot rather than served.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, Vfs, LOG_FILTER};

const BUDGET: Duration = Duration::from_secs(120);

fn env<'a>(data: &'a str, id: &'a str, adv: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("RUST_LOG", LOG_FILTER),
    ]
}

/// A default daemon serves an EMPTY `/` — no `raft`, no `sm`.
///
/// Asserted through the VFS rather than by looking at the disk, because the namespace
/// is what a client sees and the disk layout is what produced the bug.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_daemon_serves_no_zone_storage_at_root() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let mut d = Daemon::spawn(&["--bind-addr", &addr], &env(&data, &id, &addr));
    d.wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("daemon boots");

    let mut c = Vfs::dial_ready(port, BUDGET).await;
    let root = c.readdir_names("/", "").await.expect("readdir /");
    assert!(
        !root
            .iter()
            .any(|n| n.ends_with("/raft") || n.ends_with("/sm")),
        "the root mount must not be a zone's storage dir; readdir / = {root:?}"
    );

    // And the files themselves are not reachable through the namespace.
    assert!(
        !c.stat_found("/raft/raft.redb", "").await,
        "the consensus log must not be visible in the namespace"
    );
    drop(d);
}

/// A root mount that IS a zone storage directory is refused at boot.
///
/// The case that matters is a data dir from before the default moved: `<data>/root`
/// then holds the root zone's `raft/` + `sm`, and a daemon told to serve it would put
/// them back in the namespace. Passing it explicitly is the same mistake stated out
/// loud, so it gets the same refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_root_mount_that_is_zone_storage_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_path = tmp.path().join("data");
    let data = data_path.to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let e = env(&data, &id, &addr);

    // Boot once so the root zone's storage exists on disk.
    {
        let mut d = Daemon::spawn(&["--bind-addr", &addr], &e);
        d.wait_for_log("VFS data plane ready", BUDGET)
            .await
            .expect("first boot creates the root zone");
    }
    let zone_storage = data_path.join("root");
    assert!(
        zone_storage.join("raft").is_dir(),
        "the root zone's storage should be at {zone_storage:?}"
    );

    // Now point the root mount at it, the way a pre-move data dir would.
    let zone_storage_s = zone_storage.to_string_lossy().into_owned();
    let mut d = Daemon::spawn(&["--bind-addr", &addr, "--root-path", &zone_storage_s], &e);
    let logs = d
        .wait_exit(BUDGET)
        .await
        .expect("a daemon told to serve a zone's storage at / must refuse to boot");
    assert!(
        logs.contains("zone's storage directory") && logs.contains("raft"),
        "the refusal must name what it found and why:\n{logs}"
    );
    assert!(
        !logs.to_lowercase().contains("panic"),
        "the refusal must be an error, not a panic:\n{logs}"
    );
}
