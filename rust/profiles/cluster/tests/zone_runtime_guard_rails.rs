//! Black-box E2E for the typed ZoneRuntime admission guard rails:
//!
//!   1. `zone_mount`/`zone_unmount` admit ONLY contract-valid mount paths —
//!      the zone-wire-path contract (`validate_zone_wire_path`) is wired at the API
//!      boundary, so relative paths, `..` segments, `\\`, kernel-reserved
//!      prefixes and over-length inputs are refused `InvalidArgument`
//!      BEFORE any journal claim or execution.
//!   2. A reserved zone id (`root`) cannot be joined through the RPC
//!      surface — the `RemoteLearned` projection admits it, but the
//!      operator surface must not (boot joins reserved zones internally,
//!      never via RPC).
//!   3. `zone_deprovision` enforces the same POSIX i_links guard
//!      `remove_replica` does: a still-mounted zone is refused until it is
//!      unmounted, so no parent is left holding a dangling DT_MOUNT.
//!
//! Single-node NoAuth loopback suffices — these are admission guards, not
//! replication behaviors.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, ZoneRuntime, LOG_FILTER};

const ZONE: &str = "tenant-a";
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_mount_paths_are_refused_at_admission() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");

    let mut daemon = Daemon::spawn(&["--bind-addr", &adv, "--no-tls"], &env(&data, &id, &adv));
    daemon
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("boot wires the typed zone runtime surface");
    let mut rt = ZoneRuntime::dial_ready(port, BUDGET).await;

    rt.zone_create(ZONE, &[], "op-gr-create-0001", "")
        .await
        .expect("create");

    // Every shape the zone-path contract refuses. Each one must come back
    // InvalidArgument WITHOUT consuming an operation id into the journal.
    let bad_paths = [
        "relative-path",      // not absolute
        "/has/../dotdot",     // forbidden component
        "/has/./dot",         // forbidden component
        "/trailing/",         // trailing slash = empty component
        "/__sys__/reserved",  // kernel-owned prefix
        "/back\\slash",       // charset violation (Windows separator)
        "/has%20space",       // charset violation
        &format!("/{}", "a".repeat(300)), // over-length component
    ];
    for (i, path) in bad_paths.iter().enumerate() {
        let refused = rt
            .zone_mount("root", path, ZONE, &format!("op-gr-bad-{i:03}"), "")
            .await
            .expect_err("a contract-invalid mount path must be refused");
        assert_eq!(
            refused.code(),
            tonic::Code::InvalidArgument,
            "path {path:?}: {refused:?}"
        );
        // The refused operation id must NOT be pinned in the journal —
        // admission ran before the claim.
        let op = rt
            .get_zone_operation(&format!("op-gr-bad-{i:03}"), "")
            .await
            .expect_err("an unclaimed operation id has no journal record");
        assert_eq!(op.code(), tonic::Code::NotFound, "path {path:?}");
    }

    // The same paths are refused on the unmount side too.
    let refused = rt
        .zone_unmount("root", "relative-path", "op-gr-unmount-bad", "")
        .await
        .expect_err("unmount of a contract-invalid path must be refused");
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);

    // Control: a contract-valid path still mounts (the guard is admission,
    // not a blanket refusal).
    let ok = rt
        .zone_mount("root", "/tenant-a", ZONE, "op-gr-mount-ok-0001", "")
        .await
        .expect("a valid mount path is admitted");
    assert_eq!(ok.outcome, "MOUNTED");

    let unmounted = rt
        .zone_unmount("root", "/tenant-a", "op-gr-unmount-ok-0001", "")
        .await
        .expect("a valid unmount path is admitted");
    assert_eq!(unmounted.outcome, "UNMOUNTED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joining_a_reserved_zone_over_rpc_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");

    let mut daemon = Daemon::spawn(&["--bind-addr", &adv, "--no-tls"], &env(&data, &id, &adv));
    daemon
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("boot wires the typed zone runtime surface");
    let mut rt = ZoneRuntime::dial_ready(port, BUDGET).await;

    for reserved in ["root", "__control__"] {
        let refused = rt
            .zone_join(reserved, &[], false, "op-gr-join-reserved", "")
            .await
            .expect_err("joining a reserved zone via RPC must be refused");
        assert_eq!(
            refused.code(),
            tonic::Code::FailedPrecondition,
            "{reserved}: {refused:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deprovision_of_a_mounted_zone_is_refused_until_unmounted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");

    let mut daemon = Daemon::spawn(&["--bind-addr", &adv, "--no-tls"], &env(&data, &id, &adv));
    daemon
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("boot wires the typed zone runtime surface");
    let mut rt = ZoneRuntime::dial_ready(port, BUDGET).await;

    rt.zone_create(ZONE, &[], "op-dg-create-0001", "")
        .await
        .expect("create");
    rt.zone_mount("root", "/tenant-a", ZONE, "op-dg-mount-0002", "")
        .await
        .expect("mount");

    // Still mounted (i_links > 0): deprovision is refused — destroying the
    // target now would leave the parent holding a dangling DT_MOUNT.
    let refused = rt
        .zone_deprovision(ZONE, "op-dg-deprovision-refused-0003", "")
        .await
        .expect_err("deprovision of a mounted zone must be refused");
    assert_eq!(
        refused.code(),
        tonic::Code::FailedPrecondition,
        "{refused:?}"
    );

    // Unmount first, then deprovision succeeds.
    rt.zone_unmount("root", "/tenant-a", "op-dg-unmount-0004", "")
        .await
        .expect("unmount");
    let done = rt
        .zone_deprovision(ZONE, "op-dg-deprovision-0005", "")
        .await
        .expect("deprovision after unmount");
    assert_eq!(done.outcome, "DEPROVISIONED");
}
