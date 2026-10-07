//! Black-box E2E (H-2): a single-zone deployment survives a NORMAL reboot
//! (no `--force`) after its declared zone was deprovisioned — the data
//! plane must report ready instead of wedging forever on a mount whose
//! target was skipped by the D9 guard.
//!
//! Before the fix, bootstrap_static skipped the deprovisioned zone (D9,
//! correct) but still injected the three default prefix mounts targeting
//! it into pending_mounts. The topology loop then wrote a dangling
//! DT_MOUNT into the root metastore, ensure_links_count failed forever
//! against a target that never comes back, apply_topology never
//! converged, and mark_ready never fired — the daemon answered every RPC
//! with Unavailable after the boot-gate budget. The fix drops declared
//! mounts whose target was D9-skipped, so the topology converges over an
//! empty pending set.

mod common;

use std::time::Duration;

use common::{free_port_pair, Daemon, ZoneRuntime, LOG_FILTER};

const ZONE: &str = "victim";
const BUDGET: Duration = Duration::from_secs(240);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_zone_deprovision_then_normal_restart_converges() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();

    let fport = free_port_pair();
    let fadv = format!("127.0.0.1:{fport}");

    let founder_env = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
        ("NEXUS_ACCEPT_ENROLLMENTS", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("RUST_LOG", LOG_FILTER),
    ];

    // ── 1. Found, unmount the three auto-prefixes, deprovision ─────────
    let mut founder = Daemon::spawn(&["--bind-addr", &fadv], &founder_env);
    founder
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("TLS founder boots the typed surface");
    let tls = |data: &str| {
        let dir = std::path::Path::new(data).join("tls");
        (
            std::fs::read(dir.join("ca.pem")).expect("ca"),
            std::fs::read(dir.join("node.pem")).expect("cert"),
            std::fs::read(dir.join("node-key.pem")).expect("key"),
        )
    };
    let (ca, cert, key) = tls(&fdata);
    let mut rt = ZoneRuntime::dial_tls(fport, &ca, &cert, &key, BUDGET).await;
    // `victim` is the ONLY declared zone, so the boot's auto-prefix mount
    // landed /agents, /conversations and /sessions on it; deprovision
    // (rightly) refuses a still-referenced zone, so undo them first (the
    // same operator cleanup force_refound_zone_resumes performs).
    for (i, prefix) in ["/agents", "/conversations", "/sessions"]
        .into_iter()
        .enumerate()
    {
        let _ = rt
            .zone_unmount("root", prefix, &format!("op-conv-unmount-{i:04}"), "")
            .await;
    }
    let receipt = rt
        .zone_deprovision(ZONE, "op-conv-dep-0001", "")
        .await
        .expect("deprovision succeeds (unmounted zone)");
    assert_eq!(receipt.outcome, "DEPROVISIONED");
    drop(rt);
    drop(founder);

    // ── 2. NORMAL reboot (no --force): the D9 guard skips the zone, and
    //       the mounts targeting it must be dropped with it — the data
    //       plane must reach ready. Before the fix this wait timed out:
    //       the pending mounts chased a target that never comes back.
    let mut normal = Daemon::spawn(&["--bind-addr", &fadv], &founder_env);
    normal
        .wait_for_log("refusing to re-found a deprovisioned zone", BUDGET)
        .await
        .expect("the D9 guard fires for the declared-but-deleted zone");
    normal
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("topology converges (mounts targeting the skipped zone are dropped)");

    // The ready claim is real: the typed surface answers over the fresh
    // boot, and the deleted zone answers DELETED, not resurrected.
    let mut rt2 = ZoneRuntime::dial_tls(fport, &ca, &cert, &key, BUDGET).await;
    let status = rt2.zone_status(ZONE, "").await.expect("status");
    assert_eq!(
        status.presence,
        i32::from(kernel::kernel::vfs_proto::zone_status_response::Presence::Deleted),
        "the deprovisioned zone stays deleted across the normal reboot"
    );
}
