//! Black-box E2E (R12/D9 escape hatch): `--force` re-founds a deprovisioned
//! zone AND the re-found survives subsequent NORMAL boots — the operator's
//! recovery is durable, not a one-boot illusion.
//!
//! The closed loop under test:
//!   1. TLS founder founds `victim` (declared topology + mount).
//!   2. `zone_deprovision` records the deletion epoch and tears it down.
//!   3. `--force` boot re-founds it — the escape hatch stamps a FRESH
//!      local creation epoch (outranking the recorded deletion).
//!   4. A NORMAL boot (no `--force`) then RESUMES the zone instead of
//!      skipping it or letting the sweep destroy it — proving the epoch
//!      ordering, not the flag, now carries the operator's intent.
//!   5. Data written under the re-found zone survives the normal reboot
//!      (the replica is real, not a metadata illusion).
//!
//! Documented trade (pinned here): the deletion RECORD is never cleared,
//! so `zone_status` keeps answering DELETED for the zone even while it
//! serves — recorded-epoch semantics.

mod common;

use std::time::Duration;

use common::{free_port_pair, Daemon, Vfs, ZoneRuntime, LOG_FILTER};
use kernel::kernel::vfs_proto::zone_status_response::Presence;

const ZONE: &str = "victim";
const BUDGET: Duration = Duration::from_secs(240);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn force_refound_survives_subsequent_normal_boots() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();

    let fport = free_port_pair();
    let fadv = format!("127.0.0.1:{fport}");

    // No NEXUS_CLUSTER_INIT_MOUNTS here: a topology-declared mount keeps
    // the zone's i_links above zero, and deprovision (rightly) refuses to
    // destroy a still-mounted zone. The zone rides `--cluster-init` alone;
    // the test mounts it explicitly over RPC when it needs a global path
    // (the mount lives in the per-node root's persistent metastore, so it
    // survives the reboots below).
    let founder_env = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
        ("NEXUS_ACCEPT_ENROLLMENTS", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("RUST_LOG", LOG_FILTER),
    ];

    // ── 1. Found, then deprovision ──────────────────────────────────
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
    let receipt = rt
        .zone_deprovision(ZONE, "op-force-dep-0001", "")
        .await
        .expect("deprovision succeeds (unmounted zone)");
    assert_eq!(receipt.outcome, "DEPROVISIONED");
    let status = rt.zone_status(ZONE, "").await.expect("status");
    assert_eq!(status.presence, i32::from(Presence::Deleted));
    drop(rt);
    drop(founder);

    // ── 2. --force boot re-founds it ────────────────────────────────
    let mut forced = Daemon::spawn(&["--bind-addr", &fadv, "--force"], &founder_env);
    forced
        .wait_for_log(
            "--force: re-founding registry-deleted zones is ENABLED",
            BUDGET,
        )
        .await
        .expect("the escape hatch is engaged (the startup warning always fires)");
    forced
        .wait_for_log(&format!("Zone '{ZONE}' registered"), BUDGET)
        .await
        .expect("the --force boot re-founds the deprovisioned zone");

    // The re-found zone is a REAL filesystem: mount it (persistent in the
    // per-node root) and write through the mount.
    forced
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("data plane open");
    let mut rt2 = ZoneRuntime::dial_tls(fport, &ca, &cert, &key, BUDGET).await;
    let mounted = rt2
        .zone_mount("root", &format!("/{ZONE}"), ZONE, "op-force-mount-0002", "")
        .await
        .expect("mount the re-found zone");
    assert_eq!(mounted.outcome, "MOUNTED");
    let mut vfs = Vfs::connect_mtls(fport, &ca, &cert, &key, BUDGET).await;
    vfs.write_file(&format!("/{ZONE}/force-proof.txt"), b"re-found", "")
        .await
        .expect("write through the re-found zone's mount");

    // Documented trade: the deletion record stays, so status answers
    // DELETED even while the zone serves.
    let status = rt2.zone_status(ZONE, "").await.expect("status");
    assert_eq!(
        status.presence,
        i32::from(Presence::Deleted),
        "the deletion RECORD is never cleared — recorded-epoch semantics"
    );
    drop(rt2);
    drop(vfs);
    drop(forced);

    // ── 3. NORMAL boot resumes it (the loop closes here) ────────────
    // The re-found dir is already hosted, so the normal boot produces no
    // "registered" log for it (hosted zones skip the bootstrap loop and
    // materialize on first access) — the RESUME proof is the data path.
    let mut normal = Daemon::spawn(&["--bind-addr", &fadv], &founder_env);
    normal
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("normal boot completes");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !normal.log_contains("predates a recorded deletion"),
        "the sweep must NOT destroy the re-found zone — the force boot's fresh \
         creation epoch outranks the recorded deletion"
    );

    normal
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("normal boot opens the data plane");
    let mut vfs2 = Vfs::connect_mtls(fport, &ca, &cert, &key, BUDGET).await;
    let back = vfs2
        .read_file(&format!("/{ZONE}/force-proof.txt"), "")
        .await
        .expect("the re-found zone's data survived the normal reboot (real resume)");
    assert_eq!(back, b"re-found");
}
