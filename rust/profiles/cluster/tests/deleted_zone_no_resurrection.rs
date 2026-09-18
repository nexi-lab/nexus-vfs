//! Black-box E2E (acceptance 6, R12): a replica that MISSED a deprovision's
//! peer fan-out (it was down when the zone was deleted) must not resurrect
//! the deleted zone when it comes back.
//!
//! MUST run TLS-on: the deletion epoch lives in the CONTROL ZONE, which only
//! boots under TLS (an auth-off node binds its control store to per-node
//! `root`, so epochs never replicate — the property is untestable there).
//!
//!   1. TLS founder + joiner; joiner joins the victim zone (holds a replica).
//!   2. Joiner goes DOWN.
//!   3. Founder deprovisions the victim: epoch recorded (replicated to the
//!      joiner's control-zone learner replica too — via the control plane,
//!      not the missed data-plane fan-out), local teardown succeeds, the
//!      missed fan-out only warns.
//!   4. Joiner restarts: the boot resurrection check (deletion epoch >
//!      the local dir's creation epoch) destroys the stale replica, and
//!      the join of the deleted zone is refused. Status answers DELETED.

mod common;

use std::time::Duration;

use common::{free_port, free_port_pair, Daemon, ZoneRuntime, LOG_FILTER};
use kernel::kernel::vfs_proto::zone_status_response::Presence;
use tonic::Code;

const ZONE: &str = "victim";
const BUDGET: Duration = Duration::from_secs(180);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_replica_cannot_resurrect_a_deleted_zone() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();
    let jdata = tmp.path().join("j-data").to_string_lossy().into_owned();
    let jid = tmp.path().join("j-id").to_string_lossy().into_owned();

    let fport = free_port_pair();
    let jport = loop {
        let p = free_port();
        if p != fport && p != fport + 1 {
            break p;
        }
    };
    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");

    // ── Founder: TLS-on, enrollments open, victim zone declared ──
    let token = {
        let env = vec![
            ("NEXUS_DATA_DIR", fdata.as_str()),
            ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ];
        let (ok, out, err) = common::cli(&env, &["enroll-token"]);
        assert!(ok, "enroll-token failed: {err}");
        out.trim().to_string()
    };
    // A joiner discovers federation zones through the mount topology —
    // declare the victim as a mount so it is discoverable.
    let mounts = format!("/{ZONE}={ZONE}");
    let founder_env = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
        ("NEXUS_ACCEPT_ENROLLMENTS", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut founder = Daemon::spawn(&["--bind-addr", &fadv], &founder_env);
    founder
        .wait_for_log("control zone up", BUDGET)
        .await
        .expect("TLS founder founds the control zone (the epoch home)");
    founder
        .wait_for_log(&format!("Zone '{ZONE}' registered"), BUDGET)
        .await
        .expect("founder founds the victim zone (static topology)");
    founder
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("typed surface wired on the founder");

    // ── Joiner: enroll + join the victim (a live replica exists) ──
    let joiner_env = vec![
        ("NEXUS_DATA_DIR", jdata.as_str()),
        ("NEXUS_IDENTITY_DIR", jid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", jadv.as_str()),
        ("NEXUS_PEERS", fadv.as_str()),
        ("NEXUS_JOIN_TOKEN", token.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut joiner = Daemon::spawn(&["--bind-addr", &jadv], &joiner_env);
    joiner
        .wait_for_log(&format!("Zone '{ZONE}' registered"), BUDGET)
        .await
        .expect("joiner joins the victim zone");
    // The joiner must ALSO hold a control-zone learner replica BEFORE it
    // goes down — that local replica is how the deletion epoch reaches it
    // while it is offline (the data-plane fan-out it is about to miss).
    joiner
        .wait_for_log("Zone '__control__' registered", BUDGET)
        .await
        .expect("joiner joins the control zone (the epoch home's replica)");

    // Founder's client: mTLS with its own node cert (admin+system peer).
    let ca = std::fs::read(std::path::Path::new(&jdata).join("tls/ca.pem"))
        .or_else(|_| std::fs::read(std::path::Path::new(&fdata).join("tls/ca.pem")))
        .expect("cluster CA pem");
    let (fcert, fkey) = (
        std::fs::read(std::path::Path::new(&fdata).join("tls/node.pem")).expect("node cert"),
        std::fs::read(std::path::Path::new(&fdata).join("tls/node-key.pem")).expect("node key"),
    );
    let mut f_rt = ZoneRuntime::dial_tls(fport, &ca, &fcert, &fkey, BUDGET).await;
    let status = f_rt.zone_status(ZONE, "").await.expect("victim status");
    assert_eq!(status.presence, i32::from(Presence::Resident));

    // The joiner's local replica dir exists (it joined, then still holds it).
    let victim_dir = std::path::Path::new(&jdata).join(ZONE);
    assert!(
        victim_dir.join("raft").exists(),
        "the joiner must hold a real replica dir before going down"
    );

    // ── The joiner goes DOWN (it will miss the fan-out) ──
    drop(joiner);

    // ── Deprovision on the founder, while the joiner is down ──
    let receipt = f_rt
        .zone_deprovision(ZONE, "op-dep-victim-0001", "")
        .await
        .expect("deprovision succeeds — a down peer must not block it");
    assert_eq!(receipt.outcome, "DEPROVISIONED");
    let post = f_rt.zone_status(ZONE, "").await.expect("post status");
    assert_eq!(post.presence, i32::from(Presence::Deleted));
    assert!(
        post.deletion
            .as_ref()
            .expect("deletion info")
            .deletion_epoch
            > 0,
        "the DELETED answer must carry the recorded epoch"
    );

    // ── The joiner comes back ──
    let mut joiner2 = Daemon::spawn(&["--bind-addr", &jadv], &joiner_env);
    joiner2
        .wait_for_log("predates a recorded deletion", BUDGET)
        .await
        .expect(
            "the restarted joiner must DESTROY the stale replica (boot resurrection check), \
             not re-index it",
        );

    // Its status answers DELETED — the epoch reached it through the
    // control zone (the data-plane fan-out it missed was never needed).
    let (jcert, jkey) = (
        std::fs::read(std::path::Path::new(&jdata).join("tls/node.pem")).expect("j node cert"),
        std::fs::read(std::path::Path::new(&jdata).join("tls/node-key.pem")).expect("j node key"),
    );
    let mut j_rt = ZoneRuntime::dial_tls(jport, &ca, &jcert, &jkey, BUDGET).await;
    let j_status = j_rt.zone_status(ZONE, "").await.expect("joiner status");
    assert_eq!(
        j_status.presence,
        i32::from(Presence::Deleted),
        "global identity: the restarted stale replica answers DELETED, not RESIDENT"
    );

    // ── And the deleted zone cannot be re-created or re-joined (R12) ──
    let err = f_rt
        .zone_create(ZONE, &[], "op-recreate-victim-0002", "")
        .await
        .expect_err("creating a deprovisioned zone must be refused");
    assert_eq!(err.code(), Code::FailedPrecondition, "{}", err.message());
    let err = j_rt
        .zone_join(ZONE, &[fadv.clone()], false, "op-rejoin-victim-0003", "")
        .await
        .expect_err("joining a deprovisioned zone must be refused");
    assert_eq!(
        err.code(),
        Code::FailedPrecondition,
        "the join path refuses too — no resurrection via rejoin: {}",
        err.message()
    );
}
