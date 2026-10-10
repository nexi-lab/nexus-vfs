//! Black-box E2E (M-4, CLI face): the offline `join` CLI must not
//! re-found a zone that was deprovisioned while this node was down.
//!
//! The CLI's deletion guard reads this node's LOCAL epoch-zone replica —
//! the replica stopped with the daemon, so the deletion the founder
//! recorded in the meantime is invisible until the replica catches up.
//! The CLI now runs the same catch-up the daemon's boot runs before the
//! guard reads; without it the guard sees "no record", creates a solo
//! zone with a FRESH creation epoch, and the deleted zone resurrects
//! permanently (the epoch comparison never fires again).
//!
//!   1. TLS founder + joiner; the joiner joins the victim explicitly.
//!   2. The joiner goes DOWN.
//!   3. The founder deprovisions the victim (epoch recorded).
//!   4. The joiner runs the offline `join` CLI against the victim id.
//!   5. Refused: after a daemon restart the victim still answers DELETED
//!      — no fresh creation epoch was ever stamped.

mod common;

use std::time::Duration;

use common::{free_port, free_port_pair, Daemon, ZoneRuntime, LOG_FILTER};
use kernel::kernel::vfs_proto::zone_status_response::Presence;

const ZONE: &str = "victim";
const BUDGET: Duration = Duration::from_secs(240);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_join_cli_does_not_refound_a_zone_deleted_while_the_node_was_down() {
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

    // ── Founder: TLS-on, enrollments open, victim declared (no mount:
    //    a mounted zone is not deprovisionable) ──────────────────────────
    let token = {
        let env = vec![
            ("NEXUS_DATA_DIR", fdata.as_str()),
            ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ];
        let (ok, out, err) = common::cli(&env, &["enroll-token"]);
        assert!(ok, "enroll-token failed: {err}");
        out.trim().to_string()
    };
    // Discovery needs a DECLARED mount, but a topology-declared mount of
    // the victim (or the single-zone auto-prefix mounts landing on it)
    // keeps its i_links above zero and deprovision — rightly — refuses a
    // still-mounted zone. So the discovery mount rides a harmless dummy
    // zone, and the victim joins explicitly over RPC (the same shape
    // deleted_zone_no_resurrection uses).
    const DUMMY: &str = "discovery-dummy";
    let init_zones = format!("{ZONE},{DUMMY}");
    let mounts = format!("/{DUMMY}={DUMMY}");
    let founder_env = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
        ("NEXUS_ACCEPT_ENROLLMENTS", "true"),
        ("NEXUS_CLUSTER_INIT", init_zones.as_str()),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut founder = Daemon::spawn(&["--bind-addr", &fadv], &founder_env);
    founder
        .wait_for_log(&format!("Zone '{ZONE}' registered"), BUDGET)
        .await
        .expect("founder founds the victim zone");
    founder
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("typed surface wired on the founder");

    // ── Joiner: enroll, join the victim explicitly ─────────────────────
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
        .wait_for_log("Zone '__control__' registered", BUDGET)
        .await
        .expect("joiner holds a control-zone replica (the epoch home)");
    joiner
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("typed surface wired on the joiner");

    let ca = std::fs::read(std::path::Path::new(&jdata).join("tls/ca.pem"))
        .or_else(|_| std::fs::read(std::path::Path::new(&fdata).join("tls/ca.pem")))
        .expect("cluster CA pem");
    let (fcert, fkey) = (
        std::fs::read(std::path::Path::new(&fdata).join("tls/node.pem")).expect("node cert"),
        std::fs::read(std::path::Path::new(&fdata).join("tls/node-key.pem")).expect("node key"),
    );
    let (jcert, jkey) = (
        std::fs::read(std::path::Path::new(&jdata).join("tls/node.pem")).expect("j node cert"),
        std::fs::read(std::path::Path::new(&jdata).join("tls/node-key.pem")).expect("j node key"),
    );

    let mut j_rt = ZoneRuntime::dial_tls(jport, &ca, &jcert, &jkey, BUDGET).await;
    let joined = j_rt
        .zone_join(
            ZONE,
            std::slice::from_ref(&fadv),
            true,
            "op-m4-join-0000",
            "",
        )
        .await
        .expect("joiner joins the victim zone over RPC");
    assert_eq!(joined.outcome, "JOINED");
    drop(j_rt);

    // ── The joiner goes DOWN; the founder deprovisions the victim ──────
    drop(joiner);
    let mut f_rt = ZoneRuntime::dial_tls(fport, &ca, &fcert, &fkey, BUDGET).await;
    let receipt = f_rt
        .zone_deprovision(ZONE, "op-m4-dep-0001", "")
        .await
        .expect("deprovision succeeds while the joiner is down");
    assert_eq!(receipt.outcome, "DEPROVISIONED");

    // ── The offline `join` CLI on the joiner's data dir: the local
    //    epoch replica is stale (it stopped with the daemon), so the CLI
    //    must catch it up before its deletion guard reads it.
    let cli_env = vec![
        ("NEXUS_DATA_DIR", jdata.as_str()),
        ("NEXUS_IDENTITY_DIR", jid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", jadv.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let (_ok, _out, err) = common::cli(&cli_env, &["join", &fadv, ZONE, "/victim"]);
    // The CLI's exit shape is not the point; the PHYSICAL state is — log
    // whatever it said for triage.
    eprintln!("join cli: ok? err={err}");

    // ── A daemon restart on the joiner must still see the victim
    //    DELETED: the CLI did not stamp a fresh creation epoch. (With the
    //    stale-replica guard alone — no catch-up — the CLI would have
    //    created a solo victim whose new epoch outranks the deletion, and
    //    this restart would answer RESIDENT.)
    let mut joiner2 = Daemon::spawn(&["--bind-addr", &jadv], &joiner_env);
    joiner2
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("joiner restarts");
    let mut j_rt2 = ZoneRuntime::dial_tls(jport, &ca, &jcert, &jkey, BUDGET).await;
    let j_status = j_rt2.zone_status(ZONE, "").await.expect("joiner status");
    assert_eq!(
        j_status.presence,
        i32::from(Presence::Deleted),
        "the join CLI must not have resurrected the deprovisioned zone: {:?}",
        j_status
    );
    let f_status = f_rt.zone_status(ZONE, "").await.expect("founder status");
    assert_eq!(
        f_status.presence,
        i32::from(Presence::Deleted),
        "global identity: still deleted everywhere"
    );
}
