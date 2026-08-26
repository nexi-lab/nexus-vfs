//! Regression: federation boot must be ORDER-INDEPENDENT. A joiner started
//! BEFORE its founder must auto-discover + join the federation once the founder
//! appears — without a restart and without the manual `nexusd-cluster join`
//! sidecar.
//!
//! Root cause (code + the Mac↔Win duet bring-up): a fresh joiner's federation
//! discovery (`reconcile_federation_from_peers` → `DiscoverZones`) was ONE-SHOT.
//! A joiner that booted first found no reachable peer, came up
//! rootless-with-peers, and never auto-joined — the operator had to restart it
//! or run the join sidecar. Every other federation test dodges this by booting
//! the founder first and gating on `wait_for_log("Static topology applied")`
//! before spawning the joiner (see the ordering note in `common::wait_for_log`);
//! that ordering requirement WAS the bug's fingerprint.
//!
//! Fix: the fresh-joiner discovery stage retries with a bounded budget — the
//! same self-healing the control-zone join already had (`max_attempts`) and the
//! same retry-join model a first-timer expects from etcd / k3s / consul. Start
//! order no longer matters. Drives `--no-tls` so a plaintext client verifies the
//! REAL read path (stat + content) through the `/agents` mount, not just a log.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, Vfs, LOG_FILTER};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(90);

fn founder_env<'a>(
    data: &'a str,
    id: &'a str,
    adv: &'a str,
    mounts: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts),
        ("RUST_LOG", LOG_FILTER),
    ]
}

fn joiner_env<'a>(
    data: &'a str,
    id: &'a str,
    adv: &'a str,
    peers: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_PEERS", peers),
        ("RUST_LOG", LOG_FILTER),
    ]
}

/// The joiner boots FIRST, with `--peers` pointing at a founder that is not up
/// yet. It must keep retrying discovery (logging the "waiting for a founder…"
/// guidance) rather than one-shotting to rootless; then, once the founder
/// appears, it must auto-join and serve a working `/agents` mount — with no
/// restart in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joiner_started_before_founder_auto_joins() {
    let zone_registered = format!("Zone '{ZONE}' registered");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fport = free_port();
    let jport = free_port();
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();
    let jdata = tmp.path().join("j-data").to_string_lossy().into_owned();
    let jid = tmp.path().join("j-id").to_string_lossy().into_owned();
    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");
    let mounts = format!("{MOUNT}={ZONE}");
    let peers = fadv.clone();

    // 1) Joiner FIRST — its founder is not listening yet.
    let mut joiner = Daemon::spawn(
        &["--bind-addr", &jadv],
        &joiner_env(&jdata, &jid, &jadv, &peers),
    );

    // 2) It must NOT one-shot to rootless: it retries discovery and says so.
    //    This is the assertion the pre-fix one-shot path could never satisfy —
    //    it would have logged "daemon up rootless-with-peers" and stopped.
    joiner
        .wait_for_log("waiting for a founder to become reachable", BUDGET)
        .await
        .expect("joiner retries discovery instead of one-shotting to rootless");

    // 3) NOW bring the founder up — the reversed (harder) order.
    let mut founder = Daemon::spawn(
        &["--bind-addr", &fadv],
        &founder_env(&fdata, &fid, &fadv, &mounts),
    );
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder forms + persists the sharedzone mount");

    // 4) The joiner auto-joins WITHOUT a restart or the sidecar.
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("joiner auto-joins once the founder appears (no restart, no sidecar)");

    // 5) Deep read path: the `/agents` mount is wired and replicates. A joiner
    //    that came up rootless would fail this — sharedzone would be unroutable.
    let mut fc = Vfs::dial_ready(fport, BUDGET).await;
    let mut jc = Vfs::dial_ready(jport, BUDGET).await;
    let probe = format!("{MOUNT}/order-independent.txt");
    fc.write_file(&probe, b"pong", "")
        .await
        .expect("founder write through /agents");

    let deadline = std::time::Instant::now() + BUDGET;
    let mut replicated = false;
    while std::time::Instant::now() < deadline {
        if jc.stat_found(&probe, "").await {
            if let Ok(v) = jc.read_file(&probe, "").await {
                if v.as_slice() == b"pong" {
                    replicated = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    let j_agents = jc.readdir_names(MOUNT, "").await;
    assert!(
        replicated,
        "a joiner that started BEFORE its founder could not read {probe} through {MOUNT} after \
         auto-join — it likely came up rootless instead of retrying discovery.\n\
         joiner readdir({MOUNT})={j_agents:?}"
    );

    drop(joiner);
    drop(founder);
}
