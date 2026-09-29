//! Regression test for nexi-lab/nexus-vfs#344 — "VFS data plane ready" must not be
//! announced while a write would still be refused.
//!
//! Routing resolved is not write-admitted. A wal DT_STREAM push replicates through
//! raft, so a zone with no leader refuses it, and the readiness line used to fire on
//! topology convergence alone. In CI that read:
//!
//! ```text
//! 18:00:24  VFS data plane ready — … serving client requests
//! 18:00:36  wal DT_STREAM push failed to replicate (no reachable leader?)
//! ```
//!
//! Twelve seconds apart, and the client did exactly what the line invited it to do.
//! That line is the one observable every harness and embedder waits on, so it has to
//! mean a write will be admitted.
//!
//! ## Why this shape, and not a simpler one
//!
//! The gap needs convergence WITHOUT leadership, and the two are usually simultaneous.
//! Declaring an absent peer is refused outright (`--cluster-init` and `--peers` are
//! mutually exclusive — founding and joining are different jobs, and doing both is the
//! split-brain). A solo node elects in milliseconds, so there is no window to observe.
//!
//! So: enroll a real joiner, which makes the zone two voters, then stop the founder and
//! restart the joiner. Its topology is ALREADY applied from the first boot, so
//! convergence needs no proposal and returns immediately — while an election needs a
//! majority of two and can never reach one. That is #344's window, held open.
//!
//! The happy path is asserted here too, before the restart: with both nodes up the same
//! node does become ready, so this test would also catch a gate that over-blocks.

mod common;

use std::time::Duration;

use common::{cli, free_port, free_port_pair, Daemon, LOG_FILTER};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/shared";
const BUDGET: Duration = Duration::from_secs(90);

#[tokio::test]
async fn a_zone_that_cannot_elect_keeps_the_data_plane_shut() {
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
    let mounts = format!("{MOUNT}={ZONE}");

    // ── founder mints a join token, then serves ───────────────────────────────
    let token = {
        let env = vec![
            ("NEXUS_DATA_DIR", fdata.as_str()),
            ("NEXUS_IDENTITY_DIR", fid.as_str()),
            ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
        ];
        let (ok, out, err) = cli(&env, &["enroll-token"]);
        assert!(ok, "enroll-token failed: {err}");
        out.trim().to_string()
    };

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
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder forms the zone");

    // ── joiner enrolls: the zone is now TWO voters ────────────────────────────
    let joiner_env = vec![
        ("NEXUS_DATA_DIR", jdata.as_str()),
        ("NEXUS_IDENTITY_DIR", jid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", jadv.as_str()),
        ("NEXUS_PEERS", fadv.as_str()),
        ("NEXUS_JOIN_TOKEN", token.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut joiner = Daemon::spawn(&["--bind-addr", &jadv], &joiner_env);

    // The happy path, asserted before the interesting part: with a reachable leader
    // this node DOES announce readiness. A gate that simply never opens would pass the
    // assertions below while breaking every deployment.
    joiner
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("a joiner with a reachable leader must become ready");

    // ── the founder goes away, and the joiner restarts alone ──────────────────
    drop(founder);
    drop(joiner);

    let mut alone = Daemon::spawn(&["--bind-addr", &jadv], &joiner_env);

    // Gate on the WAITING line rather than a sleep: this is what makes the absence
    // below mean something. It proves the daemon reached the leadership check and
    // decided to hold the gate — a fixed wait would also "pass" on a build where the
    // readiness line simply had not been printed yet.
    alone
        .wait_for_log("holding the data plane closed", BUDGET)
        .await
        .expect("a node whose zone cannot elect must say it is waiting for a leader");

    assert!(
        !alone.log_contains("VFS data plane ready"),
        "readiness was announced with no leader — a write would be refused after it, \
         which is #344"
    );

    // "my peer is not up" and "my own zone is broken" call for opposite actions, and
    // this line is the only place an operator learns which one it is — so it has to
    // carry the zone and its voter count.
    //
    // The assertion is on the message's SHAPE, not on a zone name, and that is
    // deliberate: which zone loses its leader first is not this contract. Here it is
    // `__control__`, where this node enrolled as a learner and the founder was the sole
    // voter, while `root` elects itself as its own only voter. Pinning `sharedzone`
    // would have been pinning my assumption — it is what I wrote first, and it failed.
    let waiting = alone
        .drain()
        .lines()
        .find(|l| l.contains("holding the data plane closed"))
        .map(str::to_string)
        .expect("the waiting line was matched above");
    assert!(
        waiting.contains("zone=") && waiting.contains("voters="),
        "the wait message must name the zone and how many voters it needs; got: {waiting}"
    );
}
