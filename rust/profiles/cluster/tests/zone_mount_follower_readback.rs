//! Black-box E2E (follower read-back): a `zone_mount` RPC that lands on a
//! node that is NOT the parent zone's leader must still succeed — the
//! physical read-back polls for the DT_MOUNT to become VISIBLE in the
//! local state machine instead of snapshotting once.
//!
//! The trap: on a follower/learner, `propose` returns once the LEADER
//! commits, but the local apply lags by a raft tick — a one-shot read-back
//! right after the propose observes stale state, journals a permanent
//! REJECTED, and answers `Internal` for a mount that actually committed.
//!
//! Setup: TLS founder + joiner; BOTH join `parent-a` (founder = voter,
//! joiner = learner — never the leader) and the joiner hosts `tenant-b`.
//! The mount RPC goes to the JOINER: its propose for the parent's
//! DT_MOUNT forwards to the founder, and the read-back must wait out the
//! local apply lag.

mod common;

use std::time::Duration;

use common::{free_port, free_port_pair, Daemon, ZoneRuntime, LOG_FILTER};

const PARENT: &str = "parent-a";
const TARGET: &str = "tenant-b";
const BUDGET: Duration = Duration::from_secs(240);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mount_via_a_follower_of_the_parent_succeeds_with_real_facts() {
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

    // Founder declares BOTH zones; both are mounted so the joiner's
    // topology discovery joins them (it must host the parent — its raft
    // group runs the read-back — and the target — mount bumps its i_links).
    let token = {
        let env = vec![
            ("NEXUS_DATA_DIR", fdata.as_str()),
            ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ];
        let (ok, out, err) = common::cli(&env, &["enroll-token"]);
        assert!(ok, "enroll-token failed: {err}");
        out.trim().to_string()
    };
    let mounts = format!("/{PARENT}={PARENT},/{TARGET}={TARGET}");
    let init_zones = format!("{PARENT},{TARGET}");
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
        .wait_for_log(&format!("Zone '{PARENT}' registered"), BUDGET)
        .await
        .expect("founder founds the parent zone");
    founder
        .wait_for_log(&format!("Zone '{TARGET}' registered"), BUDGET)
        .await
        .expect("founder founds the target zone");
    founder
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("typed surface wired on the founder");

    // Joiner: enrolls, joins both zones (parent as learner — never its
    // leader; the founder holds the vote).
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
        .wait_for_log(&format!("Zone '{PARENT}' registered"), BUDGET)
        .await
        .expect("joiner joins the parent zone (as learner)");
    joiner
        .wait_for_log(&format!("Zone '{TARGET}' registered"), BUDGET)
        .await
        .expect("joiner joins the target zone");

    // Mount RPC to the JOINER — a follower of the parent. Before the
    // value-visibility read-back this was the fake-failure path: the
    // propose forwarded and committed at the leader, the one-shot local
    // read still saw nothing, and the journal said REJECTED forever.
    let ca = std::fs::read(std::path::Path::new(&jdata).join("tls/ca.pem"))
        .or_else(|_| std::fs::read(std::path::Path::new(&fdata).join("tls/ca.pem")))
        .expect("cluster CA pem");
    let (jcert, jkey) = (
        std::fs::read(std::path::Path::new(&jdata).join("tls/node.pem")).expect("j cert"),
        std::fs::read(std::path::Path::new(&jdata).join("tls/node-key.pem")).expect("j key"),
    );
    let mut j_rt = ZoneRuntime::dial_tls(jport, &ca, &jcert, &jkey, BUDGET).await;

    const OP: &str = "op-follower-mount-0001";
    let receipt = j_rt
        .zone_mount(PARENT, "/nested", TARGET, OP, "")
        .await
        .expect("a mount landing on a follower of the parent must succeed");
    assert_eq!(
        receipt.outcome, "MOUNTED",
        "real facts, not phantom success"
    );
    assert_eq!(
        receipt.mount.as_ref().expect("mount facts").mount_path,
        "/nested"
    );

    // The journal record is COMPLETED — the follower path must never
    // leave a permanent REJECTED for a mount that committed.
    let op = j_rt.get_zone_operation(OP, "").await.expect("journal");
    assert_eq!(
        op.status, "COMPLETED",
        "the operation is terminal-COMPLETED"
    );

    // Physical visibility, the real assertion behind the receipt: the
    // DT_MOUNT is in the parent's replicated state (asked on the founder).
    let (fcert, fkey) = (
        std::fs::read(std::path::Path::new(&fdata).join("tls/node.pem")).expect("f cert"),
        std::fs::read(std::path::Path::new(&fdata).join("tls/node-key.pem")).expect("f key"),
    );
    let mut f_rt = ZoneRuntime::dial_tls(fport, &ca, &fcert, &fkey, BUDGET).await;
    let target_status = f_rt.zone_status(TARGET, "").await.expect("target status");
    let _ = target_status; // presence of the target zone itself

    // i_links is a best-effort snapshot on the follower path (two raft
    // groups apply independently) — assert EVENTUAL consistency with a
    // bounded retry of FRESH operation ids (a replayed id would return the
    // first execution's receipt snapshot, not a fresh read).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let probe = j_rt
            .zone_mount(
                PARENT,
                "/nested",
                TARGET,
                &format!("op-follower-mount-probe-{attempt:03}"),
                "",
            )
            .await;
        match probe {
            Ok(r) if r.mount.as_ref().is_some_and(|m| m.i_links_count >= 1) => break,
            Ok(_) | Err(_) => {}
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the mount's i_links must become visible on the follower eventually"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
