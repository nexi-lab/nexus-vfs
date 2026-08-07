//! Black-box E2E: an `sk-` credential minted on the FOUNDER replicates to a
//! JOINER's control-zone replica, observed live through the joiner's own daemon.
//!
//! This is the cross-node proof for the control zone (B2 / the auth-CLI-as-
//! daemon-client work): auth records used to live in per-node `root`, so a
//! founder-minted key never reached a joiner. Now they live in a replicated
//! control zone (founder voter, joiner learner), so the whole chain holds on a
//! real two-node cluster:
//!
//!   founder `auth mint` (→ MintKey RPC → control-zone leader apply)
//!     → raft replicates the PutControlState to the joiner's learner replica
//!       → joiner `auth list` (→ ListKeys RPC → reads its LOCAL replica) sees it.
//!
//! Both daemons stay UP throughout — the mint/list route through the live
//! daemons (no offline store-open, which the joiner's gate refuses anyway). A
//! revoke on the founder then propagates the DeleteControlState the same way.
//!
//! Loopback two-node (no second machine needed); the cross-MACHINE Win↔Mac run
//! is the same flow over Tailscale.

mod common;

use std::time::{Duration, Instant};

use common::{cli, free_port, free_port_pair, Daemon, LOG_FILTER};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(120);

/// Poll the joiner's daemon-backed `auth list` until `needle` is present/absent
/// (or the budget expires), returning the last listing for diagnosis.
/// Replication + apply to the learner replica takes a beat, so this polls.
fn await_listed(joiner_env: &[(&str, &str)], needle: &str, present: bool) -> (bool, String) {
    let deadline = Instant::now() + BUDGET;
    loop {
        let (ok, out, err) = cli(joiner_env, &["auth", "list"]);
        let last = format!("ok={ok}\nstdout:\n{out}\nstderr:\n{err}");
        if ok && (out.contains(needle) == present) {
            return (true, last);
        }
        if Instant::now() >= deadline {
            return (false, last);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sk_key_minted_on_the_founder_replicates_to_a_joiner() {
    let zone_registered = format!("Zone '{ZONE}' registered");
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

    // ── Founder: token → boot (auth-on, control zone + sharedzone) ──
    let token = {
        let env = vec![
            ("NEXUS_DATA_DIR", fdata.as_str()),
            ("NEXUS_IDENTITY_DIR", fid.as_str()),
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
        .wait_for_log("control zone up", BUDGET)
        .await
        .expect("founder founds the control zone (auth home)");
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder forms sharedzone over mTLS");

    // ── Joiner: auto-enroll + join (becomes a control-zone LEARNER) ──
    let joiner_env_boot = vec![
        ("NEXUS_DATA_DIR", jdata.as_str()),
        ("NEXUS_IDENTITY_DIR", jid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", jadv.as_str()),
        ("NEXUS_PEERS", fadv.as_str()),
        ("NEXUS_JOIN_TOKEN", token.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut joiner = Daemon::spawn(&["--bind-addr", &jadv], &joiner_env_boot);
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("enrolled joiner joins over mTLS");

    // ── Mint an sk- user key ON THE FOUNDER, via its live daemon (MintKey) ──
    // ADVERTISE_ADDR lets the CLI find the founder's own daemon on loopback.
    let founder_cli = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
    ];
    let (mok, mout, merr) = cli(
        &founder_cli,
        &[
            "auth",
            "mint",
            "--subject-type",
            "user",
            "--subject-id",
            "cross-node",
            "--admin",
            "--name",
            "e2e",
        ],
    );
    assert!(
        mok && mout.trim().starts_with("sk-"),
        "founder sk- mint (via daemon) must succeed.\nstdout: {mout}\nstderr: {merr}"
    );
    assert!(
        merr.contains("via the local daemon"),
        "founder mint must go the daemon RPC path — got: {merr}"
    );

    // ── The joiner, via ITS OWN daemon (ListKeys → local replica), must see the
    //    key replicate in. This is the cross-node proof.
    let joiner_cli = vec![
        ("NEXUS_DATA_DIR", jdata.as_str()),
        ("NEXUS_IDENTITY_DIR", jid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", jadv.as_str()),
    ];
    let (seen, listing) = await_listed(&joiner_cli, "user:cross-node", true);
    assert!(
        seen,
        "the founder-minted sk- key must replicate to the joiner's control-zone \
         replica and show in the joiner's daemon-backed `auth list`.\nlast: {listing}"
    );

    // ── Revoke on the founder → the DeleteControlState propagates → the joiner's
    //    list no longer shows it. Proves revocation replicates too, live.
    let key = mout.trim();
    let (rok, _ro, re) = cli(&founder_cli, &["auth", "revoke", "--key", key]);
    assert!(rok, "founder revoke (via daemon) must succeed: {re}");
    let (gone, listing2) = await_listed(&joiner_cli, "user:cross-node", false);
    assert!(
        gone,
        "the revoked key must disappear from the joiner's list (DeleteControlState \
         replicated).\nlast: {listing2}"
    );

    drop(joiner);
    drop(founder);
}
