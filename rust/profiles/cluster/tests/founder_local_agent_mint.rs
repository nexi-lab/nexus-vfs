//! Black-box E2E: `auth mint --subject-type agent` just-works on the FOUNDER
//! WHILE its own daemon is up (Half A of the auth-CLI-uniformity work).
//!
//! Pre-Half-A this failed with a redb data-dir lock error ("stop the daemon
//! first"): the CA holder took the offline store-open path, which cannot open a
//! store the running daemon already holds. Now the mint routes through the
//! founder's OWN live daemon over loopback mTLS (`self_daemon_endpoint` — the
//! `MintAgent` slot is armed on the CA holder), so it signs through raft without
//! ever contending the store lock. The discriminator is daemon-reachability, not
//! "do I hold the CA key".
//!
//! Its own file (not folded into `remote_agent_mint`) so only ONE founder+enroll
//! flow runs per test binary — two heavy founder flows in one binary race for
//! ephemeral ports under cargo's within-file test parallelism.

mod common;

use std::time::Duration;

use common::{cli, free_port_pair, Daemon, LOG_FILTER};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_mint_agent_on_the_founder_while_its_daemon_is_up() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();
    let fport = free_port_pair();
    let fadv = format!("127.0.0.1:{fport}");
    let mounts = format!("{MOUNT}={ZONE}");

    let founder_env = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut founder = Daemon::spawn(&["--bind-addr", &fadv], &founder_env);
    founder
        .wait_for_log("CA holder armed MintAgent RPC", BUDGET)
        .await
        .expect("founder arms the local MintAgent");
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder forms sharedzone");

    // The operator's shell carries the same advertise addr the daemon booted
    // with, so the CLI finds the local daemon's data-plane port.
    let mint_env = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
    ];
    let (ok, out, err) = cli(
        &mint_env,
        &[
            "auth",
            "mint",
            "--subject-type",
            "agent",
            "--subject-id",
            "founder-local",
            "--name",
            "e2e",
        ],
    );
    assert!(
        ok,
        "the founder must mint an agent WHILE its own daemon is up (no redb-lock \
         'stop the daemon' error).\nstdout: {out}\nstderr: {err}"
    );
    assert!(
        err.contains(&format!("via https://127.0.0.1:{fport}")),
        "the founder mint must forward to its OWN live daemon (self-localhost), \
         not fall back to an offline sign — got stderr: {err}"
    );
    let bundle_dir = std::path::PathBuf::from(out.trim());
    for f in ["agent.pem", "agent-key.pem", "ca.pem"] {
        assert!(
            bundle_dir.join(f).exists(),
            "founder-local mint must write {f}"
        );
    }

    // B1: an `sk-` user key ALSO mints while the daemon is up — via the local
    // daemon's MintKey RPC (the store write forwards to the control-zone
    // leader). Pre-B1 this was the offline store-open path, which fails on the
    // running daemon's redb lock ("stop the daemon first"). The founder set no
    // NEXUS_API_KEY_SECRET (self-provisioned at boot); the CLI never needs it —
    // the daemon HMACs server-side.
    let (sk_ok, sk_out, sk_err) = cli(
        &mint_env,
        &[
            "auth",
            "mint",
            "--subject-type",
            "user",
            "--subject-id",
            "admin",
            "--admin",
            "--name",
            "e2e",
        ],
    );
    assert!(
        sk_ok,
        "an sk- user key must mint WHILE the daemon is up (no redb-lock error).\n\
         stdout: {sk_out}\nstderr: {sk_err}"
    );
    let key = sk_out.trim().to_string();
    assert!(
        key.starts_with("sk-") && key.len() >= 32,
        "MintKey must return a well-formed sk- key, got: {key:?}"
    );
    assert!(
        sk_err.contains("via the local daemon"),
        "the sk- mint must go the daemon RPC path, not offline — got stderr: {sk_err}"
    );

    // And revoke it while the daemon is up (RevokeKey RPC — the delete forwards
    // to the leader).
    let (rv_ok, rv_out, rv_err) = cli(&mint_env, &["auth", "revoke", "--key", &key]);
    assert!(
        rv_ok,
        "revoke must succeed WHILE the daemon is up.\nstdout: {rv_out}\nstderr: {rv_err}"
    );
    assert!(
        rv_out.trim() == "revoked",
        "revoke of a just-minted key should report 'revoked', got: {rv_out:?}"
    );

    drop(founder);
}
