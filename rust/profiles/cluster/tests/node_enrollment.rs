//! Black-box E2E: a brand-new node with NO cluster cert ENROLLS with a join
//! token, then boots into the mTLS federation using its issued cert.
//!
//! This is the production onboarding path (#22) — the k3s/kubeadm "join token"
//! model on nexus's dedicated `NodeEnrollmentService` bootstrap plane. It
//! proves the whole chain on the REAL binary, each step consuming the last:
//!
//! 1. TOKEN — founder mints a CA-fingerprint-pinned join token (`enroll-token`),
//!    which also bootstraps the cluster CA.
//! 2. LISTEN — founder boots TLS-ON with `--enroll-listen` (the plaintext
//!    bootstrap plane) and forms `sharedzone`.
//! 3. ENROLL — a CERTLESS joiner runs `enroll <founder-enroll-addr> <token>` and
//!    receives + writes its signed node cert (ca/node/node-key).
//! 4. FEDERATE — the joiner boots TLS-ON with `--peers` and JOINS `sharedzone`
//!    over mTLS — a handshake it could only complete with a cert chaining to the
//!    founder's CA, i.e. the one enrollment issued.
//!
//! mTLS data-flow itself is covered by `federation_mtls_from_stamp`; the delta
//! here is that the joiner's cert came from ENROLLMENT, not a hand-placed bundle.

mod common;

use std::time::Duration;

use common::{cli, free_port, Daemon, LOG_FILTER};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const SECRET: &str = "e2e-enroll-secret";
const BUDGET: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certless_node_enrolls_with_a_token_then_federates_over_mtls() {
    let zone_registered = format!("Zone '{ZONE}' registered");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();
    let jdata = tmp.path().join("j-data").to_string_lossy().into_owned();
    let jid = tmp.path().join("j-id").to_string_lossy().into_owned();

    let fport = free_port();
    let fenroll = free_port();
    let jport = free_port();
    let fadv = format!("127.0.0.1:{fport}");
    let fenroll_addr = format!("127.0.0.1:{fenroll}");
    let jadv = format!("127.0.0.1:{jport}");
    let mounts = format!("{MOUNT}={ZONE}");

    // ── 1. TOKEN — founder mints a join token (bootstraps its cluster CA) ──
    let token = {
        let env = vec![
            ("NEXUS_DATA_DIR", fdata.as_str()),
            ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ];
        let (ok, out, err) = cli(&env, &["enroll-token"]);
        assert!(ok, "enroll-token failed: {err}");
        out.trim().to_string()
    };
    assert!(
        token.starts_with("K10") && token.contains("::server:SHA256:"),
        "unexpected join token shape: {token:?}"
    );

    // ── 2. LISTEN — founder boots TLS-ON + enroll listener + sharedzone ────
    let founder_env = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
        ("NEXUS_ENROLL_LISTEN", fenroll_addr.as_str()),
        ("NEXUS_FEDERATION_ZONES", ZONE),
        ("NEXUS_FEDERATION_MOUNTS", mounts.as_str()),
        ("RUST_LOG", LOG_FILTER),
        // NEXUS_NO_TLS deliberately UNSET — TLS is ON (the founder owns the CA).
    ];
    let mut founder = Daemon::spawn(&["--bind-addr", &fadv], &founder_env);
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder forms + persists sharedzone over mTLS");

    // ── 3. ENROLL — the certless joiner obtains a signed cert via the token ─
    {
        let env = vec![
            ("NEXUS_DATA_DIR", jdata.as_str()),
            ("NEXUS_IDENTITY_DIR", jid.as_str()),
        ];
        let (ok, _out, err) = cli(&env, &["enroll", &fenroll_addr, &token]);
        assert!(ok, "enroll failed: {err}");
    }
    // The joiner now holds an issued identity but NOT the CA key (it is not a CA).
    let jtls = std::path::Path::new(&jdata).join("tls");
    for f in ["ca.pem", "node.pem", "node-key.pem"] {
        assert!(
            jtls.join(f).exists(),
            "enroll must write {f} into the joiner tls dir"
        );
    }
    assert!(
        !jtls.join("ca-key.pem").exists(),
        "an enrolled node must NOT receive the cluster CA private key"
    );

    // ── 4. FEDERATE — joiner boots TLS-ON with --peers and joins over mTLS ─
    let joiner_env = vec![
        ("NEXUS_DATA_DIR", jdata.as_str()),
        ("NEXUS_IDENTITY_DIR", jid.as_str()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_ADVERTISE_ADDR", jadv.as_str()),
        ("NEXUS_PEERS", fadv.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut joiner = Daemon::spawn(&["--bind-addr", &jadv], &joiner_env);
    let joined = joiner.wait_for_log(&zone_registered, BUDGET).await;
    let tail = |d: &Daemon| {
        let mut v: Vec<String> = d.drain().lines().rev().take(40).map(String::from).collect();
        v.reverse();
        v.join("\n")
    };
    assert!(
        joined.is_ok(),
        "the ENROLLED joiner must join sharedzone over mTLS — its cert chains to \
         the founder's CA, so the handshake succeeds.\n--- founder tail ---\n{}\n\
         --- joiner tail ---\n{}",
        tail(&founder),
        tail(&joiner),
    );

    drop(joiner);
    drop(founder);
}
