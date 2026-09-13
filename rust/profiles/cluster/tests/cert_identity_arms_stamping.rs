//! Black-box E2E: on a daemon whose ONLY credential plane is mTLS — a
//! reachable bind, TLS on, **no `NEXUS_API_KEY_SECRET`** — the A2A `from` is
//! still stamped to the caller's certificate identity.
//!
//! ## The hole this pins shut
//!
//! mTLS decides *who may connect*; a provider that reads the certificate
//! decides *who they are*. Before `AuthPosture::CertIdentity`, a daemon in
//! exactly this shape did the first and skipped the second: it resolved every
//! CA-verified caller as nobody-in-particular, which left
//! `ServiceBootCtx::auth_armed` false, so the A2A stamp hook ran fail-open and
//! an envelope's authored `from` passed through untouched. The deployment that
//! demanded a certificate from everybody was the one where `from` was
//! forgeable.
//!
//! So this test writes a **forged** `from` over a genuine agent cert and
//! requires the read-back to name the certificate's identity instead. It fails
//! on the old behaviour (the forged value survives) and passes on the new one.
//!
//! Distinct from its siblings: `federation_mtls_from_stamp` proves the stamp
//! across a two-node federation, and `agent_signed_authorship` proves the
//! CA-signed authorship guarantee — both with an `sk-` secret set, i.e. the
//! posture that was never broken. The variable HERE is the posture itself.
//!
//! ## Which deployments actually land here
//!
//! Narrower than "any mTLS node", and worth stating so nobody reads this test
//! as covering the common path: a **founder** self-provisions a random
//! `tls/api-key-secret` on first boot, and **enrollment** writes that secret to
//! a joiner — both end up on the `sk-` posture. What is left is a node whose
//! certificates arrived **out of band**: the CA cert plus this node's cert
//! copied in by an operator (a customer PKI, a hand-built compose/E2E fixture)
//! with no CA key and no cluster secret. That is the shape below: mint first
//! while the CA key is present, then take it away — which is exactly what a
//! node that never enrolled looks like on disk.

mod common;

use std::time::Duration;

use common::{cli, free_port, write_tls_bundle, Daemon, Vfs, LOG_FILTER};
use nexus_raft::transport::{generate_join_token, generate_zone_ca};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(120);
const AGENT: &str = "cert-only-ai";
const FORGED: &str = "impostor";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_whose_only_credential_plane_is_mtls_still_stamps_from() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let ident = tmp.path().join("id");

    // ── 1. CA + node cert bundle; TLS ON, and deliberately NO secret ────────
    let (ca, ca_key) = generate_zone_ca("root").expect("gen CA");
    let (_token, hash) = generate_join_token(&ca).expect("join token");
    write_tls_bundle(&data, 1, &ca, &ca_key, &hash);

    let data_s = data.to_string_lossy();
    let ident_s = ident.to_string_lossy();
    let port = free_port();
    // REACHABLE bind: loopback would be the trusted-local plane (`Open`), which
    // is a different posture and not what this test is about.
    let bind = format!("0.0.0.0:{port}");
    let adv = format!("127.0.0.1:{port}");
    let daemon_env = vec![
        ("NEXUS_DATA_DIR", data_s.as_ref()),
        ("NEXUS_IDENTITY_DIR", ident_s.as_ref()),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];

    // ── 2. Form the mailbox zone while still a founder ──────────────────────
    // A2A mailboxes live in a RAFT-backed zone (`/agents` mounted at one), the
    // same shape every other stamping test uses; a host-fs path is not a
    // replicated DT_STREAM and reads nothing back. Forming it needs
    // `--cluster-init`, which also makes this a founder — so do it first, then
    // take the founder's artifacts away below.
    let mounts = format!("{MOUNT}={ZONE}");
    {
        let mut e = daemon_env.clone();
        e.push(("NEXUS_CLUSTER_INIT", ZONE));
        e.push(("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()));
        let mut f = Daemon::spawn(&["--bind-addr", &bind], &e);
        f.wait_for_log("Static topology applied", BUDGET)
            .await
            .expect("founder forms the mailbox zone + persists the mount");
    }

    // ── 3. MINT the cert-agent offline (daemon down; the CA signs it) ───────
    // The mint CLI is a separate process: giving IT a secret says nothing
    // about the daemon's posture, and an agent cert resolves from its SAN with
    // no store lookup, so nothing about this identity depends on one.
    let mint_env = {
        let mut e = daemon_env.clone();
        e.push(("NEXUS_API_KEY_SECRET", "mint-side-only"));
        e
    };
    let (ok, bundle_dir, err) = cli(
        &mint_env,
        &[
            "auth",
            "mint",
            "--subject-type",
            "agent",
            "--subject-id",
            AGENT,
            "--name",
            "e2e-cert-identity",
        ],
    );
    assert!(ok, "agent mint failed: {err}");
    let bundle = std::path::PathBuf::from(bundle_dir.trim());
    let agent_cert = std::fs::read(bundle.join("agent.pem")).expect("read agent.pem");
    let agent_key = std::fs::read(bundle.join("agent-key.pem")).expect("read agent-key.pem");

    // ── 4. Become the out-of-band shape: CA cert + node cert, nothing else ──
    // Dropping the CA key is what makes this node a non-founder, so it does NOT
    // self-provision a cluster secret on boot; and it never enrolled, so nobody
    // wrote one for it either. Both halves are required to reach the posture
    // under test — with either one present the daemon takes the `sk-` plane and
    // proves nothing about certificates.
    std::fs::remove_file(data.join("tls").join("ca-key.pem")).expect("drop the CA key");
    std::fs::remove_file(data.join("tls").join("api-key-secret"))
        .expect("drop the secret the founder boot self-provisioned");
    assert!(
        !data.join("tls").join("api-key-secret").exists(),
        "this node must hold no cluster secret, or the posture under test is not the one that boots"
    );

    // ── 5. Boot with mTLS as the only credential plane ──────────────────────
    // Wait on the SOCKET, not on a log line: what this test is about is the
    // behaviour, so a build that regressed it must fail on the forged `from`
    // surviving — not on a missing log message. (The log line is asserted at
    // the end, as the operator-visible half.)
    let mut founder = Daemon::spawn(&["--bind-addr", &bind], &daemon_env);
    founder
        .wait_tcp(port, BUDGET)
        .await
        .expect("the daemon serves");

    // ── 6. The agent writes a FORGED `from` over its genuine cert ───────────
    let mut c = Vfs::connect_mtls(port, &ca, &agent_cert, &agent_key, BUDGET).await;
    c.mkdir(&format!("{MOUNT}/{AGENT}"), "")
        .await
        .expect("the agent makes its own dir");
    let mailbox = format!("{MOUNT}/{AGENT}/chat-with-me");
    c.create_stream(&mailbox, "")
        .await
        .expect("the agent opens its mailbox");

    let envelope = format!(r#"{{"from":"{FORGED}","to":"{AGENT}","body":"cert-only stamping"}}"#);
    c.stream_write(&mailbox, envelope.as_bytes(), "")
        .await
        .expect("write the forged envelope");

    // ── 7. It comes back naming the CERTIFICATE, not the claim ─────────────
    // POLL rather than read once: the write returns when the entry is accepted,
    // while what this asserts on is the entry as APPLIED. Reading immediately
    // raced that and made the test fail once in two runs — a flake that would
    // have been read as "stamping is unreliable" rather than "the reader looked
    // too early". Same reason `federation_mtls_from_stamp` polls.
    let want = format!(r#""from":"{AGENT}""#);
    let deadline = std::time::Instant::now() + BUDGET;
    let mut got = String::new();
    while std::time::Instant::now() < deadline {
        let raw = c
            .stream_collect_all(&mailbox, "")
            .await
            .expect("collect the mailbox");
        got = String::from_utf8_lossy(&raw).into_owned();
        if got.contains(&want) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        got.contains(&want),
        "mTLS alone must arm identity: `from` should be stamped to {AGENT:?}; got: {got:?}"
    );
    assert!(
        founder.log_contains("certificate identity plane armed"),
        "the boot log must name the certificate plane, so an operator can tell          `callers are identified` from `callers merely got in`"
    );
    assert!(
        !got.contains(FORGED),
        "the forged `from` {FORGED:?} must not survive anywhere; got: {got}"
    );
}
