//! Black-box E2E: the A2A `from` is UNFORGEABLE ACROSS TRUST DOMAINS via a
//! CA-signed agent cert — the G1 signed-authorship guarantee, end to end
//! through the real `nexusd-cluster` binary.
//!
//! Distinct from its two siblings, which test the server-side STAMP (the
//! ingress node rewrites `from`, a same-trust-domain guarantee):
//! `agent_bind_from_stamp` on the loopback token plane, and
//! `federation_mtls_from_stamp` across an mTLS federation. HERE the agent
//! itself SIGNS the message with its identity cert's key, and the consumer
//! VERIFIES the signature against the cluster CA. The proof rides the CA, not
//! the ingesting node's posture — so a `from` backed by a cert that does not
//! chain to OUR CA is rejected on read no matter who wrote it. This is the
//! cross-org / cross-trust-domain property the stamp alone cannot give.
//!
//! The journey, each step consuming the last:
//!
//! 1. CA+TLS — bootstrap a cluster CA + node cert; the founder boots TLS-on.
//! 2. MINT — offline `auth mint --subject-type agent --cert win-ai` → a
//!    CA-signed bundle (agent.pem / agent-key.pem / ca.pem).
//! 3. CONNECT — win-ai dials the mTLS plane presenting that cert; its SAN
//!    `nexus://agent/win-ai` resolves to `agent_id=win-ai`, grants ride in the
//!    cert (no per-node store lookup).
//! 4. SEAL — win-ai seals a message (signs the content with its cert key) and
//!    writes the envelope to its mailbox stream.
//! 5. OPEN — read it back and OPEN it against the CA — `from` is a VERIFIED
//!    win-ai and the content survived the raft stream round-trip.
//! 6. FORGE — an envelope sealed by a FOREIGN CA's cert (a different trust
//!    domain) claiming `from=win-ai`, written through the same daemon, is
//!    REJECTED on open — its cert does not chain to our CA.

mod common;

use std::time::Duration;

use common::{cli, free_port, write_tls_bundle, Daemon, Vfs, LOG_FILTER};
use lib::transport_primitives::authorship::{open, seal};
use nexus_raft::transport::{generate_agent_cert, generate_join_token, generate_zone_ca};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const SECRET: &str = "e2e-signed-authorship-secret";
const BUDGET: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_is_unforgeable_across_trust_domains_via_signed_cert() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let ident = tmp.path().join("id");

    // ── 1. CA + node cert bundle; TLS ON (the cert plane needs it) ──────────
    let (ca, ca_key) = generate_zone_ca("root").expect("gen CA");
    let (_token, hash) = generate_join_token(&ca).expect("join token");
    write_tls_bundle(&data, 1, &ca, &ca_key, &hash);

    let data_s = data.to_string_lossy();
    let ident_s = ident.to_string_lossy();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");
    let bind = format!("127.0.0.1:{port}");
    let mounts = format!("{MOUNT}={ZONE}");
    let zone_rw = format!("{ZONE}:rw");
    // TLS deliberately ON — NEXUS_NO_TLS is unset.
    let env = vec![
        ("NEXUS_DATA_DIR", data_s.as_ref()),
        ("NEXUS_IDENTITY_DIR", ident_s.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let zone_registered = format!("Zone '{ZONE}' registered");

    // Form the zone (and persist the `/agents → sharedzone` mount to root),
    // then stop to release the data-dir lock for the offline mint.
    {
        let mut f = Daemon::spawn(&["--bind-addr", &bind], &env);
        f.wait_for_log("Static topology applied", BUDGET)
            .await
            .expect("founder forms sharedzone + persists the mount");
    }

    // ── 2. MINT the cert-agent offline — reads the CA from <data>/tls ───────
    let (ok, bundle_dir, err) = cli(
        &env,
        &[
            "auth",
            "mint",
            "--subject-type",
            "agent",
            "--cert",
            "--subject-id",
            "win-ai",
            "--zone",
            &zone_rw,
            "--name",
            "e2e",
        ],
    );
    assert!(ok, "mint --cert failed: {err}");
    let bundle = std::path::PathBuf::from(bundle_dir.trim());
    let agent_cert = std::fs::read(bundle.join("agent.pem")).expect("read agent.pem");
    let agent_key = std::fs::read(bundle.join("agent-key.pem")).expect("read agent-key.pem");
    let bundle_ca = std::fs::read(bundle.join("ca.pem")).expect("read ca.pem");
    // The bundle's ca.pem is the very CA we bootstrapped — the agent trusts the
    // server through it, and we open the envelope against it below.
    assert_eq!(bundle_ca, ca, "the minted bundle ships the cluster CA");

    // ── 3. RESTART TLS-on; win-ai connects on the mTLS plane with its cert ──
    let mut founder = Daemon::spawn(&["--bind-addr", &bind], &env);
    founder
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("founder resumes sharedzone");
    let mut c = Vfs::connect_mtls(port, &ca, &agent_cert, &agent_key, BUDGET).await;

    // ── 4-5. SEAL → write → read → OPEN: `from` is a VERIFIED win-ai ────────
    c.mkdir(&format!("{MOUNT}/win-ai"), "")
        .await
        .expect("win-ai makes its own dir");
    let mailbox = format!("{MOUNT}/win-ai/chat-with-me");
    c.create_stream(&mailbox, "")
        .await
        .expect("win-ai opens its mailbox");

    let body = b"hello from a signed agent";
    let sealed = seal("win-ai", body, &agent_key, &agent_cert).expect("seal");
    c.stream_write(&mailbox, &sealed, "")
        .await
        .expect("write the sealed envelope");
    let got = c.stream_collect_all(&mailbox, "").await.expect("collect");
    let (from, content) = open(&got, &ca).expect("the envelope opens against the cluster CA");
    assert_eq!(from, "win-ai", "open recovers the VERIFIED signer");
    assert_eq!(
        content, body,
        "the signed content survived the raft stream round-trip byte-for-byte"
    );

    // ── 6. FORGE: a foreign-CA cert claiming win-ai is REJECTED on open ─────
    // A different trust domain: a CA we do not anchor, signing a cert whose SAN
    // still says `nexus://agent/win-ai`. Written through the same daemon (win-ai
    // is authenticated, so the stamp leaves the matching `from` alone), it is
    // caught the moment a consumer opens it against OUR CA.
    let (foreign_ca, foreign_ca_key) = generate_zone_ca("evil").expect("foreign CA");
    let grants = contracts::AgentGrants {
        is_admin: false,
        zone_perms: vec![(ZONE.to_string(), "rw".to_string())],
    };
    let (foreign_cert, foreign_key) =
        generate_agent_cert("win-ai", &grants, &foreign_ca, &foreign_ca_key)
            .expect("foreign agent cert");
    let forged = seal(
        "win-ai",
        b"i am not really win-ai",
        &foreign_key,
        &foreign_cert,
    )
    .expect("seal forged");

    c.mkdir(&format!("{MOUNT}/forge"), "")
        .await
        .expect("mk forge dir");
    let forge_mbox = format!("{MOUNT}/forge/chat-with-me");
    c.create_stream(&forge_mbox, "")
        .await
        .expect("open forge mailbox");
    c.stream_write(&forge_mbox, &forged, "")
        .await
        .expect("write the forged envelope");
    let forged_back = c
        .stream_collect_all(&forge_mbox, "")
        .await
        .expect("collect forged");
    assert!(
        open(&forged_back, &ca).is_err(),
        "a cert that does not chain to OUR CA must be rejected on open — \
         the cross-trust-domain guarantee the stamp alone cannot provide"
    );

    drop(founder);
}
