//! Black-box E2E: the A2A `from` is UNFORGEABLE ACROSS TRUST DOMAINS via a
//! CA-signed agent cert — the G1 signed-authorship guarantee, end to end
//! through the real `nexusd-cluster` binary.
//!
//! Distinct from its sibling `federation_mtls_from_stamp`, which tests the
//! server-side STAMP (the ingress node rewrites `from` — a same-trust-domain
//! guarantee) across an mTLS federation. HERE the agent itself SIGNS the
//! message with its identity cert's key, and the consumer
//! VERIFIES the signature against the cluster CA. The proof rides the CA, not
//! the ingesting node's posture — so a `from` backed by a cert that does not
//! chain to OUR CA is rejected on read no matter who wrote it. This is the
//! cross-org / cross-trust-domain property the stamp alone cannot give.
//!
//! The journey, each step consuming the last:
//!
//! 1. CA+TLS — bootstrap a cluster CA + node cert; the founder boots TLS-on.
//! 2. MINT — offline `auth mint --subject-type agent win-ai` → a CA-signed
//!    bundle (agent.pem / agent-key.pem / ca.pem); agents are cert-only.
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

use std::time::{Duration, Instant};

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
            "--subject-id",
            "win-ai",
            "--name",
            "e2e",
        ],
    );
    assert!(ok, "agent mint failed: {err}");
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
    let (foreign_cert, foreign_key) =
        generate_agent_cert("win-ai", &foreign_ca, &foreign_ca_key).expect("foreign agent cert");
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

    // ── 7. STAMP: an UNSIGNED mailbox write still gets a truthful `from` ─────
    // The same-domain floor: win-ai authenticated over mTLS, so the kernel
    // stamps `from` to the authenticated agent_id regardless of what the
    // (unsigned) envelope claimed. A client that does not seal is still caught.
    c.mkdir(&format!("{MOUNT}/stamp"), "")
        .await
        .expect("mk stamp dir");
    let stamp_mbox = format!("{MOUNT}/stamp/chat-with-me");
    c.create_stream(&stamp_mbox, "")
        .await
        .expect("open stamp mailbox");
    c.stream_write(&stamp_mbox, br#"{"from":"impostor","body":"unsigned"}"#, "")
        .await
        .expect("write an unsigned envelope");
    let stamped = c
        .stream_collect_all(&stamp_mbox, "")
        .await
        .expect("collect stamped");
    let stamped = String::from_utf8_lossy(&stamped);
    assert!(
        stamped.contains(r#""from":"win-ai""#),
        "an unsigned mailbox write must be stamped to the authenticated agent; got: {stamped}"
    );
    assert!(
        !stamped.contains("impostor"),
        "the forged `from` must not survive the stamp; got: {stamped}"
    );

    drop(founder);
}

/// Two-node federation: a signed envelope written by a cert-agent on the FOUNDER
/// replicates over raft and OPENS on the JOINER against the shared CA — the
/// cross-NODE half of the guarantee. The joiner never trusts the founder's
/// posture; it re-verifies the signature itself. A foreign-CA forge, ingested
/// and replicated the same way, is rejected on the joiner too — proving raft is
/// not the trust boundary, the consumer's `open` is.
///
/// This is the acceptance-gate shape (mint on founder → sign on node A →
/// replicate → verify on node B → forge rejected) as a CI-native multi-process
/// test; the Docker/live multi-machine run is the same journey at higher
/// fidelity.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_from_replicates_and_verifies_on_a_peer_node() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (ca, ca_key) = generate_zone_ca("root").expect("gen CA");
    let (_token, hash) = generate_join_token(&ca).expect("join token");

    let fdata = tmp.path().join("f-data");
    let jdata = tmp.path().join("j-data");
    std::fs::create_dir_all(&fdata).unwrap();
    std::fs::create_dir_all(&jdata).unwrap();
    write_tls_bundle(&fdata, 1, &ca, &ca_key, &hash);
    write_tls_bundle(&jdata, 2, &ca, &ca_key, &hash);
    let fid = tmp.path().join("f-id");
    let jid = tmp.path().join("j-id");

    let fdata_s = fdata.to_string_lossy();
    let jdata_s = jdata.to_string_lossy();
    let fid_s = fid.to_string_lossy();
    let jid_s = jid.to_string_lossy();
    let fport = free_port();
    let jport = free_port();
    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");
    let fbind = format!("127.0.0.1:{fport}");
    let jbind = format!("127.0.0.1:{jport}");
    let mounts = format!("{MOUNT}={ZONE}");
    let zone_registered = format!("Zone '{ZONE}' registered");

    let founder_env = vec![
        ("NEXUS_DATA_DIR", fdata_s.as_ref()),
        ("NEXUS_IDENTITY_DIR", fid_s.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let joiner_env = vec![
        ("NEXUS_DATA_DIR", jdata_s.as_ref()),
        ("NEXUS_IDENTITY_DIR", jid_s.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_ADVERTISE_ADDR", jadv.as_str()),
        ("NEXUS_PEERS", fadv.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];

    // Founder forms the zone (persists the mount) → stop → mint win-ai (cert)
    // offline → restart, then the joiner joins over real mTLS.
    {
        let mut f = Daemon::spawn(&["--bind-addr", &fbind], &founder_env);
        f.wait_for_log("Static topology applied", BUDGET)
            .await
            .expect("founder forms sharedzone + persists the mount");
    }
    let (ok, bundle_dir, err) = cli(
        &founder_env,
        &[
            "auth",
            "mint",
            "--subject-type",
            "agent",
            "--subject-id",
            "win-ai",
            "--name",
            "e2e",
        ],
    );
    assert!(ok, "agent mint failed: {err}");
    let bundle = std::path::PathBuf::from(bundle_dir.trim());
    let agent_cert = std::fs::read(bundle.join("agent.pem")).expect("read agent.pem");
    let agent_key = std::fs::read(bundle.join("agent-key.pem")).expect("read agent-key.pem");

    let mut founder = Daemon::spawn(&["--bind-addr", &fbind], &founder_env);
    founder
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("founder resumes sharedzone");
    let mut joiner = Daemon::spawn(&["--bind-addr", &jbind], &joiner_env);
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("joiner joins sharedzone over mTLS");

    // The SAME cert authenticates win-ai on either node (both anchor the shared
    // CA): it writes on the founder, reads on the joiner.
    let mut wc = Vfs::connect_mtls(fport, &ca, &agent_cert, &agent_key, BUDGET).await;
    let mut rc = Vfs::connect_mtls(jport, &ca, &agent_cert, &agent_key, BUDGET).await;

    let dump = |founder: &Daemon, joiner: &Daemon| {
        let tail = |s: String| {
            let mut v: Vec<String> = s.lines().rev().take(40).map(String::from).collect();
            v.reverse();
            v.join("\n")
        };
        format!(
            "\n--- FOUNDER tail ---\n{}\n--- JOINER tail ---\n{}",
            tail(founder.drain()),
            tail(joiner.drain())
        )
    };

    // Federation-readiness barrier (mirrors `federation_mtls_from_stamp`): a
    // plain file written by the cert-agent on the founder must replicate to the
    // joiner before the mailbox round-trip runs. Both "zone registered" logs can
    // fire before the 2-node sharedzone raft is actually replicating, so gating
    // on a real founder→joiner round-trip is the only reliable readiness signal
    // — and it doubles as proof the mTLS-agent write plane commits to raft.
    let health = format!("{MOUNT}/health.txt");
    wc.write_file(&health, b"fed-ok", "")
        .await
        .expect("founder writes health.txt");
    let deadline = Instant::now() + BUDGET;
    let mut replicated_file = false;
    while Instant::now() < deadline {
        if rc.stat_found(&health, "").await {
            replicated_file = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        replicated_file,
        "health.txt written by the cert-agent on the founder never replicated to \
         the joiner — mTLS federation is not wired for this plane{}",
        dump(&founder, &joiner)
    );

    // ── SIGN on the founder → replicate → OPEN on the joiner ────────────────
    let body = b"cross-node signed hello";
    let sealed = seal("win-ai", body, &agent_key, &agent_cert).expect("seal");
    let replicated = round_trip(
        &mut wc,
        &mut rc,
        &format!("{MOUNT}/win-ai/chat-with-me"),
        &sealed,
        BUDGET,
    )
    .await;
    let (from, content) =
        open(&replicated, &ca).expect("the joiner opens the envelope against the CA");
    assert_eq!(
        from, "win-ai",
        "the peer node verifies the signer against the CA"
    );
    assert_eq!(
        content, body,
        "the signed content replicated over raft byte-for-byte"
    );

    // ── FORGE: a foreign-CA envelope, ingested + replicated, rejected on the peer ─
    let (foreign_ca, foreign_ca_key) = generate_zone_ca("evil").expect("foreign CA");
    let (foreign_cert, foreign_key) =
        generate_agent_cert("win-ai", &foreign_ca, &foreign_ca_key).expect("foreign agent cert");
    let forged = seal(
        "win-ai",
        b"forged across nodes",
        &foreign_key,
        &foreign_cert,
    )
    .expect("seal");
    let forged_replicated = round_trip(
        &mut wc,
        &mut rc,
        &format!("{MOUNT}/forge/chat-with-me"),
        &forged,
        BUDGET,
    )
    .await;
    assert!(
        open(&forged_replicated, &ca).is_err(),
        "raft replicated the forged bytes (it is not the trust boundary), but the \
         peer's open must reject a cert that does not chain to OUR CA"
    );

    drop(founder);
    drop(joiner);
}

/// Write on the founder → read on the peer. The `writer` (on the founder, which
/// holds the sharedzone leadership) creates the stream and appends `payload`, so
/// the entry commits to raft directly rather than forwarding a follower
/// proposal. The `reader` then opens its OWN local stream handle on the peer — a
/// replicated DT_STREAM only surfaces on a node once that node has opened its
/// own wal backend — and we poll until the replicated entry lands. Returns the
/// raw bytes of the single entry.
async fn round_trip(
    writer: &mut Vfs,
    reader: &mut Vfs,
    mailbox: &str,
    payload: &[u8],
    budget: Duration,
) -> Vec<u8> {
    writer
        .create_stream(mailbox, "")
        .await
        .expect("writer opens the mailbox on the founder");
    writer
        .stream_write(mailbox, payload, "")
        .await
        .expect("writer appends the envelope");
    reader
        .create_stream(mailbox, "")
        .await
        .expect("reader materializes its own handle on the peer");

    let deadline = Instant::now() + budget;
    loop {
        let got = reader
            .stream_collect_all(mailbox, "")
            .await
            .expect("collect on the peer");
        if !got.is_empty() {
            return got;
        }
        assert!(
            Instant::now() < deadline,
            "the entry never replicated to the peer within budget"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}
