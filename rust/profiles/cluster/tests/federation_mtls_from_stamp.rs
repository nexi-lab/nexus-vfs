//! Black-box E2E: auth-ON + mTLS-ON, two-node federation — an A2A `from` is
//! unforgeable ACROSS nodes, both directions, via the server-side STAMP.
//!
//! Every cert-agent authenticates over mTLS (the peer plane) and the kernel
//! stamps `from` to its `agent_id` on each mailbox write; the stamped bytes
//! replicate over raft and the peer node reads a truthful `from`. This is the
//! same-trust-domain complement to `agent_signed_authorship` (where the agent
//! SIGNS and the consumer verifies against the CA); here the ingress node
//! rewrites `from`, so both nodes must be inside one trust domain — which an
//! mTLS federation is.
//!
//! Wired like a live Win↔Mac deployment on loopback: two daemons, each with a
//! required-mTLS bind; `sharedzone` mounted at `/agents`; a per-node cert-agent
//! minted offline against the shared CA. The journey, each step consuming the
//! last:
//!
//! 1. CERTS  one shared CA signs both node certs and both agent certs.
//! 2. BOOT   founder forms `sharedzone`; joiner joins over real mTLS.
//! 3. MINT   each node mints its OWN cert-agent (win-ai on the founder, mac-ai
//!    on the joiner; the boot→stop→mint→restart dance a live node runs).
//! 4. HEALTH founder writes under `/agents`, joiner reads it back — the mTLS
//!    federation replicates, and it is the readiness barrier for the mailbox
//!    steps (both "zone registered" logs fire before the raft is replicating).
//! 5. FWD→   win-ai writes mac-ai's mailbox claiming a forged `from`; the joiner
//!    reads it back stamped to `win-ai`.
//! 6. FWD←   mac-ai writes win-ai's mailbox forged; the founder reads it stamped
//!    to `mac-ai`.

mod common;

use std::time::Duration;

use common::{
    await_replicated, free_port, mint_agent_cert, write_tls_bundle, Daemon, Vfs, LOG_FILTER,
};
use nexus_raft::transport::{generate_join_token, generate_zone_ca};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const SECRET: &str = "e2e-fed-mtls-secret";
const BUDGET: Duration = Duration::from_secs(120);

fn founder_env<'a>(
    data: &'a str,
    id: &'a str,
    adv: &'a str,
    mounts: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts),
        ("RUST_LOG", LOG_FILTER),
        // NOTE: NEXUS_NO_TLS deliberately UNSET — TLS is on.
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
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_PEERS", peers),
        ("RUST_LOG", LOG_FILTER),
    ]
}

/// Poll a mailbox until the stamped envelope replicates in, then assert `from`
/// is `expect_from` and the forged sender never appears. The cert-agent that
/// owns the connection is already authenticated over mTLS, so the read carries
/// an empty token.
///
/// Must POLL the stream entries, not rely on a stat-based `await_replicated`:
/// once the reader has materialized its own mailbox, the path stats present
/// immediately, so only the DT_STREAM entry itself signals the peer's write
/// actually arrived over raft.
async fn assert_stamped(v: &mut Vfs, mailbox: &str, expect_from: &str, forged: &str) {
    let want = format!(r#""from":"{expect_from}""#);
    let deadline = std::time::Instant::now() + BUDGET;
    let mut got = String::new();
    while std::time::Instant::now() < deadline {
        let raw = v
            .stream_collect_all(mailbox, "")
            .await
            .expect("collect mailbox");
        got = String::from_utf8_lossy(&raw).into_owned();
        if got.contains(&want) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        got.contains(&want),
        "`from` must be stamped to {expect_from:?}; got: {got}"
    );
    assert!(
        !got.contains(forged),
        "the forged `from` {forged:?} must not survive anywhere; got: {got}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn from_is_unforgeable_across_an_mtls_federation_both_directions() {
    let zone_registered = format!("Zone '{ZONE}' registered");
    let tmp = tempfile::tempdir().expect("tempdir");

    // ── 1. CERTS: one shared CA, two node certs (loopback SANs), join hash ──
    let (ca, ca_key) = generate_zone_ca("root").expect("gen CA");
    let (_token, hash) = generate_join_token(&ca).expect("gen join token");

    let fdata = tmp.path().join("f-data");
    let fid = tmp.path().join("f-id");
    let jdata = tmp.path().join("j-data");
    let jid = tmp.path().join("j-id");
    std::fs::create_dir_all(&fdata).unwrap();
    std::fs::create_dir_all(&jdata).unwrap();
    write_tls_bundle(&fdata, 1, &ca, &ca_key, &hash);
    write_tls_bundle(&jdata, 2, &ca, &ca_key, &hash);

    let fdata = fdata.to_string_lossy();
    let fid = fid.to_string_lossy();
    let jdata = jdata.to_string_lossy();
    let jid = jid.to_string_lossy();

    let fport = free_port();
    let jport = free_port();
    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");
    let fbind = format!("127.0.0.1:{fport}");
    let jbind = format!("127.0.0.1:{jport}");
    let mounts = format!("{MOUNT}={ZONE}");
    let peers = fadv.clone();
    let zone_rw = format!("{ZONE}:rw");

    // ── 2-3a. FOUNDER: form sharedzone → stop → mint win-ai cert → restart ──
    // A live node's dance: minting is offline (redb lock), and it must NOT run
    // first (a mint-created root makes the next boot resume and skip the
    // federation bootstrap), so: form the zone, stop, mint, restart.
    {
        let mut f = Daemon::spawn(
            &["--bind-addr", &fbind],
            &founder_env(&fdata, &fid, &fadv, &mounts),
        );
        // Gate on "Static topology applied", NOT just "sharedzone registered":
        // the `/agents → sharedzone` DT_MOUNT (what DiscoverZones serves to a
        // joiner) is written to root by bootstrap_static AFTER the zone
        // registers. Dropping at "registered" would resume a founder whose root
        // has no mount entry, and the joiner would discover nothing.
        f.wait_for_log("Static topology applied", BUDGET)
            .await
            .expect("founder forms + persists the sharedzone mount");
        // drop → kill → release the data-dir lock for the offline mint.
    }
    let win_bundle = mint_agent_cert(
        &founder_env(&fdata, &fid, &fadv, &mounts),
        "win-ai",
        &zone_rw,
    );
    let win_cert = std::fs::read(win_bundle.join("agent.pem")).expect("win-ai cert");
    let win_key = std::fs::read(win_bundle.join("agent-key.pem")).expect("win-ai key");
    let mut founder = Daemon::spawn(
        &["--bind-addr", &fbind],
        &founder_env(&fdata, &fid, &fadv, &mounts),
    );
    founder
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("founder resumes sharedzone");

    // ── 2-3b. JOINER: join over mTLS → stop → mint mac-ai cert → restart ────
    {
        let mut j = Daemon::spawn(
            &["--bind-addr", &jbind],
            &joiner_env(&jdata, &jid, &jadv, &peers),
        );
        j.wait_for_log(&zone_registered, BUDGET)
            .await
            .expect("joiner joins sharedzone over mTLS");
    }
    let mac_bundle = mint_agent_cert(&joiner_env(&jdata, &jid, &jadv, &peers), "mac-ai", &zone_rw);
    let mac_cert = std::fs::read(mac_bundle.join("agent.pem")).expect("mac-ai cert");
    let mac_key = std::fs::read(mac_bundle.join("agent-key.pem")).expect("mac-ai key");
    let mut joiner = Daemon::spawn(
        &["--bind-addr", &jbind],
        &joiner_env(&jdata, &jid, &jadv, &peers),
    );
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("joiner rejoins sharedzone");

    // Each agent presents its cert on its node's mTLS bind; the handshake is the
    // readiness gate (both certs chain to the one shared CA).
    let mut wc = Vfs::connect_mtls(fport, &ca, &win_cert, &win_key, BUDGET).await;
    let mut mc = Vfs::connect_mtls(jport, &ca, &mac_cert, &mac_key, BUDGET).await;

    // ── 4. HEALTH: mTLS federation actually replicates founder→joiner ───────
    let health = format!("{MOUNT}/health.txt");
    let wrote = wc.write_file(&health, b"mtls-federation-ok", "").await;
    // DIAGNOSTIC: on any failure here, dump both daemons' recent raft state so we
    // can see WHY (no leader? node-2 Progress stuck in Probe? mount missing on the
    // resumed joiner?) rather than a bare timeout.
    let dump = |founder: &Daemon, joiner: &Daemon| {
        let tail = |s: String| {
            let mut v: Vec<String> = s.lines().rev().take(30).map(String::from).collect();
            v.reverse();
            v.join("\n")
        };
        format!(
            "\n--- FOUNDER tail ---\n{}\n--- JOINER tail ---\n{}",
            tail(founder.drain()),
            tail(joiner.drain())
        )
    };
    if let Err(e) = wrote {
        panic!(
            "founder write of health.txt FAILED (no quorum?): {e}{}",
            dump(&founder, &joiner)
        );
    }
    let deadline = std::time::Instant::now() + BUDGET;
    let mut replicated = false;
    while std::time::Instant::now() < deadline {
        if mc.stat_found(&health, "").await {
            replicated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        replicated,
        "health.txt did NOT replicate to the joiner within budget{}",
        dump(&founder, &joiner)
    );
    assert_eq!(
        mc.read_file(&health, "").await.expect("joiner read"),
        b"mtls-federation-ok",
        "joiner must read the founder's bytes over mTLS"
    );

    // ── 5. FWD→ : win-ai writes mac-ai's mailbox forged; mac-ai reads stamped ─
    // Ownership pattern (mirrors `a2a_wakeup`): a replicated DT_STREAM is
    // readable on a node only once THAT node has opened its own local wal
    // backend — the entries replicate over raft, the local stream handle does
    // not. So mac-ai (the owner) materializes its OWN mailbox before reading,
    // and win-ai (the peer sender) opens the same path before writing.
    let mac_mbox = format!("{MOUNT}/mac-ai/chat-with-me");
    mc.create_stream(&mac_mbox, "")
        .await
        .expect("mac-ai opens its OWN mailbox");
    await_replicated(&mut wc, &mac_mbox, "", BUDGET).await;
    wc.create_stream(&mac_mbox, "")
        .await
        .expect("win-ai opens mac-ai's mailbox to send");
    let forged = r#""from":"impostor-A""#;
    wc.stream_write(
        &mac_mbox,
        br#"{"from":"impostor-A","to":"mac-ai","body":"win->mac"}"#,
        "",
    )
    .await
    .expect("win-ai sends");
    assert_stamped(&mut mc, &mac_mbox, "win-ai", forged).await;

    // ── 6. FWD← : mac-ai writes win-ai's mailbox forged; win-ai reads stamped ─
    let win_mbox = format!("{MOUNT}/win-ai/chat-with-me");
    wc.create_stream(&win_mbox, "")
        .await
        .expect("win-ai opens its OWN mailbox");
    await_replicated(&mut mc, &win_mbox, "", BUDGET).await;
    mc.create_stream(&win_mbox, "")
        .await
        .expect("mac-ai opens win-ai's mailbox to send");
    mc.stream_write(
        &win_mbox,
        br#"{"from":"impostor-B","to":"win-ai","body":"mac->win"}"#,
        "",
    )
    .await
    .expect("mac-ai sends");
    assert_stamped(&mut wc, &win_mbox, "mac-ai", r#""from":"impostor-B""#).await;

    drop(founder);
    drop(joiner);
}
