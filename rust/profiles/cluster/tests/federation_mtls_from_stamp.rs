//! Black-box E2E: auth-ON + mTLS-ON, two-node federation — an A2A `from` is
//! unforgeable ACROSS nodes, both directions.
//!
//! This is the first e2e that turns **TLS on** (every other cluster e2e runs
//! `--no-tls`), and it has to: with auth on, the federation peer fan-out sends
//! an empty token, and the ONLY thing that authenticates it is the mTLS node
//! cert (the peer plane). So "auth-on federation" and "mTLS" are inseparable —
//! this exercises both at once, the gap the §B drive-out called out.
//!
//! Wired like a live Win↔Mac Option-X deployment on loopback: two daemons,
//! each with a required-mTLS federation bind (peer plane) AND a loopback
//! `--agent-bind-addr` (token plane); `sharedzone` mounted at `/agents`; a
//! per-node `sk-` Agent key minted offline. The journey, each step consuming
//! the last:
//!
//! 1. CERTS  one shared CA signs both node certs (loopback SANs).
//! 2. BOOT   founder forms `sharedzone`; joiner joins over real mTLS.
//! 3. MINT   each node mints its OWN agent key (root is per-node SOLO, so the
//!    credential store is node-local — win-ai on the founder, mac-ai on the
//!    joiner; the boot→stop→mint→restart dance a live node runs).
//! 4. HEALTH founder writes under `/agents`, joiner reads it back (mTLS
//!    federation actually replicates).
//! 5. FWD→   win-ai (founder agent bind) writes mac-ai's mailbox claiming a
//!    forged `from`; the joiner reads it back stamped to `win-ai`.
//! 6. FWD←   mac-ai (joiner agent bind) writes win-ai's mailbox forged; the
//!    founder reads it back stamped to `mac-ai`.
//! 7. DENY   an empty-token write on an agent bind is refused.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{await_replicated, free_port, mint_agent_key, Daemon, Vfs, LOG_FILTER};
use nexus_raft::transport::{generate_join_token, generate_node_cert, generate_zone_ca};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const SECRET: &str = "e2e-fed-mtls-secret";
const BUDGET: Duration = Duration::from_secs(120);

/// Write a TLS bundle (a shared CA + a fresh node cert with loopback SANs) plus
/// the persisted `node_id` into `data_dir`, so `bootstrap_tls` finds the bundle
/// present and reuses it (TLS on, no self-generated CA). All nodes share one CA
/// so their client certs verify against each other — that IS cluster membership.
fn write_bundle(data_dir: &Path, node_id: u64, ca: &[u8], ca_key: &[u8], token_hash: &str) {
    let tls = data_dir.join("tls");
    std::fs::create_dir_all(&tls).expect("mkdir tls");
    let (cert, key) =
        generate_node_cert(node_id, "root", ca, ca_key, &[], Some("localhost")).expect("node cert");
    std::fs::write(tls.join("ca.pem"), ca).unwrap();
    std::fs::write(tls.join("ca-key.pem"), ca_key).unwrap();
    std::fs::write(tls.join("node.pem"), cert).unwrap();
    std::fs::write(tls.join("node-key.pem"), key).unwrap();
    std::fs::write(tls.join("join-token-hash"), token_hash).unwrap();
    // read_or_mint_node_id reads an 8-byte big-endian u64 (matches the cert's
    // node/{id} identity SAN so the running node and its cert agree).
    std::fs::write(data_dir.join(".node_id"), node_id.to_be_bytes()).unwrap();
}

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
        ("NEXUS_FEDERATION_ZONES", ZONE),
        ("NEXUS_FEDERATION_MOUNTS", mounts),
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

/// Poll a mailbox on `port` as `token` until the stamped envelope replicates
/// in, then assert `from` is `expect_from` and the forged sender never appears.
///
/// Must POLL the stream entries, not rely on a stat-based `await_replicated`:
/// once the reader has materialized its own mailbox, the path stats present
/// immediately, so only the DT_STREAM entry itself signals the peer's write
/// actually arrived over raft.
async fn assert_stamped(v: &mut Vfs, mailbox: &str, token: &str, expect_from: &str, forged: &str) {
    let want = format!(r#""from":"{expect_from}""#);
    let deadline = std::time::Instant::now() + BUDGET;
    let mut got = String::new();
    while std::time::Instant::now() < deadline {
        let raw = v
            .stream_collect_all(mailbox, token)
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

    // ── 1. CERTS: one CA, two node certs (loopback SANs), shared join hash ──
    let (ca, ca_key) = generate_zone_ca("root").expect("gen CA");
    let (_token, hash) = generate_join_token(&ca).expect("gen join token");

    let fdata = tmp.path().join("f-data");
    let fid = tmp.path().join("f-id");
    let jdata = tmp.path().join("j-data");
    let jid = tmp.path().join("j-id");
    std::fs::create_dir_all(&fdata).unwrap();
    std::fs::create_dir_all(&jdata).unwrap();
    write_bundle(&fdata, 1, &ca, &ca_key, &hash);
    write_bundle(&jdata, 2, &ca, &ca_key, &hash);

    let fdata = fdata.to_string_lossy();
    let fid = fid.to_string_lossy();
    let jdata = jdata.to_string_lossy();
    let jid = jid.to_string_lossy();

    let fport = free_port();
    let fagent = free_port();
    let jport = free_port();
    let jagent = free_port();
    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");
    let fbind = format!("127.0.0.1:{fport}");
    let jbind = format!("127.0.0.1:{jport}");
    let fagent_bind = format!("127.0.0.1:{fagent}");
    let jagent_bind = format!("127.0.0.1:{jagent}");
    let mounts = format!("{MOUNT}={ZONE}");
    let peers = fadv.clone();

    // ── 2-3a. FOUNDER: form sharedzone → stop → mint win-ai → restart ───────
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
    let win_key = mint_agent_key(
        &founder_env(&fdata, &fid, &fadv, &mounts),
        "win-ai",
        &format!("{ZONE}:rw"),
    );
    let mut founder = Daemon::spawn(
        &["--bind-addr", &fbind, "--agent-bind-addr", &fagent_bind],
        &founder_env(&fdata, &fid, &fadv, &mounts),
    );
    founder
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("founder resumes sharedzone");

    // ── 2-3b. JOINER: join over mTLS → stop → mint mac-ai → restart ─────────
    {
        let mut j = Daemon::spawn(
            &["--bind-addr", &jbind],
            &joiner_env(&jdata, &jid, &jadv, &peers),
        );
        j.wait_for_log(&zone_registered, BUDGET)
            .await
            .expect("joiner joins sharedzone over mTLS");
    }
    let mac_key = mint_agent_key(
        &joiner_env(&jdata, &jid, &jadv, &peers),
        "mac-ai",
        &format!("{ZONE}:rw"),
    );
    let mut joiner = Daemon::spawn(
        &["--bind-addr", &jbind, "--agent-bind-addr", &jagent_bind],
        &joiner_env(&jdata, &jid, &jadv, &peers),
    );
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("joiner rejoins sharedzone");

    // Agent binds authenticate their local key (the token-plane readiness gate).
    let mut wc = Vfs::connect_authenticated(fagent, &win_key, BUDGET).await;
    let mut mc = Vfs::connect_authenticated(jagent, &mac_key, BUDGET).await;

    // ── 4. HEALTH: mTLS federation actually replicates founder→joiner ───────
    let health = format!("{MOUNT}/health.txt");
    let wrote = wc
        .write_file(&health, b"mtls-federation-ok", &win_key)
        .await;
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
        if mc.stat_found(&health, &mac_key).await {
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
        mc.read_file(&health, &mac_key).await.expect("joiner read"),
        b"mtls-federation-ok",
        "joiner must read the founder's bytes over mTLS"
    );

    // ── 5. FWD→ : win-ai writes mac-ai's mailbox forged; mac-ai reads stamped ─
    // Ownership pattern (mirrors `a2a_wakeup`): a replicated DT_STREAM is
    // readable on a node only once THAT node has opened its own local wal
    // backend — the entries replicate over raft, the local stream handle does
    // not. So mac-ai (the owner) materializes its OWN mailbox before reading,
    // and win-ai (the peer sender) opens the same path before writing. This is
    // exactly how a real agent owns `/agents/{self}/chat-with-me`.
    let mac_mbox = format!("{MOUNT}/mac-ai/chat-with-me");
    mc.create_stream(&mac_mbox, &mac_key)
        .await
        .expect("mac-ai opens its OWN mailbox");
    await_replicated(&mut wc, &mac_mbox, &win_key, BUDGET).await;
    wc.create_stream(&mac_mbox, &win_key)
        .await
        .expect("win-ai opens mac-ai's mailbox to send");
    let forged = r#""from":"impostor-A""#;
    wc.stream_write(
        &mac_mbox,
        br#"{"from":"impostor-A","to":"mac-ai","body":"win->mac"}"#,
        &win_key,
    )
    .await
    .expect("win-ai sends");
    assert_stamped(&mut mc, &mac_mbox, &mac_key, "win-ai", forged).await;

    // ── 6. FWD← : mac-ai writes win-ai's mailbox forged; win-ai reads stamped ─
    let win_mbox = format!("{MOUNT}/win-ai/chat-with-me");
    wc.create_stream(&win_mbox, &win_key)
        .await
        .expect("win-ai opens its OWN mailbox");
    await_replicated(&mut mc, &win_mbox, &mac_key, BUDGET).await;
    mc.create_stream(&win_mbox, &mac_key)
        .await
        .expect("mac-ai opens win-ai's mailbox to send");
    mc.stream_write(
        &win_mbox,
        br#"{"from":"impostor-B","to":"win-ai","body":"mac->win"}"#,
        &mac_key,
    )
    .await
    .expect("mac-ai sends");
    assert_stamped(
        &mut wc,
        &win_mbox,
        &win_key,
        "mac-ai",
        r#""from":"impostor-B""#,
    )
    .await;

    // ── 7. DENY: an empty-token write on an agent bind is refused ───────────
    assert!(
        wc.stream_write(&mac_mbox, br#"{"from":"x"}"#, "")
            .await
            .is_err(),
        "an empty-token mailbox write must be refused when auth is on"
    );

    drop(founder);
    drop(joiner);
}
