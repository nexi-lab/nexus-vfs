//! Black-box E2E: auth-ON + mTLS-ON, two-node federation — an agent cert is
//! revoked on the founder and, after a CRL refresh, rejected on the OTHER node.
//!
//! Revocation is the one thing a valid CA chain does not settle: a stolen agent
//! key still chains to the CA, so `peer_identity` still resolves it. The cluster
//! CRL closes that. It rides the CA plane (not raft): the founder holds the
//! revoked-serial file and CA-signs a CRL on demand; every other node fetches
//! that CRL from the founder's enroll listener, verifies it against its own CA,
//! and drops the named serial. This proves the whole loop on a real 2-node
//! cluster:
//!
//! 1. CERTS   one shared CA; the founder accepts enrollments (serves the CRL).
//! 2. BOOT    founder forms `sharedzone`; the joiner joins over real mTLS. The
//!    joiner's CA *key* is removed so it behaves like a real enrolled node —
//!    only `ca.pem`, no signing key — and therefore FETCHES the CRL rather than
//!    reading a local file.
//! 3. MINT    the founder mints two cert-agents: `win-ai` (to be revoked) and
//!    `mac-ai` (the control that must keep working).
//! 4. BEFORE  both agents connect to the JOINER over mTLS and write — the joiner
//!    resolves both from the cert alone.
//! 5. REVOKE  `auth revoke --agent win-ai` on the founder (file-based; runs while
//!    the daemon is up), then the joiner's CRL refresh picks up the serial.
//! 6. AFTER   `win-ai` is rejected on the joiner (its chain is still valid — the
//!    CRL is what rejects it), while `mac-ai` still writes: only the revoked
//!    serial is dropped, not the whole cert plane.

mod common;

use std::time::Duration;

use common::{free_port, mint_agent_cert, write_tls_bundle, Daemon, Vfs, LOG_FILTER};
use nexus_raft::transport::{generate_join_token, generate_zone_ca};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const SECRET: &str = "e2e-revoke-secret";
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
        // The founder holds the CA, so it serves the CRL from its enroll
        // listener — every other node refreshes its revocation view there.
        ("NEXUS_ACCEPT_ENROLLMENTS", "true"),
        ("RUST_LOG", LOG_FILTER),
        // NEXUS_NO_TLS deliberately UNSET — TLS is on.
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

/// Poll `write_file` on the joiner until it flips to the wanted state (Ok or
/// Err), or the budget runs out — the joiner drops the serial only after a CRL
/// refresh cycle, so revocation is eventually-consistent, not instant.
async fn poll_write(v: &mut Vfs, path: &str, want_ok: bool) -> bool {
    let deadline = std::time::Instant::now() + BUDGET;
    while std::time::Instant::now() < deadline {
        if v.write_file(path, b"probe", "").await.is_ok() == want_ok {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_agent_cert_is_rejected_on_a_peer_node_after_crl_refresh() {
    let zone_registered = format!("Zone '{ZONE}' registered");
    let tmp = tempfile::tempdir().expect("tempdir");

    // ── 1. CERTS: one shared CA, two node certs, join hash ──────────────────
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
    // A real enrolled joiner holds only `ca.pem`, never the CA signing key. The
    // test bundle writes both for convenience; drop the joiner's key so it is
    // classified as a non-authority and FETCHES the CRL from the founder,
    // exercising the cross-node distribution path.
    std::fs::remove_file(jdata.join("tls").join("ca-key.pem")).unwrap();

    let fdata = fdata.to_string_lossy();
    let fid = fid.to_string_lossy();
    let jdata = jdata.to_string_lossy();
    let jid = jid.to_string_lossy();

    // The founder's enroll listener binds data-port + 1, so keep the two data
    // ports non-adjacent or that +1 would land on the joiner's bind.
    let fport = free_port();
    let mut jport = free_port();
    while jport == fport || jport == fport + 1 || jport + 1 == fport {
        jport = free_port();
    }
    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");
    let fbind = format!("127.0.0.1:{fport}");
    let jbind = format!("127.0.0.1:{jport}");
    let mounts = format!("{MOUNT}={ZONE}");
    let peers = fadv.clone();

    // ── 2-3. FOUNDER forms sharedzone → stop → mint win-ai + mac-ai → restart ─
    {
        let mut f = Daemon::spawn(
            &["--bind-addr", &fbind],
            &founder_env(&fdata, &fid, &fadv, &mounts),
        );
        f.wait_for_log("Static topology applied", BUDGET)
            .await
            .expect("founder forms + persists the sharedzone mount");
    }
    let win_bundle = mint_agent_cert(&founder_env(&fdata, &fid, &fadv, &mounts), "win-ai");
    let mac_bundle = mint_agent_cert(&founder_env(&fdata, &fid, &fadv, &mounts), "mac-ai");
    let win_cert = std::fs::read(win_bundle.join("agent.pem")).expect("win-ai cert");
    let win_key = std::fs::read(win_bundle.join("agent-key.pem")).expect("win-ai key");
    let mac_cert = std::fs::read(mac_bundle.join("agent.pem")).expect("mac-ai cert");
    let mac_key = std::fs::read(mac_bundle.join("agent-key.pem")).expect("mac-ai key");

    let mut founder = Daemon::spawn(
        &["--bind-addr", &fbind],
        &founder_env(&fdata, &fid, &fadv, &mounts),
    );
    founder
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("founder resumes sharedzone");

    // ── JOINER: join over real mTLS ─────────────────────────────────────────
    let mut joiner = Daemon::spawn(
        &["--bind-addr", &jbind],
        &joiner_env(&jdata, &jid, &jadv, &peers),
    );
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("joiner joins sharedzone over mTLS");

    // ── HEALTH: the mTLS federation actually replicates founder→joiner, so a
    // write to sharedzone on the joiner has quorum ──────────────────────────
    let mut wc_f = Vfs::connect_mtls(fport, &ca, &win_cert, &win_key, BUDGET).await;
    let health = format!("{MOUNT}/health.txt");
    wc_f.write_file(&health, b"ok", "")
        .await
        .expect("founder-side agent writes health");
    let deadline = std::time::Instant::now() + BUDGET;
    let mut replicated = false;
    // Read the health file back through a joiner-side agent connection.
    let mut probe = Vfs::connect_mtls(jport, &ca, &mac_cert, &mac_key, BUDGET).await;
    while std::time::Instant::now() < deadline {
        if probe.stat_found(&health, "").await {
            replicated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        replicated,
        "health.txt did not replicate to the joiner within budget"
    );

    // ── 4. BEFORE: both agents write on the JOINER — resolved from the cert ──
    let mut wc = Vfs::connect_mtls(jport, &ca, &win_cert, &win_key, BUDGET).await;
    let mut mc = Vfs::connect_mtls(jport, &ca, &mac_cert, &mac_key, BUDGET).await;
    let win_probe = format!("{MOUNT}/win-ai/probe.txt");
    let mac_probe = format!("{MOUNT}/mac-ai/probe.txt");
    wc.write_file(&win_probe, b"before", "")
        .await
        .expect("win-ai writes on the joiner before revocation");
    mc.write_file(&mac_probe, b"before", "")
        .await
        .expect("mac-ai writes on the joiner before revocation");

    // ── 5. REVOKE win-ai on the founder (file-based; daemon stays up) ───────
    let (ok, _out, err) = common::cli(
        &founder_env(&fdata, &fid, &fadv, &mounts),
        &["auth", "revoke", "--agent", "win-ai"],
    );
    assert!(ok, "auth revoke --agent win-ai failed: {err}");

    // ── 6. AFTER: the joiner refreshes the CRL and rejects win-ai, while
    // mac-ai (a different serial) keeps working ─────────────────────────────
    assert!(
        poll_write(&mut wc, &win_probe, false).await,
        "win-ai must be rejected on the joiner after the CRL propagates (its chain is \
         still valid — the CRL is what rejects it)"
    );
    assert!(
        mc.write_file(&mac_probe, b"after", "").await.is_ok(),
        "mac-ai is a different serial and must keep working — only win-ai was revoked"
    );

    drop(founder);
    drop(joiner);
}
