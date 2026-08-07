//! Black-box E2E: `foreign-ca register` makes a cross-org CA trusted at the mTLS
//! handshake — LIVE, without a restart — via the daemon → control zone → apply
//! observer → hot-swapped client-cert verifier chain.
//!
//! The proof is a real handshake, not a log line: a client cert signed by a
//! FOREIGN CA (`CA_B`, which the cluster CA does NOT vouch for) is REJECTED at
//! the TLS handshake before register, and ACCEPTED after — the only thing that
//! changed is the registered anchor hot-swapping the verifier. Then unregister
//! removes it from the listing. No second machine + no real customer CA needed
//! (CA_B is generated here); the cross-MACHINE run with a real DGX CA_B is the
//! same flow over Tailscale.

mod common;

use std::time::{Duration, Instant};

use common::{cli, free_port_pair, Daemon, LOG_FILTER};
use lib::transport_primitives::TlsConfig;

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(120);

/// Does the founder ACCEPT `client_tls` (a foreign-CA client identity) at the
/// mTLS handshake? Polls the *ungated* `DiscoverZones` RPC until it returns `Ok`
/// or `budget` expires, and reports whether it ever did.
///
/// `DiscoverZones` is the ideal probe: it takes no auth and reads only public
/// topology, so the ONLY thing that can make it fail for a well-formed request
/// is the TLS layer refusing the client cert. We can't judge trust by
/// `Endpoint::connect()` alone — under TLS 1.3 the client's connect completes
/// before the server has validated the client cert, so a doomed cert still
/// "connects"; the rejection only surfaces when a real request tries to read.
/// Issuing an actual RPC forces that read: `Ok` ⟺ the cert's issuing CA is in
/// the live client-cert verifier's roots (i.e. registered + hot-swapped).
async fn handshake_accepted(port: u16, client_tls: &TlsConfig, budget: Duration) -> bool {
    let endpoint = format!("https://127.0.0.1:{port}");
    let deadline = Instant::now() + budget;
    loop {
        if nexus_raft::transport::call_discover_zones_rpc(&endpoint, Some(client_tls.clone()), 5)
            .await
            .is_ok()
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_foreign_ca_makes_it_trusted_at_the_handshake_live() {
    // A foreign org's CA (CA_B) + a client cert IT signs — the cluster CA does
    // NOT vouch for this cert, so the founder trusts it ONLY once CA_B is
    // registered + hot-swapped into the verifier.
    let (ca_b_pem, ca_b_key_pem) =
        nexus_raft::transport::generate_zone_ca("hospital-a").expect("gen CA_B");
    let (foreign_cert, foreign_key) =
        nexus_raft::transport::generate_agent_cert("cardio", &ca_b_pem, &ca_b_key_pem)
            .expect("gen CA_B-signed client cert");
    let fingerprint = lib::transport_primitives::ForeignCaAnchor::from_pem("hospital-a", &ca_b_pem)
        .expect("anchor from CA_B pem")
        .fingerprint_hex();

    let tmp = tempfile::tempdir().expect("tempdir");
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();
    let ca_b_path = tmp.path().join("ca_b.pem");
    std::fs::write(&ca_b_path, &ca_b_pem).expect("write CA_B pem");
    let ca_b_path = ca_b_path.to_string_lossy().into_owned();

    let fport = free_port_pair();
    let fadv = format!("127.0.0.1:{fport}");
    let mounts = format!("{MOUNT}={ZONE}");

    // Founder: auth-on (TLS), control zone founded → the foreign-ca observer is
    // wired to the client-cert verifier.
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
        .wait_for_log("control zone up", BUDGET)
        .await
        .expect("founder founds the control zone (foreign-ca observer wired)");
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder forms sharedzone over mTLS");

    // The client identity we're proving gets trusted: the CA_B-signed leaf as the
    // client cert/key, and the founder's own cluster CA to verify the SERVER cert
    // (the server is cluster-signed; only the client cert is foreign).
    let cluster_ca = std::fs::read(std::path::Path::new(&fdata).join("tls").join("ca.pem"))
        .expect("read founder cluster CA");
    let ca_b_client_tls = TlsConfig {
        cert_pem: foreign_cert,
        key_pem: foreign_key,
        ca_pem: cluster_ca,
    };

    // ── BEFORE register: the CA_B-signed cert must be REJECTED at the handshake
    //    (CA_B is not a trusted root). The server is fully up (topology applied),
    //    so a genuine cluster cert would connect in <1s — 10s of failures is a
    //    true rejection, not slowness.
    let pre = handshake_accepted(fport, &ca_b_client_tls, Duration::from_secs(10)).await;
    assert!(
        !pre,
        "a CA_B-signed cert must NOT be accepted at the handshake BEFORE its CA is registered"
    );

    // ── REGISTER CA_B via the live daemon (routes to the control-zone leader).
    let cli_env = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
    ];
    let (rok, rout, rerr) = cli(
        &cli_env,
        &[
            "foreign-ca",
            "register",
            "--domain",
            "hospital-a",
            "--ca-pem",
            &ca_b_path,
            "--fingerprint",
            &fingerprint,
        ],
    );
    assert!(
        rok && rout.trim() == fingerprint,
        "register must succeed + echo the fingerprint.\nstdout: {rout}\nstderr: {rerr}"
    );

    // list shows it.
    let (lok, lout, _) = cli(&cli_env, &["foreign-ca", "list"]);
    assert!(
        lok && lout.contains("hospital-a") && lout.contains(&fingerprint),
        "list must show the registered anchor, got:\n{lout}"
    );

    // ── AFTER register: the SAME CA_B-signed cert is now accepted at the
    //    handshake — the ONLY change is the apply observer hot-swapping the
    //    client-cert verifier to trust CA_B.
    let post = handshake_accepted(fport, &ca_b_client_tls, BUDGET).await;
    assert!(
        post,
        "after registering CA_B, a CA_B-signed cert MUST be accepted at the mTLS handshake \
         (the apply observer hot-swapped the client-cert verifier)"
    );

    // ── UNREGISTER removes it from the listing (coarse per-org revocation).
    let (uok, uout, uerr) = cli(
        &cli_env,
        &["foreign-ca", "unregister", "--fingerprint", &fingerprint],
    );
    assert!(
        uok && uout.trim() == "unregistered",
        "unregister must succeed.\nstdout: {uout}\nstderr: {uerr}"
    );
    let (l2ok, l2out, _) = cli(&cli_env, &["foreign-ca", "list"]);
    assert!(
        l2ok && !l2out.contains("hospital-a"),
        "after unregister the anchor must be gone from the listing, got:\n{l2out}"
    );

    drop(founder);
}
