//! Black-box E2E for the cross-org (cross-CA) plane, two halves:
//!
//! * ADMISSION — `foreign-ca register` makes a foreign CA trusted at the mTLS
//!   handshake, LIVE without a restart, via the daemon → control zone → apply
//!   observer → hot-swapped client-cert verifier chain. The proof is a real
//!   handshake, not a log line: a `CA_B`-signed cert is REJECTED before
//!   register, ACCEPTED after, and dropped again by unregister.
//! * ATTRIBUTION — a foreign agent's mailbox write is stamped with its QUALIFIED
//!   cross-org id `{trust_domain}/agent/{name}`, so a receiver sees which ORG
//!   actually wrote it, not a spoofable claim in the envelope.
//!
//! No second machine + no real customer CA needed (`CA_B` is generated here);
//! the cross-MACHINE run with a real DGX CA_B is the same flow over Tailscale.

mod common;

use std::time::{Duration, Instant};

use common::{cli, free_port_pair, Daemon, Vfs, LOG_FILTER};
use lib::transport_primitives::TlsConfig;

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(120);
/// The foreign org (its CA is `CA_B`) and one of its agents. The qualified
/// cross-org identity the plane must attribute is `{ORG}/agent/{AGENT}`.
const ORG: &str = "hospital-a";
const AGENT: &str = "cardio";

/// A booted TLS-on founder (control zone up, `/agents` formed) plus a freshly
/// generated foreign CA (`CA_B`, org [`ORG`]) and a `CA_B`-signed agent leaf
/// ([`AGENT`]). Shared by both cross-org tests: each registers `CA_B` at its own
/// point (admission checks the pre-register REJECT first, attribution registers
/// straight away) and drives its own assertion.
struct XorgFixture {
    founder: Daemon,
    /// `CA_B`-signed agent leaf — the CLIENT identity a foreign agent presents.
    foreign_cert: Vec<u8>,
    foreign_key: Vec<u8>,
    /// The cluster CA (`CA_A`) — verifies the SERVER cert on the client side.
    cluster_ca: Vec<u8>,
    fingerprint: String,
    ca_b_path: String,
    fport: u16,
    fdata: String,
    fid: String,
    fadv: String,
    /// Declared LAST so it drops LAST: the founder (child process holding files
    /// under the data dir) must die before the dir is deleted — else the delete
    /// fails on Windows.
    _tmp: tempfile::TempDir,
}

impl XorgFixture {
    /// The env a `foreign-ca` CLI call needs to reach this founder's daemon.
    fn cli_env(&self) -> Vec<(&str, &str)> {
        vec![
            ("NEXUS_DATA_DIR", &self.fdata),
            ("NEXUS_IDENTITY_DIR", &self.fid),
            ("NEXUS_ADVERTISE_ADDR", &self.fadv),
        ]
    }

    /// Register `CA_B` (trust domain [`ORG`]) through the live daemon and assert
    /// the register echoes the fingerprint back.
    fn register_ca_b(&self) {
        let (ok, out, err) = cli(
            &self.cli_env(),
            &[
                "foreign-ca",
                "register",
                "--domain",
                ORG,
                "--ca-pem",
                &self.ca_b_path,
                "--fingerprint",
                &self.fingerprint,
            ],
        );
        assert!(
            ok && out.trim() == self.fingerprint,
            "register must succeed + echo the fingerprint.\nstdout: {out}\nstderr: {err}"
        );
    }
}

/// Generate `CA_B` + a `CA_B`-signed [`AGENT`] leaf, then boot a TLS-on founder
/// that founds the control zone (wiring the foreign-ca apply observer) and forms
/// `/agents`. Does NOT register `CA_B` — the caller does, at its own point.
async fn boot_founder_with_ca_b() -> XorgFixture {
    let (ca_b_pem, ca_b_key_pem) = nexus_raft::transport::generate_zone_ca(ORG).expect("gen CA_B");
    let (foreign_cert, foreign_key) =
        nexus_raft::transport::generate_agent_cert(AGENT, &ca_b_pem, &ca_b_key_pem)
            .expect("gen CA_B-signed agent cert");
    let fingerprint = lib::transport_primitives::ForeignCaAnchor::from_pem(ORG, &ca_b_pem)
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

    let cluster_ca = std::fs::read(std::path::Path::new(&fdata).join("tls").join("ca.pem"))
        .expect("read founder cluster CA");

    XorgFixture {
        founder,
        foreign_cert,
        foreign_key,
        cluster_ca,
        fingerprint,
        ca_b_path,
        fport,
        fdata,
        fid,
        fadv,
        _tmp: tmp,
    }
}

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
    let fx = boot_founder_with_ca_b().await;

    // The client identity we're proving gets trusted: the CA_B-signed leaf as
    // the client cert/key, and the cluster CA to verify the (cluster-signed)
    // SERVER cert — only the client cert is foreign.
    let ca_b_client_tls = TlsConfig {
        cert_pem: fx.foreign_cert.clone(),
        key_pem: fx.foreign_key.clone(),
        ca_pem: fx.cluster_ca.clone(),
    };

    // ── BEFORE register: the CA_B-signed cert must be REJECTED at the handshake
    //    (CA_B is not a trusted root). The server is fully up (topology applied),
    //    so a genuine cluster cert would connect in <1s — 10s of failures is a
    //    true rejection, not slowness.
    let pre = handshake_accepted(fx.fport, &ca_b_client_tls, Duration::from_secs(10)).await;
    assert!(
        !pre,
        "a CA_B-signed cert must NOT be accepted at the handshake BEFORE its CA is registered"
    );

    // ── REGISTER CA_B via the live daemon (routes to the control-zone leader).
    fx.register_ca_b();

    // list shows it.
    let (lok, lout, _) = cli(&fx.cli_env(), &["foreign-ca", "list"]);
    assert!(
        lok && lout.contains(ORG) && lout.contains(&fx.fingerprint),
        "list must show the registered anchor, got:\n{lout}"
    );

    // ── AFTER register: the SAME CA_B-signed cert is now accepted at the
    //    handshake — the ONLY change is the apply observer hot-swapping the
    //    client-cert verifier to trust CA_B.
    let post = handshake_accepted(fx.fport, &ca_b_client_tls, BUDGET).await;
    assert!(
        post,
        "after registering CA_B, a CA_B-signed cert MUST be accepted at the mTLS handshake \
         (the apply observer hot-swapped the client-cert verifier)"
    );

    // ── UNREGISTER removes it from the listing (coarse per-org revocation).
    let (uok, uout, uerr) = cli(
        &fx.cli_env(),
        &["foreign-ca", "unregister", "--fingerprint", &fx.fingerprint],
    );
    assert!(
        uok && uout.trim() == "unregistered",
        "unregister must succeed.\nstdout: {uout}\nstderr: {uerr}"
    );
    let (l2ok, l2out, _) = cli(&fx.cli_env(), &["foreign-ca", "list"]);
    assert!(
        l2ok && !l2out.contains(ORG),
        "after unregister the anchor must be gone from the listing, got:\n{l2out}"
    );

    drop(fx.founder);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn foreign_agent_mailbox_write_is_stamped_with_qualified_id() {
    let fx = boot_founder_with_ca_b().await;
    fx.register_ca_b();

    // The foreign agent connects: the cluster CA verifies the SERVER cert; the
    // CA_B leaf is the CLIENT identity (admitted only because ORG is now a
    // registered anchor).
    let mut wc = Vfs::connect_mtls(
        fx.fport,
        &fx.cluster_ca,
        &fx.foreign_cert,
        &fx.foreign_key,
        BUDGET,
    )
    .await;

    // It writes a PLAIN-JSON envelope that LIES about `from`. The mailbox stamp
    // must overwrite it with the qualified cross-org id — never the spoof.
    let mbox_dir = format!("{MOUNT}/xorg");
    wc.mkdir(&mbox_dir, "")
        .await
        .expect("foreign agent makes a dir");
    let mailbox = format!("{mbox_dir}/chat-with-me");
    wc.create_stream(&mailbox, "")
        .await
        .expect("foreign agent opens a mailbox");
    wc.stream_write(
        &mailbox,
        br#"{"from":"i-am-whoever-i-say","to":"broker","body":"hi from a foreign agent"}"#,
        "",
    )
    .await
    .expect("foreign agent writes its mailbox over the cross-org mTLS plane");

    let got = wc
        .stream_collect_all(&mailbox, "")
        .await
        .expect("collect the stamped envelope");
    let got = String::from_utf8_lossy(&got);
    let qualified = format!("{ORG}/agent/{AGENT}");
    assert!(
        got.contains(&format!(r#""from":"{qualified}""#)),
        "the foreign agent's mailbox `from` MUST be stamped to its QUALIFIED \
         cross-org id `{qualified}` (classify + agent-context); got: {got}"
    );
    assert!(
        !got.contains("i-am-whoever-i-say"),
        "the spoofed `from` must not survive the stamp; got: {got}"
    );

    drop(fx.founder);
}
