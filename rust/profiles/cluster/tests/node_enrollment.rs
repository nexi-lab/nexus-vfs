//! Black-box E2E: a brand-new node with NO cluster cert joins the mTLS
//! federation in ONE command, auto-enrolling with a join token at boot.
//!
//! This is the production onboarding path (#22) — the k3s `agent --server
//! --token` model on nexus's dedicated `NodeEnrollmentService` bootstrap plane.
//! It proves the whole chain on the REAL binary, each step consuming the last:
//!
//! 1. TOKEN — founder mints a CA-fingerprint-pinned join token (`enroll-token`),
//!    which also bootstraps the cluster CA. (In production the founder also
//!    prints this at boot; the CLI is the test's clean way to capture the value.)
//! 2. LISTEN — founder boots TLS-ON with `--accept-enrollments`; the plaintext
//!    enrollment listener rides the data-plane port + 1 (derived, not typed) and
//!    the founder forms `sharedzone`.
//! 3. FEDERATE — a CERTLESS joiner boots with `--peers` + `--token` and NOTHING
//!    else: at boot it auto-enrolls against the founder's derived enrollment
//!    port (obtaining + writing ca/node/node-key), then JOINS `sharedzone` over
//!    mTLS — a handshake it could only complete with a cert chaining to the
//!    founder's CA, i.e. the one enrollment just issued.
//!
//! mTLS data-flow itself is covered by `federation_mtls_from_stamp`; the delta
//! here is that the joiner's cert came from BOOT-TIME auto-enrollment, in one
//! command, not a separate `enroll` step or a hand-placed bundle.

mod common;

use std::time::Duration;

use common::{cli, free_port, free_port_pair, Daemon, LOG_FILTER};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certless_node_auto_enrolls_at_boot_then_federates_over_mtls() {
    let zone_registered = format!("Zone '{ZONE}' registered");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();
    let jdata = tmp.path().join("j-data").to_string_lossy().into_owned();
    let jid = tmp.path().join("j-id").to_string_lossy().into_owned();

    // Founder data port + its derived enroll port (data + 1) must BOTH be free.
    let fport = free_port_pair();
    // The joiner's data port must avoid BOTH the founder's data port and its
    // derived enroll port (fport + 1) — else the joiner's gRPC bind collides
    // with the founder's enrollment listener.
    let jport = loop {
        let p = free_port();
        if p != fport && p != fport + 1 {
            break p;
        }
    };
    let fadv = format!("127.0.0.1:{fport}");
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

    // ── 2. LISTEN — founder boots TLS-ON + accepts enrollments + sharedzone ─
    // No enroll ADDRESS: the listener derives data-plane port + 1.
    let founder_env = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
        ("NEXUS_ACCEPT_ENROLLMENTS", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("RUST_LOG", LOG_FILTER),
        // NEXUS_NO_TLS deliberately UNSET — TLS is ON (the founder owns the CA).
        // NEXUS_API_KEY_SECRET deliberately UNSET — an auth-on founder
        // SELF-GENERATES the durable cluster secret at bootstrap (like the CA),
        // so the minimal-info contract is "founder states neither secret nor peers".
    ];
    let mut founder = Daemon::spawn(&["--bind-addr", &fadv], &founder_env);
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder forms + persists sharedzone over mTLS");

    // The founder set NO NEXUS_API_KEY_SECRET, yet an auth-on founder must
    // SELF-PROVISION a durable cluster secret at bootstrap (the same way it
    // self-provisions the CA) — else it comes up with no api-key auth and
    // enrollment distributes nothing. Capture the generated value to prove the
    // joiner inherits THIS exact secret below.
    let founder_secret = {
        let p = std::path::Path::new(&fdata)
            .join("tls")
            .join("api-key-secret");
        let s = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("founder must self-generate tls/api-key-secret: {e}"))
            .trim()
            .to_string();
        assert_eq!(
            s.len(),
            32,
            "self-generated secret is 32 hex chars (128 bits)"
        );
        assert!(
            s.chars().all(|c| c.is_ascii_hexdigit()),
            "secret must be hex"
        );
        s
    };

    // ── 3. FEDERATE — joiner boots with ONLY --peers + --token: it auto-enrolls
    //       at boot (derives the founder's enroll port from --peers), then joins.
    // The joiner sets NO NEXUS_API_KEY_SECRET: an auth-on node inherits the
    // cluster secret from ENROLLMENT (served over the same token-gated channel
    // as the CA), so the one-command joiner needs nothing but --peers + --token.
    let joiner_env = vec![
        ("NEXUS_DATA_DIR", jdata.as_str()),
        ("NEXUS_IDENTITY_DIR", jid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", jadv.as_str()),
        ("NEXUS_PEERS", fadv.as_str()),
        ("NEXUS_JOIN_TOKEN", token.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut joiner = Daemon::spawn(&["--bind-addr", &jadv], &joiner_env);
    let joined = joiner.wait_for_log(&zone_registered, BUDGET).await;

    // The boot-time auto-enroll must have written an issued identity — but NOT
    // the CA key (an enrolled node is not a CA).
    let jtls = std::path::Path::new(&jdata).join("tls");
    for f in ["ca.pem", "node.pem", "node-key.pem"] {
        assert!(
            jtls.join(f).exists(),
            "auto-enroll must write {f} into the joiner tls dir"
        );
    }
    assert!(
        !jtls.join("ca-key.pem").exists(),
        "an enrolled node must NOT receive the cluster CA private key"
    );
    // The delta this feature adds: the joiner set NO NEXUS_API_KEY_SECRET, yet
    // auto-enroll must have written the cluster's api-key secret into its tls
    // dir (served by the founder over the same token-gated channel as the CA),
    // so it can verify a founder-minted `sk-` key with zero local auth config.
    // Without the fix this file never appears (the founder didn't serve it) and
    // the joiner would silently come up auth-off.
    let secret_path = jtls.join("api-key-secret");
    assert!(
        secret_path.exists(),
        "auto-enroll must write the cluster api-key secret to tls/api-key-secret \
         (the joiner set no NEXUS_API_KEY_SECRET)"
    );
    assert_eq!(
        std::fs::read_to_string(&secret_path)
            .expect("read joiner api-key-secret")
            .trim(),
        founder_secret,
        "the enrolled secret must equal the founder's SELF-GENERATED one, so a \
         cluster-minted key resolves identically on the joiner (hash_key is over \
         the shared secret)"
    );
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
