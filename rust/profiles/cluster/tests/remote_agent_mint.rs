//! Black-box E2E: `auth mint --subject-type agent NAME` just-works on a node
//! that does NOT hold the cluster CA private key — the joiner half of task #40.
//!
//! The intuitive command must succeed on ANY node, not only the founder. A
//! joiner holds `ca.pem` (to verify peers) but never `ca-key.pem` (only the
//! founder signs), so a local sign is impossible. Instead the CLI forwards the
//! mint to the founder over mTLS (`MintAgent` on the co-hosted `ZoneApiService`):
//! the founder signs the identity cert with the cluster CA and records the agent
//! for cluster-wide uniqueness, and the joiner writes the returned bundle exactly
//! as a local mint would. The whole chain runs on the REAL binary + real wire:
//!
//! 1. FEDERATE — a founder (TLS-on, CA holder, accepts enrollments) forms
//!    `sharedzone`; a certless joiner auto-enrolls with a join token and joins
//!    over mTLS (the `node_enrollment` recipe — its prerequisite here).
//! 2. MINT — on the joiner, with NO `--peers` (the founder is read from the
//!    persisted `identity.json` address book), `auth mint --subject-type agent`
//!    succeeds while BOTH daemons stay up: the remote path opens no local store,
//!    so the joiner's redb lock is irrelevant.
//! 3. AUTHENTICATE — the joiner-minted agent cert authenticates against the
//!    founder's mTLS VFS plane, proving it is a real cluster-CA identity.
//! 4. UNIQUE — re-minting the same name (no `--allow-existing`) is refused,
//!    proving the founder recorded it cluster-wide through the remote path.

mod common;

use std::time::Duration;

use common::{cli, free_port, free_port_pair, Daemon, Vfs, LOG_FILTER};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_mint_agent_just_works_on_a_joiner_via_the_founder() {
    let zone_registered = format!("Zone '{ZONE}' registered");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();
    let jdata = tmp.path().join("j-data").to_string_lossy().into_owned();
    let jid = tmp.path().join("j-id").to_string_lossy().into_owned();

    let fport = free_port_pair();
    let jport = loop {
        let p = free_port();
        if p != fport && p != fport + 1 {
            break p;
        }
    };
    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");
    let mounts = format!("{MOUNT}={ZONE}");

    // ── 1a. Founder mints a join token (bootstraps its cluster CA) ──
    let token = {
        let env = vec![
            ("NEXUS_DATA_DIR", fdata.as_str()),
            ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ];
        let (ok, out, err) = cli(&env, &["enroll-token"]);
        assert!(ok, "enroll-token failed: {err}");
        out.trim().to_string()
    };

    // ── 1b. Founder boots TLS-ON + accepts enrollments + forms sharedzone ──
    let founder_env = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
        ("NEXUS_ACCEPT_ENROLLMENTS", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut founder = Daemon::spawn(&["--bind-addr", &fadv], &founder_env);
    founder
        .wait_for_log("CA holder armed MintAgent RPC", BUDGET)
        .await
        .expect("the CA holder must arm the remote agent-cert minter at boot");
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder forms + persists sharedzone over mTLS");

    // ── 1c. Certless joiner auto-enrolls (--peers + --token) then joins ──
    let joiner_env = vec![
        ("NEXUS_DATA_DIR", jdata.as_str()),
        ("NEXUS_IDENTITY_DIR", jid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", jadv.as_str()),
        ("NEXUS_PEERS", fadv.as_str()),
        ("NEXUS_JOIN_TOKEN", token.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut joiner = Daemon::spawn(&["--bind-addr", &jadv], &joiner_env);
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("the enrolled joiner joins sharedzone over mTLS");

    // Precondition for the whole point of this test: the joiner has the CA cert
    // but NOT the CA private key, so it cannot sign an agent cert locally.
    let jtls = std::path::Path::new(&jdata).join("tls");
    assert!(
        jtls.join("ca.pem").exists() && jtls.join("node.pem").exists(),
        "joiner must be enrolled (ca.pem + node.pem present)"
    );
    assert!(
        !jtls.join("ca-key.pem").exists(),
        "an enrolled joiner must NOT hold the cluster CA private key"
    );

    // ── 2. MINT on the joiner with NO --peers: the founder is discovered from
    //       the persisted identity.json, and both daemons stay up (the remote
    //       path opens no local store, so the joiner's redb lock is irrelevant).
    let agent = "win-w1";
    let mint_env = vec![
        ("NEXUS_DATA_DIR", jdata.as_str()),
        ("NEXUS_IDENTITY_DIR", jid.as_str()),
    ];
    let (ok, out, err) = cli(
        &mint_env,
        &[
            "auth",
            "mint",
            "--subject-type",
            "agent",
            "--subject-id",
            agent,
            "--name",
            "e2e",
        ],
    );
    assert!(
        ok,
        "agent mint on the joiner must just-work by forwarding to the founder.\n\
         stdout: {out}\nstderr: {err}"
    );
    assert!(
        err.contains("via founder"),
        "the joiner mint must go the REMOTE path (forwarded to the founder), \
         got stderr: {err}"
    );
    let bundle_dir = std::path::PathBuf::from(out.trim());
    assert_eq!(
        bundle_dir,
        std::path::Path::new(&jdata).join("agents").join(agent),
        "the bundle lands under the joiner's own data dir, byte-identical layout"
    );
    for f in ["agent.pem", "agent-key.pem", "ca.pem"] {
        assert!(
            bundle_dir.join(f).exists(),
            "remote mint must write {f} into the joiner bundle dir"
        );
    }

    // ── 3. AUTHENTICATE — the joiner-minted cert is a real cluster identity:
    //       it authenticates against the FOUNDER's mTLS VFS plane.
    let ca = std::fs::read(bundle_dir.join("ca.pem")).unwrap();
    let cert = std::fs::read(bundle_dir.join("agent.pem")).unwrap();
    let key = std::fs::read(bundle_dir.join("agent-key.pem")).unwrap();
    let mut vfs = Vfs::connect_mtls(fport, &ca, &cert, &key, BUDGET).await;
    vfs.ping("")
        .await
        .expect("the joiner-minted agent cert must authenticate against the founder");

    // ── 4. UNIQUE — re-minting the same name (no --allow-existing) is refused,
    //       proving the founder recorded the agent cluster-wide via the RPC.
    let (dup_ok, _dup_out, dup_err) = cli(
        &mint_env,
        &[
            "auth",
            "mint",
            "--subject-type",
            "agent",
            "--subject-id",
            agent,
            "--name",
            "e2e",
        ],
    );
    assert!(
        !dup_ok,
        "a second mint of the same agent name must be refused (uniqueness)"
    );
    assert!(
        dup_err.contains("already has an active credential"),
        "the refusal must cite the recorded active credential, got: {dup_err}"
    );

    drop(joiner);
    drop(founder);
}
