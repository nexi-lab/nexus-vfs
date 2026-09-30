//! Black-box E2E: an agent needs ONE credential and an endpoint. Nothing else.
//!
//! The claim is easy to state and was, until this test, unproven from the outside: a
//! client dialing a nexus node as an agent needs the directory `auth mint
//! --subject-type agent` printed, plus somewhere to dial. No API key beside it, no
//! separately-configured CA / cert / key paths, and no knowledge of the TLS server
//! name — a value that is not a file and so used to be a constant each client
//! declared for itself.
//!
//! Written as a client would have to do it: read the credential, dial, and work. The
//! test deliberately does not touch `agent.pem` or `ca.pem` by name anywhere, because
//! a client that has to know those names does not have one credential — it has a
//! convention it must keep in step with ours.

mod common;

use std::time::Duration;

use common::{cli, free_port, write_tls_bundle, Daemon, Vfs, LOG_FILTER};
use lib::transport_primitives::{AgentCredential, TlsConfig, CREDENTIAL_MANIFEST};
use nexus_raft::transport::{generate_join_token, generate_zone_ca};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const SECRET: &str = "e2e-one-credential-secret";
const BUDGET: Duration = Duration::from_secs(120);

/// Mint an agent, then use only its credential to write and read its own mailbox.
///
/// The write carries an EMPTY auth token on purpose: if a key were required, this
/// fails, and the FR asking for one credential would be asking for something the
/// server does not support. It passes, so the extra settings a client carries today
/// are client-side surface, not a cluster requirement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_credential_and_an_endpoint_are_enough_to_work() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let ident = tmp.path().join("id");

    // TLS on (the cert plane needs it) and auth ON — no `--insecure-no-auth`, so the
    // daemon really is deciding who this caller is.
    let (ca, ca_key) = generate_zone_ca("root").expect("gen CA");
    let (_token, hash) = generate_join_token(&ca).expect("join token");
    write_tls_bundle(&data, 1, &ca, &ca_key, &hash);

    let data_s = data.to_string_lossy();
    let ident_s = ident.to_string_lossy();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mounts = format!("{MOUNT}={ZONE}");
    let env = vec![
        ("NEXUS_DATA_DIR", data_s.as_ref()),
        ("NEXUS_IDENTITY_DIR", ident_s.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_ADVERTISE_ADDR", addr.as_str()),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];

    // Form the zone, then stop so the offline mint can take the data-dir lock.
    {
        let mut f = Daemon::spawn(&["--bind-addr", &addr], &env);
        f.wait_for_log("Static topology applied", BUDGET)
            .await
            .expect("founder forms the zone and persists the mount");
    }

    let (ok, printed, err) = cli(
        &env,
        &[
            "auth",
            "mint",
            "--subject-type",
            "agent",
            "--subject-id",
            "solo-ai",
            "--name",
            "e2e",
        ],
    );
    assert!(ok, "agent mint failed: {err}");

    // What the mint printed is the whole credential — this is the only path the rest
    // of the test knows.
    let credential_path = std::path::PathBuf::from(printed.trim());
    let cred = AgentCredential::load(&credential_path).expect("the printed path is a credential");
    assert_eq!(cred.agent, "solo-ai", "the credential knows who it is");
    assert_eq!(
        cred.server_name,
        TlsConfig::CLUSTER_SERVER_NAME,
        "the credential carries the TLS name to verify, so no client declares its own"
    );
    assert!(
        credential_path.join(CREDENTIAL_MANIFEST).exists(),
        "the manifest lives in the bundle the mint printed"
    );

    let mut founder = Daemon::spawn(&["--bind-addr", &addr], &env);
    founder
        .wait_for_log(&format!("Zone '{ZONE}' registered"), BUDGET)
        .await
        .expect("founder resumes the zone");

    // Dial with the credential alone, then do real work with an EMPTY token.
    let mut c = Vfs::connect_as_agent(port, &cred, BUDGET).await;
    let mailbox = format!("{MOUNT}/{}/chat-with-me", cred.agent);
    c.mkdir(&format!("{MOUNT}/{}", cred.agent), "")
        .await
        .expect("an authenticated agent may create its own directory");
    c.create_stream(&mailbox, "")
        .await
        .expect("provision the mailbox stream");
    c.stream_write(&mailbox, b"one credential is enough", "")
        .await
        .expect("write to the mailbox with NO token — the cert is the authentication");

    let read = c
        .stream_collect_all(&mailbox, "")
        .await
        .expect("read the mailbox back");
    assert!(
        String::from_utf8_lossy(&read).contains("one credential is enough"),
        "the agent must read back what it wrote; got {:?}",
        String::from_utf8_lossy(&read)
    );

    drop(founder);
}
