//! Real daemon, mTLS, credential replacement and durable reopening for a confined owner.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{free_port, Daemon, Vfs, LOG_FILTER};
use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient, CallRequest, ReadRequest,
};
use lib::transport_primitives::{user_runtime_server_name, AgentCredential, LoadedCredential};
use nexus_raft::transport::{
    generate_session_agent_cert, generate_user_runtime_cert, generate_zone_ca,
};

const BUDGET: Duration = Duration::from_secs(30);

async fn dial_client(
    port: u16,
    credential: &LoadedCredential,
) -> Result<NexusVfsServiceClient<tonic::transport::Channel>, tonic::transport::Error> {
    use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&credential.ca_pem))
        .identity(Identity::from_pem(
            &credential.cert_pem,
            &credential.key_pem,
        ))
        .domain_name(&credential.server_name);
    let channel = Endpoint::from_shared(format!("https://127.0.0.1:{port}"))
        .unwrap()
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(3))
        .connect()
        .await?;
    Ok(NexusVfsServiceClient::new(channel))
}

fn assert_owner_refusal(is_error: bool, payload: &[u8]) {
    assert!(is_error, "cross-owner operation was accepted");
    let error: serde_json::Value = serde_json::from_slice(payload).unwrap();
    assert_eq!(error["code"], -32003, "{error}");
    assert_eq!(
        error["message"],
        "request does not belong to this user runtime"
    );
}

fn bundle(
    dir: &Path,
    actor: &str,
    owner: &str,
    ca: &[u8],
    cert: &[u8],
    key: &[u8],
) -> LoadedCredential {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("ca.pem"), ca).unwrap();
    std::fs::write(dir.join("agent.pem"), cert).unwrap();
    std::fs::write(dir.join("agent-key.pem"), key).unwrap();
    let mut manifest = AgentCredential::for_bundle(actor);
    manifest.server_name = user_runtime_server_name(owner).unwrap();
    manifest.write_to(dir).unwrap();
    AgentCredential::load(dir).unwrap()
}

fn start(data: &Path, credential: &Path, owner: &str, port: u16) -> Daemon {
    Daemon::spawn(
        &[
            "--data-dir",
            data.to_str().unwrap(),
            "--bind-addr",
            &format!("127.0.0.1:{port}"),
            "serve-user",
            "--owner",
            owner,
            "--credential",
            credential.to_str().unwrap(),
        ],
        &[("RUST_LOG", LOG_FILTER)],
    )
}

#[tokio::test]
async fn owner_boundary_stream_history_and_memory_survive_a_real_process_restart() {
    let root = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (server_cert, server_key) =
        generate_user_runtime_cert("runtime-alice", "alice", 300, &ca, &ca_key).unwrap();
    let credential_dir = root.path().join("server-credential");
    bundle(
        &credential_dir,
        "runtime-alice",
        "alice",
        &ca,
        &server_cert,
        &server_key,
    );
    let (alice_cert, alice_key) =
        generate_session_agent_cert("session-alice", "alice", 300, &ca, &ca_key).unwrap();
    let alice = bundle(
        &root.path().join("alice"),
        "session-alice",
        "alice",
        &ca,
        &alice_cert,
        &alice_key,
    );
    let (bob_cert, bob_key) =
        generate_session_agent_cert("session-bob", "bob", 300, &ca, &ca_key).unwrap();
    let mut bob = bundle(
        &root.path().join("bob"),
        "session-bob",
        "bob",
        &ca,
        &bob_cert,
        &bob_key,
    );
    bob.server_name = alice.server_name.clone();
    let data = root.path().join("data");
    let port = free_port();
    let mut daemon = start(&data, &credential_dir, "alice", port);
    daemon
        .wait_for_log("confined user runtime ready", BUDGET)
        .await
        .unwrap();
    let mut owner = Vfs::connect_as_agent(port, &alice, BUDGET).await;
    owner
        .write_file(
            "/agents/agent-a/memory/MEMORY.md",
            b"durable-agent-memory",
            "",
        )
        .await
        .unwrap();
    owner
        .create_stream("/sessions/original-id/transcript.jsonl", "")
        .await
        .unwrap();
    owner
        .stream_write(
            "/sessions/original-id/transcript.jsonl",
            b"original-history\n",
            "",
        )
        .await
        .unwrap();
    // A valid foreign-owner certificate completes mTLS, but cannot pass the owner gate.
    let mut other_owner = dial_client(port, &bob).await.unwrap();
    let refusal = other_owner
        .read(ReadRequest {
            path: "/agents/agent-a/memory/MEMORY.md".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_owner_refusal(refusal.is_error, &refusal.error_payload);
    let refusal = other_owner
        .call(CallRequest {
            method: "managed_agent.cancel_v1".into(),
            payload: br#"{"session_id":"original-id"}"#.to_vec(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        refusal.message(),
        "request does not belong to this user runtime"
    );
    assert!(!data.join("tls/ca-key.pem").exists());
    assert!(!data.join("tls/api-key-secret").exists());
    assert!(data.join(".node_id").exists());
    let original_node = std::fs::read(data.join(".node_id")).unwrap();
    drop(other_owner);
    drop(owner);
    drop(daemon);

    let mut daemon = start(&data, &credential_dir, "alice", port);
    daemon
        .wait_for_log("confined user runtime ready", BUDGET)
        .await
        .unwrap();
    let mut owner = Vfs::connect_as_agent(port, &alice, BUDGET).await;
    assert_eq!(std::fs::read(data.join(".node_id")).unwrap(), original_node);
    assert_eq!(
        owner
            .read_file("/agents/agent-a/memory/MEMORY.md", "")
            .await
            .unwrap(),
        b"durable-agent-memory"
    );
    assert_eq!(
        owner
            .stream_collect_all("/sessions/original-id/transcript.jsonl", "")
            .await
            .unwrap(),
        b"original-history\n"
    );
    drop(owner);
    drop(daemon);

    let (bob_server, bob_server_key) =
        generate_user_runtime_cert("runtime-bob", "bob", 300, &ca, &ca_key).unwrap();
    bundle(
        &credential_dir,
        "runtime-bob",
        "bob",
        &ca,
        &bob_server,
        &bob_server_key,
    );
    let mut mismatch = start(&data, &credential_dir, "bob", port);
    let log = mismatch
        .wait_exit(BUDGET)
        .await
        .expect("wrong owner must fail boot");
    assert!(
        log.contains("data directory belongs to another owner"),
        "{log}"
    );
}

#[tokio::test]
async fn boot_refuses_cluster_authority_and_a_client_only_identity_before_creating_data() {
    let root = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert, key) =
        generate_user_runtime_cert("runtime-alice", "alice", 300, &ca, &ca_key).unwrap();
    let credential_dir = root.path().join("credential");
    bundle(&credential_dir, "runtime-alice", "alice", &ca, &cert, &key);
    for (index, flags) in [
        vec!["--no-tls"],
        vec!["--insecure-no-auth"],
        vec!["--accept-enrollments"],
        vec!["--cluster-init", "other-zone"],
        vec![],
    ]
    .into_iter()
    .enumerate()
    {
        let data = root.path().join(format!("rejected-{index}"));
        let mut args = vec![
            "--data-dir",
            data.to_str().unwrap(),
            "serve-user",
            "--owner",
            "alice",
            "--credential",
            credential_dir.to_str().unwrap(),
        ];
        args.extend(flags);
        let env = if index == 4 {
            vec![("NEXUS_API_KEY_SECRET", "unexpected-cluster-authority")]
        } else {
            vec![]
        };
        let mut rejected = Daemon::spawn(&args, &env);
        let log = rejected.wait_exit(BUDGET).await.unwrap();
        assert!(log.contains("cluster authority, federation, plugins and unauthenticated listeners are unavailable"), "{log}");
        assert!(
            !data.exists(),
            "invalid options must not initialize durable storage"
        );
    }
    let (cert, key) =
        generate_session_agent_cert("session-alice", "alice", 300, &ca, &ca_key).unwrap();
    bundle(&credential_dir, "session-alice", "alice", &ca, &cert, &key);
    let data = root.path().join("client-only");
    let mut rejected = start(&data, &credential_dir, "alice", free_port());
    let log = rejected.wait_exit(BUDGET).await.unwrap();
    assert!(
        log.contains("another owner or lacks server capability"),
        "{log}"
    );
    assert!(!data.exists());
}

#[tokio::test]
async fn rotation_keeps_existing_connections_and_expiry_refuses_them_until_a_valid_replacement() {
    let root = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert, key) =
        generate_user_runtime_cert("runtime-alice", "alice", 30, &ca, &ca_key).unwrap();
    let credential_dir = root.path().join("server-credential");
    bundle(&credential_dir, "runtime-alice", "alice", &ca, &cert, &key);
    let (client_cert, client_key) =
        generate_session_agent_cert("session-alice", "alice", 300, &ca, &ca_key).unwrap();
    let client = bundle(
        &root.path().join("client"),
        "session-alice",
        "alice",
        &ca,
        &client_cert,
        &client_key,
    );
    let port = free_port();
    let mut daemon = start(&root.path().join("data"), &credential_dir, "alice", port);
    daemon
        .wait_for_log("confined user runtime ready", BUDGET)
        .await
        .unwrap();
    let mut connected = Vfs::connect_as_agent(port, &client, BUDGET).await;
    connected
        .write_file("/memory.txt", b"original-bytes", "")
        .await
        .unwrap();
    let (replacement, replacement_key) =
        generate_user_runtime_cert("runtime-alice", "alice", 12, &ca, &ca_key).unwrap();
    bundle(
        &credential_dir,
        "runtime-alice",
        "alice",
        &ca,
        &replacement,
        &replacement_key,
    );
    daemon
        .wait_for_log("runtime server identity rotated", BUDGET)
        .await
        .unwrap();
    let mut fresh = Vfs::connect_as_agent(port, &client, BUDGET).await;
    assert_eq!(
        fresh.read_file("/memory.txt", "").await.unwrap(),
        b"original-bytes"
    );
    let (wrong_owner, wrong_key) =
        generate_user_runtime_cert("runtime-bob", "bob", 300, &ca, &ca_key).unwrap();
    bundle(
        &credential_dir,
        "runtime-bob",
        "bob",
        &ca,
        &wrong_owner,
        &wrong_key,
    );
    daemon
        .wait_for_log("runtime credential replacement refused", BUDGET)
        .await
        .unwrap();
    let deadline = std::time::Instant::now() + BUDGET;
    loop {
        match connected.read_file("/memory.txt", "").await {
            Ok(bytes) => assert_eq!(bytes, b"original-bytes"),
            Err(error) => {
                assert!(
                    error.contains("user runtime server credential expired"),
                    "{error}"
                );
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expired server must stop authorizing old connections"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        dial_client(port, &client).await.is_err(),
        "expired server must refuse a new TLS connection"
    );
    let (restored, restored_key) =
        generate_user_runtime_cert("runtime-alice", "alice", 300, &ca, &ca_key).unwrap();
    bundle(
        &credential_dir,
        "runtime-alice",
        "alice",
        &ca,
        &restored,
        &restored_key,
    );
    daemon
        .wait_for_log_count("runtime server identity rotated", 2, BUDGET)
        .await
        .unwrap();
    assert_eq!(
        connected.read_file("/memory.txt", "").await.unwrap(),
        b"original-bytes"
    );
    let mut fresh = Vfs::connect_as_agent(port, &client, BUDGET).await;
    assert_eq!(
        fresh.read_file("/memory.txt", "").await.unwrap(),
        b"original-bytes"
    );
}
