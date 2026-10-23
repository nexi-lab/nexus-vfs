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

const BUDGET: Duration = Duration::from_secs(90);

#[tokio::test]
async fn signed_search_keeps_the_owner_boundary_and_reopens_committed_indexes() {
    use nexus_search_plugin::search_proto::{
        search_service_client::SearchServiceClient, DeletePathContextRequest, IndexRequest,
        ListPathContextsRequest, PutPathContextRequest, QueryRequest, QueryType, StatsRequest,
    };

    async fn assert_owned_hits(
        search: &mut SearchServiceClient<tonic::transport::Channel>,
        template: QueryRequest,
        real_models: bool,
    ) {
        let kinds: &[QueryType] = if real_models {
            &[QueryType::Keyword, QueryType::Semantic, QueryType::Hybrid]
        } else {
            &[QueryType::Keyword]
        };
        for &kind in kinds {
            let hits = search
                .query(QueryRequest {
                    query_type: kind as i32,
                    ..template.clone()
                })
                .await
                .unwrap()
                .into_inner();
            assert!(hits.error.is_none(), "{kind:?}: {hits:?}");
            assert!(
                hits.results.iter().any(|hit| hit.path == "/owner-note.md"),
                "{kind:?}: {hits:?}"
            );
        }
    }

    let root = tempfile::tempdir().unwrap();
    let plugins = common::search_plugin::signed_plugin(root.path());
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert, key) =
        generate_user_runtime_cert("runtime-alice", "alice", 300, &ca, &ca_key).unwrap();
    let credential = root.path().join("server");
    bundle(&credential, "runtime-alice", "alice", &ca, &cert, &key);
    let mut clients = Vec::new();
    for owner in ["alice", "bob"] {
        let actor = format!("session-{owner}");
        let (cert, key) = generate_session_agent_cert(&actor, owner, 300, &ca, &ca_key).unwrap();
        clients.push(bundle(
            &root.path().join(owner),
            &actor,
            "alice",
            &ca,
            &cert,
            &key,
        ));
    }
    let models = root.path().join("empty-models");
    std::fs::create_dir(&models).unwrap();
    let real_models = std::env::var("NEXUS_SEARCH_E2E_MODEL_DIR").ok();
    let model_dir = real_models
        .as_deref()
        .unwrap_or_else(|| models.to_str().unwrap());
    let binary = std::env::var("NEXUS_SEARCH_USER_RUNTIME_BINARY")
        .unwrap_or_else(|_| common::bin().to_owned());
    eprintln!(
        "Search runtime binary under test: {binary}; real model: {}",
        real_models.is_some()
    );
    let data = root.path().join("owned-data");
    let unrelated = root.path().join("unrelated-data");
    let port = free_port();
    let spawn = || {
        Daemon::spawn_binary(
            &binary,
            &[
                "--data-dir",
                data.to_str().unwrap(),
                "--plugin-dir",
                plugins.to_str().unwrap(),
                "--bind-addr",
                &format!("127.0.0.1:{port}"),
                "serve-user",
                "--owner",
                "alice",
                "--credential",
                credential.to_str().unwrap(),
            ],
            &[
                ("RUST_LOG", LOG_FILTER),
                (
                    "NEXUS_LOCAL_TRUSTED_KEYS_DIR",
                    root.path().join("trust").to_str().unwrap(),
                ),
                ("NEXUS_DATA_DIR", unrelated.to_str().unwrap()),
                ("NEXUS_SEARCH_MODEL_DIR", model_dir),
                ("NEXUS_SEARCH_EMBED_API_URL", ""),
                ("NEXUS_SEARCH_QUERY_EXPANSION", "false"),
                ("NEXUS_SEARCH_CONTEXTUAL_CHUNKING", "false"),
            ],
        )
    };
    let mut daemon = spawn();
    daemon
        .wait_for_log("confined user runtime ready", BUDGET)
        .await
        .unwrap();
    let mut owner = Vfs::connect_as_agent(port, &clients[0], BUDGET).await;
    owner
        .write_file("/owner-note.md", b"gentian durable owner document", "")
        .await
        .unwrap();
    let query = || QueryRequest {
        q: "gentian".into(),
        limit: 10,
        query_type: QueryType::Keyword as i32,
        ..Default::default()
    };
    let mut foreign = SearchServiceClient::new(dial_channel(port, &clients[1]).await.unwrap());
    let refusal = foreign.query(query()).await.unwrap_err();
    assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        refusal.message(),
        "request does not belong to this user runtime"
    );
    assert_eq!(
        foreign
            .index(IndexRequest::default())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        foreign
            .stats(StatsRequest::default())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let mut search = SearchServiceClient::new(dial_channel(port, &clients[0]).await.unwrap());
    let indexed = search
        .index(IndexRequest {
            root_path: "/".into(),
            recursive: true,
            max_docs: 10,
            ..Default::default()
        })
        .await
        .expect("the confined owner must be able to index its own workspace")
        .into_inner();
    assert_eq!(indexed.indexed_count, 1, "{indexed:?}");
    assert_owned_hits(&mut search, query(), real_models.is_some()).await;
    let before = search
        .stats(StatsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert!(before.last_index_seq > 0, "{before:?}");
    assert_eq!(
        search
            .put_path_context(PutPathContextRequest::default())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        search
            .delete_path_context(DeletePathContextRequest::default())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        search
            .list_path_contexts(ListPathContextsRequest::default())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let mut invalid = tonic::Request::new(query());
    invalid
        .metadata_mut()
        .insert("authorization", "Bearer invalid".parse().unwrap());
    assert_eq!(
        search.query(invalid).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    assert!(!unrelated.exists());
    assert!(!data.join("tls/ca-key.pem").exists());
    assert!(!data.join("tls/api-key-secret").exists());
    drop(search);
    drop(foreign);
    drop(owner);
    drop(daemon);
    let mut restarted = spawn();
    restarted
        .wait_for_log("confined user runtime ready", BUDGET)
        .await
        .unwrap();
    let mut search = SearchServiceClient::new(dial_channel(port, &clients[0]).await.unwrap());
    assert_owned_hits(&mut search, query(), real_models.is_some()).await;
    let after = search
        .stats(StatsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert!(after.last_index_seq >= before.last_index_seq, "{after:?}");
    assert_eq!(after.pending, 0);
    assert_eq!(after.indexing_in_progress, 0);
}

async fn dial_client(
    port: u16,
    credential: &LoadedCredential,
) -> Result<NexusVfsServiceClient<tonic::transport::Channel>, tonic::transport::Error> {
    Ok(NexusVfsServiceClient::new(
        dial_channel(port, credential).await?,
    ))
}

async fn dial_channel(
    port: u16,
    credential: &LoadedCredential,
) -> Result<tonic::transport::Channel, tonic::transport::Error> {
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
    Ok(channel)
}

#[derive(Clone, PartialEq, prost::Message)]
struct EmptyMessage {}

async fn list_vault_metadata(
    port: u16,
    credential: &LoadedCredential,
) -> Result<tonic::Response<EmptyMessage>, tonic::Status> {
    let channel = dial_channel(port, credential).await.unwrap();
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.unwrap();
    grpc.unary(
        tonic::Request::new(EmptyMessage {}),
        "/nexus.secrets.v1.GenericSecretsService/ListSecrets"
            .parse()
            .unwrap(),
        tonic_prost::ProstCodec::default(),
    )
    .await
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

#[cfg(feature = "driver-ai")]
#[tokio::test]
async fn local_backend_configuration_serves_model_requests_without_granting_mount_authority() {
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&requests);
    let key = "runtime-provider-key-must-not-be-durable";
    let provider = tokio::spawn(async move {
        for text in ["MODEL-FIRST", "MODEL-AFTER-RESTART"] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0, "provider request closed before its body");
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&bytes[..end]).unwrap().to_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length:")
                                .map(|value| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            captured
                .lock()
                .unwrap()
                .push(String::from_utf8(bytes).unwrap());
            let body = format!(
                "data: {{\"model\":\"fixture\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{text}\"}}}}]}}\n\n\
                 data: {{\"model\":\"fixture\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
                 data: [DONE]\n\n"
            );
            socket.write_all(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
            ).as_bytes()).await.unwrap();
        }
    });
    let root = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (server_cert, server_key) =
        generate_user_runtime_cert("runtime-alice", "alice", 300, &ca, &ca_key).unwrap();
    let credential = root.path().join("credential");
    bundle(
        &credential,
        "runtime-alice",
        "alice",
        &ca,
        &server_cert,
        &server_key,
    );
    let (cert, key_material) =
        generate_session_agent_cert("session-alice", "alice", 300, &ca, &ca_key).unwrap();
    let alice = bundle(
        &root.path().join("alice"),
        "session-alice",
        "alice",
        &ca,
        &cert,
        &key_material,
    );
    let data = root.path().join("data");
    let config = root.path().join("backends.json");
    std::fs::write(&config, serde_json::to_vec(&serde_json::json!({"mounts": [{
        "path": "/models/openai", "backend_type": "openai", "backend_name": "user-provider",
        "backend_params": {"base_url": provider_url, "blob_root": data.join("model-blobs"), "api_key": key}
    }]})).unwrap()).unwrap();
    let port = free_port();
    for (index, reply) in ["MODEL-FIRST", "MODEL-AFTER-RESTART"].iter().enumerate() {
        let mut daemon = Daemon::spawn(
            &[
                "--data-dir",
                data.to_str().unwrap(),
                "--bind-addr",
                &format!("127.0.0.1:{port}"),
                "serve-user",
                "--owner",
                "alice",
                "--credential",
                credential.to_str().unwrap(),
                "--backend-config",
                config.to_str().unwrap(),
            ],
            &[("RUST_LOG", LOG_FILTER)],
        );
        daemon
            .wait_for_log("confined user runtime ready", BUDGET)
            .await
            .unwrap();
        let mut owner = Vfs::connect_as_agent(port, &alice, BUDGET).await;
        let request = serde_json::json!({"model": "fixture", "messages": [{"role": "user", "content": "boot-model-probe"}], "max_tokens": 32});
        let prompt = format!("/models/openai/turn-{index}.prompt");
        let response = format!("/models/openai/turn-{index}.reply");
        owner
            .write_file(&prompt, request.to_string().as_bytes(), "")
            .await
            .unwrap();
        let deadline = std::time::Instant::now() + BUDGET;
        loop {
            if let Ok(bytes) = owner.stream_collect_all(&response, "").await {
                let text = String::from_utf8(bytes).unwrap();
                assert!(!text.contains("\"error\""), "{text}");
                if text.contains("\"done\"") {
                    assert!(text.contains(reply), "{text}");
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "reply did not complete: {}",
                daemon.drain()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if index == 1 {
            assert!(String::from_utf8(
                owner
                    .read_file("/models/openai/turn-0.prompt", "")
                    .await
                    .unwrap()
            )
            .unwrap()
            .contains("boot-model-probe"));
        }
        assert!(
            owner
                .mount_backend(
                    "/another-model",
                    "openai",
                    &[("blob_root", root.path().to_str().unwrap())],
                    ""
                )
                .await
                .is_err(),
            "ordinary user must still lack mount authority"
        );
        drop(owner);
        drop(daemon);
    }
    provider.await.unwrap();
    let captured = requests.lock().unwrap();
    assert_eq!(captured.len(), 2);
    for request in &*captured {
        assert!(request
            .to_lowercase()
            .contains(&format!("authorization: bearer {key}")));
        assert!(request.contains("boot-model-probe"));
    }
    fn assert_no_key(dir: &Path, key: &[u8]) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                assert_no_key(&path, key);
            } else {
                assert!(
                    !std::fs::read(&path)
                        .unwrap()
                        .windows(key.len())
                        .any(|part| part == key),
                    "provider credential persisted in {}",
                    path.display()
                );
            }
        }
    }
    assert_no_key(&data, key.as_bytes());
    assert!(!data.join("tls/ca-key.pem").exists());
}

#[tokio::test]
async fn malformed_startup_backends_fail_before_touching_owner_storage() {
    let root = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert, key) =
        generate_user_runtime_cert("runtime-alice", "alice", 300, &ca, &ca_key).unwrap();
    let credential = root.path().join("credential");
    bundle(&credential, "runtime-alice", "alice", &ca, &cert, &key);
    let mount =
        serde_json::json!({"path": "/model", "backend_type": "openai", "backend_name": "fixture"});
    let cases = [
        serde_json::json!({"mounts": [{"path": "/proc/model", "backend_type": "openai", "backend_name": "fixture"}]}),
        serde_json::json!({"mounts": [{"path": "/model/../agent", "backend_type": "openai", "backend_name": "fixture"}]}),
        serde_json::json!({"mounts": [mount.clone(), mount]}),
        serde_json::json!({"mounts": [{"path": "/external", "backend_type": "remote", "backend_name": "fixture"}]}),
        serde_json::json!({"mounts": [], "zone_id": "foreign-zone"}),
    ];
    for (index, config) in cases.into_iter().enumerate() {
        let data = root.path().join(format!("data-{index}"));
        let config_path = root.path().join(format!("config-{index}.json"));
        std::fs::write(&config_path, config.to_string()).unwrap();
        let mut daemon = Daemon::spawn(
            &[
                "--data-dir",
                data.to_str().unwrap(),
                "serve-user",
                "--owner",
                "alice",
                "--credential",
                credential.to_str().unwrap(),
                "--backend-config",
                config_path.to_str().unwrap(),
            ],
            &[("RUST_LOG", LOG_FILTER)],
        );
        let log = daemon
            .wait_exit(BUDGET)
            .await
            .expect("malformed backends must refuse startup");
        assert!(!data.exists(), "case {index} touched storage: {log}");
        assert!(log.contains("runtime backend"), "{log}");
    }
}

#[tokio::test]
async fn a_requested_unsigned_plugin_blocks_the_confined_server() {
    let root = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert, key) =
        generate_user_runtime_cert("runtime-alice", "alice", 300, &ca, &ca_key).unwrap();
    let credential = root.path().join("credential");
    bundle(&credential, "runtime-alice", "alice", &ca, &cert, &key);
    let plugins = root.path().join("plugins");
    std::fs::create_dir(&plugins).unwrap();
    let name = format!("unsigned{}", std::env::consts::DLL_SUFFIX);
    std::fs::write(plugins.join(&name), b"unverified bytes").unwrap();
    let data = root.path().join("data");
    let mut rejected = Daemon::spawn(
        &[
            "--data-dir",
            data.to_str().unwrap(),
            "--plugin-dir",
            plugins.to_str().unwrap(),
            "serve-user",
            "--owner",
            "alice",
            "--credential",
            credential.to_str().unwrap(),
        ],
        &[("RUST_LOG", LOG_FILTER)],
    );
    let log = rejected.wait_exit(BUDGET).await.unwrap();
    assert!(
        log.contains(&name) && log.to_lowercase().contains("signature"),
        "{log}"
    );
    assert!(!log.contains("confined user runtime ready"), "{log}");
}

#[tokio::test]
#[ignore = "requires NEXUS_VAULT_PLUGIN_DIR containing the signed release library"]
async fn signed_vault_uses_the_owned_data_root_and_keeps_the_owner_boundary() {
    let plugins = std::env::var("NEXUS_VAULT_PLUGIN_DIR").expect("signed Vault fixture directory");
    let root = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert, key) =
        generate_user_runtime_cert("runtime-alice", "alice", 300, &ca, &ca_key).unwrap();
    let credential = root.path().join("server");
    bundle(&credential, "runtime-alice", "alice", &ca, &cert, &key);
    let data = root.path().join("owned-data");
    let unrelated = root.path().join("unrelated-data");
    let port = free_port();
    let mut daemon = Daemon::spawn(
        &[
            "--data-dir",
            data.to_str().unwrap(),
            "--plugin-dir",
            &plugins,
            "--bind-addr",
            &format!("127.0.0.1:{port}"),
            "serve-user",
            "--owner",
            "alice",
            "--credential",
            credential.to_str().unwrap(),
        ],
        &[
            ("RUST_LOG", LOG_FILTER),
            ("NEXUS_DATA_DIR", unrelated.to_str().unwrap()),
        ],
    );
    daemon
        .wait_for_log("confined user runtime ready", BUDGET)
        .await
        .unwrap();
    assert!(data.join("vault/master.key").is_file());
    assert!(
        !unrelated.exists(),
        "plugins must use the selected durable data root"
    );
    let runtime_client = AgentCredential::load(&credential).unwrap();
    list_vault_metadata(port, &runtime_client).await.unwrap();
    for owner in ["alice", "bob"] {
        let (cert, key) =
            generate_session_agent_cert("session-reader", owner, 300, &ca, &ca_key).unwrap();
        let client_bundle = bundle(
            &root.path().join(owner),
            "session-reader",
            "alice",
            &ca,
            &cert,
            &key,
        );
        let mut client = dial_client(port, &client_bundle).await.unwrap();
        // An empty protobuf ListSecretsRequest asks the actual Vault for its metadata.
        let result = client
            .call(CallRequest {
                method: "password-vault.secret_list".into(),
                payload: Vec::new(),
                auth_token: String::new(),
            })
            .await;
        if owner == "alice" {
            let result = result.unwrap().into_inner();
            assert!(!result.is_error, "{result:?}");
            assert!(
                result.payload.is_empty(),
                "a fresh Vault contains no secrets"
            );
        } else {
            let refusal = result.unwrap_err();
            assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
            assert_eq!(
                refusal.message(),
                "request does not belong to this user runtime"
            );
        }
        let native_result = list_vault_metadata(port, &client_bundle).await;
        if owner == "alice" {
            native_result.unwrap();
        } else {
            assert_eq!(
                native_result.unwrap_err().code(),
                tonic::Code::PermissionDenied
            );
        }
    }
    drop(daemon);
}

#[tokio::test]
#[ignore = "requires NEXUS_VAULT_PLUGIN_DIR containing the signed release library"]
async fn signed_vault_on_the_control_plane_refuses_a_user_runtime_identity() {
    let plugins = std::env::var("NEXUS_VAULT_PLUGIN_DIR").unwrap();
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("root-data");
    let identity = root.path().join("identity");
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (_, hash) = nexus_raft::transport::generate_join_token(&ca).unwrap();
    common::write_tls_bundle(&data, 1, &ca, &ca_key, &hash);
    let port = common::free_port_pair();
    let address = format!("127.0.0.1:{port}");
    let mut daemon = Daemon::spawn(
        &[
            "--data-dir",
            data.to_str().unwrap(),
            "--identity-dir",
            identity.to_str().unwrap(),
            "--plugin-dir",
            &plugins,
            "--bind-addr",
            &address,
        ],
        &[
            ("RUST_LOG", LOG_FILTER),
            ("NEXUS_CLUSTER_INIT", "control-data"),
            ("NEXUS_API_KEY_SECRET", "synthetic-control-plane-secret"),
            ("NEXUS_ADVERTISE_ADDR", &address),
        ],
    );
    daemon
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .unwrap();
    let mut operator = bundle(
        &root.path().join("operator"),
        "operator",
        "alice",
        &ca,
        &std::fs::read(data.join("tls/node.pem")).unwrap(),
        &std::fs::read(data.join("tls/node-key.pem")).unwrap(),
    );
    operator.server_name = "nexus-node".into();
    let mut privileged = dial_client(port, &operator).await.unwrap();
    let request = || CallRequest {
        method: "password-vault.secret_list".into(),
        ..Default::default()
    };
    let positive = privileged.call(request()).await.unwrap().into_inner();
    assert!(!positive.is_error, "{positive:?}");
    let (cert, key) =
        generate_user_runtime_cert("runtime-alice", "alice", 300, &ca, &ca_key).unwrap();
    let mut runtime = bundle(
        &root.path().join("runtime"),
        "runtime-alice",
        "alice",
        &ca,
        &cert,
        &key,
    );
    runtime.server_name = operator.server_name.clone();
    let mut unprivileged = dial_client(port, &runtime).await.unwrap();
    let refused = unprivileged.call(request()).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    list_vault_metadata(port, &operator).await.unwrap();
    let refused = list_vault_metadata(port, &runtime).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    let positive = privileged.call(request()).await.unwrap().into_inner();
    assert!(!positive.is_error, "{positive:?}");
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
        assert!(
            log.contains(
                "cluster authority, federation and unauthenticated listeners are unavailable"
            ),
            "{log}"
        );
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
async fn restart_with_expired_identity_waits_for_renewal_without_losing_owner_data() {
    let root = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert, key) =
        generate_user_runtime_cert("runtime-alice", "alice", 300, &ca, &ca_key).unwrap();
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
    let data = root.path().join("data");
    let port = free_port();
    let mut daemon = start(&data, &credential_dir, "alice", port);
    daemon
        .wait_for_log("confined user runtime ready", BUDGET)
        .await
        .unwrap();
    let mut connected = Vfs::connect_as_agent(port, &client, BUDGET).await;
    connected
        .write_file(
            "/agents/agent-a/memory/MEMORY.md",
            b"retained-owner-memory",
            "",
        )
        .await
        .unwrap();
    let original_node = std::fs::read(data.join(".node_id")).unwrap();
    drop(connected);
    drop(daemon);

    let (expired, expired_key) =
        generate_user_runtime_cert("runtime-alice", "alice", 1, &ca, &ca_key).unwrap();
    let expires_at = transport::peer_identity::not_after_unix_from_pem(&expired).unwrap();
    bundle(
        &credential_dir,
        "runtime-alice",
        "alice",
        &ca,
        &expired,
        &expired_key,
    );
    while std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        <= expires_at as u64
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut daemon = start(&data, &credential_dir, "alice", port);
    daemon
        .wait_for_log("confined user runtime ready", BUDGET)
        .await
        .unwrap();
    assert!(
        dial_client(port, &client).await.is_err(),
        "bootstrap must not make expired server authority usable"
    );
    let (renewed, renewed_key) =
        generate_user_runtime_cert("runtime-alice", "alice", 300, &ca, &ca_key).unwrap();
    bundle(
        &credential_dir,
        "runtime-alice",
        "alice",
        &ca,
        &renewed,
        &renewed_key,
    );
    daemon
        .wait_for_log("runtime server identity rotated", BUDGET)
        .await
        .unwrap();
    let mut connected = Vfs::connect_as_agent(port, &client, BUDGET).await;
    assert_eq!(std::fs::read(data.join(".node_id")).unwrap(), original_node);
    assert_eq!(
        connected
            .read_file("/agents/agent-a/memory/MEMORY.md", "")
            .await
            .unwrap(),
        b"retained-owner-memory"
    );
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
