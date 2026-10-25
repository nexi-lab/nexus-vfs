use super::*;
use crate::{managed_csr::tests::LoseReply, FounderAgentMinter};
use kernel::kernel::vfs_proto::{nexus_vfs_service_client::NexusVfsServiceClient, CallRequest};
use managed_agent::{SpawnHandle, SpawnOptions, SpawnTask};
use nexus_raft::{
    auth_key_store::RaftAuthKeyStore,
    raft::ZoneRaftRegistry,
    transport::{
        generate_agent_cert, generate_node_cert, generate_session_agent_cert, generate_zone_ca,
    },
};
use std::time::Duration;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};

// Only the runtime body is a fixture. It returns a selected native mailbox and
// durable SID through the real ManagedAgentService host-validation seam.
struct Host;
struct Handle(a2a::session::SessionEndpoint);
impl SpawnHandle for Handle {
    fn abort(&self) {}
    fn session_endpoint(&self) -> Option<&a2a::session::SessionEndpoint> {
        Some(&self.0)
    }
    fn durable_session_id(&self) -> Option<&str> {
        Some("session-original-managed-runtime")
    }
}
impl SpawnTask<Kernel> for Host {
    fn spawn(
        &self,
        _: Arc<Kernel>,
        _: kernel::core::agents::registry::AgentDescriptor,
        _: Arc<dyn Fn(kernel::core::agents::registry::AgentState, Option<String>) + Send + Sync>,
    ) -> Result<Box<dyn SpawnHandle>, String> {
        Err("native options are required".into())
    }
    fn spawn_with_options(
        &self,
        _: Arc<Kernel>,
        _: kernel::core::agents::registry::AgentDescriptor,
        options: SpawnOptions,
        observer: Arc<
            dyn Fn(kernel::core::agents::registry::AgentState, Option<String>) + Send + Sync,
        >,
    ) -> Result<Box<dyn SpawnHandle>, String> {
        observer(kernel::core::agents::registry::AgentState::Ready, None);
        Ok(Box::new(Handle(
            options.session_endpoint.ok_or("missing native mailbox")?,
        )))
    }
}

async fn connect(
    address: std::net::SocketAddr,
    ca: &[u8],
    cert: &[u8],
    key: &[u8],
) -> NexusVfsServiceClient<Channel> {
    NexusVfsServiceClient::new(
        Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .timeout(Duration::from_secs(5))
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name(TlsConfig::CLUSTER_SERVER_NAME)
                    .ca_certificate(Certificate::from_pem(ca))
                    .identity(Identity::from_pem(cert, key)),
            )
            .unwrap()
            .connect()
            .await
            .unwrap(),
    )
}

async fn raw(
    client: &mut NexusVfsServiceClient<Channel>,
    method: &str,
    value: Value,
) -> (bool, Value) {
    let wire = client
        .call(CallRequest {
            method: method.into(),
            payload: serde_json::to_vec(&value).unwrap(),
            auth_token: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    (
        wire.is_error,
        serde_json::from_slice(&wire.payload).unwrap(),
    )
}
async fn call(
    client: &mut NexusVfsServiceClient<Channel>,
    verb: &str,
    pid: &str,
    op: &str,
) -> Value {
    let (error, response) = raw(
        client,
        &format!("{NAME}.{verb}"),
        json!({"pid":pid,"operation_id":op}),
    )
    .await;
    assert!(!error, "native owner operation failed: {response}");
    assert!(!response.to_string().contains("PRIVATE KEY"));
    assert_eq!(response["managedRuntimeActivated"], false);
    response
}
async fn start(client: &mut NexusVfsServiceClient<Channel>, name: &str) -> String {
    let (error, response) = raw(
        client,
        "managed_agent.start_session_v1",
        json!({"agent_id":name}),
    )
    .await;
    assert!(!error, "native managed host failed: {response}");
    response["session_id"].as_str().unwrap().into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_mtls_owner_uses_existing_issuer_and_recovers_applied_i_and_f_without_new_keys() {
    lib::transport_primitives::ensure_crypto_provider();
    let private = tempfile::tempdir().unwrap();
    let tls_dir = private.path().join("tls");
    std::fs::create_dir(&tls_dir).unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    std::fs::write(tls_dir.join("ca.pem"), &ca).unwrap();
    std::fs::write(tls_dir.join("ca-key.pem"), &ca_key).unwrap();
    let (node_cert, node_key) = generate_node_cert(1, "root", &ca, &ca_key, &[], None).unwrap();
    let tls = TlsConfig {
        ca_pem: ca.clone(),
        cert_pem: node_cert.clone(),
        key_pem: node_key.clone(),
    };
    let runtime = tokio::runtime::Handle::current();
    let zones = Arc::new(ZoneRaftRegistry::new(private.path().join("raft"), 1));
    let node = zones
        .create_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !node.is_leader() || node.applied_index() < node.last_index() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let store = Arc::new(LoseReply::new(RaftAuthKeyStore::new_arc(
        node,
        runtime.clone(),
    )));
    let verifier = lib::transport_primitives::FederatedClientCertVerifier::new(&ca).unwrap();
    let verifier_slot = Arc::new(std::sync::OnceLock::new());
    verifier_slot.set(verifier).unwrap();
    let slot = nexus_raft::agent_minter::new_agent_minter_slot();
    *slot.write() = Some(Arc::new(FounderAgentMinter {
        store: store.clone(),
        tls_dir: tls_dir.clone(),
        data_dir: private.path().to_path_buf(),
        session_allow: nexus_raft::session_mint_allow_store::new_session_mint_allow_slot(),
        peer_verifier: verifier_slot.clone(),
    }));
    let kernel = Arc::new(Kernel::new());
    kernel
        .bring_up_services(vec![
            managed_agent::service_decl_with_spawn(Arc::new(Host)),
            service_decl(
                tls_dir.clone(),
                true,
                Some(NativeIssuer::from_tls(slot.clone(), &tls, runtime.clone()).unwrap()),
            )
            .unwrap(),
        ])
        .unwrap();
    let routes = transport::grpc::build_vfs_routes(
        kernel.clone(),
        Arc::new(auth::ApiKeyAuthProvider::cert_identity_only()),
        verifier_slot,
        transport::grpc::DataPlaneReady::open(),
        contracts::constants::MAX_GRPC_MESSAGE_BYTES,
        "native-managed-csr-fixture",
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async move {
        Server::builder()
            .tls_config(
                ServerTlsConfig::new()
                    .identity(Identity::from_pem(node_cert, node_key))
                    .client_ca_root(Certificate::from_pem(&tls.ca_pem)),
            )
            .unwrap()
            .add_routes(routes)
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    stopped.await.expect("explicit fixture shutdown");
                },
            )
            .await
            .unwrap();
    });
    let (alice, alice_key) =
        generate_session_agent_cert("session-owner-alice", "alice", 3600, &ca, &ca_key).unwrap();
    let (bob, bob_key) =
        generate_session_agent_cert("session-owner-bob", "bob", 3600, &ca, &ca_key).unwrap();
    let mut owner = connect(address, &ca, &alice, &alice_key).await;
    let mut other = connect(address, &ca, &bob, &bob_key).await;
    let (err, caps) = raw(&mut owner, &format!("{NAME}.capabilities_v1"), json!({})).await;
    assert!(!err);
    assert_eq!(
        (
            caps["prepareVersion"].as_u64(),
            caps["issuanceVersion"].as_u64(),
            caps["activationVersion"].as_u64()
        ),
        (Some(1), Some(1), Some(0))
    );
    let pid = start(&mut owner, "original-product-agent").await;
    let op = "native-owner-original-operation";
    for verb in [
        "prepare_v1",
        "inspect_v1",
        "issue_v1",
        "query_v1",
        "publish_v1",
    ] {
        assert!(
            raw(
                &mut other,
                &format!("{NAME}.{verb}"),
                json!({"pid":pid,"operation_id":op})
            )
            .await
            .0
        );
    }
    let prepared = call(&mut owner, "prepare_v1", &pid, op).await;
    assert_eq!(prepared["binding"]["ownerId"], "alice");
    assert_eq!(prepared["binding"]["agentId"], "original-product-agent");
    let pending = tls_dir.join(format!(
        "managed-csr-{}.json",
        PreparationService::operation_key("original-product-agent", "alice", op)
    ));
    let original_key_request = std::fs::read(&pending).unwrap();
    let bundle = tls_dir.join(format!(
        "managed-agent-{}",
        PreparationService::operation_key("original-product-agent", "alice", op)
    ));
    assert_eq!(
        call(&mut owner, "query_v1", &pid, op).await["issuerObservation"],
        "not_observed"
    );
    assert!(!bundle.exists());

    // I reply is lost after REAL Raft apply. Signing key is absent: the losing
    // result must not proceed to sign or infer that I was not committed.
    std::fs::rename(tls_dir.join("ca-key.pem"), tls_dir.join("held-key.pem")).unwrap();
    store.lose_next_applied_reply(1);
    let lost_i = call(&mut owner, "issue_v1", &pid, op).await;
    assert_eq!(lost_i["submissionAttempted"], true);
    assert_eq!(lost_i["issuanceOutcome"], "unknown");
    assert_eq!(
        call(&mut owner, "query_v1", &pid, op).await["issuerObservation"],
        "intent_committed"
    );
    assert_eq!(
        call(&mut owner, "publish_v1", &pid, op).await["credentialPublished"],
        false
    );
    assert!(!bundle.exists());
    assert_eq!(std::fs::read(&pending).unwrap(), original_key_request);
    std::fs::rename(tls_dir.join("held-key.pem"), tls_dir.join("ca-key.pem")).unwrap();
    let finalized = call(&mut owner, "issue_v1", &pid, op).await;
    assert_eq!(finalized["issuanceOutcome"], "finalized");
    assert_eq!(finalized["requestSha256"], prepared["requestSha256"]);
    assert!(
        !bundle.exists(),
        "issue must not implicitly publish or activate"
    );
    // Publishing is read-only at the issuer and needs no signing key.
    std::fs::rename(tls_dir.join("ca-key.pem"), tls_dir.join("held-key.pem")).unwrap();
    let published = call(&mut owner, "publish_v1", &pid, op).await;
    assert_eq!(published["credentialPublished"], true);
    assert_eq!(published["submissionAttempted"], false);
    assert_eq!(
        published["certificateSha256"],
        finalized["certificateSha256"]
    );
    let manifest = bundle.join(lib::transport_primitives::CREDENTIAL_MANIFEST);
    let credential = lib::transport_primitives::AgentCredential::load(&manifest).unwrap();
    assert_eq!(credential.agent, "original-product-agent");
    let mut issued_agent = connect(
        address,
        &credential.ca_pem,
        &credential.cert_pem,
        &credential.key_pem,
    )
    .await;
    // The published leaf really authenticates as an ordinary Agent; it does
    // not acquire Alice's owner credential or Node authority from publication.
    let (agent_error, agent_view) = raw(&mut issued_agent, "agent_list", json!({})).await;
    assert!(
        !agent_error,
        "published ordinary Agent did not authenticate: {agent_view}"
    );
    assert!(
        raw(
            &mut issued_agent,
            &format!("{NAME}.issue_v1"),
            json!({"pid":pid,"operation_id":op})
        )
        .await
        .0
    );
    let manifest_bytes = std::fs::read(&manifest).unwrap();
    assert_eq!(call(&mut owner, "publish_v1", &pid, op).await, published);
    assert_eq!(std::fs::read(&manifest).unwrap(), manifest_bytes);
    assert_eq!(std::fs::read(&pending).unwrap(), original_key_request);
    std::fs::rename(tls_dir.join("held-key.pem"), tls_dir.join("ca-key.pem")).unwrap();

    // A local Node remains ineligible to act as an owner's managed caller.
    let (admin_cert, admin_key) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let mut admin = connect(address, &ca, &admin_cert, &admin_key).await;
    assert!(
        raw(
            &mut admin,
            &format!("{NAME}.issue_v1"),
            json!({"pid":pid,"operation_id":op})
        )
        .await
        .0
    );
    // No caller-supplied owner, issuer, DER or path is accepted.
    for field in [
        "owner_id",
        "agent_name",
        "issuer_url",
        "caller_cert_der",
        "directory",
    ] {
        let mut input = json!({"pid":pid,"operation_id":op});
        input[field] = "forged".into();
        assert!(raw(&mut owner, &format!("{NAME}.issue_v1"), input).await.0);
    }

    // F reply is lost after actual final apply. Explicit query and publication
    // recover F with the original key/op; no second issue request is needed.
    let second_pid = start(&mut owner, "second-product-agent").await;
    let second_op = "native-owner-lost-final";
    let second = call(&mut owner, "prepare_v1", &second_pid, second_op).await;
    store.lose_next_applied_reply(2);
    assert_eq!(
        call(&mut owner, "issue_v1", &second_pid, second_op).await["issuanceOutcome"],
        "unknown"
    );
    let found = call(&mut owner, "query_v1", &second_pid, second_op).await;
    assert_eq!(found["issuanceOutcome"], "finalized");
    assert_eq!(found["requestSha256"], second["requestSha256"]);
    let recovered = call(&mut owner, "publish_v1", &second_pid, second_op).await;
    assert_eq!(recovered["credentialPublished"], true);
    assert_eq!(recovered["certificateSha256"], found["certificateSha256"]);
    assert_eq!(std::fs::read(&pending).unwrap(), original_key_request);
    use kernel::hal::auth_key_store::AuthKeyStore;
    let records = store.list().unwrap();
    assert_eq!(records.len(), 4, "exactly two original immutable I/F pairs");
    assert_eq!(
        records
            .iter()
            .filter(|(k, _)| k.starts_with("agent:"))
            .count(),
        2
    );
    assert_eq!(
        records
            .iter()
            .filter(|(k, _)| k.starts_with("credential-final:"))
            .count(),
        2
    );
    drop((owner, other, admin, issued_agent));
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .unwrap()
        .unwrap();
    zones.shutdown_all();
}

#[test]
fn native_issuer_rejects_non_node_and_foreign_tls_selection_without_request_authority() {
    let runtime = lib::rt::OwnedRuntime::new(tokio::runtime::Runtime::new().unwrap());
    let (ca, ca_key) = generate_zone_ca("local").unwrap();
    let (agent, key) = generate_agent_cert("ordinary", &ca, &ca_key).unwrap();
    let slot = nexus_raft::agent_minter::new_agent_minter_slot();
    let tls = TlsConfig {
        ca_pem: ca.clone(),
        cert_pem: agent,
        key_pem: key,
    };
    assert!(NativeIssuer::from_tls(slot.clone(), &tls, runtime.handle().clone()).is_err());
    let (foreign, foreign_key) = generate_zone_ca("foreign").unwrap();
    let (node, key) = generate_node_cert(9, "root", &foreign, &foreign_key, &[], None).unwrap();
    let tls = TlsConfig {
        ca_pem: ca,
        cert_pem: node,
        key_pem: key,
    };
    assert!(NativeIssuer::from_tls(slot, &tls, runtime.handle().clone()).is_err());
}
