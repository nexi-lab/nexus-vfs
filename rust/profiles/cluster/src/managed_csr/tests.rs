use super::*;
use kernel::hal::auth_key_store::{AuthKeyStore, AuthKeyStoreError};
use nexus_raft::transport::proto::{
    zone_api_service_client::ZoneApiServiceClient, AgentCsrCapabilitiesRequest,
};
use nexus_raft::transport::{
    generate_agent_cert, generate_node_cert, generate_zone_ca, RaftGrpcServer, ServerConfig,
    TlsConfig,
};
use nexus_raft::{auth_key_store::RaftAuthKeyStore, raft::ZoneRaftRegistry};
use std::{
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use x509_parser::prelude::{FromDer, X509Certificate};

// Inject reply loss AFTER the existing real Raft store has applied I or F.
// No fake consensus, issuer, authorization decision or certificate is used.
pub(crate) struct LoseReply {
    inner: Arc<dyn AuthKeyStore>,
    stage: AtomicU8,
}
impl LoseReply {
    pub(crate) fn new(inner: Arc<dyn AuthKeyStore>) -> Self {
        Self {
            inner,
            stage: AtomicU8::new(0),
        }
    }
    pub(crate) fn lose_next_applied_reply(&self, stage: u8) {
        assert!(matches!(stage, 1 | 2));
        self.stage.store(stage, Ordering::SeqCst);
    }
}
impl AuthKeyStore for LoseReply {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
        self.inner.get(key)
    }
    fn get_linearizable(&self, key: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
        self.inner.get_linearizable(key)
    }
    fn put(&self, key: &str, value: &[u8]) -> Result<(), AuthKeyStoreError> {
        self.inner.put(key, value)
    }
    fn delete(&self, key: &str) -> Result<bool, AuthKeyStoreError> {
        self.inner.delete(key)
    }
    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError> {
        self.inner.list()
    }
    fn put_if_absent_atomic(&self, key: &str, value: &[u8]) -> Result<bool, AuthKeyStoreError> {
        let applied = self.inner.put_if_absent_atomic(key, value)?;
        let stage = if key.starts_with("credential-final:") {
            2
        } else {
            1
        };
        if self
            .stage
            .compare_exchange(stage, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Err(AuthKeyStoreError::Backend(
                "injected response loss after actual apply".into(),
            ));
        }
        Ok(applied)
    }
}
fn der(pem: &[u8]) -> Vec<u8> {
    ::pem::parse(pem).unwrap().into_contents()
}
async fn connect(addr: &str, ca: &[u8], cert: &[u8], key: &[u8]) -> ZoneApiServiceClient<Channel> {
    ZoneApiServiceClient::new(
        Endpoint::from_shared(format!("https://{addr}"))
            .unwrap()
            .timeout(Duration::from_secs(5))
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name("localhost")
                    .ca_certificate(Certificate::from_pem(ca))
                    .identity(Identity::from_pem(cert, key)),
            )
            .unwrap()
            .connect()
            .await
            .unwrap(),
    )
}
fn request(ca: &[u8], name: &str) -> (AgentCsrRequest, rcgen::KeyPair) {
    let key = rcgen::KeyPair::generate().unwrap();
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    (
        AgentCsrRequest {
            agent_name: name.into(),
            owner_id: "existing-product-owner".into(),
            display_name: "原设备 Agent".into(),
            operation_id: format!("original-{name}"),
            csr_pem: csr.into_bytes(),
            issuer_sha256: Sha256::digest(der(ca)).to_vec(),
        },
        key,
    )
}
fn state(reply: &AgentCsrResponse, expected: AgentCsrState) {
    assert_eq!(
        reply.state, expected as i32,
        "unexpected CSR state: {reply:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_mtls_issuance_preserves_original_key_and_reconciles_both_lost_replies() {
    let private = tempfile::tempdir().unwrap();
    let tls = private.path().join("tls");
    std::fs::create_dir(&tls).unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    std::fs::write(tls.join("ca.pem"), &ca).unwrap();
    std::fs::write(tls.join("ca-key.pem"), &ca_key).unwrap();
    let registry = Arc::new(ZoneRaftRegistry::new(private.path().join("raft"), 1));
    let runtime = tokio::runtime::Handle::current();
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !node.is_leader() || node.applied_index() < node.last_index() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("singleton must apply its leader entry before ReadIndex");
    let store = Arc::new(LoseReply {
        inner: RaftAuthKeyStore::new_arc(node.clone(), runtime),
        stage: AtomicU8::new(0),
    });
    let verifier = lib::transport_primitives::FederatedClientCertVerifier::new(&ca).unwrap();
    let peer_slot = Arc::new(std::sync::OnceLock::new());
    peer_slot.set(verifier.clone()).unwrap();
    let minter = Arc::new(FounderAgentMinter {
        store: store.clone(),
        tls_dir: tls.clone(),
        data_dir: private.path().to_path_buf(),
        session_allow: nexus_raft::session_mint_allow_store::new_session_mint_allow_slot(),
        peer_verifier: peer_slot,
    });
    let slot = nexus_raft::agent_minter::new_agent_minter_slot();
    *slot.write() = Some(minter);
    let (server_cert, server_key) = generate_node_cert(1, "root", &ca, &ca_key, &[], None).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = port.local_addr().unwrap().to_string();
    drop(port);
    let server = RaftGrpcServer::new(
        registry.clone(),
        ServerConfig {
            bind_address: address.parse().unwrap(),
            tls: Some(TlsConfig {
                ca_pem: ca.clone(),
                cert_pem: server_cert,
                key_pem: server_key,
            }),
            ..Default::default()
        },
    )
    .with_agent_minter_slot(slot)
    .with_foreign_ca_verifier(Some(verifier.clone()));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        server
            .serve_with_shutdown(async {
                stopped
                    .await
                    .expect("fixture shutdown must be explicitly signaled");
            })
            .await
            .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while tokio::net::TcpStream::connect(&address).await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let (node_cert, node_key) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let mut operator = connect(&address, &ca, &node_cert, &node_key).await;
    let caps = operator
        .get_agent_csr_capabilities(AgentCsrCapabilitiesRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(caps.version, 1);
    assert_eq!(caps.issuer_sha256, Sha256::digest(der(&ca)).to_vec());

    let binding = nexus_raft::agent_csr_client::AgentCsrBinding {
        agent_name: "existing-product-agent",
        owner_id: "existing-product-owner",
        display_name: "原设备 Agent",
        operation_id: "original-existing-product-agent",
    };
    let pending_path = private.path().join("caller-pending.json");
    let pending =
        nexus_raft::agent_csr_client::PendingAgentCsr::create(&pending_path, &binding, &ca)
            .unwrap();
    let first = pending.request().clone();
    let original_pending_bytes = std::fs::read(&pending_path).unwrap();
    drop(pending);
    state(
        &operator
            .query_agent_csr_v1(first.clone())
            .await
            .unwrap()
            .into_inner(),
        AgentCsrState::NotObserved,
    );
    // If preparation or losing I ever read/sign with the CA key, this fails.
    std::fs::rename(tls.join("ca-key.pem"), tls.join("held-key.pem")).unwrap();
    store.stage.store(1, Ordering::SeqCst);
    state(
        &operator
            .issue_agent_csr_v1(first.clone())
            .await
            .unwrap()
            .into_inner(),
        AgentCsrState::Unknown,
    );
    let committed = operator
        .query_agent_csr_v1(first.clone())
        .await
        .unwrap()
        .into_inner();
    state(&committed, AgentCsrState::IntentCommitted);
    assert!(committed.certificate_der.is_empty());
    // A different process can recover the same persisted operation after the
    // actual I-apply reply was lost. No replacement key or request is created.
    let pending =
        nexus_raft::agent_csr_client::PendingAgentCsr::load(&pending_path, &binding, &ca).unwrap();
    assert_eq!(pending.request(), &first);
    let bundle = private.path().join("caller-bundle");
    assert!(pending.publish(&committed, &bundle).is_err());
    assert!(!bundle.exists());
    std::fs::rename(tls.join("held-key.pem"), tls.join("ca-key.pem")).unwrap();
    let final_reply = operator
        .issue_agent_csr_v1(first.clone())
        .await
        .unwrap()
        .into_inner();
    state(&final_reply, AgentCsrState::Finalized);
    assert_eq!(final_reply.serial, committed.serial);
    assert_eq!(final_reply.intent_sha256, committed.intent_sha256);
    let manifest = pending.publish(&final_reply, &bundle).unwrap();
    let loaded = lib::transport_primitives::AgentCredential::load(&manifest).unwrap();
    let original_key =
        rcgen::KeyPair::from_pem(std::str::from_utf8(&loaded.key_pem).unwrap()).unwrap();
    assert_eq!(loaded.agent, binding.agent_name);
    assert_eq!(
        std::fs::read(&pending_path).unwrap(),
        original_pending_bytes
    );
    assert_eq!(pending.publish(&final_reply, &bundle).unwrap(), manifest);
    let (_, certificate) = X509Certificate::from_der(&final_reply.certificate_der).unwrap();
    use rcgen::PublicKeyData;
    assert_eq!(
        certificate.public_key().subject_public_key.data.as_ref(),
        original_key.der_bytes()
    );
    let ca_der = der(&ca);
    let (_, parsed_ca) = X509Certificate::from_der(&ca_der).unwrap();
    certificate
        .verify_signature(Some(parsed_ca.public_key()))
        .unwrap();
    // F replay does not require signing material or generate another serial.
    std::fs::rename(tls.join("ca-key.pem"), tls.join("held-key.pem")).unwrap();
    let replay = operator
        .issue_agent_csr_v1(first.clone())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay, final_reply);
    std::fs::rename(tls.join("held-key.pem"), tls.join("ca-key.pem")).unwrap();
    let mut changed = first.clone();
    changed.display_name.push('!');
    state(
        &operator
            .issue_agent_csr_v1(changed)
            .await
            .unwrap()
            .into_inner(),
        AgentCsrState::Unknown,
    );

    let (second, _) = request(&ca, "second-product-agent");
    store.stage.store(2, Ordering::SeqCst);
    state(
        &operator
            .issue_agent_csr_v1(second.clone())
            .await
            .unwrap()
            .into_inner(),
        AgentCsrState::Unknown,
    );
    let recovered = operator
        .query_agent_csr_v1(second.clone())
        .await
        .unwrap()
        .into_inner();
    state(&recovered, AgentCsrState::Finalized);
    assert_eq!(
        operator
            .issue_agent_csr_v1(second)
            .await
            .unwrap()
            .into_inner(),
        recovered
    );

    // Existing ordinary credentials cannot invoke the Node-only CSR door.
    let (agent, agent_key) = generate_agent_cert("frontend", &ca, &ca_key).unwrap();
    let mut frontend = connect(&address, &ca, &agent, &agent_key).await;
    assert_eq!(
        frontend
            .issue_agent_csr_v1(first.clone())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let (other_node, other_key) = generate_node_cert(3, "root", &ca, &ca_key, &[], None).unwrap();
    let mut another_operator = connect(&address, &ca, &other_node, &other_key).await;
    state(
        &another_operator
            .query_agent_csr_v1(first.clone())
            .await
            .unwrap()
            .into_inner(),
        AgentCsrState::Unknown,
    );
    // An existing unmanaged claim is never adopted or overwritten by CSR.
    let legacy_store: Arc<dyn AuthKeyStore> = store.clone();
    tokio::task::spawn_blocking(move || {
        auth::mint_agent_authz(
            &legacy_store,
            auth::AuthKeyRecord {
                key_id: "original-legacy-id".into(),
                name: "existing legacy actor".into(),
                subject_type: auth::SubjectType::Agent,
                subject_id: "occupied-legacy".into(),
                is_admin: false,
                revoked: false,
                expires_at_ms: None,
                zone_perms: vec![],
            },
            false,
        )
    })
    .await
    .unwrap()
    .unwrap();
    let legacy_before = store.get("agent:occupied-legacy").unwrap();
    let (legacy_request, _) = request(&ca, "occupied-legacy");
    state(
        &operator
            .issue_agent_csr_v1(legacy_request)
            .await
            .unwrap()
            .into_inner(),
        AgentCsrState::Unknown,
    );
    assert_eq!(store.get("agent:occupied-legacy").unwrap(), legacy_before);
    let crl = revoked_serials_path(private.path());
    std::fs::write(&crl, "malformed revocation state\n").unwrap();
    state(
        &operator
            .query_agent_csr_v1(first.clone())
            .await
            .unwrap()
            .into_inner(),
        AgentCsrState::NotSubmitted,
    );
    std::fs::write(&crl, "").unwrap();
    // Current revocation is checked even on this already-established channel.
    let serial = nexus_raft::transport::serial_from_cert_pem(&node_cert).unwrap();
    nexus_raft::transport::add_revoked_serial(&revoked_serials_path(private.path()), &serial)
        .unwrap();
    state(
        &operator
            .query_agent_csr_v1(first.clone())
            .await
            .unwrap()
            .into_inner(),
        AgentCsrState::NotSubmitted,
    );
    state(
        &operator
            .issue_agent_csr_v1(first)
            .await
            .unwrap()
            .into_inner(),
        AgentCsrState::NotSubmitted,
    );
    assert_eq!(
        store.list().unwrap().len(),
        5,
        "only two immutable I/F pairs plus the original legacy row may exist"
    );
    stop.send(()).unwrap();
    running.await.unwrap();
    drop(operator);
    drop(frontend);
    drop(another_operator);
    drop(store);
    drop(node);
    registry.shutdown_all();
    drop(registry);
    tokio::time::sleep(Duration::from_millis(500)).await;
}
