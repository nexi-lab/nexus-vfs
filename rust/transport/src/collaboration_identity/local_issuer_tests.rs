use super::*;
use contracts::crl_control::{
    CrlControlChange, CrlControlOutcome, CrlControlRequest, CrlIssuerSelection,
};
use futures::StreamExt;
use kernel::kernel::{
    vfs_proto::{
        nexus_vfs_service_client::NexusVfsServiceClient,
        nexus_vfs_service_server::NexusVfsServiceServer, PingRequest,
    },
    Kernel,
};
use lib::transport_primitives::{federated_tls_incoming, server_config, verify_signed_crl};
use nexus_raft::{
    collaboration_crl::RaftCollaborationCrlStore, transport::generate_crl, ZoneManager,
};
use std::sync::{Arc, Mutex, OnceLock};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server};

struct LiveAdmission {
    client: NexusVfsServiceClient<Channel>,
    handshakes: Arc<AtomicUsize>,
    admitted: Arc<Mutex<Vec<CertificateAgent>>>,
    stop: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<()>,
}

impl LiveAdmission {
    async fn close(self) {
        self.stop.send(()).unwrap();
        drop(self.client);
        self.server.await.unwrap();
    }
}

async fn connect(
    ca: &[u8],
    store: Arc<RaftCollaborationCrlStore>,
    server_cert: &[u8],
    server_key: &[u8],
    client_cert: &[u8],
    client_key: &[u8],
) -> LiveAdmission {
    let verifier = FederatedClientCertVerifier::new(ca).unwrap();
    let current = Arc::new(
        crate::collaboration_authority::RaftCurrentAgentAuthority::new(ca.to_vec(), store).unwrap(),
    );
    let slot = Arc::new(OnceLock::new());
    slot.set(verifier.clone()).unwrap();
    // This fixture exercises the existing request identity entry over Ping.
    // Space authorization and installed collaboration data I/O are separate.
    struct PingPeer;
    impl crate::auth::AuthProvider for PingPeer {
        fn resolve(
            &self,
            credentials: &crate::auth::AuthCredentials<'_>,
        ) -> Result<contracts::OperationContext, tonic::Status> {
            if !credentials.token.is_empty() {
                return Err(tonic::Status::unauthenticated("no bearer in this fixture"));
            }
            let agent = credentials
                .peer
                .and_then(|peer| peer.resolved_agent_id())
                .ok_or_else(|| tonic::Status::unauthenticated("Agent peer required"))?;
            Ok(contracts::OperationContext::new(
                &agent,
                "root",
                false,
                Some(&agent),
                false,
            ))
        }
    }
    let service = crate::grpc::build_vfs_service(
        Arc::new(Kernel::new()),
        Arc::new(PingPeer),
        slot,
        crate::grpc::DataPlaneReady::open(),
        "current-local-issuer-fixture",
        None,
    );
    let admitted = Arc::new(Mutex::new(Vec::new()));
    let gate_admitted = admitted.clone();
    let gate_verifier = verifier.clone();
    let service = NexusVfsServiceServer::with_interceptor(service, move |request: Request<()>| {
        let (metadata, extensions, ()) = request.into_parts();
        let request = Request::from_parts(metadata, extensions, PingRequest::default());
        let principal = authenticate_request(&request, &gate_verifier, current.as_ref())
            .map_err(|error| tonic::Status::permission_denied(format!("{error:?}")))?;
        gate_admitted
            .lock()
            .unwrap()
            .push(principal.certificate().clone());
        let (metadata, extensions, _) = request.into_parts();
        Ok(Request::from_parts(metadata, extensions, ()))
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handshakes = Arc::new(AtomicUsize::new(0));
    let count = handshakes.clone();
    let incoming = federated_tls_incoming(
        listener,
        Arc::new(server_config(verifier, server_cert, server_key).unwrap()),
    )
    .map(move |result| {
        if result.is_ok() {
            count.fetch_add(1, Ordering::SeqCst);
        }
        result
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let channel = Endpoint::from_shared(format!("https://{address}"))
        .unwrap()
        .timeout(std::time::Duration::from_secs(5))
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(Certificate::from_pem(ca))
                .identity(Identity::from_pem(client_cert, client_key)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    LiveAdmission {
        client: NexusVfsServiceClient::new(channel),
        handshakes,
        admitted,
        stop,
        server,
    }
}

fn set_issuer(
    store: &RaftCollaborationCrlStore,
    operation: &str,
    expected: Option<u64>,
    ca: Option<&[u8]>,
) -> CrlControlRequest {
    let request = CrlControlRequest {
        operation_id: operation.into(),
        change: CrlControlChange::LocalIssuer {
            expected_revision: expected,
            ca_pem: ca.map(<[u8]>::to_vec),
        },
    };
    assert!(matches!(
        store.apply_control(&request).unwrap(),
        CrlControlOutcome::LocalIssuerChanged(_)
    ));
    request
}

fn install_crl(
    store: &RaftCollaborationCrlStore,
    revision: u64,
    ca: &[u8],
    key: &[u8],
    number: u64,
) -> Vec<u8> {
    let crl = generate_crl(&[], number, ca, key).unwrap();
    let now: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();
    assert!(matches!(
        store
            .apply_control(&CrlControlRequest {
                operation_id: format!("live-local-crl-{number}"),
                change: CrlControlChange::Install {
                    issuer: CrlIssuerSelection::Local { revision },
                    crl_pem: crl.clone(),
                    observed_unix_s: now,
                    maximum_age_secs: 60
                },
            })
            .unwrap(),
        CrlControlOutcome::Installed { .. }
    ));
    crl
}

async fn refused(client: &mut NexusVfsServiceClient<Channel>, reason: &str) {
    let result = client.ping(PingRequest::default()).await;
    let error = match result {
        Ok(_) => panic!("{reason}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        error.message(),
        "CurrentAuthorityDenied",
        "refusal must come from current native authority"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn established_local_mtls_observes_withdrawal_and_same_key_replacement() {
    use rcgen::{DistinguishedName, DnType, KeyUsagePurpose};
    let directory = tempfile::tempdir().unwrap();
    // The current typed protocol supports FixedLocal. This genuine native
    // consumer fixture does not claim Managed control-zone activation.
    let manager = ZoneManager::isolated(directory.path().to_str().unwrap()).unwrap();
    let registry = manager.registry();
    let runtime = manager.runtime_handle();
    let node = registry
        .create_zone(contracts::ROOT_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !node.is_leader() || node.applied_index() < node.last_index() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let crls = Arc::new(RaftCollaborationCrlStore::new(node, runtime, 60).unwrap());
    let (ca, key) = generate_zone_ca("current-local-tls").unwrap();
    let (server_cert, server_key) = generate_node_cert(1, "root", &ca, &key, &[], None).unwrap();
    let (client_cert, client_key) = generate_agent_cert("retained-local-agent", &ca, &key).unwrap();
    let original = set_issuer(&crls, "live-local-issuer", None, Some(&ca));
    install_crl(&crls, 1, &ca, &key, 1);
    let mut live = connect(
        &ca,
        crls.clone(),
        &server_cert,
        &server_key,
        &client_cert,
        &client_key,
    )
    .await;
    live.client.ping(PingRequest::default()).await.unwrap();
    let identity = live.admitted.lock().unwrap()[0].clone();
    assert_eq!(identity.trust_domain(), None);
    assert_eq!(
        identity.issuer_sha256(),
        &ForeignCaAnchor::new("local", der(&ca)).fingerprint()
    );

    set_issuer(&crls, "live-withdraw-local", Some(1), None);
    crls.check_serial(&ca, identity.serial()).unwrap();
    refused(
        &mut live.client,
        "withdrawn issuer must refuse on the established TLS connection",
    )
    .await;
    let original_outcome = crls.reconcile_control(&original).unwrap().unwrap();
    assert_eq!(crls.apply_control(&original).unwrap(), original_outcome);
    refused(
        &mut live.client,
        "historical issuer receipt must not reactivate the connection",
    )
    .await;
    assert_eq!(live.admitted.lock().unwrap().len(), 1);

    set_issuer(&crls, "live-reinstall-original", Some(2), Some(&ca));
    let retained_crl = install_crl(&crls, 3, &ca, &key, 2);
    live.client.ping(PingRequest::default()).await.unwrap();
    assert_eq!(live.admitted.lock().unwrap().len(), 2);

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Nexus");
    dn.push(DnType::CommonName, "nexus-zone-current-local-tls-ca");
    params.distinguished_name = dn;
    params.not_after = rcgen::date_time_ymd(2045, 1, 1);
    let same_key = KeyPair::from_pem(std::str::from_utf8(&key).unwrap()).unwrap();
    let replacement = params.self_signed(&same_key).unwrap().pem().into_bytes();
    assert_ne!(der(&replacement), der(&ca));
    assert_eq!(
        lib::transport_primitives::ca_spki_sha256(&replacement).unwrap(),
        *identity.address().authority()
    );
    verify_signed_crl(&retained_crl, &replacement).unwrap();
    set_issuer(&crls, "live-replace-local", Some(3), Some(&replacement));
    crls.check_serial(&ca, identity.serial()).unwrap();
    refused(
        &mut live.client,
        "same-key replacement must refuse the retained full TLS issuer",
    )
    .await;
    assert_eq!(live.admitted.lock().unwrap().len(), 2);
    assert_eq!(
        live.handshakes.load(Ordering::SeqCst),
        1,
        "original channel has no reconnect or retry"
    );

    install_crl(&crls, 4, &replacement, &key, 3);
    // A second real TLS listener selects the replacement anchor. Reuse the
    // same leaf and key so a signature/serial difference cannot mask the test.
    let mut current = connect(
        &replacement,
        crls.clone(),
        &server_cert,
        &server_key,
        &client_cert,
        &client_key,
    )
    .await;
    current.client.ping(PingRequest::default()).await.unwrap();
    let selected = current.admitted.lock().unwrap()[0].clone();
    assert_eq!(selected.address(), identity.address());
    assert_eq!(selected.leaf_sha256(), identity.leaf_sha256());
    assert_ne!(selected.issuer_sha256(), identity.issuer_sha256());
    assert_eq!(
        selected.issuer_sha256(),
        &ForeignCaAnchor::new("local", der(&replacement)).fingerprint()
    );
    assert_eq!(current.handshakes.load(Ordering::SeqCst), 1);
    current.close().await;
    live.close().await;
    drop(crls);
    registry.shutdown().released().await;
    manager.shutdown();
}
