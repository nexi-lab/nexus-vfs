//! Versioned wire routing uses actual loopback gRPC and the production client.
use super::*;
use nexus_raft::transport::{ClientConfig, NodeAddress, RaftClientPool, TransportError};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tonic::{
    body::Body,
    codegen::{http, BoxFuture, Service},
    server::NamedService,
    Status,
};

fn message(from: u64, to: u64) -> Vec<u8> {
    let mut message = raft::eraftpb::Message::default();
    message.set_msg_type(raft::eraftpb::MessageType::MsgHeartbeatResponse);
    message.from = from;
    message.to = to;
    message.term = 1;
    message.write_to_bytes().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versioned_step_retains_sender_identity_and_storage_activation_gates() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let (cert, server_key) = generate_node_cert(7, "root", &ca, &key, &[], None).unwrap();
    let server = PeerServer::start(TlsConfig {
        ca_pem: ca.clone(),
        cert_pem: cert,
        key_pem: server_key,
    })
    .await;
    let (cert, client_key) = generate_node_cert(2, "root", &ca, &key, &[], None).unwrap();
    let pool = RaftClientPool::with_config(ClientConfig {
        tls: Arc::new(std::sync::RwLock::new(Some(TlsConfig {
            ca_pem: ca.clone(),
            cert_pem: cert.clone(),
            key_pem: client_key.clone(),
        }))),
        ..Default::default()
    });
    let peer = NodeAddress::new(7, server.endpoint.clone());
    let mut client = pool.get(&peer).await.unwrap();
    client
        .step_storage_v1(message(2, 7), "root".into(), "127.0.0.1:19998".into())
        .await
        .unwrap();
    assert!(server.registry.get_peers("root").unwrap().contains_key(&2));
    let error = client
        .step_storage_v1(message(9, 7), "unopened".into(), "127.0.0.1:19999".into())
        .await
        .unwrap_err();
    assert!(
        matches!(error, TransportError::Status(ref status) if status.code() == tonic::Code::PermissionDenied)
    );
    assert!(server.registry.get_node("unopened").is_none());
    client
        .step_storage_v1(message(2, 7), "unopened".into(), "127.0.0.1:19998".into())
        .await
        .unwrap();
    assert!(server.registry.get_node("unopened").is_some());
    assert!(server
        .registry
        .get_peers("unopened")
        .unwrap()
        .contains_key(&2));
    assert!(!server.registry.get_peers("root").unwrap().contains_key(&9));

    let node = server.registry.get_node("root").unwrap();
    let before = node.last_index();
    let command =
        Command::ReserveNodeIdentity(Box::new(contracts::node_identity::NodeIdentityRequest {
            operation_id: "unactivated-wire".into(),
            identity: contracts::node_identity::NodeIdentity {
                node_id: 42,
                subject_public_key_sha256: [4; 32],
            },
        }));
    let mut protected = raft::eraftpb::Message::default();
    protected.set_msg_type(raft::eraftpb::MessageType::MsgPropose);
    protected.from = 2;
    protected.to = 7;
    let mut entry = raft::eraftpb::Entry::default();
    let mut bytes = 0_u64.to_be_bytes().to_vec();
    bytes.extend(bincode::serialize(&command).unwrap());
    entry.data = bytes.into();
    protected.entries.push(entry);
    let error = client
        .step_storage_v1(
            protected.write_to_bytes().unwrap(),
            "root".into(),
            String::new(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, TransportError::Rpc(ref reason) if reason.contains("qualified fixed-local storage"))
    );
    assert_eq!(node.last_index(), before);
    let identities = nexus_raft::replica_binding_store::RaftReplicaBindingStore::new(
        node.clone(),
        tokio::runtime::Handle::current(),
    );
    assert!(identities.node_identity(42).unwrap().is_none());

    let address = server.endpoint.strip_prefix("http://").unwrap();
    let (agent, agent_key) = generate_agent_cert("ordinary-agent", &ca, &key).unwrap();
    let mut raw = ZoneTransportServiceClient::new(connect(address, &ca, agent, agent_key).await);
    let refusal = raw
        .step_storage_v1(StepMessageRequest {
            message: vec![0xff],
            zone_id: "root".into(),
            sender_address: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
    drop(raw);
    drop(client);
    drop(pool);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versioned_step_checks_current_replica_zone_membership_on_the_same_channel() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let (cert, server_key) = generate_node_cert(7, "root", &ca, &key, &[], None).unwrap();
    let server = PeerServer::start(TlsConfig {
        ca_pem: ca.clone(),
        cert_pem: cert,
        key_pem: server_key,
    })
    .await;
    let node = server
        .registry
        .create_zone("shared", &tokio::runtime::Handle::current())
        .unwrap();
    node.campaign().await.unwrap();
    node.propose_conf_change(raft::eraftpb::ConfChangeType::AddLearnerNode, 4, Vec::new())
        .await
        .unwrap();
    let (cert, replica_key) =
        generate_user_replica_cert("replica", "alice", 4, 300, &ca, &key).unwrap();
    let address = server.endpoint.strip_prefix("http://").unwrap();
    let mut client =
        ZoneTransportServiceClient::new(connect(address, &ca, cert, replica_key).await);
    let request = |zone: &str| StepMessageRequest {
        message: message(4, 7),
        zone_id: zone.into(),
        sender_address: "127.0.0.1:19994".into(),
    };
    assert!(
        client
            .step_storage_v1(request("shared"))
            .await
            .unwrap()
            .into_inner()
            .success
    );
    for zone in ["root", "unadmitted"] {
        assert_eq!(
            client
                .step_storage_v1(request(zone))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
    assert!(server.registry.get_node("unadmitted").is_none());
    node.propose_conf_change(raft::eraftpb::ConfChangeType::RemoveNode, 4, Vec::new())
        .await
        .unwrap();
    assert_eq!(
        client
            .step_storage_v1(request("shared"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    drop(client);
    server.shutdown().await;
}

/// An actual legacy gRPC route table: only StepMessage has a decoder/handler.
/// Unknown methods return Unimplemented before the protobuf body is decoded.
#[derive(Clone)]
struct LegacyTransport {
    legacy_calls: Arc<AtomicUsize>,
    unsupported_calls: Arc<AtomicUsize>,
}

impl NamedService for LegacyTransport {
    const NAME: &'static str = "nexus.raft.ZoneTransportService";
}

impl Service<http::Request<Body>> for LegacyTransport {
    type Response = http::Response<Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        if request.uri().path() != "/nexus.raft.ZoneTransportService/StepMessage" {
            self.unsupported_calls.fetch_add(1, Ordering::SeqCst);
            return Box::pin(async {
                Ok(Status::unimplemented("legacy method table").into_http())
            });
        }
        struct Step(Arc<AtomicUsize>);
        impl tonic::server::UnaryService<StepMessageRequest> for Step {
            type Response = nexus_raft::transport::proto::StepMessageResponse;
            type Future = BoxFuture<tonic::Response<Self::Response>, Status>;
            fn call(&mut self, _: tonic::Request<StepMessageRequest>) -> Self::Future {
                self.0.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    Ok(tonic::Response::new(Self::Response {
                        success: true,
                        error: None,
                    }))
                })
            }
        }
        let step = Step(self.legacy_calls.clone());
        Box::pin(async move {
            let codec = tonic_prost::ProstCodec::default();
            Ok(tonic::server::Grpc::new(codec).unary(step, request).await)
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versioned_client_never_falls_back_on_legacy_peer_or_reconnect() {
    let address = common::node_bind_addr();
    let legacy = Arc::new(AtomicUsize::new(0));
    let unsupported = Arc::new(AtomicUsize::new(0));
    let pool = RaftClientPool::new();
    let peer = NodeAddress::new(7, format!("http://{address}"));
    let directory = tempfile::tempdir().unwrap();
    let registry = Arc::new(ZoneRaftRegistry::new(directory.path().to_path_buf(), 7));
    let node = registry
        .create_zone("root", &tokio::runtime::Handle::current())
        .unwrap();
    node.campaign().await.unwrap();
    let server = RaftGrpcServer::new(
        registry.clone(),
        ServerConfig {
            bind_address: address.parse().unwrap(),
            ..Default::default()
        },
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let current = tokio::spawn(async move {
        server
            .serve_with_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    listener_ready(&address).await;
    let mut client = pool.get(&peer).await.unwrap();
    client
        .step_storage_v1(message(2, 7), "root".into(), "127.0.0.1:19992".into())
        .await
        .unwrap();
    assert!(registry.get_peers("root").unwrap().contains_key(&2));
    drop(client);
    pool.remove(7).await;
    stop.send(()).unwrap();
    current.await.unwrap();
    registry.shutdown_all();
    // Each iteration replaces the actual listening server at the same address.
    // Pool eviction uses the same recovery entry used by transport send errors.
    for _ in 0..2 {
        let service = LegacyTransport {
            legacy_calls: legacy.clone(),
            unsupported_calls: unsupported.clone(),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let socket = address.parse().unwrap();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_shutdown(socket, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        listener_ready(&address).await;
        let mut client = pool.get(&peer).await.unwrap();
        let baseline = legacy.load(Ordering::SeqCst);
        client
            .step_message(message(2, 7), "root".into(), String::new())
            .await
            .unwrap();
        assert_eq!(legacy.load(Ordering::SeqCst), baseline + 1);
        for _ in 0..2 {
            let before = unsupported.load(Ordering::SeqCst);
            let outcome = client
                .step_storage_v1(vec![0xff], "root".into(), String::new())
                .await;
            assert_eq!(
                legacy.load(Ordering::SeqCst),
                baseline + 1,
                "versioned call reached legacy decoder"
            );
            assert!(matches!(outcome, Err(TransportError::Status(ref status))
                if status.code() == tonic::Code::Unimplemented));
            assert_eq!(unsupported.load(Ordering::SeqCst), before + 1);
        }
        drop(client);
        pool.remove(7).await;
        stop.send(()).unwrap();
        task.await.unwrap();
    }
    assert_eq!(legacy.load(Ordering::SeqCst), 2);
    assert_eq!(unsupported.load(Ordering::SeqCst), 4);
}
