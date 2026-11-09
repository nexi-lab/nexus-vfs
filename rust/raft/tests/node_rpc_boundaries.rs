//! Real mTLS control-plane refusal, not an Agent/VFS mock. All CA keys and
//! consensus data are isolated; no fleet endpoint or model is used.
#![cfg(all(feature = "grpc", has_protos))]
mod common;

use lib::transport_primitives::{FederatedClientCertVerifier, ForeignCaAnchor};
use nexus_raft::transport::proto::{
    zone_api_service_client::ZoneApiServiceClient,
    zone_transport_service_client::ZoneTransportServiceClient, EcReplicationEntry,
    MintSessionAgentRequest, ProposeRequest, ReplicateEntriesRequest, SnapshotEcStateRequest,
    StepMessageRequest,
};
use nexus_raft::{
    prelude::Command,
    raft::ZoneRaftRegistry,
    transport::{
        generate_agent_cert, generate_node_cert, generate_user_replica_cert, generate_zone_ca,
        RaftGrpcServer, RaftWitnessServer, ServerConfig, TlsConfig, WitnessZoneRegistry,
    },
};
use protobuf::Message as _;
use std::{sync::Arc, time::Duration};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

async fn connect(address: &str, ca: &[u8], cert: Vec<u8>, key: Vec<u8>) -> Channel {
    Endpoint::from_shared(format!("https://{address}"))
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
        .unwrap()
}

async fn listener_ready(address: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("isolated listener must bind");
}

struct PeerServer {
    _directory: tempfile::TempDir,
    registry: Arc<ZoneRaftRegistry>,
    endpoint: String,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl PeerServer {
    async fn start(tls: TlsConfig) -> Self {
        lib::transport_primitives::ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let registry = Arc::new(ZoneRaftRegistry::new(directory.path().to_path_buf(), 7));
        let root = registry
            .create_zone("root", vec![], &tokio::runtime::Handle::current())
            .unwrap();
        root.campaign().await.unwrap();
        let address = common::node_bind_addr();
        let server = RaftGrpcServer::new(
            registry.clone(),
            ServerConfig {
                bind_address: address.parse().unwrap(),
                tls: Some(tls),
                ..Default::default()
            },
        );
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .serve_with_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        listener_ready(&address).await;
        Self {
            _directory: directory,
            registry,
            endpoint: format!("http://{address}"),
            stop,
            task,
        }
    }

    async fn shutdown(self) {
        self.stop.send(()).unwrap();
        self.task.await.unwrap();
        self.registry.shutdown_all();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outgoing_peer_tls_binds_node_and_owner_replica_before_any_rpc() {
    use lib::transport_primitives::{create_peer_channel, ClientConfig};
    use nexus_raft::transport::{generate_user_runtime_cert, proto::GetClusterInfoRequest};

    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (foreign_ca, foreign_key) = generate_zone_ca("root").unwrap();
    let (client_cert, client_key) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let config = ClientConfig {
        tls: Some(TlsConfig {
            ca_pem: ca.clone(),
            cert_pem: client_cert,
            key_pem: client_key,
        }),
        ..Default::default()
    };
    let cases = [
        (
            "node",
            generate_node_cert(7, "root", &ca, &ca_key, &[], None).unwrap(),
            None,
        ),
        (
            "replica",
            generate_user_replica_cert("peer", "alice", 7, 300, &ca, &ca_key).unwrap(),
            None,
        ),
        (
            "other node",
            generate_node_cert(8, "root", &ca, &ca_key, &[], None).unwrap(),
            Some("server certificate does not name the expected replication peer"),
        ),
        (
            "other replica",
            generate_user_replica_cert("peer", "alice", 8, 300, &ca, &ca_key).unwrap(),
            Some("server certificate does not name the expected replication peer"),
        ),
        (
            "runtime without replica",
            generate_user_runtime_cert("peer", "alice", 300, &ca, &ca_key).unwrap(),
            Some("Node certificate must carry exactly one Nexus identity"),
        ),
        (
            "other issuer",
            generate_node_cert(7, "root", &foreign_ca, &foreign_key, &[], None).unwrap(),
            Some("UnknownIssuer"),
        ),
    ];
    for (label, (cert_pem, key_pem), refusal) in cases {
        let server = PeerServer::start(TlsConfig {
            ca_pem: ca.clone(),
            cert_pem,
            key_pem,
        })
        .await;
        let channel = create_peer_channel(&server.endpoint, &config, 7.try_into().unwrap()).await;
        if let Some(refusal) = refusal {
            let error = channel.expect_err("unexpected peer must fail before any RPC");
            assert!(format!("{error:?}").contains(refusal), "{label}: {error:?}");
        } else {
            let mut rpc = ZoneApiServiceClient::new(channel.unwrap());
            let info = rpc
                .get_cluster_info(GetClusterInfoRequest {
                    zone_id: "root".into(),
                })
                .await
                .unwrap()
                .into_inner();
            assert_eq!(info.node_id, 7, "{label}");
            drop(rpc);
        }
        server.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raft_pool_rechecks_changed_routes_and_tls_before_reusing_a_channel() {
    use nexus_raft::transport::{ClientConfig, NodeAddress, RaftClientPool};

    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert_pem, key_pem) = generate_node_cert(7, "root", &ca, &ca_key, &[], None).unwrap();
    let expected = PeerServer::start(TlsConfig {
        ca_pem: ca.clone(),
        cert_pem,
        key_pem,
    })
    .await;
    let (cert_pem, key_pem) = generate_node_cert(8, "root", &ca, &ca_key, &[], None).unwrap();
    let other = PeerServer::start(TlsConfig {
        ca_pem: ca.clone(),
        cert_pem,
        key_pem,
    })
    .await;
    let (cert_pem, key_pem) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let tls = Arc::new(std::sync::RwLock::new(Some(TlsConfig {
        ca_pem: ca,
        cert_pem,
        key_pem,
    })));
    let pool = RaftClientPool::with_config(ClientConfig {
        tls: tls.clone(),
        ..Default::default()
    });
    let address = NodeAddress::new(7, expected.endpoint.clone());
    drop(
        pool.get(&address)
            .await
            .expect("the expected peer connects"),
    );
    for address in [
        NodeAddress::new(7, other.endpoint.clone()),
        NodeAddress::new(8, expected.endpoint.clone()),
    ] {
        let error = pool
            .get(&address)
            .await
            .err()
            .expect("changed route or requested identity must be rechecked");
        assert!(
            format!("{error:?}")
                .contains("server certificate does not name the expected replication peer"),
            "{error:?}"
        );
    }
    tls.write().unwrap().as_mut().unwrap().ca_pem = generate_zone_ca("root").unwrap().0;
    let error = pool
        .get(&address)
        .await
        .err()
        .expect("changed trust roots must invalidate an established channel");
    assert!(format!("{error:?}").contains("UnknownIssuer"), "{error:?}");
    drop(pool);
    expected.shutdown().await;
    other.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raft_pool_rejects_an_in_flight_dial_after_credentials_change() {
    use nexus_raft::transport::{ClientConfig, NodeAddress, RaftClientPool};

    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert_pem, key_pem) = generate_node_cert(7, "root", &ca, &ca_key, &[], None).unwrap();
    let server = PeerServer::start(TlsConfig {
        ca_pem: ca.clone(),
        cert_pem,
        key_pem,
    })
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = NodeAddress::new(7, format!("http://{}", listener.local_addr().unwrap()));
    let backend = server.endpoint.strip_prefix("http://").unwrap().to_owned();
    let (connected, accepted) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let proxy = tokio::spawn(async move {
        let (mut incoming, _) = listener.accept().await.unwrap();
        connected.send(()).unwrap();
        released.await.unwrap();
        let mut outgoing = tokio::net::TcpStream::connect(backend).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
    });
    let (cert_pem, key_pem) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let tls = Arc::new(std::sync::RwLock::new(Some(TlsConfig {
        ca_pem: ca.clone(),
        cert_pem,
        key_pem,
    })));
    let pool = RaftClientPool::with_config(ClientConfig {
        tls: tls.clone(),
        ..Default::default()
    });
    let old_pool = pool.clone();
    let dial = tokio::spawn(async move { old_pool.get(&address).await });
    tokio::time::timeout(Duration::from_secs(5), accepted)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !dial.is_finished(),
        "the old TLS handshake must still be pending"
    );
    let (cert_pem, key_pem) = generate_node_cert(3, "root", &ca, &ca_key, &[], None).unwrap();
    *tls.write().unwrap() = Some(TlsConfig {
        ca_pem: ca,
        cert_pem,
        key_pem,
    });
    release.send(()).unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), dial)
        .await
        .unwrap()
        .unwrap()
        .err()
        .expect("a dial under the previous identity cannot publish a connection");
    assert!(
        error
            .to_string()
            .contains("TLS configuration changed while connecting"),
        "{error}"
    );
    assert_eq!(pool.connection_count().await, 0);
    drop(pool);
    proxy.abort();
    let _ = proxy.await;
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_local_root_refuses_incremental_ec_and_state_snapshots() {
    let directory = tempfile::tempdir().unwrap();
    let manager = nexus_raft::ZoneManager::isolated(directory.path().to_str().unwrap()).unwrap();
    let root = manager.create_zone_async("root", vec![]).await.unwrap();
    assert!(root.wait_for_leader(Duration::from_secs(5)));
    let node = root.consensus_node();
    node.propose(Command::SetMetadata {
        key: "/private-root".into(),
        value: b"local durable value".to_vec(),
    })
    .await
    .unwrap();
    node.read_linearizable(|_| ()).await.unwrap();
    let original_index = node.last_index();
    let original_wal = node.ec_wal_bounds();
    let address = common::node_bind_addr();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert, key) =
        generate_node_cert(manager.node_id(), "root", &ca, &ca_key, &[], None).unwrap();
    let server = RaftGrpcServer::new(
        manager.registry(),
        ServerConfig {
            bind_address: address.parse().unwrap(),
            tls: Some(TlsConfig {
                cert_pem: cert,
                key_pem: key,
                ca_pem: ca.clone(),
            }),
            ..Default::default()
        },
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let listener = tokio::spawn(server.serve_with_shutdown(async move {
        let _ = stopped.await;
    }));
    listener_ready(&address).await;
    let (cert, key) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let channel = connect(&address, &ca, cert, key).await;
    let mut client = ZoneTransportServiceClient::new(channel);
    let entry = EcReplicationEntry {
        seq: 1,
        command: bincode::serialize(&Command::SetMetadata {
            key: "/private-root".into(),
            value: b"remote overwrite".to_vec(),
        })
        .unwrap(),
        timestamp: u64::MAX,
        node_id: 2,
    };
    let incremental = client
        .replicate_entries(ReplicateEntriesRequest {
            zone_id: "root".into(),
            sender_node_id: 2,
            entries: vec![entry.clone()],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!incremental.success);
    assert_eq!(incremental.applied_up_to, 0);
    let snapshot = client
        .snapshot_ec_state(SnapshotEcStateRequest {
            zone_id: "root".into(),
            sender_node_id: 2,
            entries: vec![entry],
            covering_seq: 1,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!snapshot.success);
    assert_eq!(snapshot.acked_up_to, 0);
    assert_eq!(node.last_index(), original_index);
    assert_eq!(node.ec_wal_bounds(), original_wal);
    assert_eq!(
        node.with_state_machine(|state| state.get_metadata("/private-root"))
            .await
            .unwrap(),
        Some(b"local durable value".to_vec())
    );
    drop(client);
    stop.send(()).unwrap();
    listener.await.unwrap().unwrap();
    manager.shutdown();
}

async fn assert_owner_replica_data_scope(
    registry: &Arc<ZoneRaftRegistry>,
    address: &str,
    ca: &[u8],
    ca_key: &[u8],
) {
    use nexus_raft::transport::proto::{GetClusterInfoRequest, JoinZoneRequest, QueryRequest};
    use raft::eraftpb::{ConfChangeType, Entry, EntryType, MessageType};
    const ZONE: &str = "owner-replica-data";
    let node = registry
        .create_zone(ZONE, vec![], &tokio::runtime::Handle::current())
        .unwrap();
    node.campaign().await.unwrap();
    let membership = node
        .propose_conf_change(ConfChangeType::AddLearnerNode, 4, Vec::new())
        .await
        .unwrap();
    assert!(membership.learners.contains(&4));
    let (cert, key) =
        generate_user_replica_cert("session-member", "alice", 4, 300, ca, ca_key).unwrap();
    let channel = connect(address, ca, cert, key).await;
    let mut member = ZoneApiServiceClient::new(channel.clone());
    let mut proposal = put("member-data");
    proposal.zone_id = ZONE.into();
    assert!(member.propose(proposal).await.unwrap().into_inner().success);
    assert_eq!(
        node.read_linearizable(|sm| sm.get_control_state("node-boundary-fixture", "member-data"))
            .await
            .unwrap()
            .unwrap(),
        Some(b"private fixture value".to_vec())
    );
    assert!(member
        .get_cluster_info(GetClusterInfoRequest {
            zone_id: ZONE.into()
        })
        .await
        .is_ok());
    assert_eq!(
        member
            .join_zone(JoinZoneRequest {
                zone_id: ZONE.into(),
                node_id: 5,
                node_address: String::new(),
                as_learner: true
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let mut member_transport = ZoneTransportServiceClient::new(channel);
    let mut entry = metadata_entry("/member-ec");
    entry.node_id = 4;
    let applied = member_transport
        .replicate_entries(ReplicateEntriesRequest {
            zone_id: ZONE.into(),
            entries: vec![entry],
            sender_node_id: 4,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(applied.success);
    assert_eq!(applied.applied_up_to, 1);
    assert!(node
        .read_linearizable(|sm| sm.get_metadata("/member-ec"))
        .await
        .unwrap()
        .unwrap()
        .is_some());
    let mut membership_proposal = raft::eraftpb::Message {
        from: 4,
        to: 1,
        ..Default::default()
    };
    membership_proposal.set_msg_type(MessageType::MsgPropose);
    let mut change = Entry::default();
    change.set_entry_type(EntryType::EntryConfChangeV2);
    membership_proposal.entries.push(change);
    assert_eq!(
        member_transport
            .step_message(StepMessageRequest {
                zone_id: ZONE.into(),
                message: membership_proposal.write_to_bytes().unwrap(),
                sender_address: String::new(),
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );

    let (cert, key) =
        generate_user_replica_cert("session-outsider", "charlie", 5, 300, ca, ca_key).unwrap();
    let channel = connect(address, ca, cert, key).await;
    let mut outsider = ZoneApiServiceClient::new(channel.clone());
    let mut attempted = put("outsider-data");
    attempted.zone_id = ZONE.into();
    assert_eq!(
        outsider.propose(attempted).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        outsider
            .query(QueryRequest {
                zone_id: ZONE.into(),
                query: None,
                read_from_leader: false
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        outsider
            .get_cluster_info(GetClusterInfoRequest {
                zone_id: ZONE.into()
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let mut transport = ZoneTransportServiceClient::new(channel);
    assert_eq!(
        transport
            .replicate_entries(ReplicateEntriesRequest {
                zone_id: ZONE.into(),
                sender_node_id: 5,
                entries: vec![metadata_entry("/outsider-ec")]
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        transport
            .snapshot_ec_state(SnapshotEcStateRequest {
                zone_id: ZONE.into(),
                sender_node_id: 5,
                covering_seq: 73,
                entries: vec![metadata_entry("/outsider-snapshot")]
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let mut snapshot = raft::eraftpb::Message {
        from: 5,
        to: 1,
        term: 1,
        ..Default::default()
    };
    snapshot.set_msg_type(MessageType::MsgSnapshot);
    snapshot.mut_snapshot().mut_metadata().index = 10;
    snapshot.mut_snapshot().mut_metadata().term = 1;
    snapshot
        .mut_snapshot()
        .mut_metadata()
        .mut_conf_state()
        .voters = vec![1, 5];
    for zone in [ZONE, "unadmitted-data"] {
        assert_eq!(
            transport
                .step_message(StepMessageRequest {
                    zone_id: zone.into(),
                    message: snapshot.write_to_bytes().unwrap(),
                    sender_address: "127.0.0.1:19997".into()
                })
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
    assert!(!registry.hosts("unadmitted-data"));
    assert!(!registry.get_peers(ZONE).unwrap().contains_key(&5));
    for path in ["/outsider-ec", "/outsider-snapshot"] {
        assert!(node
            .read_linearizable(|sm| sm.get_metadata(path))
            .await
            .unwrap()
            .unwrap()
            .is_none());
    }
    node.propose_conf_change(ConfChangeType::RemoveNode, 4, Vec::new())
        .await
        .unwrap();
    assert_eq!(
        member
            .get_cluster_info(GetClusterInfoRequest {
                zone_id: ZONE.into()
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
}

fn put(key: &str) -> ProposeRequest {
    ProposeRequest {
        zone_id: "root".into(),
        request_id: format!("isolated-{key}"),
        command: None,
        forwarded: false,
        raw_command: bincode::serialize(&Command::PutControlState {
            namespace: "node-boundary-fixture".into(),
            key: key.into(),
            value: b"private fixture value".to_vec(),
            if_absent: true,
        })
        .unwrap(),
    }
}

fn metadata_entry(path: &str) -> EcReplicationEntry {
    EcReplicationEntry {
        seq: 1,
        command: bincode::serialize(&Command::SetMetadata {
            key: path.into(),
            value: br#"{"fixture":"node sender boundary"}"#.to_vec(),
        })
        .unwrap(),
        timestamp: 1,
        node_id: 2,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agents_and_foreign_nodes_cannot_propose_or_step_but_local_nodes_can() {
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (foreign, foreign_key) = generate_zone_ca("root").unwrap();
    let (server_cert, server_key) = generate_node_cert(1, "root", &ca, &ca_key, &[], None).unwrap();
    let verifier = FederatedClientCertVerifier::new(&ca).unwrap();
    verifier
        .set_foreign_cas(&[ForeignCaAnchor::from_pem("edge", &foreign).unwrap()])
        .unwrap();
    let private = tempfile::tempdir().unwrap();
    let registry = Arc::new(ZoneRaftRegistry::new(private.path().to_path_buf(), 1));
    let node = registry
        .create_zone("root", vec![], &tokio::runtime::Handle::current())
        .unwrap();
    node.campaign().await.unwrap();
    let address = common::node_bind_addr();
    let server = RaftGrpcServer::new(
        registry.clone(),
        ServerConfig {
            bind_address: address.parse().unwrap(),
            tls: Some(TlsConfig {
                ca_pem: ca.clone(),
                cert_pem: server_cert,
                key_pem: server_key,
            }),
            ..ServerConfig::default()
        },
    )
    .with_foreign_ca_verifier(Some(verifier));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        server
            .serve_with_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap()
    });
    // Readiness only, before any data submission. No RPC/write is retried.
    listener_ready(&address).await;

    let (node_cert, node_key) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let channel = connect(&address, &ca, node_cert, node_key).await;
    let mut local = ZoneApiServiceClient::new(channel.clone());
    assert!(
        local
            .propose(put("local-node"))
            .await
            .unwrap()
            .into_inner()
            .success
    );
    let stored = node
        .read_linearizable(|sm| sm.get_control_state("node-boundary-fixture", "local-node"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored, Some(b"private fixture value".to_vec()));
    drop(local);

    let mut transport = ZoneTransportServiceClient::new(channel);
    let mut message = raft::eraftpb::Message::default();
    message.set_msg_type(raft::eraftpb::MessageType::MsgHeartbeatResponse);
    message.set_from(7);
    message.set_to(1);
    message.set_term(1);
    let step = transport
        .step_message(StepMessageRequest {
            message: message.write_to_bytes().unwrap(),
            zone_id: "root".into(),
            sender_address: "127.0.0.1:19999".into(),
        })
        .await;
    let incremental = transport
        .replicate_entries(ReplicateEntriesRequest {
            zone_id: "root".into(),
            entries: vec![metadata_entry("/forged-incremental")],
            sender_node_id: 7,
        })
        .await;
    let snapshot = transport
        .snapshot_ec_state(SnapshotEcStateRequest {
            zone_id: "root".into(),
            entries: vec![metadata_entry("/forged-snapshot")],
            covering_seq: 73,
            sender_node_id: 7,
        })
        .await;
    let outcomes = [
        step.map(|_| ()),
        incremental.map(|_| ()),
        snapshot.map(|_| ()),
    ];
    assert!(
        outcomes.iter().all(
            |result| matches!(result, Err(status) if status.code() == tonic::Code::PermissionDenied)
        ),
        "Node 2 must not submit Raft or EC as Node 7: {outcomes:?}"
    );
    assert!(
        !registry.get_peers("root").unwrap().contains_key(&7),
        "refusal must precede learning the forged sender address"
    );
    for path in ["/forged-incremental", "/forged-snapshot"] {
        assert_eq!(
            node.read_linearizable(|sm| sm.get_metadata(path))
                .await
                .unwrap()
                .unwrap(),
            None,
            "refusal must precede applying metadata"
        );
    }

    let unopened_zone = "forged-unopened-zone";
    assert!(registry.get_node(unopened_zone).is_none());
    let refusal = transport
        .step_message(StepMessageRequest {
            message: message.write_to_bytes().unwrap(),
            zone_id: unopened_zone.into(),
            sender_address: "127.0.0.1:19999".into(),
        })
        .await
        .expect_err("sender refusal must precede zone auto-join");
    assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
    assert!(registry.get_node(unopened_zone).is_none());
    assert!(!private.path().join(unopened_zone).exists());

    message.set_from(2);
    transport
        .step_message(StepMessageRequest {
            message: message.write_to_bytes().unwrap(),
            zone_id: "root".into(),
            sender_address: "127.0.0.1:19998".into(),
        })
        .await
        .unwrap();
    assert!(registry.get_peers("root").unwrap().contains_key(&2));
    assert!(
        transport
            .replicate_entries(ReplicateEntriesRequest {
                zone_id: "root".into(),
                entries: vec![metadata_entry("/accepted-incremental")],
                sender_node_id: 2,
            })
            .await
            .unwrap()
            .into_inner()
            .success
    );
    assert_eq!(
        transport
            .snapshot_ec_state(SnapshotEcStateRequest {
                zone_id: "root".into(),
                entries: vec![metadata_entry("/accepted-snapshot")],
                covering_seq: 74,
                sender_node_id: 2,
            })
            .await
            .unwrap()
            .into_inner()
            .acked_up_to,
        74
    );
    for path in ["/accepted-incremental", "/accepted-snapshot"] {
        assert_eq!(
            node.read_linearizable(|sm| sm.get_metadata(path))
                .await
                .unwrap()
                .unwrap(),
            Some(br#"{"fixture":"node sender boundary"}"#.to_vec())
        );
    }

    // Exercise raft-rs itself: a follower relays these requests with the
    // original caller's `from`, rather than its own connection identity.
    for message_type in [
        raft::eraftpb::MessageType::MsgPropose,
        raft::eraftpb::MessageType::MsgReadIndex,
        raft::eraftpb::MessageType::MsgTransferLeader,
    ] {
        let storage = raft::storage::MemStorage::new_with_conf_state((vec![1, 2, 3], vec![]));
        let mut follower = raft::RawNode::new(
            &raft::Config {
                id: 2,
                ..raft::Config::default()
            },
            storage,
            &slog::Logger::root(slog::Discard, slog::o!()),
        )
        .unwrap();
        follower.raft.become_follower(1, 1);
        let mut request = raft::eraftpb::Message::default();
        request.set_msg_type(message_type);
        request.set_from(3);
        request.set_to(2);
        let mut entry = raft::eraftpb::Entry::default();
        let mut data = (u64::MAX - 1).to_be_bytes().to_vec();
        data.extend(put("relayed-proposal").raw_command);
        entry.set_data(data.into());
        request.mut_entries().push(entry);
        follower.step(request).unwrap();
        let forwarded = follower
            .raft
            .msgs
            .iter()
            .find(|m| m.get_msg_type() == message_type)
            .expect("the actual follower must forward this request");
        assert_eq!((forwarded.from, forwarded.to), (3, 1));
        transport
            .step_message(StepMessageRequest {
                message: forwarded.write_to_bytes().unwrap(),
                zone_id: "root".into(),
                sender_address: "127.0.0.1:19998".into(),
            })
            .await
            .expect("a follower must preserve the original request sender");
        assert!(
            !registry.get_peers("root").unwrap().contains_key(&3),
            "the forwarder's address must not be assigned to the logical origin"
        );
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let stored = node
            .read_linearizable(|sm| {
                sm.get_control_state("node-boundary-fixture", "relayed-proposal")
            })
            .await
            .unwrap()
            .unwrap();
        if stored == Some(b"private fixture value".to_vec()) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the relayed proposal must commit"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let domestic = generate_agent_cert("domestic-agent", &ca, &ca_key).unwrap();
    let replica =
        generate_user_replica_cert("session-replica", "alice", 19, 300, &ca, &ca_key).unwrap();
    let foreign_agent = generate_agent_cert("foreign-agent", &foreign, &foreign_key).unwrap();
    let foreign_node = generate_node_cert(2, "root", &foreign, &foreign_key, &[], None).unwrap();
    for (label, (cert, key)) in [
        ("domestic-agent", domestic),
        ("owner-replica", replica),
        ("foreign-agent", foreign_agent),
        ("foreign-node", foreign_node),
    ] {
        let channel = connect(&address, &ca, cert, key).await;
        let mut api = ZoneApiServiceClient::new(channel.clone());
        let refusal = api
            .propose(put(label))
            .await
            .expect_err("Agent or foreign Node reached the Node-only Propose RPC");
        assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
        let stored = node
            .read_linearizable(|sm| sm.get_control_state("node-boundary-fixture", label))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, None, "refusal must precede control-state mutation");
        let mut transport = ZoneTransportServiceClient::new(channel);
        let refusal = transport
            .step_message(StepMessageRequest {
                message: vec![0xff],
                zone_id: "root".into(),
                sender_address: String::new(),
            })
            .await
            .expect_err("unprivileged peer reached Raft message parsing");
        assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
        if label != "foreign-node" {
            // This allowed door still reaches its own issuer gate. An empty
            // minter slot refuses minting; RPC acceptance confers no credential.
            let reply = api
                .mint_session_agent(MintSessionAgentRequest {
                    owner_id: "owner".into(),
                    validity_secs: 300,
                })
                .await
                .unwrap()
                .into_inner();
            assert!(!reply.success);
        }
    }
    assert_owner_replica_data_scope(&registry, &address, &ca, &ca_key).await;
    stop.send(()).unwrap();
    running.await.unwrap();
    drop(node);
    registry.shutdown_all();
    drop(registry);
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn witness_checks_the_authenticated_sender_before_auto_join() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let (cert_pem, key_pem) = generate_node_cert(1, "root", &ca, &key, &[], None).unwrap();
    let tls = TlsConfig {
        ca_pem: ca.clone(),
        cert_pem,
        key_pem,
    };
    let private = tempfile::tempdir().unwrap();
    let registry = Arc::new(WitnessZoneRegistry::new(
        private.path().to_path_buf(),
        1,
        Some(tls.clone()),
    ));
    let address = common::node_bind_addr();
    let server = RaftWitnessServer::new(
        registry.clone(),
        ServerConfig {
            bind_address: address.parse().unwrap(),
            tls: Some(tls),
            ..ServerConfig::default()
        },
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        server
            .serve_with_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    listener_ready(&address).await;
    let (cert, node_key) = generate_node_cert(2, "root", &ca, &key, &[], None).unwrap();
    let mut transport =
        ZoneTransportServiceClient::new(connect(&address, &ca, cert, node_key).await);
    let mut message = raft::eraftpb::Message::default();
    message.set_msg_type(raft::eraftpb::MessageType::MsgHeartbeatResponse);
    message.set_from(7);
    message.set_to(1);
    message.set_term(1);
    let refused_zone = "forged-witness-zone";
    let refusal = transport
        .step_message(StepMessageRequest {
            message: message.write_to_bytes().unwrap(),
            zone_id: refused_zone.into(),
            sender_address: "127.0.0.1:19999".into(),
        })
        .await
        .expect_err("Node 2 must not auto-join a witness as Node 7");
    assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
    assert!(registry.get_node(refused_zone).is_none());
    assert!(!private.path().join(refused_zone).exists());
    message.set_from(2);
    let (cert, replica_key) =
        generate_user_replica_cert("session-replica", "alice", 2, 300, &ca, &key).unwrap();
    let mut replica =
        ZoneTransportServiceClient::new(connect(&address, &ca, cert, replica_key).await);
    let refused_zone = "owner-replica-witness-zone";
    let refusal = replica
        .step_message(StepMessageRequest {
            message: message.write_to_bytes().unwrap(),
            zone_id: refused_zone.into(),
            sender_address: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
    assert!(registry.get_node(refused_zone).is_none());
    assert!(!private.path().join(refused_zone).exists());
    let accepted_zone = "accepted-witness-zone";
    transport
        .step_message(StepMessageRequest {
            message: message.write_to_bytes().unwrap(),
            zone_id: accepted_zone.into(),
            sender_address: "127.0.0.1:19998".into(),
        })
        .await
        .unwrap();
    assert!(registry.get_node(accepted_zone).is_some());
    stop.send(()).unwrap();
    running.await.unwrap();
    registry.shutdown_all();
    drop(registry);
    tokio::time::sleep(Duration::from_millis(500)).await;
}
