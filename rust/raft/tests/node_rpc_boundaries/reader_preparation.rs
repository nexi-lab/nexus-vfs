//! Reader preparation crosses real mTLS and the original persistent Raft driver.
use super::*;
use nexus_raft::{
    raft::RaftStorage,
    transport::{
        proto::{GetClusterInfoRequest, PrepareReplicaControlReaderRequest},
        ClientConfig, NodeAddress, RaftClientPool, TransportError,
    },
};

pub(super) fn node_tls(ca: &[u8], key: &[u8], id: u64) -> TlsConfig {
    let (cert_pem, key_pem) = generate_node_cert(id, "root", ca, key, &[], None).unwrap();
    TlsConfig {
        ca_pem: ca.to_vec(),
        cert_pem,
        key_pem,
    }
}

pub(super) fn pool(tls: TlsConfig) -> RaftClientPool {
    RaftClientPool::with_config(ClientConfig {
        tls: lib::transport_primitives::SharedTlsConfig::new(Some(tls)),
        ..Default::default()
    })
}

pub(super) async fn reopened(directory: &std::path::Path) -> RaftStorage {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match RaftStorage::open(directory.join("root/raft")) {
                Ok(store) => return store,
                Err(error) => {
                    assert!(error.to_string().contains("already open"), "{error}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    })
    .await
    .expect("original transport must release its store")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reader_preparation_acknowledges_durable_original_full_node_store() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let server = PeerServer::start(node_tls(&ca, &key, 7)).await;
    let clients = pool(node_tls(&ca, &key, 2));
    let address = NodeAddress::new(7, server.endpoint.clone());
    let mut general = clients.get(&address).await.unwrap();
    let refusal = general
        .prepare_replica_control_reader("root")
        .await
        .unwrap_err();
    assert!(matches!(refusal, TransportError::Connection(ref text)
        if text == "storage reader preparation requires an exact cluster Node channel"));

    let mut control = clients.get_node(&address).await.unwrap();
    assert_eq!(clients.connection_count().await, 2);
    let node = server.registry.get_node("root").unwrap();
    let last = node.last_index();
    for _ in 0..2 {
        control
            .prepare_replica_control_reader("root")
            .await
            .unwrap();
    }
    assert_eq!(
        node.last_index(),
        last,
        "preparation must not append a Raft command"
    );
    let identities = nexus_raft::replica_binding_store::RaftReplicaBindingStore::new(
        node.clone(),
        tokio::runtime::Handle::current(),
    );
    let error = identities
        .reserve_node(&contracts::node_identity::NodeIdentityRequest {
            operation_id: "reader-is-not-activation".into(),
            identity: contracts::node_identity::NodeIdentity {
                node_id: 99,
                subject_public_key_sha256: [9; 32],
            },
        })
        .unwrap_err();
    assert!(matches!(
        error,
        nexus_raft::replica_binding_store::ReplicaBindingError::Unsupported
    ));
    drop(identities);
    assert_eq!(node.last_index(), last);

    let error = control
        .prepare_replica_control_reader("absent")
        .await
        .unwrap_err();
    assert!(
        matches!(error, TransportError::Status(ref status) if status.code() == tonic::Code::NotFound)
    );
    assert!(server.registry.get_node("absent").is_none());
    assert!(!server._directory.path().join("absent").exists());
    drop(node);
    drop(general);
    drop(control);
    clients.remove(7).await;
    assert_eq!(clients.connection_count().await, 0);
    drop(clients);
    let directory = server.shutdown_preserving_storage().await;
    let store = reopened(directory.path()).await;
    assert!(store.replica_control_reader_required().unwrap());
    assert_eq!(store.last_index_impl().unwrap(), last);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reader_preparation_refuses_agent_replica_and_plaintext_without_durable_effects() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let server = PeerServer::start(node_tls(&ca, &key, 7)).await;
    let address = server.endpoint.strip_prefix("http://").unwrap();
    for (cert, client_key) in [
        generate_agent_cert("agent", &ca, &key).unwrap(),
        generate_user_replica_cert("replica", "alice", 2, 300, &ca, &key).unwrap(),
    ] {
        let mut client =
            ZoneTransportServiceClient::new(connect(address, &ca, cert, client_key).await);
        for zone in ["root", "absent"] {
            let error = client
                .prepare_replica_control_reader_v1(PrepareReplicaControlReaderRequest {
                    zone_id: zone.into(),
                })
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::PermissionDenied);
        }
        assert!(server.registry.get_node("absent").is_none());
    }
    let directory = server.shutdown_preserving_storage().await;
    assert!(!reopened(directory.path())
        .await
        .replica_control_reader_required()
        .unwrap());

    let plain_directory = tempfile::tempdir().unwrap();
    let registry = Arc::new(ZoneRaftRegistry::new(
        plain_directory.path().to_path_buf(),
        7,
    ));
    let root = registry
        .create_zone("root", &tokio::runtime::Handle::current())
        .unwrap();
    root.campaign().await.unwrap();
    let address = common::node_bind_addr();
    let server = RaftGrpcServer::new(
        registry.clone(),
        ServerConfig {
            bind_address: address.parse().unwrap(),
            ..Default::default()
        },
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        server
            .serve_with_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    listener_ready(&address).await;
    let endpoint = format!("http://{address}");
    let channel = Endpoint::from_shared(endpoint.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut ordinary = ZoneApiServiceClient::new(channel.clone());
    assert_eq!(
        ordinary
            .get_cluster_info(GetClusterInfoRequest {
                zone_id: "root".into()
            })
            .await
            .unwrap()
            .into_inner()
            .node_id,
        7
    );
    let mut raw = ZoneTransportServiceClient::new(channel);
    let error = raw
        .prepare_replica_control_reader_v1(PrepareReplicaControlReaderRequest {
            zone_id: "root".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    let plain_pool = RaftClientPool::new();
    let error = plain_pool
        .get_node(&NodeAddress::new(7, endpoint))
        .await
        .err()
        .unwrap();
    assert!(
        matches!(error, TransportError::Connection(ref text) if text == "authenticated peer channels require TLS")
    );
    drop(raw);
    drop(ordinary);
    stop.send(()).unwrap();
    task.await.unwrap();
    registry.shutdown_all();
    drop(root);
    drop(registry);
    assert!(!reopened(plain_directory.path())
        .await
        .replica_control_reader_required()
        .unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_pool_refuses_cached_replica_role_and_changed_node_identity() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let (cert_pem, key_pem) =
        generate_user_replica_cert("replica", "alice", 7, 300, &ca, &key).unwrap();
    let server = PeerServer::start(TlsConfig {
        ca_pem: ca.clone(),
        cert_pem,
        key_pem,
    })
    .await;
    let clients = pool(node_tls(&ca, &key, 2));
    let address = NodeAddress::new(7, server.endpoint.clone());
    let general = clients.get(&address).await.unwrap();
    let error = clients
        .get_node(&address)
        .await
        .err()
        .expect("a cached replica cannot become a Node");
    assert_peer_refusal(
        &error,
        PeerRefusal::Identity("server certificate must name a cluster Node"),
    );
    assert_eq!(clients.connection_count().await, 1);
    drop(general);
    clients.remove(7).await;
    server.shutdown().await;

    let correct = PeerServer::start(node_tls(&ca, &key, 7)).await;
    let wrong = PeerServer::start(node_tls(&ca, &key, 8)).await;
    drop(
        clients
            .get_node(&NodeAddress::new(7, correct.endpoint.clone()))
            .await
            .unwrap(),
    );
    let error = clients
        .get_node(&NodeAddress::new(7, wrong.endpoint.clone()))
        .await
        .err()
        .unwrap();
    assert_peer_refusal(
        &error,
        PeerRefusal::Identity("server certificate does not name the expected replication peer"),
    );
    drop(clients);
    correct.shutdown().await;
    wrong.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reader_preparation_acknowledges_original_witness_store_without_leadership() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let tls = node_tls(&ca, &key, 7);
    let directory = tempfile::tempdir().unwrap();
    let registry = Arc::new(WitnessZoneRegistry::new(
        directory.path().to_path_buf(),
        7,
        Some(tls.clone()),
    ));
    let node = registry
        .create_zone("root", Vec::new(), &tokio::runtime::Handle::current())
        .unwrap();
    assert!(!node.is_leader());
    let last = node.last_index();
    let address = common::node_bind_addr();
    let server = RaftWitnessServer::new(
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
            .serve_with_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    listener_ready(&address).await;
    let clients = pool(node_tls(&ca, &key, 2));
    let mut client = clients
        .get_node(&NodeAddress::new(7, format!("http://{address}")))
        .await
        .unwrap();
    client.prepare_replica_control_reader("root").await.unwrap();
    assert!(!node.is_leader());
    assert_eq!(node.last_index(), last);
    let error = client
        .prepare_replica_control_reader("absent")
        .await
        .unwrap_err();
    assert!(
        matches!(error, TransportError::Status(ref status) if status.code() == tonic::Code::NotFound)
    );
    assert!(registry.get_node("absent").is_none());
    assert!(!directory.path().join("absent").exists());
    drop(client);
    drop(clients);
    stop.send(()).unwrap();
    task.await.unwrap();
    registry.shutdown_all();
    drop(node);
    drop(registry);
    let store = reopened(directory.path()).await;
    assert!(store.replica_control_reader_required().unwrap());
    assert_eq!(store.last_index_impl().unwrap(), last);
}
