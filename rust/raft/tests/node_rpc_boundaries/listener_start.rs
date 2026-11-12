use super::*;
use lib::transport_primitives::{create_channel, ClientConfig, TlsPolicy};
use nexus_raft::transport::proto::PrepareReplicaControlReaderRequest;

async fn withdrawal_before_first_poll(witness: bool) {
    lib::transport_primitives::ensure_crypto_provider();
    let directory = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let identity = |id| {
        let (cert_pem, key_pem) = generate_node_cert(id, "root", &ca, &ca_key, &[], None).unwrap();
        TlsConfig {
            cert_pem,
            key_pem,
            ca_pem: ca.clone(),
        }
    };
    let initial = identity(7);
    let address = common::node_bind_addr();
    let config = ServerConfig {
        bind_address: address.parse().unwrap(),
        tls: Some(initial.clone()),
        ..Default::default()
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let shutdown = async {
        let _ = stopped.await;
    };
    let (credentials, mut task) = if witness {
        let registry = Arc::new(WitnessZoneRegistry::new(
            directory.path().to_path_buf(),
            7,
            Some(initial),
        ));
        let credentials = registry.shared_tls();
        let serving = RaftWitnessServer::new(registry, config).serve_with_shutdown(shutdown);
        credentials.replace(TlsPolicy::Rejected("withdrawn before listener poll"));
        (credentials, tokio::spawn(serving))
    } else {
        let registry = Arc::new(ZoneRaftRegistry::with_tls(
            directory.path().to_path_buf(),
            7,
            Some(initial),
        ));
        let credentials = registry.shared_tls();
        let serving = RaftGrpcServer::new(registry, config).serve_with_shutdown(shutdown);
        credentials.replace(TlsPolicy::Rejected("withdrawn before listener poll"));
        (credentials, tokio::spawn(serving))
    };
    tokio::select! {
        result = &mut task => panic!("withdrawal before the first poll must preserve the prepared listener: {result:?}"),
        () = listener_ready(&address) => {},
    }
    let client = ClientConfig {
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(5),
        tls: Some(identity(2)),
        ..Default::default()
    };
    let endpoint = format!("http://{address}");
    let refused = tokio::time::timeout(Duration::from_secs(5), create_channel(&endpoint, &client))
        .await
        .expect("withdrawn listener must promptly refuse the handshake");
    assert!(
        refused.is_err(),
        "withdrawn credentials must not authenticate"
    );
    assert!(!task.is_finished(), "withdrawal must retain the listener");

    // A rejected installation never turns this port into plaintext service.
    let plain = Endpoint::from_shared(endpoint.clone())
        .unwrap()
        .timeout(Duration::from_secs(5))
        .connect_lazy();
    assert!(ZoneTransportServiceClient::new(plain)
        .prepare_replica_control_reader_v1(PrepareReplicaControlReaderRequest {
            zone_id: "absent".into()
        })
        .await
        .is_err());

    credentials.replace(TlsPolicy::Configured(identity(7)));
    let channel = create_channel(&endpoint, &client).await.unwrap();
    let mut restored = ZoneTransportServiceClient::new(channel);
    let error = restored
        .prepare_replica_control_reader_v1(PrepareReplicaControlReaderRequest {
            zone_id: "absent".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        tonic::Code::NotFound,
        "the restored Node reaches the original handler"
    );
    drop(restored);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_listener_survives_withdrawal_before_first_poll_and_accepts_replacement() {
    withdrawal_before_first_poll(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn witness_listener_survives_withdrawal_before_first_poll_and_accepts_replacement() {
    withdrawal_before_first_poll(true).await;
}
