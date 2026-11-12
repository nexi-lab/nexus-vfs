use super::{
    forward_propose, generate_node_cert, generate_zone_ca, ClientConfig, NodeAddress,
    RaftApiClient, RaftClientPool, RaftGrpcServer, ServerConfig, TlsConfig,
};
use crate::raft::{Command, ZoneRaftRegistry};
use std::{sync::Arc, time::Duration};

#[path = "../../tests/common/mod.rs"]
mod common;

struct Peer {
    directory: tempfile::TempDir,
    registry: Arc<ZoneRaftRegistry>,
    address: NodeAddress,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Peer {
    async fn start(tls: TlsConfig) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let registry = Arc::new(ZoneRaftRegistry::with_tls(
            directory.path().to_path_buf(),
            7,
            Some(tls.clone()),
        ));
        let root = registry
            .create_zone("root", &tokio::runtime::Handle::current())
            .unwrap();
        root.campaign().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !root.is_leader() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the real root must elect its leader");
        let address = common::node_bind_socket_addr();
        let server = RaftGrpcServer::new(
            registry.clone(),
            ServerConfig {
                bind_address: address,
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
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if tokio::net::TcpStream::connect(address).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the actual TLS listener must bind");
        Self {
            directory,
            registry,
            address: NodeAddress::new(7, format!("http://{address}")),
            stop,
            task,
        }
    }

    async fn read(&self, path: &str) -> Option<Vec<u8>> {
        self.registry
            .get_node("root")
            .unwrap()
            .read_linearizable(|state| state.get_metadata(path))
            .await
            .unwrap()
            .unwrap()
    }

    async fn shutdown(self) {
        self.stop.send(()).unwrap();
        self.task.await.unwrap();
        self.registry.shutdown_all();
        drop(self.registry);
        drop(self.directory);
    }
}

fn node_tls(id: u64, ca: &[u8], key: &[u8]) -> TlsConfig {
    let (cert_pem, key_pem) = generate_node_cert(id, "root", ca, key, &[], None).unwrap();
    TlsConfig {
        cert_pem,
        key_pem,
        ca_pem: ca.to_vec(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_raft_and_api_clients_refuse_reinstalled_credentials() {
    use lib::transport_primitives::{SharedTlsConfig, TlsPolicy};
    let (ca, key) = generate_zone_ca("root").unwrap();
    let peer = Peer::start(node_tls(7, &ca, &key)).await;
    let original = node_tls(2, &ca, &key);
    let tls = SharedTlsConfig::new(Some(original.clone()));
    let config = ClientConfig {
        tls: tls.clone(),
        ..Default::default()
    };
    let pool = RaftClientPool::with_config(config.clone());
    let mut retained = pool.get(&peer.address).await.unwrap();
    let mut api = RaftApiClient::connect(&peer.address.endpoint, config.clone())
        .await
        .unwrap()
        .with_zone_id("root".into());
    assert_eq!(api.get_cluster_info().await.unwrap().node_id, 7);
    tls.replace(TlsPolicy::Configured(original));
    assert!(!api.uses_current_credentials(&config));
    for result in [
        retained
            .replicate_entries("root".into(), vec![], 2)
            .await
            .map(|_| ()),
        api.get_cluster_info().await.map(|_| ()),
    ] {
        assert!(
            matches!(result, Err(super::TransportError::Connection(ref reason))
            if reason == "Raft connection credential installation is no longer current"),
            "{result:?}"
        );
    }
    let current = pool.get(&peer.address).await.unwrap();
    let mut fresh = RaftApiClient::connect(&peer.address.endpoint, config)
        .await
        .unwrap()
        .with_zone_id("root".into());
    assert_eq!(fresh.get_cluster_info().await.unwrap().node_id, 7);
    drop((current, retained, fresh, api, pool));
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_control_connection_observes_listener_credential_rejection() {
    use lib::transport_primitives::{SharedTlsConfig, TlsPolicy};
    let (ca, key) = generate_zone_ca("root").unwrap();
    let server_tls = node_tls(7, &ca, &key);
    let peer = Peer::start(server_tls.clone()).await;
    let mut api = RaftApiClient::connect(
        &peer.address.endpoint,
        ClientConfig {
            tls: SharedTlsConfig::new(Some(node_tls(2, &ca, &key))),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .with_zone_id("root".into());
    assert_eq!(api.get_cluster_info().await.unwrap().node_id, 7);
    peer.registry
        .shared_tls()
        .replace(TlsPolicy::Rejected("test renewal unavailable"));
    let error = api.get_cluster_info().await.unwrap_err();
    assert!(
        error.to_string().contains("test renewal unavailable"),
        "{error}"
    );
    let mut wrong_anchor = server_tls.clone();
    wrong_anchor.ca_pem = generate_zone_ca("other").unwrap().0;
    peer.registry
        .shared_tls()
        .replace(TlsPolicy::Configured(wrong_anchor));
    let error = api.get_cluster_info().await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("local listener trust anchor changed"),
        "{error}"
    );
    peer.registry
        .shared_tls()
        .replace(TlsPolicy::Configured(server_tls));
    assert_eq!(api.get_cluster_info().await.unwrap().node_id, 7);
    drop(api);
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_refuses_credentials_different_from_its_registry() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let registry = Arc::new(ZoneRaftRegistry::new(directory.path().to_path_buf(), 7));
    let address = common::node_bind_socket_addr();
    let server = RaftGrpcServer::new(
        registry.clone(),
        ServerConfig {
            bind_address: address,
            tls: Some(node_tls(7, &ca, &key)),
            ..Default::default()
        },
    );
    let error = server.serve_with_shutdown(async {}).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("listener and registry TLS configuration differ"),
        "{error}"
    );
    let probe = tokio::net::TcpListener::bind(address).await.unwrap();
    drop(probe);
    registry.shutdown_all();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarded_write_rechecks_credentials_on_the_same_leader_address() {
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let peer = Peer::start(node_tls(7, &ca, &ca_key)).await;
    let original_tls = node_tls(2, &ca, &ca_key);
    let tls = lib::transport_primitives::SharedTlsConfig::new(Some(original_tls.clone()));
    let pool = RaftClientPool::with_config(ClientConfig {
        tls: tls.clone(),
        ..Default::default()
    });
    let cache = tokio::sync::Mutex::new(None);
    let command = |path: &str| Command::SetMetadata {
        key: path.into(),
        value: b"actual forwarded write".to_vec(),
    };
    let deadline = || tokio::time::Instant::now() + Duration::from_secs(5);
    forward_propose(
        &pool,
        &peer.address,
        &command("/before"),
        "root",
        deadline(),
        &cache,
    )
    .await
    .unwrap();
    assert_eq!(
        peer.read("/before").await,
        Some(b"actual forwarded write".to_vec())
    );
    assert!(cache.lock().await.is_some());

    let mut replacement = tls.snapshot().config().unwrap().unwrap().clone();
    replacement.ca_pem = generate_zone_ca("root").unwrap().0;
    tls.replace(lib::transport_primitives::TlsPolicy::Configured(
        replacement,
    ));
    let refused = forward_propose(
        &pool,
        &peer.address,
        &command("/after-replacement"),
        "root",
        deadline(),
        &cache,
    )
    .await;
    assert!(
        refused.is_err(),
        "the old cached authority cannot carry a new write"
    );
    assert!(cache.lock().await.is_none());
    assert_eq!(peer.read("/after-replacement").await, None);
    assert_eq!(
        peer.read("/before").await,
        Some(b"actual forwarded write".to_vec())
    );

    tls.replace(lib::transport_primitives::TlsPolicy::Configured(
        original_tls,
    ));
    forward_propose(
        &pool,
        &peer.address,
        &command("/restored"),
        "root",
        deadline(),
        &cache,
    )
    .await
    .unwrap();
    assert_eq!(
        peer.read("/restored").await,
        Some(b"actual forwarded write".to_vec())
    );
    drop(cache);
    drop(pool);
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proposal_client_refuses_a_completed_dial_from_the_previous_credentials() {
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let peer = Peer::start(node_tls(7, &ca, &ca_key)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let backend = peer
        .address
        .endpoint
        .strip_prefix("http://")
        .unwrap()
        .to_owned();
    let (connected, accepted) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let proxy = tokio::spawn(async move {
        let (mut incoming, _) = listener.accept().await.unwrap();
        connected.send(()).unwrap();
        released.await.unwrap();
        let mut outgoing = tokio::net::TcpStream::connect(backend).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
    });
    let tls = lib::transport_primitives::SharedTlsConfig::new(Some(node_tls(2, &ca, &ca_key)));
    let config = ClientConfig {
        tls: tls.clone(),
        ..Default::default()
    };
    let dialing = tokio::spawn(async move { RaftApiClient::connect(&endpoint, config).await });
    tokio::time::timeout(Duration::from_secs(5), accepted)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !dialing.is_finished(),
        "the actual connection is paused before TLS"
    );
    tls.replace(lib::transport_primitives::TlsPolicy::Configured(node_tls(
        3, &ca, &ca_key,
    )));
    release.send(()).unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), dialing)
        .await
        .unwrap()
        .unwrap()
        .err()
        .expect("the prior credential dial must be refused");
    assert!(
        error
            .to_string()
            .contains("Raft API TLS configuration changed while connecting"),
        "{error}"
    );
    let current = RaftApiClient::connect(
        &peer.address.endpoint,
        ClientConfig {
            tls,
            ..Default::default()
        },
    )
    .await
    .expect("the replacement credential remains valid");
    drop(current);
    proxy.abort();
    let _ = proxy.await;
    peer.shutdown().await;
}
