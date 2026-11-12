use nexus_raft::{
    raft::ZoneRaftRegistry,
    transport::{
        generate_node_cert, RaftGrpcServer, RaftWitnessServer, ServerConfig, TlsConfig,
        WitnessZoneRegistry,
    },
};
use raft::{eraftpb::Snapshot, Storage};
use std::{sync::Arc, time::Duration};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

pub const ZONE: &str = "root";
pub const LARGE: usize = 5 * 1024 * 1024;

pub fn node_tls(ca: &[u8], key: &[u8], id: u64) -> TlsConfig {
    let (cert_pem, key_pem) = generate_node_cert(id, ZONE, ca, key, &[], None).unwrap();
    TlsConfig {
        ca_pem: ca.to_vec(),
        cert_pem,
        key_pem,
    }
}

pub enum Role {
    Leader,
    Learner,
    Witness,
}
enum Registry {
    Full(Arc<ZoneRaftRegistry>),
    Witness(Arc<WitnessZoneRegistry>),
}

pub struct Server {
    directory: Option<tempfile::TempDir>,
    registry: Option<Registry>,
    pub address: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    pub async fn start(id: u64, tls: TlsConfig, role: Role, limit: usize) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let address = super::common::node_bind_addr();
        let config = ServerConfig {
            bind_address: address.parse().unwrap(),
            max_message_size: limit,
            tls: Some(tls.clone()),
            ..Default::default()
        };
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let handle = tokio::runtime::Handle::current();
        let (registry, task) = match role {
            Role::Witness => {
                let registry = Arc::new(WitnessZoneRegistry::new(
                    directory.path().into(),
                    id,
                    Some(tls),
                ));
                registry.create_zone(ZONE, Vec::new(), &handle).unwrap();
                let server = RaftWitnessServer::new(registry.clone(), config);
                let task = tokio::spawn(async move {
                    server
                        .serve_with_shutdown(async {
                            let _ = stopped.await;
                        })
                        .await
                        .unwrap();
                });
                (Registry::Witness(registry), task)
            }
            Role::Leader | Role::Learner => {
                let registry = Arc::new(ZoneRaftRegistry::with_tls(
                    directory.path().into(),
                    id,
                    Some(tls),
                ));
                registry.set_self_address(address.clone());
                if matches!(role, Role::Leader) {
                    registry
                        .create_zone(ZONE, &handle)
                        .unwrap()
                        .campaign()
                        .await
                        .unwrap();
                } else {
                    registry.join_zone(ZONE, true, &handle).unwrap();
                }
                let server = RaftGrpcServer::new(registry.clone(), config);
                let task = tokio::spawn(async move {
                    server
                        .serve_with_shutdown(async {
                            let _ = stopped.await;
                        })
                        .await
                        .unwrap();
                });
                (Registry::Full(registry), task)
            }
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while tokio::net::TcpStream::connect(&address).await.is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("private mTLS listener must start");
        Self {
            directory: Some(directory),
            registry: Some(registry),
            address,
            stop: Some(stop),
            task,
        }
    }

    pub fn full(&self) -> &Arc<ZoneRaftRegistry> {
        match self.registry.as_ref().unwrap() {
            Registry::Full(registry) => registry,
            _ => panic!("full node required"),
        }
    }

    pub fn snapshot_ready(&self, index: u64) -> bool {
        match self.registry.as_ref().unwrap() {
            Registry::Full(registry) => registry.get_node(ZONE).unwrap().applied_index() >= index,
            // Witnesses have no shared state-machine applied-index counter.
            // The driver publishes commit_index after persistence; shutdown
            // additionally reopens the store and compares the exact snapshot.
            Registry::Witness(registry) => registry.get_node(ZONE).unwrap().commit_index() >= index,
        }
    }

    pub async fn channel(&self, tls: TlsConfig) -> Channel {
        Endpoint::from_shared(format!("https://{}", self.address))
            .unwrap()
            .timeout(Duration::from_secs(5))
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name("localhost")
                    .ca_certificate(Certificate::from_pem(tls.ca_pem))
                    .identity(Identity::from_pem(tls.cert_pem, tls.key_pem)),
            )
            .unwrap()
            .connect()
            .await
            .unwrap()
    }

    pub async fn shutdown(self) {
        self.finish(None).await;
    }

    pub async fn shutdown_with_snapshot(self, expected: &Snapshot) {
        self.finish(Some(expected)).await;
    }

    async fn finish(mut self, expected: Option<&Snapshot>) {
        self.stop.take().unwrap().send(()).unwrap();
        (&mut self.task).await.unwrap();
        self.stop_registry();
        drop(self.registry.take());
        let directory = self.directory.take().unwrap();
        let store = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match nexus_raft::raft::RaftStorage::open(directory.path().join(ZONE).join("raft"))
                {
                    Ok(store) => break store,
                    Err(error) => {
                        assert!(error.to_string().contains("already open"), "{error}");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        })
        .await
        .expect("private actor must release its original store");
        if let Some(expected) = expected {
            let metadata = expected.get_metadata();
            assert_eq!(store.snapshot(metadata.index, 0).unwrap(), *expected);
            let state = store.initial_state().unwrap();
            assert_eq!(&state.conf_state, metadata.get_conf_state());
            assert!(state.hard_state.commit >= metadata.index);
            assert!(state.hard_state.term >= metadata.term);
            assert_eq!(store.first_index().unwrap(), metadata.index + 1);
        }
        drop(store);
        directory
            .close()
            .expect("private data directory must be removed");
    }

    fn stop_registry(&self) {
        match &self.registry {
            Some(Registry::Full(registry)) => registry.shutdown_all(),
            Some(Registry::Witness(registry)) => registry.shutdown_all(),
            None => {}
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.stop_registry();
    }
}
