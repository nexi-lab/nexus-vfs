//! Real mTLS and gRPC federation. Static membership only; no Raft claim.

use super::*;
use auth::ApiKeyAuthProvider;
use contracts::lock_state::Locks;
use contracts::runtime_status::RuntimeDirectory;
use kernel::abc::meta_store::MetaStore;
use kernel::hal::distributed_coordinator::*;
use nexus_raft::transport::{
    generate_node_cert, generate_session_agent_cert, generate_zone_ca, TlsConfig,
};
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};
use transport::federation::{runtime_directory, FederationClient};

const PEER_NAMESPACE: &str = "/runtime-observation-peers";
const PEER_ZONE: &str = "runtime-collaboration";

struct Membership(Vec<String>);

// Membership is an input fixture. Production dispatch, authorization, TLS,
// peer pool, scope filters and registries are exercised without substitution.
impl DistributedCoordinator for Membership {
    fn list_zones(&self, _: &Kernel) -> Vec<String> {
        vec!["root".into()]
    }
    fn zone_peers(&self, _: &Kernel, zone: &str) -> Vec<String> {
        if zone == PEER_ZONE {
            self.0.clone()
        } else {
            Vec::new()
        }
    }
    fn cluster_info(&self, _: &Kernel, _: &str) -> CoordinatorResult<ClusterInfo> {
        Err("unused".into())
    }
    fn create_zone(&self, _: &Kernel, _: &str) -> CoordinatorResult<()> {
        Err("unused".into())
    }
    fn remove_zone(&self, _: &Kernel, _: &str, _: bool) -> CoordinatorResult<()> {
        Err("unused".into())
    }
    fn join_zone(&self, _: &Kernel, _: &str, _: bool) -> CoordinatorResult<()> {
        Err("unused".into())
    }
    fn wire_mount(&self, _: &Kernel, _: &str, _: &str, _: &str) -> CoordinatorResult<()> {
        Err("unused".into())
    }
    fn unwire_mount(&self, _: &Kernel, _: &str, _: &str) -> CoordinatorResult<()> {
        Err("unused".into())
    }
    fn share_zone(&self, _: &Kernel, _: &str, _: &str) -> CoordinatorResult<ShareInfo> {
        Err("unused".into())
    }
    fn lookup_share(&self, _: &Kernel, _: &str) -> CoordinatorResult<Option<ShareInfo>> {
        Err("unused".into())
    }
    fn metastore_for_zone(&self, _: &Kernel, _: &str) -> CoordinatorResult<Arc<dyn MetaStore>> {
        Err("unused".into())
    }
    fn locks_for_zone(&self, _: &Kernel, _: &str) -> CoordinatorResult<Arc<dyn Locks>> {
        Err("unused".into())
    }
}

struct TlsNode {
    node: Node,
    endpoint: String,
}

impl TlsNode {
    async fn start(ca: &[u8], key: &[u8], node_id: u64, owner: &str) -> Self {
        lib::transport_primitives::ensure_crypto_provider();
        let (cert, private) =
            generate_node_cert(node_id, "root", ca, key, &[], None).expect("node cert");
        let kernel = Arc::new(Kernel::new());
        kernel.vfs_router_arc().add(
            PEER_NAMESPACE,
            "root",
            kernel::core::vfs_router::MountEntry::new(None).with_target_zone(PEER_ZONE),
        );
        let routes = build_vfs_routes(
            Arc::clone(&kernel),
            Arc::new(ApiKeyAuthProvider::cert_identity_only()),
            Arc::new(OnceLock::new()),
            DataPlaneReady::open(),
            MAX_GRPC_MESSAGE_BYTES,
            "runtime-directory-mtls",
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let endpoint = format!("https://{}", listener.local_addr().expect("endpoint"));
        let configured = Server::builder()
            .tls_config(
                ServerTlsConfig::new()
                    .identity(Identity::from_pem(&cert, &private))
                    .client_ca_root(Certificate::from_pem(ca)),
            )
            .expect("server TLS")
            .add_routes(routes);
        let server = tokio::spawn(async move {
            configured
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .expect("serve");
        });
        let (client_cert, client_key) =
            generate_session_agent_cert("agent-a", owner, 60, ca, key).expect("owner cert");
        let channel = Endpoint::from_shared(endpoint.clone())
            .expect("endpoint")
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name(TlsConfig::CLUSTER_SERVER_NAME)
                    .ca_certificate(Certificate::from_pem(ca))
                    .identity(Identity::from_pem(client_cert, client_key)),
            )
            .expect("client TLS")
            .connect()
            .await
            .expect("connect");
        let tls = TlsConfig {
            cert_pem: cert,
            key_pem: private,
            ca_pem: ca.to_vec(),
        };
        let pool = Arc::new(FederationClient::new(
            kernel.runtime().handle().clone(),
            Some(tls.clone()),
        ));
        runtime_directory::install(&kernel, pool, PEER_NAMESPACE).expect("install same pool");
        assert_eq!(
            Arc::strong_count(kernel.runtime()),
            1,
            "a directory/peer pool must not become an async runtime shutdown owner"
        );
        Self {
            node: Node {
                kernel,
                client: NexusVfsServiceClient::new(channel),
                server,
                is_certificate_auth: true,
            },
            endpoint,
        }
    }

    async fn directory(&mut self, payload: Value) -> RuntimeDirectory {
        let response = self
            .node
            .call("", "runtime_directory.list_v1", payload)
            .await;
        assert!(
            !response.is_error,
            "{}",
            String::from_utf8_lossy(&response.payload)
        );
        serde_json::from_slice(&response.payload).expect("raw service response")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_directory_preserves_owner_scope_and_partial_coverage() {
    let (ca, key) = generate_zone_ca("root").expect("CA");
    let mut first = TlsNode::start(&ca, &key, 1, "alice").await;
    let mut second = TlsNode::start(&ca, &key, 2, "alice").await;
    let mut foreign = TlsNode::start(&ca, &key, 3, "mallory").await;
    // On each node the same Agent/SID has its own current instance.
    let one = first.node.register(&uuid::Uuid::new_v4().to_string()).await;
    let two = second
        .node
        .register(&uuid::Uuid::new_v4().to_string())
        .await;
    let hidden = foreign
        .node
        .register(&uuid::Uuid::new_v4().to_string())
        .await;
    first
        .node
        .publish(&one, &update(1, ForegroundState::Running))
        .await;
    second
        .node
        .publish(
            &two,
            &update(1, ForegroundState::AwaitingInput(InputReason::Question)),
        )
        .await;
    foreign
        .node
        .publish(&hidden, &update(1, ForegroundState::Running))
        .await;
    first
        .node
        .kernel
        .set_distributed_coordinator(Arc::new(Membership(vec![
            second.endpoint.clone(),
            foreign.endpoint.clone(),
        ])));
    let view = first.directory(json!({})).await;
    assert_eq!(view.inventories.len(), 3);
    assert!(view.unavailable.is_empty());
    assert!(view
        .inventories
        .iter()
        .all(
            |inventory| inventory.scope.owner_id.as_deref() == Some("alice")
                && inventory.scope.zone_id == "root"
        ));
    let observations: Vec<_> = view
        .inventories
        .iter()
        .flat_map(|scope| &scope.instances)
        .collect();
    assert_eq!(
        observations.len(),
        2,
        "other owner's node contributes an empty authorized scope"
    );
    assert!(observations.iter().any(|item| item.instance == one));
    assert!(observations.iter().any(|item| item.instance == two));
    assert!(!observations.iter().any(|item| item.instance == hidden));
    assert!(
        first
            .node
            .call(
                "",
                "runtime_directory.list_v1",
                json!({"owner_id":"mallory"})
            )
            .await
            .is_error
    );
    assert!(
        first
            .node
            .call("", "runtime_directory.list_v1", json!({"zone_id":"other"}))
            .await
            .is_error
    );
    // Authenticated entry points reject arbitrary user-supplied fan-out addresses.
    assert!(
        first
            .node
            .call(
                "",
                "runtime_directory.list_v1",
                json!({"peers":[foreign.endpoint]})
            )
            .await
            .is_error
    );
    // A bound socket that never serves HTTP/2 deterministically exercises the
    // whole connection deadline, including with a cached healthy peer channel.
    let silent_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("silent peer");
    let silent_endpoint = format!(
        "https://{}",
        silent_listener.local_addr().expect("silent address")
    );
    first
        .node
        .kernel
        .set_distributed_coordinator(Arc::new(Membership(vec![
            silent_endpoint.clone(),
            foreign.endpoint.clone(),
        ])));
    let started = std::time::Instant::now();
    let partial = first.directory(json!({})).await;
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "one bounded deadline includes connection and queue time"
    );
    assert_eq!(partial.unavailable.len(), 1);
    assert_eq!(partial.unavailable[0].endpoint, silent_endpoint);
    assert_eq!(partial.inventories.len(), 2);
    assert_eq!(
        partial
            .inventories
            .iter()
            .flat_map(|scope| &scope.instances)
            .count(),
        1
    );
    // Even a shared pool without node identity must fail closed.
    let no_identity = Arc::new(FederationClient::new(
        first.node.kernel.runtime().handle().clone(),
        None,
    ));
    assert!(first.node.kernel.unregister_service("runtime_directory"));
    runtime_directory::install(&first.node.kernel, no_identity, PEER_NAMESPACE)
        .expect("replace service");
    let unavailable = first.directory(json!({})).await;
    assert_eq!(unavailable.unavailable.len(), 2);
    assert!(unavailable
        .unavailable
        .iter()
        .all(|scope| scope.reason == "peer_identity_unavailable"));
}
