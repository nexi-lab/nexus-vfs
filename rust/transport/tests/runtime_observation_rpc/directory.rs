//! Real mTLS and gRPC federation. Static membership only; no Raft claim.

use super::*;
use auth::ApiKeyAuthProvider;
use contracts::lock_state::Locks;
use contracts::runtime_status::OnlineAgents;
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
    async fn start(ca: &[u8], key: &[u8], node_id: u64, owner: &str, agent: &str) -> Self {
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
            generate_session_agent_cert(agent, owner, 60, ca, key).expect("owner cert");
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

    async fn presence(&mut self, payload: Value) -> OnlineAgents {
        let response = self
            .node
            .call("", "runtime_directory.presence_v1", payload)
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
async fn zone_presence_names_every_owners_online_agents_only() {
    let (ca, key) = generate_zone_ca("root").expect("CA");
    let mut first = TlsNode::start(&ca, &key, 1, "alice", "agent-a").await;
    let mut second = TlsNode::start(&ca, &key, 2, "bob", "agent-b").await;
    let mut third = TlsNode::start(&ca, &key, 3, "mallory", "agent-c").await;
    let one = first
        .node
        .register_as("agent-a", &uuid::Uuid::new_v4().to_string())
        .await;
    let two = second
        .node
        .register_as("agent-b", &uuid::Uuid::new_v4().to_string())
        .await;
    let gone = third
        .node
        .register_as("agent-c", &uuid::Uuid::new_v4().to_string())
        .await;
    assert!(
        !third
            .node
            .call("", "agent_runtime_unregister_v1", json!({"instance": gone}))
            .await
            .is_error
    );
    first
        .node
        .kernel
        .set_distributed_coordinator(Arc::new(Membership(vec![
            second.endpoint.clone(),
            third.endpoint.clone(),
        ])));
    // Every member of the zone sees every owner's online Agents, by name only.
    assert_eq!(
        first.presence(json!({})).await,
        OnlineAgents {
            version: 1,
            zone_id: "root".into(),
            online: vec!["agent-a".into(), "agent-b".into()],
        }
    );
    for refused in [
        ("runtime_directory.presence_v1", json!({"zone_id": "other"})),
        (
            "runtime_directory.presence_v1",
            json!({"peers": [third.endpoint]}),
        ),
        ("runtime_directory.list_v1", json!({})),
    ] {
        assert!(
            first
                .node
                .call("", refused.0, refused.1.clone())
                .await
                .is_error,
            "{refused:?}"
        );
    }
    // A bound socket that never serves HTTP/2 holds the whole connection
    // deadline; its Agents are simply not seen online.
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
            silent_endpoint,
            second.endpoint.clone(),
        ])));
    for (node, instance) in [(&mut first, &one), (&mut second, &two)] {
        assert!(
            !node
                .node
                .call(
                    "",
                    "agent_runtime_heartbeat_v1",
                    json!({"instance": instance})
                )
                .await
                .is_error
        );
    }
    let started = std::time::Instant::now();
    let partial = first.presence(json!({})).await;
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "one bounded deadline includes connection and queue time"
    );
    assert_eq!(partial.online, vec!["agent-a", "agent-b"]);
    // A pool without node identity reads this node alone.
    let no_identity = Arc::new(FederationClient::new(
        first.node.kernel.runtime().handle().clone(),
        None,
    ));
    assert!(first.node.kernel.unregister_service("runtime_directory"));
    runtime_directory::install(&first.node.kernel, no_identity, PEER_NAMESPACE)
        .expect("replace service");
    assert_eq!(first.presence(json!({})).await.online, vec!["agent-a"]);
}
