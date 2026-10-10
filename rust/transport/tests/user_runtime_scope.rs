//! Real mTLS requests preserve the original principal within a user runtime.

use std::sync::{Arc, Mutex};

use auth::ApiKeyAuthProvider;
use backends::storage::path_local::PathLocalBackend;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient, PingRequest, ReadRequest, WriteRequest,
};
use kernel::kernel::{Kernel, KernelError, OperationContext};
use kernel::vfs_router::RouteResult;
use kernel::{Permission, PermissionProvider};
use nexus_raft::transport::{
    generate_node_cert, generate_session_agent_cert, generate_zone_ca, TlsConfig,
};
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};
use tonic::{Code, Request};
use transport::grpc::{build_user_runtime_routes, build_vfs_routes, DataPlaneReady};
use transport::runtime_scope::{RuntimeDelegation, RuntimeScope, RUNTIME_DELEGATION_METADATA_KEY};

struct ObservePrincipal(Arc<Mutex<Vec<OperationContext>>>);

impl PermissionProvider for ObservePrincipal {
    fn check(
        &self,
        _path: &str,
        _route: Option<&RouteResult>,
        _permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        self.0.lock().unwrap().push(ctx.clone());
        Ok(())
    }
}

struct Listener {
    url: String,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    observed: Arc<Mutex<Vec<OperationContext>>>,
    _root: tempfile::TempDir,
}

impl Listener {
    async fn start(ca: &[u8], cert: &[u8], key: &[u8], scope: Option<RuntimeScope>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let kernel = Arc::new(Kernel::new());
        kernel
            .mount(
                "/",
                MountOptions::new("local")
                    .with_backend(Arc::new(PathLocalBackend::new(root.path(), false).unwrap())),
            )
            .unwrap();
        let observed = Arc::new(Mutex::new(Vec::new()));
        kernel.set_permission_provider(Arc::new(Box::new(ObservePrincipal(Arc::clone(&observed)))));
        let auth = Arc::new(ApiKeyAuthProvider::cert_identity_only());
        let routes = match scope {
            Some(scope) => build_user_runtime_routes(
                kernel,
                auth,
                scope,
                Arc::new(std::sync::OnceLock::new()),
                DataPlaneReady::open(),
                1024 * 1024,
                "scope-test",
            ),
            None => build_vfs_routes(
                kernel,
                auth,
                Arc::new(std::sync::OnceLock::new()),
                DataPlaneReady::open(),
                1024 * 1024,
                "root-test",
            ),
        };
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}", socket.local_addr().unwrap());
        let (stop, stopped) = oneshot::channel();
        let server = Server::builder()
            .tls_config(
                ServerTlsConfig::new()
                    .identity(Identity::from_pem(cert, key))
                    .client_ca_root(Certificate::from_pem(ca)),
            )
            .unwrap()
            .add_routes(routes);
        let task = tokio::spawn(server.serve_with_incoming_shutdown(
            TcpListenerStream::new(socket),
            async {
                let _ = stopped.await;
            },
        ));
        Self {
            url,
            stop: Some(stop),
            task,
            observed,
            _root: root,
        }
    }

    async fn client(&self, ca: &[u8], cert: &[u8], key: &[u8]) -> NexusVfsServiceClient<Channel> {
        NexusVfsServiceClient::new(
            Endpoint::from_shared(self.url.clone())
                .unwrap()
                .tls_config(
                    ClientTlsConfig::new()
                        .domain_name(TlsConfig::CLUSTER_SERVER_NAME)
                        .ca_certificate(Certificate::from_pem(ca))
                        .identity(Identity::from_pem(cert, key)),
                )
                .unwrap()
                .connect()
                .await
                .unwrap(),
        )
    }

    async fn close(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.task.await.unwrap().unwrap();
    }
}

fn ping(delegation: &RuntimeDelegation) -> Request<PingRequest> {
    let mut request = Request::new(PingRequest::default());
    delegation.apply(request.metadata_mut()).unwrap();
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verified_gateway_preserves_owner_and_actor_and_cannot_cross_user_runtimes() {
    lib::transport_primitives::ensure_crypto_provider();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (gateway_cert, gateway_key) =
        generate_node_cert(1, "root", &ca, &ca_key, &[], None).unwrap();
    let (other_cert, other_key) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let (other_zone_cert, other_zone_key) =
        generate_node_cert(1, "other-zone", &ca, &ca_key, &[], None).unwrap();
    let (alice_cert, alice_key) =
        generate_session_agent_cert("session-alice", "alice", 300, &ca, &ca_key).unwrap();
    let (bob_cert, bob_key) =
        generate_session_agent_cert("session-bob", "bob", 300, &ca, &ca_key).unwrap();
    let root = Listener::start(&ca, &gateway_cert, &gateway_key, None).await;
    let alice_runtime = Listener::start(
        &ca,
        &other_cert,
        &other_key,
        Some(RuntimeScope::new("alice".into(), [1]).unwrap()),
    )
    .await;
    let bob_runtime = Listener::start(
        &ca,
        &other_cert,
        &other_key,
        Some(RuntimeScope::new("bob".into(), [1]).unwrap()),
    )
    .await;

    let mut alice = root.client(&ca, &alice_cert, &alice_key).await;
    let written = alice
        .write(WriteRequest {
            path: "/origin.txt".into(),
            content: b"original caller".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!written.is_error);
    let mut original = root.observed.lock().unwrap().last().unwrap().clone();
    original.request_id = "cloud-runtime-e2e".into();
    assert_eq!(original.user_id, "alice");
    assert_eq!(original.agent_id.as_deref(), Some("session-alice"));
    let delegation = RuntimeDelegation::from_context(&original).unwrap();
    let mut privileged = original.clone();
    privileged.is_admin = true;
    assert!(RuntimeDelegation::from_context(&privileged).is_err());

    let mut gateway = alice_runtime.client(&ca, &gateway_cert, &gateway_key).await;
    let mut write = Request::new(WriteRequest {
        path: "/retained.txt".into(),
        content: b"alice's real bytes".to_vec(),
        ..Default::default()
    });
    write.metadata_mut().append_bin(
        RUNTIME_DELEGATION_METADATA_KEY,
        MetadataValue::from_bytes(b"untrusted caller's identity"),
    );
    write.metadata_mut().append_bin(
        RUNTIME_DELEGATION_METADATA_KEY,
        MetadataValue::from_bytes(b"second forged identity"),
    );
    delegation.apply(write.metadata_mut()).unwrap();
    assert_eq!(
        write
            .metadata()
            .get_all_bin(RUNTIME_DELEGATION_METADATA_KEY)
            .iter()
            .count(),
        1
    );
    assert!(!gateway.write(write).await.unwrap().into_inner().is_error);
    let mut read = Request::new(ReadRequest {
        path: "/retained.txt".into(),
        ..Default::default()
    });
    delegation.apply(read.metadata_mut()).unwrap();
    let bytes = gateway.read(read).await.unwrap().into_inner();
    assert!(!bytes.is_error);
    assert_eq!(bytes.content, b"alice's real bytes");
    let observed = alice_runtime.observed.lock().unwrap().clone();
    assert!(
        observed.len() >= 2,
        "actual VFS operations must reach the permission provider"
    );
    for ctx in &observed {
        assert_eq!(ctx.user_id, original.user_id);
        assert_eq!(ctx.agent_id, original.agent_id);
        assert_eq!(ctx.subject_type, original.subject_type);
        assert_eq!(ctx.subject_id, original.subject_id);
        assert_eq!(ctx.request_id, original.request_id);
        assert!(!ctx.is_admin && !ctx.is_system);
    }

    let mut other_gateway = bob_runtime.client(&ca, &gateway_cert, &gateway_key).await;
    let mut bob = bob_runtime.client(&ca, &bob_cert, &bob_key).await;
    assert!(
        !bob.write(WriteRequest {
            path: "/bob-private.txt".into(),
            content: b"bob's private bytes".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .is_error
    );
    let mut wrong_owner_read = Request::new(ReadRequest {
        path: "/bob-private.txt".into(),
        ..Default::default()
    });
    delegation.apply(wrong_owner_read.metadata_mut()).unwrap();
    let refusal = other_gateway
        .read(wrong_owner_read)
        .await
        .unwrap()
        .into_inner();
    assert!(refusal.is_error);
    assert!(refusal.content.is_empty());
    assert!(String::from_utf8(refusal.error_payload)
        .unwrap()
        .contains("belongs to another user"));
    assert_eq!(
        other_gateway
            .ping(ping(&delegation))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        gateway
            .ping(PingRequest::default())
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let mut untrusted = alice_runtime.client(&ca, &other_cert, &other_key).await;
    assert_eq!(
        untrusted.ping(ping(&delegation)).await.unwrap_err().code(),
        Code::Unauthenticated
    );
    let mut other_zone = alice_runtime
        .client(&ca, &other_zone_cert, &other_zone_key)
        .await;
    assert_eq!(
        other_zone.ping(ping(&delegation)).await.unwrap_err().code(),
        Code::Unauthenticated
    );
    let mut direct_alice = alice_runtime.client(&ca, &alice_cert, &alice_key).await;
    direct_alice.ping(PingRequest::default()).await.unwrap();
    assert_eq!(
        direct_alice
            .ping(ping(&delegation))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    let mut direct_bob = alice_runtime.client(&ca, &bob_cert, &bob_key).await;
    assert_eq!(
        direct_bob
            .ping(PingRequest::default())
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );

    let mut duplicate = ping(&delegation);
    let raw = duplicate
        .metadata()
        .get_bin(RUNTIME_DELEGATION_METADATA_KEY)
        .unwrap()
        .clone();
    duplicate
        .metadata_mut()
        .append_bin(RUNTIME_DELEGATION_METADATA_KEY, raw);
    assert_eq!(
        gateway.ping(duplicate).await.unwrap_err().code(),
        Code::Unauthenticated
    );
    let mut expired = serde_json::to_value(&delegation).unwrap();
    expired["issued_at_unix_ms"] = 0.into();
    let mut future = serde_json::to_value(&delegation).unwrap();
    future["issued_at_unix_ms"] = u64::MAX.into();
    let mut widened = serde_json::to_value(&delegation).unwrap();
    widened["is_admin"] = true.into();
    for (wire, code) in [
        (b"not JSON".to_vec(), Code::Unauthenticated),
        (vec![b' '; 4097], Code::Unauthenticated),
        (
            serde_json::to_vec(&expired).unwrap(),
            Code::PermissionDenied,
        ),
        (serde_json::to_vec(&future).unwrap(), Code::PermissionDenied),
        (serde_json::to_vec(&widened).unwrap(), Code::Unauthenticated),
    ] {
        let mut bad = Request::new(PingRequest::default());
        bad.metadata_mut().insert_bin(
            RUNTIME_DELEGATION_METADATA_KEY,
            MetadataValue::from_bytes(&wire),
        );
        assert_eq!(gateway.ping(bad).await.unwrap_err().code(), code);
    }
    let mut credential_conflict = ping(&delegation);
    credential_conflict.get_mut().auth_token = "sk-rejected-token".into();
    assert_eq!(
        gateway.ping(credential_conflict).await.unwrap_err().code(),
        Code::Unauthenticated
    );

    drop((
        gateway,
        untrusted,
        direct_alice,
        direct_bob,
        other_gateway,
        bob,
        other_zone,
        alice,
    ));
    alice_runtime.close().await;
    bob_runtime.close().await;
    root.close().await;
}
