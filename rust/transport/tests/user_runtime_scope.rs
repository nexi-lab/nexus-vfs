//! Real mTLS requests preserve the original principal within a user runtime.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use auth::ApiKeyAuthProvider;
use backends::storage::path_local::PathLocalBackend;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::vfs_proto::{nexus_vfs_service_client::NexusVfsServiceClient, *};
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
use transport::auth::{AuthCredentials, AuthProvider};
use transport::grpc::{
    build_runtime_gateway_routes, build_user_runtime_routes, build_vfs_routes, DataPlaneReady,
};
use transport::runtime_gateway::UserRuntimeResolver;
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
    kernel: Arc<Kernel>,
    auth_resolutions: Arc<AtomicUsize>,
    auth_contexts: Arc<Mutex<Vec<OperationContext>>>,
    _root: tempfile::TempDir,
}

enum Routing {
    Local,
    User(RuntimeScope),
    Gateway(Arc<dyn UserRuntimeResolver>),
}

struct CountingAuth {
    inner: ApiKeyAuthProvider,
    resolutions: Arc<AtomicUsize>,
    contexts: Arc<Mutex<Vec<OperationContext>>>,
}

impl AuthProvider for CountingAuth {
    fn resolve(
        &self,
        credentials: &AuthCredentials<'_>,
    ) -> Result<OperationContext, tonic::Status> {
        self.resolutions.fetch_add(1, Ordering::Relaxed);
        let ctx = self.inner.resolve(credentials)?;
        self.contexts.lock().unwrap().push(ctx.clone());
        Ok(ctx)
    }

    fn resolve_forwarded_agent(
        &self,
        user: &str,
        agent: &str,
    ) -> Result<OperationContext, tonic::Status> {
        self.inner.resolve_forwarded_agent(user, agent)
    }
}

impl Listener {
    async fn start(ca: &[u8], cert: &[u8], key: &[u8], scope: Option<RuntimeScope>) -> Self {
        let routing = scope.map_or(Routing::Local, Routing::User);
        Self::start_routed(ca, cert, key, routing).await
    }

    async fn start_routed(ca: &[u8], cert: &[u8], key: &[u8], routing: Routing) -> Self {
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
        managed_agent::install_managed_agent(&kernel).unwrap();
        let auth_resolutions = Arc::new(AtomicUsize::new(0));
        let auth_contexts = Arc::new(Mutex::new(Vec::new()));
        let auth = Arc::new(CountingAuth {
            inner: ApiKeyAuthProvider::cert_identity_only(),
            resolutions: Arc::clone(&auth_resolutions),
            contexts: Arc::clone(&auth_contexts),
        });
        let routes = match routing {
            Routing::User(scope) => build_user_runtime_routes(
                Arc::clone(&kernel),
                auth,
                scope,
                Arc::new(std::sync::OnceLock::new()),
                DataPlaneReady::open(),
                1024 * 1024,
                "scope-test",
            ),
            Routing::Local => build_vfs_routes(
                Arc::clone(&kernel),
                auth,
                Arc::new(std::sync::OnceLock::new()),
                DataPlaneReady::open(),
                1024 * 1024,
                "root-test",
            ),
            Routing::Gateway(resolver) => build_runtime_gateway_routes(
                Arc::clone(&kernel),
                auth,
                resolver,
                Arc::new(std::sync::OnceLock::new()),
                DataPlaneReady::open(),
                1024 * 1024,
                "gateway-test",
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
            kernel,
            auth_resolutions,
            auth_contexts,
            _root: root,
        }
    }

    async fn client(&self, ca: &[u8], cert: &[u8], key: &[u8]) -> NexusVfsServiceClient<Channel> {
        NexusVfsServiceClient::new(self.channel(ca, cert, key).await)
    }

    async fn channel(&self, ca: &[u8], cert: &[u8], key: &[u8]) -> Channel {
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
            .unwrap()
    }

    async fn close(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.task.await.unwrap().unwrap();
    }
}

#[derive(Default)]
struct Placement {
    channels: RwLock<HashMap<String, Channel>>,
    owners: Mutex<Vec<String>>,
}

#[tonic::async_trait]
impl UserRuntimeResolver for Placement {
    async fn resolve(&self, user_id: &str) -> Result<Channel, tonic::Status> {
        self.owners.lock().unwrap().push(user_id.into());
        self.channels
            .read()
            .unwrap()
            .get(user_id)
            .cloned()
            .ok_or_else(|| tonic::Status::unavailable("user runtime unavailable"))
    }
}

async fn managed_call(
    client: &mut NexusVfsServiceClient<Channel>,
    method: &str,
    payload: serde_json::Value,
) -> serde_json::Value {
    let response = client
        .call(CallRequest {
            method: format!("managed_agent.{method}_v1"),
            payload: serde_json::to_vec(&payload).unwrap(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(
        !response.is_error,
        "{}",
        String::from_utf8_lossy(&response.payload)
    );
    serde_json::from_slice(&response.payload).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn root_gateway_routes_real_control_and_streams_by_verified_owner_without_shadow_processes() {
    lib::transport_primitives::ensure_crypto_provider();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (gateway_cert, gateway_key) =
        generate_node_cert(1, "root", &ca, &ca_key, &[], None).unwrap();
    let (runtime_cert, runtime_key) =
        generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let (alice_cert, alice_key) =
        generate_session_agent_cert("session-alice", "alice", 300, &ca, &ca_key).unwrap();
    let (bob_cert, bob_key) =
        generate_session_agent_cert("session-bob", "bob", 300, &ca, &ca_key).unwrap();
    let alice_runtime = Listener::start(
        &ca,
        &runtime_cert,
        &runtime_key,
        Some(RuntimeScope::new("alice".into(), [1]).unwrap()),
    )
    .await;
    let bob_runtime = Listener::start(
        &ca,
        &runtime_cert,
        &runtime_key,
        Some(RuntimeScope::new("bob".into(), [1]).unwrap()),
    )
    .await;
    let placement = Arc::new(Placement::default());
    for (user, runtime) in [("alice", &alice_runtime), ("bob", &bob_runtime)] {
        let channel = runtime.channel(&ca, &gateway_cert, &gateway_key).await;
        placement
            .channels
            .write()
            .unwrap()
            .insert(user.into(), channel);
    }
    let root = Listener::start_routed(
        &ca,
        &gateway_cert,
        &gateway_key,
        Routing::Gateway(placement.clone()),
    )
    .await;
    let mut alice = root.client(&ca, &alice_cert, &alice_key).await;
    let mut bob = root.client(&ca, &bob_cert, &bob_key).await;
    let mut operator = root.client(&ca, &gateway_cert, &gateway_key).await;
    let before = root.auth_resolutions.load(Ordering::Relaxed);
    operator.ping(PingRequest::default()).await.unwrap();
    assert_eq!(
        root.auth_resolutions.load(Ordering::Relaxed) - before,
        1,
        "local dispatch must resolve identity once"
    );
    assert!(
        !operator
            .write(WriteRequest {
                path: "/root-only.txt".into(),
                content: b"root private bytes".to_vec(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
    let hidden = alice
        .read(ReadRequest {
            path: "/root-only.txt".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(hidden.is_error && hidden.content.is_empty());
    for (client, content) in [
        (&mut alice, b"alice's bytes".as_slice()),
        (&mut bob, b"bob's bytes".as_slice()),
    ] {
        let mut request = Request::new(WriteRequest {
            path: "/retained.txt".into(),
            content: content.into(),
            ..Default::default()
        });
        request.metadata_mut().append_bin(
            RUNTIME_DELEGATION_METADATA_KEY,
            MetadataValue::from_bytes(b"forged owner"),
        );
        request.metadata_mut().append_bin(
            RUNTIME_DELEGATION_METADATA_KEY,
            MetadataValue::from_bytes(b"second forged owner"),
        );
        let refusal = client.write(request).await.unwrap_err();
        assert_eq!(refusal.code(), Code::PermissionDenied);
        let before = root.auth_resolutions.load(Ordering::Relaxed);
        assert!(
            !client
                .write(WriteRequest {
                    path: "/retained.txt".into(),
                    content: content.into(),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .is_error
        );
        assert_eq!(
            root.auth_resolutions.load(Ordering::Relaxed) - before,
            1,
            "forwarded dispatch must resolve identity once"
        );
        assert_eq!(
            client
                .read(ReadRequest {
                    path: "/retained.txt".into(),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .content,
            content
        );
    }
    let start = alice
        .call(CallRequest {
            method: "managed_agent.start_session_v1".into(),
            payload: br#"{"agent_id":"writer-alice"}"#.to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(
        !start.is_error,
        "{}",
        String::from_utf8_lossy(&start.payload)
    );
    let started: serde_json::Value = serde_json::from_slice(&start.payload).unwrap();
    let pid = started["session_id"].as_str().unwrap();
    let second = managed_call(
        &mut alice,
        "start_session",
        serde_json::json!({"agent_id":"writer-alice"}),
    )
    .await;
    let second_pid = second["session_id"].as_str().unwrap();
    let bob_started = managed_call(
        &mut bob,
        "start_session",
        serde_json::json!({"agent_id":"writer-bob"}),
    )
    .await;
    let bob_pid = bob_started["session_id"].as_str().unwrap();
    assert_ne!(pid, second_pid);
    assert!(alice_runtime
        .kernel
        .agent_registry()
        .get(second_pid)
        .is_some());
    assert!(bob_runtime.kernel.agent_registry().get(bob_pid).is_some());
    for active in [pid, second_pid, bob_pid] {
        assert!(root.kernel.agent_registry().get(active).is_none());
    }
    assert!(alice_runtime.kernel.agent_registry().get(pid).is_some());
    assert!(root.kernel.agent_registry().get(pid).is_none());
    assert!(bob_runtime.kernel.agent_registry().get(pid).is_none());
    let description = alice
        .call(CallRequest {
            method: "managed_agent.get_session_v1".into(),
            payload: serde_json::to_vec(&serde_json::json!({"session_id":pid})).unwrap(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!description.is_error);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&description.payload).unwrap()["owner_id"],
        "alice"
    );
    let stream = "/nexus/streams/controller";
    assert!(
        !alice
            .setattr(SetattrRequest {
                path: stream.into(),
                entry_type: 4,
                capacity: 65536,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
    let bytes = br#"{"type":"approval","decision":"allow"}"#;
    assert!(
        !alice
            .stream_write_nowait(StreamWriteRequest {
                path: stream.into(),
                data: bytes.to_vec(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
    let reply = alice
        .stream_read_at(StreamReadAtRequest {
            path: stream.into(),
            blocking: false,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!reply.is_error && !reply.data.is_empty());
    assert!(reply.data.windows(bytes.len()).any(|value| value == bytes));
    let foreign_stream = bob
        .has_stream(IpcPathRequest {
            path: stream.into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!foreign_stream.present);
    assert!(
        !alice
            .close_stream(IpcPathRequest {
                path: stream.into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
    assert!(
        !alice
            .call(CallRequest {
                method: "managed_agent.cancel_v1".into(),
                payload: serde_json::to_vec(
                    &serde_json::json!({"session_id":pid,"mode":"session"})
                )
                .unwrap(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
    assert!(alice_runtime.kernel.agent_registry().get(pid).is_none());
    assert!(alice_runtime
        .kernel
        .agent_registry()
        .get(second_pid)
        .is_some());
    managed_call(
        &mut alice,
        "cancel",
        serde_json::json!({"session_id":second_pid,"mode":"session"}),
    )
    .await;
    managed_call(
        &mut bob,
        "cancel",
        serde_json::json!({"session_id":bob_pid,"mode":"session"}),
    )
    .await;
    let alice_channel = placement.channels.write().unwrap().remove("alice").unwrap();
    let failure = alice
        .write(WriteRequest {
            path: "/must-not-fallback.txt".into(),
            content: b"unsafe fallback".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(failure.code(), Code::Unavailable);
    let bob_channel = placement.channels.read().unwrap()["bob"].clone();
    placement
        .channels
        .write()
        .unwrap()
        .insert("alice".into(), bob_channel);
    let refusal = alice
        .read(ReadRequest {
            path: "/retained.txt".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(refusal.is_error && refusal.content.is_empty());
    let root_channel = root.channel(&ca, &gateway_cert, &gateway_key).await;
    placement
        .channels
        .write()
        .unwrap()
        .insert("alice".into(), root_channel);
    let refusal = alice
        .write(WriteRequest {
            path: "/must-not-fallback.txt".into(),
            content: b"wrong root endpoint".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(refusal.code(), Code::PermissionDenied);
    placement
        .channels
        .write()
        .unwrap()
        .insert("alice".into(), alice_channel);
    assert_eq!(
        alice
            .read(ReadRequest {
                path: "/retained.txt".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .content,
        b"alice's bytes"
    );
    assert!(
        !operator
            .stat(StatRequest {
                path: "/must-not-fallback.txt".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .found
    );
    assert!(
        !operator
            .stat(StatRequest {
                path: "/retained.txt".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .found
    );
    assert!(root
        .observed
        .lock()
        .unwrap()
        .iter()
        .all(|ctx| ctx.agent_id.is_none()));
    let lookups = placement.owners.lock().unwrap().len();
    let invalid = alice
        .write(WriteRequest {
            path: "/invalid-token.txt".into(),
            auth_token: "sk-deployment-token-must-not-override-the-user".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(invalid.code(), Code::Unauthenticated);
    let mut invalid = Request::new(WriteRequest {
        path: "/invalid-timeout.txt".into(),
        ..Default::default()
    });
    invalid
        .metadata_mut()
        .insert("grpc-timeout", "123456789S".parse().unwrap());
    assert_eq!(
        alice.write(invalid).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    assert_eq!(placement.owners.lock().unwrap().len(), lookups);
    for (runtime, owner, actor) in [
        (&alice_runtime, "alice", "session-alice"),
        (&bob_runtime, "bob", "session-bob"),
    ] {
        for ctx in runtime
            .observed
            .lock()
            .unwrap()
            .iter()
            .filter(|ctx| ctx.agent_id.is_some())
        {
            assert_eq!(ctx.user_id, owner);
            assert_eq!(ctx.agent_id.as_deref(), Some(actor));
            assert!(!ctx.is_admin && !ctx.is_system);
            assert!(
                root.auth_contexts.lock().unwrap().iter().any(|original| {
                    original.request_id == ctx.request_id
                        && original.user_id == ctx.user_id
                        && original.agent_id == ctx.agent_id
                        && original.subject_id == ctx.subject_id
                        && original.subject_type == ctx.subject_type
                }),
                "the runtime must retain the root-authenticated principal and request identity"
            );
        }
    }
    root.close().await;
    alice_runtime.close().await;
    bob_runtime.close().await;
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
    let mut unscoped = root.client(&ca, &gateway_cert, &gateway_key).await;
    assert_eq!(
        unscoped.ping(ping(&delegation)).await.unwrap_err().code(),
        Code::PermissionDenied
    );
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
