//! Real Call RPCs against isolated kernels; protocol and authority acceptance.
//! These fixtures do not claim a connected CLI/cohost engine journey.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use contracts::runtime_status::RuntimeObservationHost;
use contracts::runtime_status::{
    BackgroundTaskSummary, ForegroundState, InputReason, RegisterRuntimeRequest,
    RuntimeAvailability, RuntimeIdentity, RuntimeInstanceId, RuntimeInventory, RuntimeObservation,
    RuntimePresence, RuntimeStatus, RuntimeStatusUpdate,
};
use contracts::{OperationContext, MAX_GRPC_MESSAGE_BYTES};
use kernel::core::agents::registry::{
    AgentDescriptor, AgentKind, RuntimeRegistryHost, RuntimeStatusSource,
};
use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient, CallRequest, CallResponse,
};
use kernel::kernel::Kernel;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Endpoint, Server};
use transport::auth::{AuthCredentials, AuthProvider};
use transport::grpc::{build_vfs_routes, DataPlaneReady, ForeignCaVerifierSlot};

#[path = "runtime_observation_rpc/directory.rs"]
mod directory;

struct OwnerAuth;

impl AuthProvider for OwnerAuth {
    fn resolve(
        &self,
        credentials: &AuthCredentials<'_>,
    ) -> Result<OperationContext, tonic::Status> {
        let (owner, actor) = match credentials.token {
            "alice" => ("alice", None),
            "alice-agent-a" => ("alice", Some("agent-a")),
            "alice-agent-b" => ("alice", Some("agent-b")),
            "mallory" => ("mallory", None),
            _ => return Err(tonic::Status::unauthenticated("unknown fixture credential")),
        };
        // Agent credentials can attend as themselves without receiving a
        // zone-wide file grant. The wire never accepts caller-built contexts.
        Ok(OperationContext::new(owner, "alpha", false, actor, false))
    }
}

struct Node {
    kernel: Arc<Kernel>,
    client: NexusVfsServiceClient<Channel>,
    server: tokio::task::JoinHandle<()>,
    is_certificate_auth: bool,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Node {
    async fn start() -> Self {
        let kernel = Arc::new(Kernel::new());
        let verifier: ForeignCaVerifierSlot = Arc::new(OnceLock::new());
        let routes = build_vfs_routes(
            Arc::clone(&kernel),
            Arc::new(OwnerAuth),
            verifier,
            DataPlaneReady::open(),
            MAX_GRPC_MESSAGE_BYTES,
            "runtime-observation-rpc",
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            Server::builder()
                .add_routes(routes)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .expect("serve");
        });
        let channel = Endpoint::from_shared(format!("http://{address}"))
            .expect("endpoint")
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .connect()
            .await
            .expect("connect bound listener");
        Self {
            kernel,
            client: NexusVfsServiceClient::new(channel),
            server,
            is_certificate_auth: false,
        }
    }

    async fn call(&mut self, token: &str, method: &str, payload: Value) -> CallResponse {
        self.client
            .call(tonic::Request::new(CallRequest {
                method: method.into(),
                payload: serde_json::to_vec(&payload).expect("payload"),
                auth_token: if self.is_certificate_auth {
                    String::new()
                } else {
                    token.into()
                },
            }))
            .await
            .expect("actual Call RPC")
            .into_inner()
    }

    async fn result<T: DeserializeOwned>(
        &mut self,
        token: &str,
        method: &str,
        payload: Value,
    ) -> T {
        let response = self.call(token, method, payload).await;
        assert!(
            !response.is_error,
            "{}",
            String::from_utf8_lossy(&response.payload)
        );
        let value: Value = serde_json::from_slice(&response.payload).expect("result envelope");
        serde_json::from_value(value["result"].clone()).expect("typed result")
    }

    async fn register(&mut self, connection: &str) -> RuntimeInstanceId {
        self.result(
            "alice-agent-a",
            "agent_runtime_register_v1",
            json!(RegisterRuntimeRequest {
                name: "agent-a".into(),
                connection_id: connection.into(),
                registration_id: uuid::Uuid::new_v4().to_string(),
                owner_id: None,
                zone_id: None,
            }),
        )
        .await
    }

    async fn observe(&mut self, instance: &RuntimeInstanceId) -> RuntimeObservation {
        self.result(
            "alice",
            "agent_runtime_get_v1",
            json!({"instance": instance}),
        )
        .await
    }

    async fn publish(
        &mut self,
        instance: &RuntimeInstanceId,
        update: &RuntimeStatusUpdate,
    ) -> RuntimeObservation {
        self.result(
            "alice-agent-a",
            "agent_runtime_publish_v1",
            json!({
                "instance": instance, "update": update,
            }),
        )
        .await
    }
}

fn update(revision: u64, foreground: ForegroundState) -> RuntimeStatusUpdate {
    RuntimeStatusUpdate {
        revision,
        identity: RuntimeIdentity {
            session_id: Some("shared-sid".into()),
            os_pid: Some(std::process::id()),
        },
        status: RuntimeStatus {
            foreground,
            background: BackgroundTaskSummary {
                terminals: 1,
                agents: 1,
                execution_unconfirmed: 0,
                tool_operations: 2,
            },
        },
    }
}

#[tokio::test]
async fn runtime_registration_refuses_pid_only_legacy_aliases() {
    let mut node = Node::start().await;
    let id = node.register(&uuid::Uuid::new_v4().to_string()).await;
    let facts = update(1, ForegroundState::Running);
    node.publish(&id, &facts).await;
    for (method, payload) in [
        ("agent_get", json!({"pid": id.pid})),
        ("agent_heartbeat", json!({"pid": id.pid})),
        (
            "agent_update_state",
            json!({"pid": id.pid, "state": "READY"}),
        ),
        ("agent_signal", json!({"pid": id.pid, "sig": "SIGKILL"})),
        ("agent_unregister", json!({"pid": id.pid})),
        ("agent_unregister_external", json!({"pid": id.pid})),
    ] {
        let response = node.call("alice-agent-a", method, payload).await;
        assert!(
            response.is_error,
            "PID-only {method} downgraded a runtime registration: {}",
            String::from_utf8_lossy(&response.payload)
        );
        assert_eq!(node.observe(&id).await.update, Some(facts.clone()));
    }
}

#[tokio::test]
async fn runtime_rpc_preserves_owner_instance_reuse_and_node_scope() {
    let mut first = Node::start().await;
    let mut second = Node::start().await;
    let connection = uuid::Uuid::new_v4().to_string();
    let id = first.register(&connection).await;
    let sibling = first.register(&uuid::Uuid::new_v4().to_string()).await;
    assert_ne!(id, sibling);
    assert_eq!(
        first.observe(&id).await.availability,
        RuntimeAvailability::Unsupported
    );

    let waiting = update(1, ForegroundState::AwaitingInput(InputReason::Question));
    assert_eq!(
        first.publish(&id, &waiting).await.update,
        Some(waiting.clone())
    );
    first
        .publish(&sibling, &update(1, ForegroundState::Idle))
        .await;
    let inventory: RuntimeInventory = first
        .result("alice", "agent_runtime_list_v1", json!({}))
        .await;
    assert!(inventory.scope.complete);
    assert_eq!(inventory.scope.owner_id.as_deref(), Some("alice"));
    assert_eq!(inventory.scope.zone_id, "alpha");
    assert_eq!(inventory.instances.len(), 2);
    assert!(inventory
        .instances
        .iter()
        .all(|row| row.agent_id == "agent-a"
            && row
                .update
                .as_ref()
                .expect("fresh")
                .identity
                .session_id
                .as_deref()
                == Some("shared-sid")));
    assert_ne!(
        inventory.instances[0].instance,
        inventory.instances[1].instance
    );

    let descriptor = first.kernel.agent_registry().get(&id.pid).expect("PCB");
    assert_eq!(descriptor.state.as_str(), "AWAITING_INPUT");
    assert_eq!(descriptor.reason.as_deref(), Some("question"));
    let permission = update(2, ForegroundState::AwaitingInput(InputReason::Permission));
    first.publish(&id, &permission).await;
    assert_eq!(
        first
            .kernel
            .agent_registry()
            .get(&id.pid)
            .expect("PCB")
            .reason
            .as_deref(),
        Some("permission")
    );

    let foreign = first
        .call("mallory", "agent_runtime_get_v1", json!({"instance": id}))
        .await;
    let mut missing = id.clone();
    missing.incarnation = uuid::Uuid::new_v4().to_string();
    let absent = first
        .call(
            "mallory",
            "agent_runtime_get_v1",
            json!({"instance": missing}),
        )
        .await;
    assert!(foreign.is_error && absent.is_error);
    assert_eq!(foreign.payload, absent.payload, "no existence oracle");
    assert!(
        first
            .call(
                "alice-agent-b",
                "agent_runtime_publish_v1",
                json!({"instance": id, "update": waiting})
            )
            .await
            .is_error
    );
    assert!(first.call("alice-agent-a", "agent_runtime_register_v1", json!({
        "name":"agent-a", "connection_id":uuid::Uuid::new_v4().to_string(), "registration_id":uuid::Uuid::new_v4().to_string(), "owner_id":"mallory",
    })).await.is_error);
    assert!(
        first
            .call(
                "alice-agent-a",
                "agent_runtime_register_v1",
                json!({
                    "name":"agent-b", "connection_id":uuid::Uuid::new_v4().to_string(), "registration_id":uuid::Uuid::new_v4().to_string(),
                })
            )
            .await
            .is_error
    );
    assert!(first.call("alice-agent-a", "agent_runtime_register_v1", json!({
        "name":"agent-a", "connection_id":uuid::Uuid::new_v4().to_string(), "registration_id":uuid::Uuid::new_v4().to_string(), "zone_id":"beta",
    })).await.is_error);

    let removed: bool = first
        .result(
            "alice-agent-a",
            "agent_runtime_unregister_v1",
            json!({"instance": id}),
        )
        .await;
    assert!(removed);
    let replacement = first.register(&connection).await;
    assert_eq!(id.pid, replacement.pid);
    assert_ne!(id.incarnation, replacement.incarnation);
    for method in [
        "agent_runtime_get_v1",
        "agent_runtime_heartbeat_v1",
        "agent_runtime_unregister_v1",
    ] {
        assert!(
            first
                .call("alice-agent-a", method, json!({"instance": id}))
                .await
                .is_error,
            "{method}"
        );
    }
    assert!(
        first
            .call(
                "alice-agent-a",
                "agent_runtime_publish_v1",
                json!({"instance": id, "update": permission})
            )
            .await
            .is_error
    );
    assert_eq!(
        first.observe(&replacement).await.availability,
        RuntimeAvailability::Unsupported
    );
    let other_node = second.register(&connection).await;
    assert_eq!(replacement.pid, other_node.pid);
    assert_ne!(replacement.registry_id, other_node.registry_id);
    assert!(
        second
            .call(
                "alice",
                "agent_runtime_unregister_v1",
                json!({"instance": replacement})
            )
            .await
            .is_error
    );
    assert_eq!(second.observe(&other_node).await.instance, other_node);
}

#[tokio::test]
async fn runtime_expiry_replay_and_heartbeat_preserve_unknown() {
    let mut node = Node::start().await;
    let id = node.register(&uuid::Uuid::new_v4().to_string()).await;
    let attendance = node.observe(&id).await;
    assert_eq!(attendance.presence, RuntimePresence::Online);
    assert_eq!(attendance.availability, RuntimeAvailability::Unsupported);
    let running = update(1, ForegroundState::Running);
    node.publish(&id, &running).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    loop {
        if node.observe(&id).await.availability == RuntimeAvailability::Stale {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "actual external observation did not expire"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let stale = node.publish(&id, &running).await;
    assert_eq!(stale.availability, RuntimeAvailability::Stale);
    assert_eq!(stale.presence, RuntimePresence::Unknown);
    assert!(
        stale.update.is_none(),
        "replayed work must not become fresh or idle"
    );
    let heartbeat: bool = node
        .result(
            "alice-agent-a",
            "agent_runtime_heartbeat_v1",
            json!({"instance": id}),
        )
        .await;
    assert!(heartbeat);
    let after_heartbeat = node.observe(&id).await;
    assert_eq!(after_heartbeat.availability, RuntimeAvailability::Stale);
    assert_eq!(after_heartbeat.presence, RuntimePresence::Online);
    assert!(after_heartbeat.update.is_none());
    let idle = update(2, ForegroundState::Idle);
    let fresh = node.publish(&id, &idle).await;
    assert_eq!(fresh.availability, RuntimeAvailability::Fresh);
    assert_eq!(fresh.update, Some(idle.clone()));
    assert!(node
        .kernel
        .agent_registry()
        .get(&id.pid)
        .expect("PCB")
        .reason
        .is_none());
    assert!(
        node.call(
            "alice-agent-a",
            "agent_runtime_publish_v1",
            json!({"instance": id, "update": running})
        )
        .await
        .is_error
    );
    let mut malformed = json!({"instance": id, "update": idle});
    malformed["update"]["status"]["foreground"] = json!({"state":"awaiting_input"});
    assert!(
        node.call("alice-agent-a", "agent_runtime_publish_v1", malformed)
            .await
            .is_error
    );
    assert_eq!(
        node.observe(&id)
            .await
            .update
            .expect("unchanged revision")
            .revision,
        2
    );
}

#[tokio::test]
async fn live_source_binding_cleanup_cannot_remove_a_replacement() {
    let mut node = Node::start().await;
    let registry = Arc::clone(node.kernel.agent_registry());
    let instance = registry
        .register_instance(AgentDescriptor {
            pid: "hosted-instance".into(),
            name: "agent-a".into(),
            owner_id: "alice".into(),
            zone_id: "alpha".into(),
            kind: AgentKind::Managed,
            ..AgentDescriptor::default()
        })
        .expect("register live host");
    let id = registry
        .runtime_instance_id(&instance)
        .expect("instance identity");
    let facts = Arc::new(Mutex::new(update(1, ForegroundState::Running).into_facts()));
    let source: RuntimeStatusSource = {
        let facts = Arc::clone(&facts);
        Arc::new(move || Some(facts.lock().expect("facts").clone()))
    };
    let host =
        RuntimeRegistryHost::new(Arc::clone(&registry), instance.clone(), None).expect("host");
    let binding = host
        .bind(Arc::clone(&source))
        .expect("host observation binding");
    assert_eq!(host.instance(), Some(id.clone()));
    assert_eq!(
        node.observe(&id)
            .await
            .update
            .expect("live")
            .status
            .foreground,
        ForegroundState::Running
    );
    *facts.lock().expect("facts") =
        update(2, ForegroundState::AwaitingInput(InputReason::Question)).into_facts();
    assert_eq!(node.observe(&id).await.update.expect("live").revision, 2);
    assert!(registry.unbind_runtime_status(&instance, &source));
    let replacement: RuntimeStatusSource =
        Arc::new(|| Some(update(1, ForegroundState::Idle).into_facts()));
    assert!(registry.bind_runtime_status(&instance, Arc::clone(&replacement)));
    drop(binding);
    assert!(!registry.unbind_runtime_status(&instance, &source));
    assert_eq!(
        node.observe(&id)
            .await
            .update
            .expect("replacement source")
            .revision,
        3
    );
    registry
        .unregister_instance(&instance)
        .expect("retire first host");
    assert!(host.instance().is_none());
    assert!(host.discover().is_err());
    let new_instance = registry
        .register_instance(AgentDescriptor {
            pid: id.pid.clone(),
            name: "agent-a".into(),
            owner_id: "alice".into(),
            zone_id: "alpha".into(),
            ..AgentDescriptor::default()
        })
        .expect("reused host pid");
    assert!(!registry.bind_runtime_status(&instance, replacement));
    assert!(registry.runtime_observation(&instance).is_none());
    assert!(registry
        .runtime_observation(&new_instance)
        .expect("new host")
        .update
        .is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_retry_preserves_intent_without_adopting_a_replacement() {
    let mut node = Node::start().await;
    let request = json!(RegisterRuntimeRequest {
        name: "agent-a".into(),
        connection_id: uuid::Uuid::new_v4().to_string(),
        registration_id: uuid::Uuid::new_v4().to_string(),
        owner_id: None,
        zone_id: None,
    });
    // Discard the initial reply, then send two real duplicate admission RPCs.
    assert!(
        !node
            .call(
                "alice-agent-a",
                "agent_runtime_register_v1",
                request.clone()
            )
            .await
            .is_error
    );
    let mut concurrent = node.client.clone();
    let duplicate = request.clone();
    let peer = tokio::spawn(async move {
        concurrent
            .call(tonic::Request::new(CallRequest {
                method: "agent_runtime_register_v1".into(),
                payload: serde_json::to_vec(&duplicate).expect("request"),
                auth_token: "alice-agent-a".into(),
            }))
            .await
            .expect("duplicate RPC")
            .into_inner()
    });
    let id: RuntimeInstanceId = node
        .result(
            "alice-agent-a",
            "agent_runtime_register_v1",
            request.clone(),
        )
        .await;
    let duplicate = peer.await.expect("join");
    assert!(!duplicate.is_error);
    let body: Value = serde_json::from_slice(&duplicate.payload).expect("envelope");
    assert_eq!(
        serde_json::from_value::<RuntimeInstanceId>(body["result"].clone()).expect("identity"),
        id
    );
    let retired: bool = node
        .result(
            "alice-agent-a",
            "agent_runtime_unregister_v1",
            json!({"instance":id}),
        )
        .await;
    assert!(retired);
    let mut replacement_request = request.clone();
    replacement_request["registration_id"] = json!(uuid::Uuid::new_v4().to_string());
    let replacement: RuntimeInstanceId = node
        .result(
            "alice-agent-a",
            "agent_runtime_register_v1",
            replacement_request,
        )
        .await;
    assert_eq!(replacement.pid, id.pid);
    assert_ne!(replacement.incarnation, id.incarnation);
    assert!(
        node.call("alice-agent-a", "agent_runtime_register_v1", request)
            .await
            .is_error,
        "an old intent must not resolve whichever registration now owns its PID"
    );
    assert_eq!(node.observe(&replacement).await.instance, replacement);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inflight_retired_source_never_pairs_old_sid_with_new_engine_facts() {
    let mut node = Node::start().await;
    let registry = Arc::clone(node.kernel.agent_registry());
    let instance = registry
        .register_instance(AgentDescriptor {
            pid: "source-swap".into(),
            name: "agent-a".into(),
            owner_id: "alice".into(),
            zone_id: "alpha".into(),
            kind: AgentKind::Managed,
            ..Default::default()
        })
        .expect("host");
    let id = registry.runtime_instance_id(&instance).expect("identity");
    let (entered, receive_entered) = std::sync::mpsc::sync_channel(1);
    let (release, released) = std::sync::mpsc::sync_channel(1);
    let released = Mutex::new(released);
    let source: RuntimeStatusSource = Arc::new(move || {
        entered.send(()).expect("entered");
        released
            .lock()
            .expect("barrier")
            .recv_timeout(Duration::from_secs(10))
            .expect("release");
        Some(update(1, ForegroundState::Running).into_facts())
    });
    assert!(registry.bind_runtime_status(&instance, Arc::clone(&source)));
    let mut client = node.client.clone();
    let request = json!({"instance":id});
    let query = tokio::spawn(async move {
        client
            .call(tonic::Request::new(CallRequest {
                method: "agent_runtime_get_v1".into(),
                payload: serde_json::to_vec(&request).expect("request"),
                auth_token: "alice".into(),
            }))
            .await
            .expect("query")
            .into_inner()
    });
    tokio::task::spawn_blocking(move || {
        receive_entered
            .recv_timeout(Duration::from_secs(3))
            .expect("in-flight source read")
    })
    .await
    .expect("entered");
    assert!(registry.unbind_runtime_status(&instance, &source));
    let successor: RuntimeStatusSource =
        Arc::new(|| Some(update(1, ForegroundState::Idle).into_facts()));
    assert!(registry.bind_runtime_status(&instance, successor));
    release.send(()).expect("release retired callback");
    let response = query.await.expect("query joined");
    assert!(!response.is_error);
    let body: Value = serde_json::from_slice(&response.payload).expect("response");
    let observation: RuntimeObservation =
        serde_json::from_value(body["result"].clone()).expect("observation");
    assert_eq!(observation.availability, RuntimeAvailability::Unavailable);
    assert!(observation.update.is_none());
    assert_eq!(
        node.observe(&id)
            .await
            .update
            .expect("successor")
            .status
            .foreground,
        ForegroundState::Idle
    );
}
