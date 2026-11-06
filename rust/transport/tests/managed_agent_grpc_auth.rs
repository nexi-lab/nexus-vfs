use std::sync::{Arc, OnceLock};
use std::time::Duration;

use contracts::{OperationContext, MAX_GRPC_MESSAGE_BYTES};
use kernel::core::agents::registry::AgentState;
use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient, CallRequest, CallResponse,
};
use kernel::kernel::Kernel;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Endpoint, Server};
use tonic::Request;
use transport::auth::{AuthCredentials, AuthProvider};
use transport::grpc::{build_vfs_routes, DataPlaneReady, ForeignCaVerifierSlot};

struct TestAuth;

impl AuthProvider for TestAuth {
    fn resolve(
        &self,
        credentials: &AuthCredentials<'_>,
    ) -> Result<OperationContext, tonic::Status> {
        let mut context = match credentials.token {
            "alice" => OperationContext::new("alice", "alpha", false, None, false),
            "mallory" => OperationContext::new("mallory", "alpha", false, None, false),
            "multi" => OperationContext::new("alice", "root", false, None, false),
            _ => OperationContext::new("cluster-internal", "root", true, None, true),
        };
        context.zone_perms = match credentials.token {
            "alice" | "mallory" => vec![("alpha".to_string(), "rw".to_string())],
            "multi" => vec![
                ("alpha".to_string(), "rw".to_string()),
                ("beta".to_string(), "r".to_string()),
            ],
            _ => vec![],
        };
        Ok(context)
    }
}

async fn call(
    client: &mut NexusVfsServiceClient<tonic::transport::Channel>,
    token: &str,
    method: &str,
    payload: serde_json::Value,
) -> CallResponse {
    client
        .call(Request::new(CallRequest {
            method: method.to_string(),
            payload: serde_json::to_vec(&payload).expect("payload"),
            auth_token: token.to_string(),
        }))
        .await
        .expect("Call RPC")
        .into_inner()
}

#[tokio::test]
async fn managed_agent_call_uses_authenticated_operation_context() {
    let kernel = Arc::new(Kernel::new());
    managed_agent::install_managed_agent(&kernel).expect("install managed-agent service");

    let verifier: ForeignCaVerifierSlot = Arc::new(OnceLock::new());
    let routes = build_vfs_routes(
        Arc::clone(&kernel),
        Arc::new(TestAuth),
        verifier,
        DataPlaneReady::open(),
        MAX_GRPC_MESSAGE_BYTES,
        "managed-agent-auth-test",
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        Server::builder()
            .add_routes(routes)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("serve VFS routes");
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let channel = Endpoint::from_shared(format!("http://{address}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut client = NexusVfsServiceClient::new(channel);

    let system_start = call(
        &mut client,
        "",
        "managed_agent.start_session_v1",
        serde_json::json!({
            "agent_id": "scode-standard",
            "owner_id": "alice",
            "zone_id": "root"
        }),
    )
    .await;
    assert!(!system_start.is_error);
    let started: serde_json::Value =
        serde_json::from_slice(&system_start.payload).expect("start response");
    let session_id = started["session_id"].as_str().expect("session id");
    assert_eq!(kernel.agent_registry().count(), 1);

    let single_zone = call(
        &mut client,
        "alice",
        "managed_agent.start_session_v1",
        serde_json::json!({"agent_id": "scode-standard", "zone_id": "alpha"}),
    )
    .await;
    assert!(single_zone.is_error);
    let single_zone_error: serde_json::Value =
        serde_json::from_slice(&single_zone.payload).expect("permission error payload");
    assert_eq!(single_zone_error["code"], -32003);
    assert_eq!(kernel.agent_registry().count(), 1, "denial must not spawn");

    let multi_zone_root = call(
        &mut client,
        "multi",
        "managed_agent.start_session_v1",
        serde_json::json!({"agent_id": "scode-standard", "zone_id": "root"}),
    )
    .await;
    assert!(multi_zone_root.is_error);
    assert_eq!(
        kernel.agent_registry().count(),
        1,
        "denial must not register a descriptor"
    );

    let foreign_get = call(
        &mut client,
        "mallory",
        "managed_agent.get_session_v1",
        serde_json::json!({"session_id": session_id}),
    )
    .await;
    assert!(foreign_get.is_error);
    let foreign_cancel = call(
        &mut client,
        "mallory",
        "managed_agent.cancel_v1",
        serde_json::json!({"session_id": session_id, "mode": "session"}),
    )
    .await;
    assert!(foreign_cancel.is_error);
    assert!(kernel.agent_registry().get(session_id).is_some());

    let owner_get = call(
        &mut client,
        "alice",
        "managed_agent.get_session_v1",
        serde_json::json!({"session_id": session_id}),
    )
    .await;
    assert!(!owner_get.is_error);
    let owner_cancel = call(
        &mut client,
        "alice",
        "managed_agent.cancel_v1",
        serde_json::json!({"session_id": session_id, "mode": "session"}),
    )
    .await;
    assert!(!owner_cancel.is_error);
    assert!(kernel.agent_registry().get(session_id).is_none());

    server.abort();
}

#[tokio::test]
async fn external_registry_lifecycle_keeps_owner_scope_after_pid_reuse() {
    let kernel = Arc::new(Kernel::new());
    let routes = build_vfs_routes(
        Arc::clone(&kernel),
        Arc::new(TestAuth),
        Arc::new(OnceLock::new()),
        DataPlaneReady::open(),
        MAX_GRPC_MESSAGE_BYTES,
        "external-registry-auth-test",
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_routes(routes)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = NexusVfsServiceClient::new(channel);
    let registration = serde_json::json!({
        "name": "same-agent",
        "zone_id": "alpha",
        "connection_id": "same-connection",
        "host_pid": 424242,
    });
    let registered = call(
        &mut client,
        "alice",
        "agent_register_external",
        registration.clone(),
    )
    .await;
    assert!(!registered.is_error);
    let original = kernel.agent_registry().get_instance("424242").unwrap().0;
    for method in [
        "agent_heartbeat",
        "agent_update_state",
        "agent_signal",
        "agent_unregister",
        "agent_unregister_external",
    ] {
        let denied = call(
            &mut client,
            "mallory",
            method,
            serde_json::json!({
                "pid": "424242", "state": "warming_up", "sig": "SIGKILL",
            }),
        )
        .await;
        assert!(denied.is_error, "foreign {method} must be denied");
        let error: serde_json::Value = serde_json::from_slice(&denied.payload).unwrap();
        assert_eq!(error["code"], -32003);
    }
    assert!(kernel.agent_registry().is_current_instance(&original));
    for state in [AgentState::WarmingUp, AgentState::Ready] {
        let updated = call(
            &mut client,
            "alice",
            "agent_update_state",
            serde_json::json!({"pid": "424242", "state": state.as_str()}),
        )
        .await;
        assert!(!updated.is_error);
        let body: serde_json::Value = serde_json::from_slice(&updated.payload).unwrap();
        assert_eq!(body["result"]["owner_id"], "alice");
        assert_eq!(body["result"]["state"], state.as_str());
    }
    let heartbeat = call(
        &mut client,
        "alice",
        "agent_heartbeat",
        serde_json::json!({"pid": "424242"}),
    )
    .await;
    assert!(!heartbeat.is_error);
    let retired = call(
        &mut client,
        "alice",
        "agent_unregister_external",
        serde_json::json!({"pid": "424242"}),
    )
    .await;
    assert!(!retired.is_error);
    assert!(kernel.agent_registry().get("424242").is_none());

    let replacement = call(
        &mut client,
        "mallory",
        "agent_register_external",
        registration,
    )
    .await;
    assert!(!replacement.is_error);
    assert!(!kernel.agent_registry().is_current_instance(&original));
    for method in [
        "agent_heartbeat",
        "agent_update_state",
        "agent_signal",
        "agent_unregister",
        "agent_unregister_external",
    ] {
        let denied = call(
            &mut client,
            "alice",
            method,
            serde_json::json!({
                "pid": "424242", "state": "warming_up", "sig": "SIGKILL",
            }),
        )
        .await;
        assert!(denied.is_error, "retired owner's {method} must be denied");
        let error: serde_json::Value = serde_json::from_slice(&denied.payload).unwrap();
        assert_eq!(error["code"], -32003);
    }
    let current = kernel.agent_registry().get("424242").unwrap();
    assert_eq!(current.owner_id, "mallory");
    assert_eq!(current.state, AgentState::Registered);
    let retired = call(
        &mut client,
        "mallory",
        "agent_unregister_external",
        serde_json::json!({"pid": "424242"}),
    )
    .await;
    assert!(!retired.is_error);
    assert!(kernel.agent_registry().get("424242").is_none());
    server.abort();
}
