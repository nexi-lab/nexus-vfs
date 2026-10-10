use std::sync::{Arc, OnceLock};
use std::time::Duration;

use contracts::{OperationContext, MAX_GRPC_MESSAGE_BYTES};
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
