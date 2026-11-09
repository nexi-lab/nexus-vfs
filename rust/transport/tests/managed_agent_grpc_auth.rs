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

fn registry_result(response: CallResponse) -> serde_json::Value {
    assert!(
        !response.is_error,
        "registry error: {}",
        String::from_utf8_lossy(&response.payload)
    );
    serde_json::from_slice::<serde_json::Value>(&response.payload).unwrap()["result"].clone()
}

#[tokio::test]
async fn external_v2_rejects_delayed_same_owner_calls_and_pid_only_downgrades() {
    let kernel = Arc::new(Kernel::new());
    managed_agent::install_managed_agent(&kernel).unwrap();
    let routes = build_vfs_routes(
        Arc::clone(&kernel),
        Arc::new(TestAuth),
        Arc::new(OnceLock::new()),
        DataPlaneReady::open(),
        MAX_GRPC_MESSAGE_BYTES,
        "external-incarnation-test",
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
        "name": "same-agent", "connection_id": "same-connection", "host_pid": 424242,
        "labels": {"requires_wire_incarnation": "false"},
    });
    let mut invalid = registration.clone();
    invalid["local_id"] = serde_json::json!(u64::from(u32::MAX) + 1);
    assert!(
        call(&mut client, "alice", "agent_register_external_v2", invalid)
            .await
            .is_error
    );
    assert_eq!(kernel.agent_registry().count(), 0);
    let first = registry_result(
        call(
            &mut client,
            "alice",
            "agent_register_external_v2",
            registration.clone(),
        )
        .await,
    );
    let old_incarnation = first["incarnation"].as_str().unwrap().to_string();
    assert!(!old_incarnation.is_empty());
    assert_eq!(first["pid"], "424242");
    assert_eq!(first["owner_id"], "alice");
    let listing =
        registry_result(call(&mut client, "alice", "agent_list", serde_json::json!({})).await);
    assert_eq!(listing.as_array().unwrap().len(), 1);
    assert_eq!(listing[0]["incarnation"], old_incarnation);
    let duplicate = call(
        &mut client,
        "alice",
        "agent_register_external_v2",
        registration.clone(),
    )
    .await;
    assert!(duplicate.is_error);

    let old_request = serde_json::json!({"pid": "424242", "incarnation": old_incarnation});
    let heartbeat =
        registry_result(call(&mut client, "alice", "agent_heartbeat", old_request.clone()).await);
    assert_eq!(heartbeat["incarnation"], old_incarnation);
    assert_eq!(
        registry_result(
            call(
                &mut client,
                "alice",
                "agent_unregister_external",
                old_request
            )
            .await
        ),
        true
    );
    let second = registry_result(
        call(
            &mut client,
            "alice",
            "agent_register_external_v2",
            registration,
        )
        .await,
    );
    let new_incarnation = second["incarnation"].as_str().unwrap().to_string();
    assert_ne!(old_incarnation, new_incarnation);
    for method in [
        "managed_agent.get_session_v1",
        "managed_agent.cancel_v1",
        "managed_agent.cancel_v2",
    ] {
        let unrelated = call(
            &mut client,
            "alice",
            method,
            serde_json::json!({
                "session_id": "424242", "mode": "session", "channel_id": "unrelated-channel",
            }),
        )
        .await;
        assert!(
            unrelated.is_error,
            "{method} must not accept external registrations"
        );
    }
    let current_request = serde_json::json!({"pid": "424242", "incarnation": new_incarnation});
    let before =
        registry_result(call(&mut client, "alice", "agent_get", current_request.clone()).await);
    for method in [
        "agent_heartbeat",
        "agent_update_state",
        "agent_signal",
        "agent_unregister",
        "agent_unregister_external",
        "agent_get",
    ] {
        let request = serde_json::json!({
            "pid": "424242", "incarnation": old_incarnation,
            "state": "WARMING_UP", "sig": "SIGKILL", "payload": {"stale": "yes"},
        });
        let stale = call(&mut client, "alice", method, request.clone()).await;
        assert!(
            stale.is_error,
            "delayed same-owner {method} must refuse the replacement"
        );
        let error: serde_json::Value = serde_json::from_slice(&stale.payload).unwrap();
        assert_eq!(error["code"], -32007);
        let mut missing = request.clone();
        missing.as_object_mut().unwrap().remove("incarnation");
        assert!(
            call(&mut client, "alice", method, missing).await.is_error,
            "PID-only {method} must not downgrade a v2 registration"
        );
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!(""),
            serde_json::json!(false),
        ] {
            let mut malformed = request.clone();
            malformed["incarnation"] = invalid;
            assert!(call(&mut client, "alice", method, malformed).await.is_error);
        }
        let mut foreign = request;
        foreign["incarnation"] = serde_json::json!(new_incarnation);
        let denied = call(&mut client, "mallory", method, foreign).await;
        assert!(denied.is_error, "an incarnation does not grant ownership");
        let error: serde_json::Value = serde_json::from_slice(&denied.payload).unwrap();
        assert_eq!(error["code"], -32003);
    }
    let after =
        registry_result(call(&mut client, "alice", "agent_get", current_request.clone()).await);
    assert_eq!(
        before, after,
        "refused calls must preserve every replacement field"
    );
    for state in [AgentState::WarmingUp, AgentState::Ready] {
        let mut update = current_request.clone();
        update["state"] = serde_json::json!(state.as_str());
        let result =
            registry_result(call(&mut client, "alice", "agent_update_state", update).await);
        assert_eq!(result["state"], state.as_str());
        assert_eq!(result["incarnation"], new_incarnation);
    }
    let result = registry_result(
        call(
            &mut client,
            "alice",
            "agent_heartbeat",
            current_request.clone(),
        )
        .await,
    );
    assert_eq!(result["incarnation"], new_incarnation);
    let mut signal = current_request.clone();
    signal["sig"] = serde_json::json!("SIGUSR1");
    signal["payload"] = serde_json::json!({"live": "yes"});
    let result = registry_result(call(&mut client, "alice", "agent_signal", signal).await);
    assert_eq!(result["incarnation"], new_incarnation);
    assert_eq!(result["labels"]["live"], "yes");
    assert_eq!(
        registry_result(
            call(
                &mut client,
                "alice",
                "agent_unregister_external",
                current_request
            )
            .await
        ),
        true
    );
    assert_eq!(kernel.agent_registry().count(), 0);
    for cleanup in ["agent_unregister", "SIGTERM", "SIGKILL"] {
        let registered = registry_result(
            call(
                &mut client,
                "alice",
                "agent_register_external_v2",
                serde_json::json!({
                    "name": "same-agent", "connection_id": "same-connection", "host_pid": 424242,
                }),
            )
            .await,
        );
        let request = serde_json::json!({
            "pid": "424242", "incarnation": registered["incarnation"], "sig": cleanup,
        });
        let method = if cleanup == "agent_unregister" {
            cleanup
        } else {
            "agent_signal"
        };
        let retired = registry_result(call(&mut client, "alice", method, request).await);
        if cleanup != "agent_unregister" {
            assert_eq!(retired["incarnation"], registered["incarnation"]);
            assert_eq!(retired["state"], AgentState::Terminated.as_str());
        }
        assert_eq!(kernel.agent_registry().count(), 0);
    }
    server.abort();
}
