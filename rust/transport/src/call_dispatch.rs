//! Generic `Call` RPC dispatcher — control-plane only.
//!
//! Every syscall is now a typed RPC. This file retains the remaining
//! non-syscall Call methods: the service-lifecycle no-ops the Python
//! factory emits during boot, and explicit error stubs for the
//! lookup-shaped ops the subprocess kernel does not expose over the
//! wire (service / trie / agent registries). Anything else hits the
//! unknown-method error path.

use std::collections::HashMap;
use std::sync::Arc;

use contracts::{resolve_agent_owner, resolve_agent_zone, AgentContextError, RustCallError};
use kernel::core::agents::registry::{
    AgentDescriptor, AgentError, AgentInstance, AgentKind, AgentSignal, AgentState,
    ExternalProcessInfo,
};
use kernel::kernel::vfs_proto::CallResponse;
use kernel::kernel::{Kernel, OperationContext};
use tonic::{Response, Status};

use crate::grpc::{encode_rpc_error, RpcErrorCode};

/// What to tell a caller that asked `Call` for something it does not carry.
///
/// The generic surface is an escape hatch for registry-shaped operations and
/// `service.method` plugin dispatch — it is NOT the VFS. Every file operation
/// is a typed RPC, and a client that reaches for `call("mkdir")` gets a bare
/// "unknown" today and concludes the daemon is broken or the method
/// unimplemented. One downstream shipped `exists` / `mkdir` / `list` /
/// `delete` wrappers over this path and none had ever worked; `exists`
/// swallowed the error as `false`, so it took months to notice. Say where the
/// method actually lives.
fn unknown_method_message(method: &str) -> String {
    format!(
        "unknown Call method: {method} — the generic Call surface carries          registry ops (agent_*, get_mount_points, service_*) and          `<service>.<method>` plugin dispatch only. File operations are typed          RPCs on NexusVfsService (Read/Write/Stat/Readdir/Mkdir/Delete/Rename/         Setattr/Ping); call those instead."
    )
}

/// Dispatch a generic Call RPC. After the typed-RPC migration only the
/// non-syscall control plane stays here.
pub fn dispatch(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    method: &str,
    payload: &[u8],
) -> Result<Response<CallResponse>, Status> {
    let params: serde_json::Value =
        serde_json::from_slice(payload).unwrap_or(serde_json::Value::Object(Default::default()));

    let result = match method {
        "get_mount_points" => ok_json(serde_json::json!(kernel.get_mount_points())),

        // Service lifecycle — no-ops for subprocess mode (the Rust
        // binary manages its own service lifecycle).
        "service_start_all"
        | "service_mark_bootstrapped"
        | "service_stop_all"
        | "service_close_all" => ok_json(serde_json::json!(null)),

        // Lookup-shaped ops the subprocess kernel doesn't expose.
        "service_lookup" | "service_swap" => Err(encode_rpc_error(
            RpcErrorCode::InternalError,
            &format!("{method} is not available in subprocess mode"),
        )),

        // Trie — not exposed via gRPC.
        "trie_register" | "trie_lookup" | "trie_unregister" => Err(call_err(
            RpcErrorCode::InternalError,
            &format!("{method} is not available in subprocess mode"),
        )),

        // Agent registry
        "agent_register" | "agent_register_external" => do_agent_register(kernel, ctx, &params),
        "agent_register_external_v2" => do_agent_register_external_v2(kernel, ctx, &params),
        "agent_unregister" => do_agent_unregister(kernel, ctx, &params),
        "agent_unregister_external" => do_agent_unregister_external(kernel, ctx, &params),
        "agent_get" => do_agent_get(kernel, ctx, &params),
        "agent_list" => do_agent_list(kernel, ctx, &params),
        "agent_update_state" => do_agent_update_state(kernel, ctx, &params),
        "agent_signal" => do_agent_signal(kernel, ctx, &params),
        "agent_heartbeat" => do_agent_heartbeat(kernel, ctx, &params),

        // Dot-notation: "service_name.method" → dispatch to registered
        // RustService or dylib plugin via Kernel::dispatch_rust_call.
        // Used by vault plugin ("password-vault.secret_put") and any
        // future service plugins.
        _ if method.contains('.') => {
            if let Some((svc_name, svc_method)) = method.split_once('.') {
                match kernel.dispatch_rust_call_ctx(ctx, svc_name, svc_method, payload) {
                    Some(Ok(raw_bytes)) => {
                        // Plugin dispatch returns raw protobuf bytes — pass
                        // through without JSON wrapping.
                        return Ok(Response::new(CallResponse {
                            payload: raw_bytes,
                            is_error: false,
                        }));
                    }
                    Some(Err(RustCallError::PermissionDenied(message))) => {
                        Err(permission_err(&message))
                    }
                    Some(Err(e)) => Err(call_err(
                        RpcErrorCode::InternalError,
                        &format!("{svc_name}.{svc_method}: {e}"),
                    )),
                    None => Err(call_err(
                        RpcErrorCode::InternalError,
                        &format!("service not found: {svc_name}"),
                    )),
                }
            } else {
                Err(call_err(
                    RpcErrorCode::InternalError,
                    &unknown_method_message(method),
                ))
            }
        }

        _ => Err(call_err(
            RpcErrorCode::InternalError,
            &unknown_method_message(method),
        )),
    };

    match result {
        Ok(payload_bytes) => Ok(Response::new(CallResponse {
            payload: payload_bytes,
            is_error: false,
        })),
        Err(err_payload) => Ok(Response::new(CallResponse {
            payload: err_payload,
            is_error: true,
        })),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn s(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn opt_s(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn labels_map(v: &serde_json::Value, key: &str) -> HashMap<String, String> {
    v.get(key)
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| {
                    let value = v
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string());
                    (k.clone(), value)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn ok_json(val: serde_json::Value) -> Result<Vec<u8>, Vec<u8>> {
    let wrapped = serde_json::json!({"result": val});
    Ok(serde_json::to_vec(&wrapped).unwrap_or_else(|_| b"{}".to_vec()))
}

fn call_err(code: RpcErrorCode, msg: &str) -> Vec<u8> {
    encode_rpc_error(code, msg)
}

fn agent_err_to_payload(err: AgentError) -> Vec<u8> {
    let code = match &err {
        AgentError::NotFound(_) => RpcErrorCode::FileNotFound,
        AgentError::AlreadyExists(_) | AgentError::InvalidTransition { .. } => {
            RpcErrorCode::Conflict
        }
        AgentError::InvalidKind(_) | AgentError::Protocol(_) => RpcErrorCode::ValidationError,
        AgentError::PidExhausted => RpcErrorCode::InternalError,
    };
    encode_rpc_error(code, &err.to_string())
}

fn permission_err(message: &str) -> Vec<u8> {
    call_err(RpcErrorCode::PermissionError, message)
}

fn agent_context_err(error: AgentContextError) -> Vec<u8> {
    match error {
        AgentContextError::InvalidArgument(message) => {
            call_err(RpcErrorCode::ValidationError, &message)
        }
        AgentContextError::PermissionDenied(message) => permission_err(&message),
    }
}

fn effective_agent_owner(
    ctx: &OperationContext,
    params: &serde_json::Value,
) -> Result<String, Vec<u8>> {
    let requested = opt_s(params, "owner_id");
    resolve_agent_owner(ctx, requested.as_deref()).map_err(agent_context_err)
}

fn effective_agent_zone(
    ctx: &OperationContext,
    params: &serde_json::Value,
) -> Result<String, Vec<u8>> {
    let requested = opt_s(params, "zone_id");
    resolve_agent_zone(ctx, requested.as_deref()).map_err(agent_context_err)
}

fn authorize_agent_owner(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    pid: &str,
) -> Result<AgentInstance, Vec<u8>> {
    let (instance, descriptor) = kernel.agent_registry().get_instance(pid).ok_or_else(|| {
        call_err(
            RpcErrorCode::FileNotFound,
            &format!("process not found: {pid}"),
        )
    })?;
    if descriptor.owner_id != ctx.user_id && !ctx.is_admin && !ctx.is_system {
        return Err(permission_err(
            "agent operation requires ownership or administrator privileges",
        ));
    }
    Ok(instance)
}

fn agent_not_found(pid: &str) -> Vec<u8> {
    call_err(
        RpcErrorCode::FileNotFound,
        &format!("process not found: {pid}"),
    )
}

fn check_wire_incarnation(
    instance: &AgentInstance,
    params: &serde_json::Value,
) -> Result<(), Vec<u8>> {
    match params.get("incarnation") {
        None if !instance.requires_wire_incarnation() => Ok(()),
        Some(serde_json::Value::String(value)) if !value.is_empty() => {
            if *value == instance.incarnation().to_string() {
                Ok(())
            } else {
                Err(call_err(
                    RpcErrorCode::FileNotFound,
                    "agent incarnation not found",
                ))
            }
        }
        _ => Err(call_err(
            RpcErrorCode::ValidationError,
            "this agent operation requires its non-empty registration incarnation",
        )),
    }
}

fn authorize_agent_operation(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    pid: &str,
    params: &serde_json::Value,
) -> Result<AgentInstance, Vec<u8>> {
    let instance = authorize_agent_owner(kernel, ctx, pid)?;
    check_wire_incarnation(&instance, params)?;
    Ok(instance)
}

fn agent_instance_to_json(
    instance: &AgentInstance,
    descriptor: &AgentDescriptor,
) -> serde_json::Value {
    let mut value = agent_descriptor_to_json(descriptor);
    if instance.requires_wire_incarnation() {
        value["incarnation"] = serde_json::json!(instance.incarnation().to_string());
    }
    value
}

fn agent_descriptor_to_json(desc: &AgentDescriptor) -> serde_json::Value {
    let external_info = desc.external_info.as_ref().map(|info| {
        serde_json::json!({
            "connection_id": &info.connection_id,
            "remote_addr": &info.remote_addr,
            "protocol": &info.protocol,
            "last_heartbeat_ms": info.last_heartbeat_ms,
        })
    });
    let repos: Vec<serde_json::Value> = desc
        .repos
        .iter()
        .map(|repo| {
            serde_json::json!({
                "alias": &repo.alias,
                "mount_path": &repo.mount_path,
            })
        })
        .collect();

    serde_json::json!({
        "pid": &desc.pid,
        "name": &desc.name,
        "kind": desc.kind.as_str(),
        "owner_id": &desc.owner_id,
        "zone_id": &desc.zone_id,
        "parent_pid": &desc.parent_pid,
        "state": desc.state.as_str(),
        "reason": &desc.reason,
        "exit_code": desc.exit_code,
        "generation": desc.generation,
        "cwd": &desc.cwd,
        "root": &desc.root,
        "children": &desc.children,
        "created_at_ms": desc.created_at_ms,
        "updated_at_ms": desc.updated_at_ms,
        "last_heartbeat_ms": desc.last_heartbeat_ms,
        "connection_id": &desc.connection_id,
        "external_info": external_info,
        "labels": &desc.labels,
        "repos": repos,
    })
}

// ── Agent registry handlers ─────────────────────────────────────────

fn do_agent_register_external_v2(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    params: &serde_json::Value,
) -> Result<Vec<u8>, Vec<u8>> {
    let required = |key| {
        opt_s(params, key).ok_or_else(|| {
            call_err(
                RpcErrorCode::ValidationError,
                &format!("external registration requires {key}"),
            )
        })
    };
    let name = required("name")?;
    let connection_id = required("connection_id")?;
    let owner_id = effective_agent_owner(ctx, params)?;
    let zone_id = effective_agent_zone(ctx, params)?;
    let host_pid = params
        .get("host_pid")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_i64()
                .filter(|pid| *pid > 0)
                .ok_or_else(|| call_err(RpcErrorCode::ValidationError, "host_pid must be positive"))
        })
        .transpose()?;
    let local_id = params
        .get("local_id")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| call_err(RpcErrorCode::ValidationError, "local_id must be a u32"))
        })
        .transpose()?;
    let (instance, descriptor) = kernel
        .agent_registry()
        .register_external_with_instance(
            name,
            owner_id,
            zone_id,
            connection_id,
            host_pid,
            local_id,
            opt_s(params, "remote_addr"),
            opt_s(params, "protocol").unwrap_or_else(|| "grpc".to_string()),
            opt_s(params, "parent_pid"),
            labels_map(params, "labels"),
            true,
        )
        .map_err(agent_err_to_payload)?;
    ok_json(agent_instance_to_json(&instance, &descriptor))
}

fn do_agent_register(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    params: &serde_json::Value,
) -> Result<Vec<u8>, Vec<u8>> {
    let name = s(params, "name");
    let owner_id = effective_agent_owner(ctx, params)?;
    let zone_id = effective_agent_zone(ctx, params)?;
    let connection_id = opt_s(params, "connection_id");
    let parent_pid = opt_s(params, "parent_pid");
    let labels = labels_map(params, "labels");

    let desc = if let Some(connection_id) = connection_id {
        let host_pid = params.get("host_pid").and_then(|v| v.as_i64());
        let local_id = params
            .get("local_id")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let remote_addr = opt_s(params, "remote_addr");
        let protocol = opt_s(params, "protocol").unwrap_or_else(|| "grpc".to_string());
        kernel
            .agent_registry()
            .register_external(
                name,
                owner_id,
                zone_id,
                connection_id,
                host_pid,
                local_id,
                remote_addr,
                protocol,
                parent_pid,
                labels,
            )
            .map_err(agent_err_to_payload)?
    } else {
        let kind = opt_s(params, "kind")
            .and_then(|k| AgentKind::from_str(&k))
            .unwrap_or(AgentKind::Managed);
        let pid = opt_s(params, "pid");
        let cwd = opt_s(params, "cwd").unwrap_or_else(|| "/".to_string());
        let external_info =
            opt_s(params, "external_connection_id").map(|connection_id| ExternalProcessInfo {
                connection_id,
                remote_addr: opt_s(params, "remote_addr"),
                protocol: opt_s(params, "protocol").unwrap_or_else(|| "grpc".to_string()),
                last_heartbeat_ms: None,
            });
        kernel
            .agent_registry()
            .spawn(
                name,
                owner_id,
                zone_id,
                kind,
                parent_pid,
                pid,
                cwd,
                external_info,
                labels,
            )
            .map_err(agent_err_to_payload)?
    };
    ok_json(agent_descriptor_to_json(&desc))
}

fn do_agent_unregister(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    params: &serde_json::Value,
) -> Result<Vec<u8>, Vec<u8>> {
    let pid = s(params, "pid");
    let instance = authorize_agent_operation(kernel, ctx, &pid, params)?;
    let removed = kernel
        .agent_registry()
        .unregister_instance(&instance)
        .is_some();
    ok_json(serde_json::json!(removed))
}

fn do_agent_unregister_external(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    params: &serde_json::Value,
) -> Result<Vec<u8>, Vec<u8>> {
    let pid = s(params, "pid");
    let instance = authorize_agent_operation(kernel, ctx, &pid, params)?;
    let removed = kernel
        .agent_registry()
        .unregister_external_instance(&instance)
        .map_err(agent_err_to_payload)?;
    if !removed {
        return Err(agent_not_found(&pid));
    }
    ok_json(serde_json::json!(removed))
}

/// Same ownership rule as every other agent method: the descriptor a
/// caller reads must be their own, or the caller must be admin/system.
/// A missing pid answers with the SAME permission error as someone
/// else's pid — an error-vs-null split would hand the caller an
/// existence oracle ("does this pid belong to someone?") without ever
/// granting the descriptor.
fn do_agent_get(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    params: &serde_json::Value,
) -> Result<Vec<u8>, Vec<u8>> {
    let pid = s(params, "pid");
    match kernel.agent_registry().get_instance(&pid) {
        Some((instance, desc)) => {
            if desc.owner_id != ctx.user_id && !ctx.is_admin && !ctx.is_system {
                return Err(permission_err(
                    "agent operation requires ownership or administrator privileges",
                ));
            }
            check_wire_incarnation(&instance, params)?;
            ok_json(agent_instance_to_json(&instance, &desc))
        }
        None => Err(permission_err(
            "agent operation requires ownership or administrator privileges",
        )),
    }
}

fn do_agent_list(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    params: &serde_json::Value,
) -> Result<Vec<u8>, Vec<u8>> {
    let zone_id = opt_s(params, "zone_id");
    let requested_owner = opt_s(params, "owner_id");
    let owner_id = if ctx.is_admin || ctx.is_system {
        requested_owner
    } else {
        Some(ctx.user_id.clone())
    };
    let kind = opt_s(params, "kind").and_then(|k| AgentKind::from_str(&k));
    let state = opt_s(params, "state").and_then(|s| AgentState::from_str(&s));
    let records = kernel.agent_registry().list(
        zone_id.as_deref(),
        owner_id.as_deref(),
        kind.as_ref(),
        state.as_ref(),
    );
    let mut values = Vec::new();
    for candidate in records {
        let Some((instance, descriptor)) = kernel.agent_registry().get_instance(&candidate.pid)
        else {
            continue;
        };
        // Recheck filters on the descriptor captured with this identity: the
        // enumeration candidate may have exited or changed owners already.
        if zone_id
            .as_ref()
            .is_some_and(|zone| zone != &descriptor.zone_id)
            || owner_id
                .as_ref()
                .is_some_and(|owner| owner != &descriptor.owner_id)
            || kind.as_ref().is_some_and(|kind| kind != &descriptor.kind)
            || state
                .as_ref()
                .is_some_and(|state| state != &descriptor.state)
        {
            continue;
        }
        values.push(agent_instance_to_json(&instance, &descriptor));
    }
    ok_json(serde_json::json!(values))
}

fn do_agent_update_state(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    params: &serde_json::Value,
) -> Result<Vec<u8>, Vec<u8>> {
    let pid = s(params, "pid");
    let instance = authorize_agent_operation(kernel, ctx, &pid, params)?;
    let state = opt_s(params, "state")
        .or_else(|| opt_s(params, "new_state"))
        .and_then(|s| AgentState::from_str(&s))
        .ok_or_else(|| {
            call_err(
                RpcErrorCode::ValidationError,
                "invalid or missing agent state",
            )
        })?;
    match kernel
        .agent_registry()
        .update_instance_state(&instance, state, None)
    {
        Ok(true) => match kernel.agent_registry().get_instance_descriptor(&instance) {
            Some(desc) => ok_json(agent_instance_to_json(&instance, &desc)),
            None => Err(agent_not_found(&pid)),
        },
        Ok(false) => Err(agent_not_found(&pid)),
        Err(err) => Err(agent_err_to_payload(err)),
    }
}

fn do_agent_signal(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    params: &serde_json::Value,
) -> Result<Vec<u8>, Vec<u8>> {
    let pid = s(params, "pid");
    let instance = authorize_agent_operation(kernel, ctx, &pid, params)?;
    let sig = opt_s(params, "sig")
        .or_else(|| opt_s(params, "signal"))
        .and_then(|s| AgentSignal::from_str(&s))
        .ok_or_else(|| {
            call_err(
                RpcErrorCode::ValidationError,
                "invalid or missing agent signal",
            )
        })?;
    let payload = params
        .get("payload")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| {
                    let value = v
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string());
                    (k.clone(), value)
                })
                .collect::<HashMap<String, String>>()
        });

    let desc = kernel
        .agent_registry()
        .signal_instance(&instance, sig, payload)
        .map_err(agent_err_to_payload)?
        .ok_or_else(|| agent_not_found(&pid))?;
    ok_json(agent_instance_to_json(&instance, &desc))
}

fn do_agent_heartbeat(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    params: &serde_json::Value,
) -> Result<Vec<u8>, Vec<u8>> {
    let pid = s(params, "pid");
    let instance = authorize_agent_operation(kernel, ctx, &pid, params)?;
    let descriptor = kernel
        .agent_registry()
        .heartbeat_instance(&instance)
        .map_err(agent_err_to_payload)?
        .ok_or_else(|| agent_not_found(&pid))?;
    ok_json(agent_instance_to_json(&instance, &descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_instance_does_not_follow_a_pid_reassigned_to_another_owner() {
        let kernel = Arc::new(Kernel::new());
        let owner = OperationContext::new("alice", "alpha", false, None, false);
        let descriptor = kernel
            .agent_registry()
            .register_external(
                "same-agent".into(),
                "alice".into(),
                "alpha".into(),
                "same-connection".into(),
                Some(42),
                None,
                None,
                "grpc".into(),
                None,
                HashMap::new(),
            )
            .unwrap();
        let authorized = authorize_agent_owner(&kernel, &owner, "42").unwrap();
        kernel.agent_registry().unregister("42").unwrap();
        let mut replacement = descriptor;
        replacement.owner_id = "bob".into();
        replacement.last_heartbeat_ms = Some(1000);
        assert!(kernel.agent_registry().register(replacement));

        assert!(!kernel
            .agent_registry()
            .update_instance_state(&authorized, AgentState::WarmingUp, None)
            .unwrap());
        assert!(kernel
            .agent_registry()
            .heartbeat_instance(&authorized)
            .unwrap()
            .is_none());
        assert!(kernel
            .agent_registry()
            .signal_instance(&authorized, AgentSignal::Sigkill, None)
            .unwrap()
            .is_none());
        assert!(!kernel
            .agent_registry()
            .unregister_external_instance(&authorized)
            .unwrap());
        assert!(kernel
            .agent_registry()
            .unregister_instance(&authorized)
            .is_none());
        assert!(kernel
            .agent_registry()
            .get_instance_descriptor(&authorized)
            .is_none());
        let current = kernel.agent_registry().get("42").unwrap();
        assert_eq!(current.owner_id, "bob");
        assert_eq!(current.state, AgentState::Registered);
        assert_eq!(current.last_heartbeat_ms, Some(1000));
        assert!(authorize_agent_owner(&kernel, &owner, "42").is_err());
    }

    fn result_payload(response: kernel::kernel::vfs_proto::CallResponse) -> serde_json::Value {
        let payload: serde_json::Value =
            serde_json::from_slice(&response.payload).expect("response JSON");
        payload.get("result").cloned().expect("result envelope")
    }

    fn error_payload(response: kernel::kernel::vfs_proto::CallResponse) -> serde_json::Value {
        assert!(response.is_error, "response did not carry an error payload");
        serde_json::from_slice(&response.payload).expect("error JSON")
    }

    #[test]
    fn agent_registry_dispatch_routes_to_kernel_ssot() {
        let kernel = Arc::new(Kernel::new());
        let ctx = OperationContext::new("admin", kernel::ROOT_ZONE_ID, true, None, true);
        let payload = serde_json::to_vec(&serde_json::json!({
            "name": "E2E Agent",
            "owner_id": "admin",
            "zone_id": kernel::ROOT_ZONE_ID,
            "connection_id": "admin,e2e",
            "labels": {"capabilities": "test"},
        }))
        .expect("payload");

        let registered = dispatch(&kernel, &ctx, "agent_register_external", &payload)
            .expect("dispatch")
            .into_inner();
        assert!(!registered.is_error, "register returned error payload");
        let registered = result_payload(registered);
        assert_eq!(registered["pid"], "admin,e2e");
        assert_eq!(registered["state"], "REGISTERED");

        let list_payload = serde_json::to_vec(&serde_json::json!({
            "zone_id": kernel::ROOT_ZONE_ID,
        }))
        .expect("payload");
        let listed = dispatch(&kernel, &ctx, "agent_list", &list_payload)
            .expect("dispatch")
            .into_inner();
        let listed = result_payload(listed);
        assert_eq!(listed.as_array().expect("agent list").len(), 1);

        let update_payload = serde_json::to_vec(&serde_json::json!({
            "pid": "admin,e2e",
            "state": "warming_up",
        }))
        .expect("payload");
        let warming = dispatch(&kernel, &ctx, "agent_update_state", &update_payload)
            .expect("dispatch")
            .into_inner();
        assert_eq!(result_payload(warming)["state"], "WARMING_UP");

        let ready_payload = serde_json::to_vec(&serde_json::json!({
            "pid": "admin,e2e",
            "state": "ready",
        }))
        .expect("payload");
        let ready = dispatch(&kernel, &ctx, "agent_update_state", &ready_payload)
            .expect("dispatch")
            .into_inner();
        let ready = result_payload(ready);
        assert_eq!(ready["state"], "READY");

        let heartbeat_payload = serde_json::to_vec(&serde_json::json!({
            "pid": "admin,e2e",
        }))
        .expect("payload");
        let heartbeat = dispatch(&kernel, &ctx, "agent_heartbeat", &heartbeat_payload)
            .expect("dispatch")
            .into_inner();
        let heartbeat = result_payload(heartbeat);
        assert!(heartbeat["external_info"]["last_heartbeat_ms"].is_number());

        let unregister = dispatch(
            &kernel,
            &ctx,
            "agent_unregister_external",
            &heartbeat_payload,
        )
        .expect("dispatch")
        .into_inner();
        assert_eq!(result_payload(unregister), serde_json::json!(true));
        assert!(kernel.agent_registry().get("admin,e2e").is_none());
    }

    #[test]
    fn agent_register_external_pid_is_the_os_host_pid() {
        // Black-box over the wire: the run pid IS the OS process id, so
        // `/proc/{pid}` / ps / kill align and the mapping needs no lookup. There
        // is NO separate `host_pid` field (SSOT — it lives in the pid). This is
        // the regression guard for the pid-model change.
        let kernel = Arc::new(Kernel::new());
        let ctx = OperationContext::new("admin", kernel::ROOT_ZONE_ID, true, None, true);

        // (a) host_pid only → pid == the OS pid; connection_id stays metadata.
        let payload = serde_json::to_vec(&serde_json::json!({
            "name": "os-pid agent",
            "owner_id": "admin",
            "zone_id": kernel::ROOT_ZONE_ID,
            "connection_id": "conn-xyz",
            "host_pid": 4242,
        }))
        .expect("payload");
        let reg = result_payload(
            dispatch(&kernel, &ctx, "agent_register_external", &payload)
                .expect("dispatch")
                .into_inner(),
        );
        assert_eq!(reg["pid"], "4242", "pid must BE the OS host_pid");
        assert_eq!(
            reg["external_info"]["connection_id"], "conn-xyz",
            "connection_id stays as connection metadata, distinct from the pid"
        );
        assert!(
            reg["external_info"].get("host_pid").is_none(),
            "host_pid must NOT be a separate field — it IS the pid (SSOT)"
        );
        assert!(kernel.agent_registry().get("4242").is_some());

        // (b) host_pid + local_id → pid == "{host_pid}.{local_id}" (micro-agents
        // sharing one process). Cross-platform, runtime-assigned local_id.
        let payload = serde_json::to_vec(&serde_json::json!({
            "name": "micro agent",
            "owner_id": "admin",
            "zone_id": kernel::ROOT_ZONE_ID,
            "connection_id": "conn-abc",
            "host_pid": 4243,
            "local_id": 5,
        }))
        .expect("payload");
        let reg = result_payload(
            dispatch(&kernel, &ctx, "agent_register_external", &payload)
                .expect("dispatch")
                .into_inner(),
        );
        assert_eq!(reg["pid"], "4243.5", "pid must encode host_pid.local_id");
        assert!(kernel.agent_registry().get("4243.5").is_some());
    }

    #[test]
    fn dot_notation_routes_to_kernel_dispatch_rust_call() {
        let kernel = Arc::new(Kernel::new());
        let ctx = OperationContext::new("admin", kernel::ROOT_ZONE_ID, true, None, true);

        // No service registered → service not found
        let resp = dispatch(&kernel, &ctx, "password-vault.secret_put", b"{}")
            .expect("dispatch")
            .into_inner();
        assert!(resp.is_error, "unregistered service should return error");
        let err: serde_json::Value = serde_json::from_slice(&resp.payload).expect("error JSON");
        let msg = err["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("service not found") || msg.contains("password-vault"),
            "error should mention service name, got: {msg}"
        );
    }

    #[test]
    fn dot_notation_unknown_service_returns_error_not_panic() {
        let kernel = Arc::new(Kernel::new());
        let ctx = OperationContext::new("admin", kernel::ROOT_ZONE_ID, true, None, true);

        let resp = dispatch(&kernel, &ctx, "nonexistent-svc.some_method", b"")
            .expect("dispatch")
            .into_inner();
        assert!(resp.is_error);
    }

    #[test]
    fn plain_unknown_method_still_errors() {
        let kernel = Arc::new(Kernel::new());
        let ctx = OperationContext::new("admin", kernel::ROOT_ZONE_ID, true, None, true);

        let resp = dispatch(&kernel, &ctx, "totally_unknown", b"{}")
            .expect("dispatch")
            .into_inner();
        assert!(resp.is_error);
        let err: serde_json::Value = serde_json::from_slice(&resp.payload).expect("error JSON");
        let msg = err["message"].as_str().unwrap_or("");
        assert!(msg.contains("unknown Call method"), "got: {msg}");
    }

    #[test]
    fn agent_registry_dispatch_maps_lifecycle_errors_to_client_codes() {
        let kernel = Arc::new(Kernel::new());
        let ctx = OperationContext::new("admin", kernel::ROOT_ZONE_ID, true, None, true);
        let payload = serde_json::to_vec(&serde_json::json!({
            "name": "E2E Agent",
            "owner_id": "admin",
            "zone_id": kernel::ROOT_ZONE_ID,
            "connection_id": "admin,e2e",
        }))
        .expect("payload");

        let registered = dispatch(&kernel, &ctx, "agent_register_external", &payload)
            .expect("dispatch")
            .into_inner();
        assert!(!registered.is_error, "register returned error payload");

        let duplicate = dispatch(&kernel, &ctx, "agent_register_external", &payload)
            .expect("dispatch")
            .into_inner();
        let duplicate = error_payload(duplicate);
        assert_eq!(duplicate["code"], serde_json::json!(-32006));

        let invalid_signal_payload = serde_json::to_vec(&serde_json::json!({
            "pid": "admin,e2e",
            "sig": "NOPE",
        }))
        .expect("payload");
        let invalid_signal = dispatch(&kernel, &ctx, "agent_signal", &invalid_signal_payload)
            .expect("dispatch")
            .into_inner();
        let invalid_signal = error_payload(invalid_signal);
        assert_eq!(invalid_signal["code"], serde_json::json!(-32005));

        // The agent is REGISTERED; `Registered → ready` is illegal (it must
        // warm up first) → maps to the invalid-transition client code.
        let invalid_transition_payload = serde_json::to_vec(&serde_json::json!({
            "pid": "admin,e2e",
            "state": "ready",
        }))
        .expect("payload");
        let invalid_transition = dispatch(
            &kernel,
            &ctx,
            "agent_update_state",
            &invalid_transition_payload,
        )
        .expect("dispatch")
        .into_inner();
        let invalid_transition = error_payload(invalid_transition);
        assert_eq!(invalid_transition["code"], serde_json::json!(-32006));
    }
}
