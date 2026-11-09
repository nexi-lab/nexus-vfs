//! Versioned, authenticated runtime observations, never PID-only control.

use super::{agent_context_err, agent_err_to_payload, call_err, ok_json, permission_err};
use contracts::runtime_status::{
    resolve_runtime_scope, ListRuntimesRequest, PublishRuntimeRequest, RegisterRuntimeRequest,
    RuntimeInstanceId, RuntimeInstanceRequest,
};
use contracts::{resolve_agent_owner, resolve_agent_zone, OperationContext};
use kernel::core::agents::registry::{AgentDescriptor, AgentInstance};
use kernel::kernel::Kernel;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::Arc;

fn parse<T: DeserializeOwned>(params: Value) -> Result<T, Vec<u8>> {
    serde_json::from_value(params)
        .map_err(|error| call_err(super::RpcErrorCode::ValidationError, &error.to_string()))
}

fn denied() -> Vec<u8> {
    permission_err("runtime operation requires the authenticated owner and registered incarnation")
}

fn authorize(
    kernel: &Kernel,
    ctx: &OperationContext,
    id: &RuntimeInstanceId,
    mutation: bool,
) -> Result<(AgentInstance, AgentDescriptor), Vec<u8>> {
    let (instance, descriptor) = kernel
        .agent_registry()
        .get_runtime_instance(id)
        .ok_or_else(denied)?;
    if !ctx.is_admin
        && !ctx.is_system
        && (descriptor.owner_id != ctx.user_id
            || (mutation
                && ctx
                    .agent_id
                    .as_ref()
                    .is_some_and(|agent| agent != &descriptor.name)))
    {
        return Err(denied());
    }
    Ok((instance, descriptor))
}

fn scope_zone(ctx: &OperationContext, requested: Option<&str>) -> Result<String, Vec<u8>> {
    // Attendance is owner-private metadata, not a zone tenancy grant. A
    // session credential can report itself in its authenticated routing zone.
    // Explicit selection of another zone retains the existing grant resolver.
    match requested {
        Some(zone) if zone != ctx.zone_id => {
            resolve_agent_zone(ctx, Some(zone)).map_err(agent_context_err)
        }
        _ => Ok(ctx.zone_id.clone()),
    }
}

pub(super) fn dispatch(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    method: &str,
    params: Value,
) -> Result<Vec<u8>, Vec<u8>> {
    if ctx.trust_domain.is_some() && !ctx.is_admin && !ctx.is_system {
        return Err(denied());
    }
    let registry = kernel.agent_registry();
    match method {
        "agent_runtime_register_v1" => {
            let request: RegisterRuntimeRequest = parse(params)?;
            let owner =
                resolve_agent_owner(ctx, request.owner_id.as_deref()).map_err(agent_context_err)?;
            let zone = scope_zone(ctx, request.zone_id.as_deref())?;
            if request.name.is_empty()
                || uuid::Uuid::parse_str(&request.connection_id).is_err()
                || uuid::Uuid::parse_str(&request.registration_id).is_err()
                || (!ctx.is_admin
                    && !ctx.is_system
                    && ctx
                        .agent_id
                        .as_ref()
                        .is_some_and(|agent| agent != &request.name))
            {
                return Err(denied());
            }
            // A connection UUID is a logical remote PID. An OS PID belongs in
            // the observation, so two hosts cannot collide on the same number.
            let instance = registry
                .register_runtime_instance(&request, &owner, &zone)
                .map_err(agent_err_to_payload)?;
            let id = registry.runtime_instance_id(&instance).ok_or_else(denied)?;
            registry
                .heartbeat_instance(&instance)
                .map_err(agent_err_to_payload)?
                .ok_or_else(denied)?;
            ok_json(serde_json::to_value(id).map_err(|error| {
                call_err(super::RpcErrorCode::InternalError, &error.to_string())
            })?)
        }
        "agent_runtime_publish_v1" => {
            let request: PublishRuntimeRequest = parse(params)?;
            let (instance, _) = authorize(kernel, ctx, &request.instance, true)?;
            if !registry
                .publish_runtime_status(&instance, request.update)
                .map_err(agent_err_to_payload)?
            {
                return Err(denied());
            }
            let observation = registry.runtime_observation(&instance).ok_or_else(denied)?;
            ok_json(serde_json::to_value(observation).map_err(|error| {
                call_err(super::RpcErrorCode::InternalError, &error.to_string())
            })?)
        }
        "agent_runtime_list_v1" => {
            let request: ListRuntimesRequest = parse(params)?;
            let (owner, zone) = resolve_runtime_scope(ctx, &request).map_err(agent_context_err)?;
            let mut inventory = registry.runtime_inventory(owner.as_deref(), &zone);
            inventory.peers = kernel.distributed_coordinator().zone_peers(kernel, &zone);
            ok_json(serde_json::to_value(inventory).map_err(|error| {
                call_err(super::RpcErrorCode::InternalError, &error.to_string())
            })?)
        }
        _ => {
            let request: RuntimeInstanceRequest = parse(params)?;
            let (instance, _) = authorize(
                kernel,
                ctx,
                &request.instance,
                method != "agent_runtime_get_v1",
            )?;
            match method {
                "agent_runtime_get_v1" => {
                    let observation = registry.runtime_observation(&instance).ok_or_else(denied)?;
                    ok_json(serde_json::to_value(observation).map_err(|error| {
                        call_err(super::RpcErrorCode::InternalError, &error.to_string())
                    })?)
                }
                "agent_runtime_heartbeat_v1" => {
                    let updated = registry
                        .heartbeat_instance(&instance)
                        .map_err(agent_err_to_payload)?
                        .is_some();
                    if !updated {
                        return Err(denied());
                    }
                    ok_json(serde_json::json!(true))
                }
                "agent_runtime_unregister_v1" => {
                    let removed = registry
                        .unregister_external_instance(&instance)
                        .map_err(agent_err_to_payload)?;
                    if !removed {
                        return Err(denied());
                    }
                    ok_json(serde_json::json!(true))
                }
                _ => unreachable!("runtime method selected by Call dispatcher"),
            }
        }
    }
}
