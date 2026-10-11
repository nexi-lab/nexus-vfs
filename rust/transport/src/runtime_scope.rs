//! User-runtime requests retain the original principal across an mTLS gateway.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use kernel::kernel::OperationContext;
use serde::{Deserialize, Serialize};
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::Status;

use crate::auth::{AuthProvider, PeerIdentity};

pub const RUNTIME_DELEGATION_METADATA_KEY: &str = "x-nexus-runtime-delegation-bin";
const DELEGATION_LIFETIME_MS: u64 = 30_000;
const MAX_CLOCK_SKEW_MS: u64 = 1000;
const MAX_DELEGATION_BYTES: usize = 4096;

/// Request-scoped identity carried only by an explicitly trusted mTLS gateway.
/// Privileges and routing addresses are determined by the receiving runtime.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDelegation {
    user_id: String,
    agent_id: String,
    issued_at_unix_ms: u64,
    request_id: String,
}

impl RuntimeDelegation {
    /// Forward an authenticated domestic session agent without widening grants.
    pub fn from_context(ctx: &OperationContext) -> Result<Self, Status> {
        let agent_id = ctx.agent_id.as_deref().ok_or_else(|| {
            Status::permission_denied("runtime delegation requires a session agent")
        })?;
        if ctx.is_admin
            || ctx.is_system
            || ctx.trust_domain.is_some()
            || ctx.zone_id != contracts::ROOT_ZONE_ID
            || !ctx.zone_perms.is_empty()
            || ctx.context_zone_id.is_some()
            || !ctx.groups.is_empty()
            || !ctx.admin_capabilities.is_empty()
            || ctx.subject_type != "agent"
            || ctx.subject_id.as_deref() != Some(agent_id)
            || agent_id == ctx.user_id
        {
            return Err(Status::permission_denied(
                "runtime delegation requires an unprivileged domestic session identity",
            ));
        }
        validate_identity(&ctx.user_id)?;
        validate_identity(agent_id)?;
        validate_request_id(&ctx.request_id)?;
        Ok(Self {
            user_id: ctx.user_id.clone(),
            agent_id: agent_id.to_owned(),
            issued_at_unix_ms: now_ms()?,
            request_id: ctx.request_id.clone(),
        })
    }

    /// Replace any incoming carrier with the gateway's authenticated identity.
    pub fn apply(&self, metadata: &mut MetadataMap) -> Result<(), Status> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| Status::internal("cannot encode runtime delegation"))?;
        metadata.remove_bin(RUNTIME_DELEGATION_METADATA_KEY);
        metadata.insert_bin(
            RUNTIME_DELEGATION_METADATA_KEY,
            MetadataValue::from_bytes(&bytes),
        );
        Ok(())
    }
}

/// The user owning a runtime and the root-zone nodes allowed to forward to it.
pub struct RuntimeScope {
    user_id: String,
    gateway_nodes: HashSet<u64>,
}

impl RuntimeScope {
    pub fn new(
        user_id: String,
        gateway_nodes: impl IntoIterator<Item = u64>,
    ) -> Result<Self, Status> {
        validate_identity(&user_id)?;
        Ok(Self {
            user_id,
            gateway_nodes: gateway_nodes.into_iter().collect(),
        })
    }

    pub(crate) fn resolve(
        &self,
        auth: &dyn AuthProvider,
        ctx: OperationContext,
        peer: Option<&PeerIdentity>,
        token: &str,
        metadata: &MetadataMap,
    ) -> Result<OperationContext, Status> {
        let mut values = metadata.get_all_bin(RUNTIME_DELEGATION_METADATA_KEY).iter();
        let Some(raw) = values.next() else {
            return self.confine(ctx);
        };
        if values.next().is_some() {
            return Err(Status::unauthenticated("multiple runtime delegations"));
        }
        let is_gateway = token.is_empty()
            && peer.is_some_and(|p| {
                p.is_cluster_node()
                    && p.zone_id.as_deref() == Some(contracts::ROOT_ZONE_ID)
                    && p.node_id.is_some_and(|id| self.gateway_nodes.contains(&id))
            });
        if !is_gateway {
            return Err(Status::unauthenticated(
                "runtime delegation requires a trusted mTLS gateway",
            ));
        }
        let bytes = raw
            .to_bytes()
            .map_err(|_| Status::unauthenticated("invalid runtime delegation encoding"))?;
        if bytes.len() > MAX_DELEGATION_BYTES {
            return Err(Status::unauthenticated("runtime delegation is too large"));
        }
        let delegation: RuntimeDelegation = serde_json::from_slice(&bytes)
            .map_err(|_| Status::unauthenticated("invalid runtime delegation"))?;
        validate_identity(&delegation.user_id)?;
        validate_identity(&delegation.agent_id)?;
        validate_request_id(&delegation.request_id)?;
        let now = now_ms()?;
        if delegation.issued_at_unix_ms.saturating_sub(now) > MAX_CLOCK_SKEW_MS
            || now.saturating_sub(delegation.issued_at_unix_ms) > DELEGATION_LIFETIME_MS
            || delegation.user_id != self.user_id
            || delegation.user_id == delegation.agent_id
        {
            return Err(Status::permission_denied(
                "runtime delegation is outside its validity window or belongs to another user",
            ));
        }
        let mut forwarded =
            auth.resolve_forwarded_agent(&delegation.user_id, &delegation.agent_id)?;
        if forwarded.agent_id.as_deref() != Some(delegation.agent_id.as_str()) {
            return Err(Status::permission_denied(
                "authentication provider changed the forwarded actor",
            ));
        }
        forwarded.request_id = delegation.request_id;
        self.confine(forwarded)
    }

    fn confine(&self, ctx: OperationContext) -> Result<OperationContext, Status> {
        if ctx.user_id != self.user_id
            || ctx.is_admin
            || ctx.is_system
            || ctx.trust_domain.is_some()
            || ctx.agent_id.is_none()
            || ctx.agent_id.as_deref() == Some(ctx.user_id.as_str())
        {
            return Err(Status::permission_denied(
                "request does not belong to this user runtime",
            ));
        }
        Ok(ctx)
    }
}

fn validate_identity(value: &str) -> Result<(), Status> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(Status::invalid_argument("invalid runtime principal"));
    }
    Ok(())
}

fn validate_request_id(value: &str) -> Result<(), Status> {
    if value.len() > 256 || value.chars().any(char::is_control) {
        return Err(Status::invalid_argument("invalid runtime request ID"));
    }
    Ok(())
}

fn now_ms() -> Result<u64, Status> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Status::unavailable("runtime clock precedes the Unix epoch"))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| Status::unavailable("runtime clock cannot be represented"))
}
