//! Shared authenticated owner/zone resolution for agent control-plane calls.

use std::fmt;

use crate::{validate_zone_id_for, OperationContext, ZoneIdUse, ROOT_ZONE_ID};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentContextError {
    InvalidArgument(String),
    PermissionDenied(String),
}

impl fmt::Display for AgentContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(message) | Self::PermissionDenied(message) => {
                f.write_str(message)
            }
        }
    }
}

impl std::error::Error for AgentContextError {}

pub fn resolve_agent_owner(
    ctx: &OperationContext,
    requested: Option<&str>,
) -> Result<String, AgentContextError> {
    let requested = requested.filter(|value| !value.is_empty());
    if !ctx.is_system && requested.is_some_and(|owner| owner != ctx.user_id) {
        return Err(AgentContextError::PermissionDenied(
            "agent owner_id must match the authenticated caller".to_string(),
        ));
    }
    Ok(if ctx.is_system {
        requested.unwrap_or(&ctx.user_id).to_string()
    } else {
        ctx.user_id.clone()
    })
}

pub fn resolve_agent_zone(
    ctx: &OperationContext,
    requested: Option<&str>,
) -> Result<String, AgentContextError> {
    let requested = requested.filter(|value| !value.is_empty());
    let zone_id = if ctx.is_system {
        requested.unwrap_or(ROOT_ZONE_ID).to_string()
    } else if let Some(zone_id) = requested {
        if !ctx.zone_perms.iter().any(|(granted, _)| granted == zone_id) {
            return Err(AgentContextError::PermissionDenied(
                "agent zone_id is not explicitly granted to the authenticated caller".to_string(),
            ));
        }
        zone_id.to_string()
    } else {
        match ctx.zone_perms.as_slice() {
            [(zone_id, _)] => zone_id.clone(),
            [] => {
                return Err(AgentContextError::InvalidArgument(
                    "agent zone_id is required when the caller has no explicit zone grant"
                        .to_string(),
                ));
            }
            _ => {
                return Err(AgentContextError::InvalidArgument(
                    "agent zone_id is required when the caller has multiple explicit zone grants"
                        .to_string(),
                ));
            }
        }
    };

    validate_zone_id_for(ZoneIdUse::ExistingRef, &zone_id).map_err(|error| {
        AgentContextError::InvalidArgument(format!("invalid agent zone_id: {error}"))
    })?;
    Ok(zone_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(is_system: bool, zones: &[&str]) -> OperationContext {
        let mut ctx = OperationContext::new("alice", ROOT_ZONE_ID, false, None, is_system);
        ctx.zone_perms = zones
            .iter()
            .map(|zone| ((*zone).to_string(), "rw".to_string()))
            .collect();
        ctx
    }

    #[test]
    fn system_defaults_to_root_and_can_impersonate_owner() {
        let ctx = context(true, &[]);
        assert_eq!(resolve_agent_zone(&ctx, None).unwrap(), ROOT_ZONE_ID);
        assert_eq!(resolve_agent_owner(&ctx, Some("bob")).unwrap(), "bob");
    }

    #[test]
    fn non_system_requires_an_explicit_zone_grant() {
        let ctx = context(false, &["alpha", "beta"]);
        assert!(matches!(
            resolve_agent_zone(&ctx, Some(ROOT_ZONE_ID)),
            Err(AgentContextError::PermissionDenied(_))
        ));
        assert_eq!(resolve_agent_zone(&ctx, Some("alpha")).unwrap(), "alpha");
        assert!(matches!(
            resolve_agent_zone(&ctx, None),
            Err(AgentContextError::InvalidArgument(_))
        ));
    }

    #[test]
    fn single_zone_and_authenticated_owner_are_derived() {
        let ctx = context(false, &["alpha"]);
        assert_eq!(resolve_agent_zone(&ctx, None).unwrap(), "alpha");
        assert_eq!(resolve_agent_owner(&ctx, None).unwrap(), "alice");
        assert!(matches!(
            resolve_agent_owner(&ctx, Some("bob")),
            Err(AgentContextError::PermissionDenied(_))
        ));
    }
}
