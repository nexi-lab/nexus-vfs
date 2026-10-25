//! Resolve a credential target from the native registry and authenticated owner.
//! Public names, copied descriptors and Node/admin authority are not an owner's
//! Agent credential binding. This proof is local to one registry incarnation.

use contracts::{OperationContext, RustCallError};
use kernel::{
    core::agents::registry::{AgentInstance, AgentKind, AgentRegistry},
    kernel::Kernel,
};

use crate::ManagedAgentService;

pub struct ManagedCredentialBinding {
    instance: AgentInstance,
    pid: String,
    agent: String,
    owner: String,
    zone: String,
}

impl ManagedCredentialBinding {
    /// `ctx` is the native request context, never a deserialized request field.
    /// No administrator override: the actual principal must own this Agent.
    pub fn resolve(
        registry: &AgentRegistry,
        ctx: &OperationContext,
        pid: &str,
    ) -> Result<Self, RustCallError> {
        let (instance, descriptor) = registry.get_instance(pid).ok_or(RustCallError::NotFound)?;
        ManagedAgentService::<Kernel>::authorize_session_owner(ctx, &descriptor)?;
        let subject_matches = match ctx.agent_id.as_deref() {
            Some(actor) => ctx.subject_type == "agent" && ctx.subject_id.as_deref() == Some(actor),
            None => {
                matches!(ctx.subject_type.as_str(), "user" | "service")
                    && ctx.subject_id.as_deref() == Some(ctx.user_id.as_str())
            }
        };
        if ctx.is_system
            || ctx.trust_domain.is_some()
            || !subject_matches
            || descriptor.owner_id != ctx.user_id
            || descriptor.owner_id.is_empty()
            || descriptor.name.is_empty()
            || descriptor.zone_id.is_empty()
            || descriptor.kind != AgentKind::Managed
            || descriptor.state.is_terminal()
        {
            return Err(RustCallError::PermissionDenied(
                "managed Agent credentials require its current authenticated local owner".into(),
            ));
        }
        Ok(Self {
            instance,
            pid: descriptor.pid,
            agent: descriptor.name,
            owner: descriptor.owner_id,
            zone: descriptor.zone_id,
        })
    }

    pub fn agent(&self) -> &str {
        &self.agent
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn zone(&self) -> &str {
        &self.zone
    }
    pub fn pid(&self) -> &str {
        &self.pid
    }

    /// Call again after persistence/network work before reporting or binding it.
    /// A same-PID replacement is another incarnation even if public names match.
    pub fn ensure_current(&self, registry: &AgentRegistry) -> Result<(), RustCallError> {
        let (_, descriptor) = registry
            .get_instance(&self.pid)
            .ok_or(RustCallError::NotFound)?;
        if !registry.is_current_instance(&self.instance)
            || descriptor.state.is_terminal()
            || descriptor.kind != AgentKind::Managed
            || descriptor.name != self.agent
            || descriptor.owner_id != self.owner
            || descriptor.zone_id != self.zone
        {
            return Err(RustCallError::PermissionDenied(
                "managed Agent binding retired or changed".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::core::agents::registry::{AgentDescriptor, AgentState};

    fn owner() -> OperationContext {
        let mut ctx = OperationContext::new("alice", "root", false, Some("session-actual"), false);
        ctx.subject_type = "agent".into();
        ctx.subject_id = Some("session-actual".into());
        ctx
    }
    fn descriptor() -> AgentDescriptor {
        AgentDescriptor {
            pid: "existing.1".into(),
            name: "actual-agent".into(),
            owner_id: "alice".into(),
            zone_id: "root".into(),
            state: AgentState::Ready,
            ..Default::default()
        }
    }
    #[test]
    fn actual_owner_resolves_existing_agent_but_foreign_admin_node_and_wrong_owner_do_not() {
        let registry = AgentRegistry::new();
        assert!(registry.register(descriptor()));
        let proof = ManagedCredentialBinding::resolve(&registry, &owner(), "existing.1").unwrap();
        assert_eq!(
            (proof.agent(), proof.owner(), proof.zone()),
            ("actual-agent", "alice", "root")
        );
        proof.ensure_current(&registry).unwrap();
        let mut foreign = owner();
        foreign.trust_domain = Some("elsewhere".into());
        let mut other = owner();
        other.user_id = "bob".into();
        let mut admin = other.clone();
        admin.is_admin = true;
        let mut system = owner();
        system.is_system = true;
        let mut unproven = owner();
        unproven.subject_id = None;
        for ctx in [
            foreign,
            other,
            admin,
            system,
            unproven,
            OperationContext::new("cluster-internal", "root", true, None, true),
        ] {
            assert!(ManagedCredentialBinding::resolve(&registry, &ctx, "existing.1").is_err());
        }
        assert!(ManagedCredentialBinding::resolve(&registry, &owner(), "absent").is_err());
    }
    #[test]
    fn same_pid_replacement_and_terminated_or_unmanaged_instances_cannot_reuse_the_proof() {
        let registry = AgentRegistry::new();
        assert!(registry.register(descriptor()));
        let proof = ManagedCredentialBinding::resolve(&registry, &owner(), "existing.1").unwrap();
        registry.unregister("existing.1").unwrap();
        assert!(registry.register(descriptor()));
        assert!(proof.ensure_current(&registry).is_err());
        registry.unregister("existing.1").unwrap();
        let mut terminal = descriptor();
        terminal.state = AgentState::Terminated;
        assert!(registry.register(terminal));
        assert!(ManagedCredentialBinding::resolve(&registry, &owner(), "existing.1").is_err());
        registry.unregister("existing.1").unwrap();
        let mut unmanaged = descriptor();
        unmanaged.kind = AgentKind::Unmanaged;
        assert!(registry.register(unmanaged));
        assert!(ManagedCredentialBinding::resolve(&registry, &owner(), "existing.1").is_err());
    }
}
