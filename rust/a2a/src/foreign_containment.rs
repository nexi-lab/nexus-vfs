//! Cross-org containment: a FOREIGN agent is confined to its mailbox.
//!
//! `classify_peer_cert` admits an external org's agent (its cert chains to
//! a `foreign-ca register`ed CA) and stamps `ctx.trust_domain`. That agent
//! authors mailbox messages under its qualified id — but nothing else on
//! the platform is its business. This permission provider is the
//! enforcement: on a gate-armed profile, a caller carrying
//! `trust_domain = Some` may touch ONLY `*/chat-with-me` mailbox paths;
//! every other path is denied on read AND write. A DOMESTIC caller
//! (`trust_domain = None`) is never restricted here — this gate exists
//! solely to bound the blast radius of a semi-trusted foreign agent (e.g.
//! an on-prem DGX an FDE delivers to a customer site: authenticated to the
//! SaaS, but it must not read the SaaS's other data if tampered with).
//!
//! Scope note: `is_a2a_mailbox_path` (not `is_mailbox_path`) — a foreign
//! agent gets the REPLICATED cross-machine mailbox, never the node-local
//! `/proc/{pid}/chat-with-me` pipe.
//!
//! Composition: this is the sole provider `nexusd-cluster` installs. If a
//! second policy (e.g. zone-perms) is ever added to that profile, wrap
//! both in a composite — the kernel holds a single provider slot.

use std::sync::Arc;

use kernel::kernel::{Kernel, KernelError, OperationContext};
use kernel::vfs_router::RouteResult;
use kernel::{Permission, PermissionProvider};

use crate::mailbox_stamping_policy::is_a2a_mailbox_path;

/// Confines a foreign (cross-org) agent to `*/chat-with-me` mailboxes.
pub struct ForeignAgentMailboxOnly;

impl PermissionProvider for ForeignAgentMailboxOnly {
    #[inline]
    fn check(
        &self,
        path: &str,
        _route: Option<&RouteResult>,
        _permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        // Only a foreign agent is bounded; a domestic caller (the common
        // case) short-circuits to allow with a single branch on the hot
        // path — no allocation, no path scan.
        let Some(trust_domain) = ctx.trust_domain.as_deref() else {
            return Ok(());
        };
        if is_a2a_mailbox_path(path) {
            return Ok(());
        }
        Err(KernelError::PermissionDenied(format!(
            "foreign agent (trust domain '{trust_domain}') is confined to its \
             '*/chat-with-me' mailbox; '{path}' is out of scope"
        )))
    }
}

/// Arm the foreign-agent containment gate. Call once at daemon boot on a
/// profile that admits foreign agents (e.g. `nexusd-cluster`). Idempotent:
/// re-installing replaces the slot (`ArcSwapOption`).
pub fn install_foreign_agent_containment(kernel: &Kernel) {
    kernel.set_permission_provider(Arc::new(
        Box::new(ForeignAgentMailboxOnly) as Box<dyn PermissionProvider>
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(trust_domain: Option<&str>) -> OperationContext {
        let mut ctx = OperationContext::new("caller", "sharedzone", false, Some("worker"), false);
        ctx.trust_domain = trust_domain.map(str::to_string);
        ctx
    }

    #[test]
    fn foreign_agent_allowed_only_on_mailbox_paths() {
        let p = ForeignAgentMailboxOnly;
        let foreign = ctx_with(Some("hospital-a"));
        // Its mailbox: allowed (read + write).
        assert!(p
            .check("/agents/w/chat-with-me", None, Permission::Write, &foreign)
            .is_ok());
        assert!(p
            .check("/agents/w/chat-with-me", None, Permission::Read, &foreign)
            .is_ok());
        // Anything else: denied.
        assert!(p
            .check("/agents/secrets.txt", None, Permission::Read, &foreign)
            .is_err());
        assert!(p
            .check("/other/zone/file", None, Permission::Write, &foreign)
            .is_err());
        // The node-local pipe is NOT a foreign agent's mailbox.
        assert!(p
            .check("/proc/1/chat-with-me", None, Permission::Write, &foreign)
            .is_err());
    }

    #[test]
    fn domestic_caller_is_never_restricted() {
        let p = ForeignAgentMailboxOnly;
        let domestic = ctx_with(None);
        // A domestic agent keeps its broad (trusted-participant) access.
        assert!(p
            .check("/agents/secrets.txt", None, Permission::Read, &domestic)
            .is_ok());
        assert!(p
            .check("/any/path", None, Permission::Write, &domestic)
            .is_ok());
    }
}
