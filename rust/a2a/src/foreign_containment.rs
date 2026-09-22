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

use crate::addresses::{is_conversation_index_path, is_conversation_reader_path};
use crate::mailbox_stamping_policy::is_a2a_mailbox_path;

/// Confines a foreign (cross-org) agent to the A2A message logs it
/// participates in.
pub struct ForeignAgentMailboxOnly;

impl PermissionProvider for ForeignAgentMailboxOnly {
    #[inline]
    fn check(
        &self,
        path: &str,
        _route: Option<&RouteResult>,
        permission: Permission,
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
        // A conversation's reader registers are READABLE by a participant —
        // that is how a peer observes "has the other side read this" without a
        // human relaying offsets — but never WRITABLE by a foreign one.
        // Moving someone else's read position skips their inbound messages
        // silently: no error is raised, the sender is still told the message
        // was delivered, and nothing in the log records that it was stepped
        // over. That is a denial of delivery with no trace, so the write side
        // stays closed even though the read side is open.
        if is_conversation_reader_path(path) && matches!(permission, Permission::Read) {
            return Ok(());
        }
        // The chat-list index, writable. A conversation is provisioned by
        // whichever side SENDS first, and the side that has to discover it is
        // the other one — so a cross-org peer must be able to file the entry
        // under its recipient, or the recipient never learns the conversation
        // exists and the message waits in a transcript nobody tails.
        //
        // This does not widen what a foreign caller can reach. It can already
        // write any transcript (the allow-list above is by shape, not by
        // participant), and the stamping hook decides `from`, so it cannot
        // forge who spoke. What an entry adds is discoverability: the receiver
        // derives the conversation id from the PAIR and ignores the entry's
        // body, so a forged entry buys an idle tail on a conversation the
        // caller could already write to — not access to anyone else's.
        if is_conversation_index_path(path) {
            return Ok(());
        }
        Err(KernelError::PermissionDenied(format!(
            "foreign agent (trust domain '{trust_domain}') is confined to its \
             A2A conversation transcripts and chat-list entries (read-only on \
             reader registers); '{path}' is out of scope for {permission:?}"
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
        // Its chat-list entry: allowed. Without it a cross-org sender cannot
        // make the conversation discoverable, and the message waits in a
        // transcript nobody tails.
        assert!(p
            .check(
                "/agents/w/conversations/foreign-peer",
                None,
                Permission::Write,
                &foreign
            )
            .is_ok());
        assert!(p
            .check("/agents/w/conversations", None, Permission::Read, &foreign)
            .is_ok());
        // The rest of the agent namespace stays closed, INCLUDING the depths
        // that look like the chat list. `/agents/w/state` is as deep as
        // `/agents/w/conversations`, so the shape is what separates them.
        assert!(p
            .check("/agents/w/state", None, Permission::Write, &foreign)
            .is_err());
        assert!(p
            .check(
                "/agents/w/conversations/a/deeper",
                None,
                Permission::Write,
                &foreign
            )
            .is_err());
        // Anything else: denied.
        assert!(p
            .check("/agents/secrets.txt", None, Permission::Read, &foreign)
            .is_err());
        assert!(p
            .check("/agents/secrets.txt", None, Permission::Write, &foreign)
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
