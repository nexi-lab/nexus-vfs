//! WorkspaceBoundaryHook — INTERCEPT pre-write hook that enforces the
//! "you cannot write into another agent's workspace" convention.
//!
//! Path layout (sudowork/docs/tech/nexus-integration-architecture.md §3.4):
//!
//! ```text
//! /proc/{owner_pid}/workspace/...   ← owned by the pid named in the path
//! ```
//!
//! When a write target falls under that prefix, the hook resolves the owner
//! pid (extracted from the path) to its agent through the `AgentRegistry` and
//! compares that against the caller's `agent_id`. On mismatch the hook returns `Err` with a structured
//! teaching payload pointing at where messages DO go, so the caller (an
//! LLM) learns the convention from the error itself rather than from its
//! system prompt or memory.
//!
//! The boundary admits nobody but the owner. Messages are addressed by agent
//! name, in the conversation the two participants share, and a conversation
//! lives outside every workspace — so there is nothing inside one that a
//! non-owner needs to write.

use std::sync::Arc;

use contracts::is_system_path;
use kernel::core::agents::registry::AgentRegistry;
use kernel::core::dispatch::{HookContext, HookOutcome, NativeInterceptHook};

/// Path prefix that scopes this hook. Anything under `/proc/{pid}/workspace/`
/// is governed by the workspace boundary check. Other paths short-circuit
/// in `is_workspace_path` so the hook is zero-cost outside its scope.
const WORKSPACE_PREFIX: &str = "/proc/";
const WORKSPACE_SEGMENT: &str = "/workspace/";

/// INTERCEPT pre-write hook scoped to `/proc/{pid}/workspace/`.
///
/// One instance covers every workspace in the kernel: the owner comes from the
/// path and the caller from the dispatch context. It holds the registry
/// because those two are not the same kind of name — the path carries a PID,
/// the context carries an agent NAME — and only the registry maps one to the
/// other.
pub(crate) struct WorkspaceBoundaryHook {
    agents: Arc<AgentRegistry>,
}

impl WorkspaceBoundaryHook {
    pub(crate) fn new(agents: Arc<AgentRegistry>) -> Self {
        Self { agents }
    }

    /// Extract the workspace owner pid from a path. Returns `Some(pid)`
    /// when the path is `/proc/{pid}/workspace/...`, `None` otherwise.
    fn owner_pid(path: &str) -> Option<&str> {
        let after_proc = path.strip_prefix(WORKSPACE_PREFIX)?;
        let slash = after_proc.find('/')?;
        let pid = &after_proc[..slash];
        let rest = &after_proc[slash..];
        if !rest.starts_with(WORKSPACE_SEGMENT) {
            return None;
        }
        if pid.is_empty() {
            return None;
        }
        Some(pid)
    }

    /// Build the structured teaching error the hook returns on cross-owner
    /// writes.
    ///
    /// It names the caller's own chat list rather than a message path: the
    /// message path depends on both participants, and a `readdir` there
    /// answers the question the caller actually has in one step it can take
    /// from inside the error.
    fn teaching_error(path: &str, owner: &str, caller_agent_id: &str) -> String {
        format!(
            "EPERM at {path}: this workspace belongs to '{owner}' and is private. \
             You are '{caller_agent_id}'. Messages are not written into a workspace — they go \
             to the conversation you share with the other agent. List your conversations at \
             /agents/{caller_agent_id}/conversations/ and append to that peer's transcript.",
        )
    }
}

impl NativeInterceptHook for WorkspaceBoundaryHook {
    fn name(&self) -> &str {
        "workspace_boundary"
    }

    fn on_pre(&self, ctx: &HookContext) -> Result<HookOutcome, String> {
        // Native (unnamed) hook contract — short-circuit kernel-internal
        // paths so any future sys_read/sys_write inside this hook body
        // cannot recurse. Mirrors PermissionHook._is_system_path() in
        // Python (see `contracts::SYSTEM_PATH_PREFIX`). `/__sys__/`
        // paths are not under `/proc/{pid}/workspace/` so they pass
        // through naturally — the explicit check is the contract every
        // native hook follows.
        if is_system_path(ctx.path()) {
            return Ok(HookOutcome::Pass);
        }
        // Only mutating-write contexts gate the boundary; reads, stat, and
        // other no-mutation ops walk through.
        let path = match ctx {
            HookContext::Write(_) | HookContext::Delete(_) | HookContext::Rename(_) => ctx.path(),
            _ => return Ok(HookOutcome::Pass),
        };

        let owner_pid = match Self::owner_pid(path) {
            Some(p) => p,
            None => return Ok(HookOutcome::Pass),
        };

        // A bare/system context (kernel-internal provisioning, including
        // `proc_entry` stamping this very subtree) carries no agent and is not
        // subject to the boundary.
        let caller = &ctx.identity().agent_id;
        if caller.is_empty() {
            return Ok(HookOutcome::Pass);
        }

        // The path names a PID; the caller names an AGENT. They are different
        // namespaces, so they are compared through the registry rather than
        // directly — and the lookup reads the name alone, because this runs
        // before every write under a workspace.
        //
        // Fails CLOSED on an unknown pid: a workspace whose owner has no
        // descriptor is nobody's to write.
        match self.agents.name_of(owner_pid) {
            Some(owner) if owner == *caller => Ok(HookOutcome::Pass),
            Some(owner) => Err(Self::teaching_error(path, &owner, caller)),
            None => Err(Self::teaching_error(path, owner_pid, caller)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::core::agents::registry::AgentDescriptor;
    use kernel::core::dispatch::{HookIdentity, ReadHookCtx, WriteHookCtx};

    /// A hook over a registry where pid `p1` belongs to agent `owner-agent`.
    ///
    /// The pid and the name are deliberately DIFFERENT strings. They are in
    /// production too — a pid is uuid-allocated and a name is the profile id —
    /// and a fixture that let them coincide is what allowed a hook comparing
    /// one to the other to look correct.
    fn hook_with_p1() -> WorkspaceBoundaryHook {
        let agents = Arc::new(AgentRegistry::new());
        agents.register(AgentDescriptor {
            pid: "p1".to_string(),
            name: "owner-agent".to_string(),
            ..Default::default()
        });
        WorkspaceBoundaryHook::new(agents)
    }

    fn ctx(path: &str, caller: &str) -> HookContext {
        HookContext::Write(WriteHookCtx {
            path: path.to_string(),
            identity: HookIdentity {
                agent_id: caller.to_string(),
                user_id: caller.to_string(),
                zone_id: "root".to_string(),
                is_admin: false,
            },
            content: Vec::new(),
            is_new_file: true,
            content_id: None,
            new_version: 1,
            size_bytes: None,
        })
    }

    /// The owner may write its own workspace.
    ///
    /// This is the case that was broken: the hook compared the caller's agent
    /// NAME to the PID in the path, so the owner never matched and was refused
    /// from its own workspace. Nothing noticed because no production code
    /// writes these VFS paths — agents work against a host cwd — but a gate
    /// that refuses the one party it must admit is wrong whether or not it is
    /// currently reached.
    #[test]
    fn passes_when_caller_owns_workspace() {
        let hook = hook_with_p1();
        let c = ctx("/proc/p1/workspace/notes.md", "owner-agent");
        assert!(
            hook.on_pre(&c).is_ok(),
            "the workspace owner must be able to write its own workspace"
        );
    }

    /// A second session of the same agent reaches the same workspace.
    ///
    /// Two pids under one name are one actor: identity is minted per name, so
    /// they authenticate identically and share one conversation. A workspace
    /// they could not both write would be the only place that treated them as
    /// two.
    #[test]
    fn passes_for_another_session_of_the_same_agent() {
        let agents = Arc::new(AgentRegistry::new());
        for pid in ["p1", "p2"] {
            agents.register(AgentDescriptor {
                pid: pid.to_string(),
                name: "owner-agent".to_string(),
                ..Default::default()
            });
        }
        let hook = WorkspaceBoundaryHook::new(agents);
        assert!(hook
            .on_pre(&ctx("/proc/p1/workspace/notes.md", "owner-agent"))
            .is_ok());
    }

    /// A pid with no descriptor fails CLOSED.
    ///
    /// The workspace of a reaped or never-registered pid is nobody's to write,
    /// and a permission gate that opened on a missing record would be widest
    /// exactly when it knows least.
    #[test]
    fn rejects_when_the_owner_pid_is_unknown() {
        let hook = WorkspaceBoundaryHook::new(Arc::new(AgentRegistry::new()));
        assert!(hook
            .on_pre(&ctx("/proc/ghost/workspace/notes.md", "owner-agent"))
            .is_err());
    }

    /// A stranger gets no write into someone else's workspace, anywhere —
    /// including at a path shaped like a message leaf, because a conversation
    /// lives outside every workspace and a workspace holds no message surface
    /// a non-owner could need.
    #[test]
    fn rejects_a_stranger_everywhere_inside_the_workspace() {
        let hook = hook_with_p1();
        for path in [
            "/proc/p1/workspace/notes.md",
            "/proc/p1/workspace/transcript",
        ] {
            assert!(
                hook.on_pre(&ctx(path, "stranger")).is_err(),
                "{path} must not be writable by a non-owner"
            );
        }
    }

    #[test]
    fn passes_for_paths_outside_workspace_namespace() {
        let hook = hook_with_p1();
        let c = ctx("/agents/scode-standard/config.toml", "stranger");
        assert!(hook.on_pre(&c).is_ok());
    }

    #[test]
    fn passes_for_pid_namespace_outside_workspace_segment() {
        // /proc/{pid}/agent and /proc/{pid}/sessions/ are runtime metadata
        // paths owned by their pid but not workspace files; the hook only
        // governs the workspace segment.
        let hook = hook_with_p1();
        let c = ctx("/proc/p1/sessions/foo.jsonl", "stranger");
        assert!(hook.on_pre(&c).is_ok());
    }

    #[test]
    fn rejects_cross_owner_write_with_teaching_payload() {
        let hook = hook_with_p1();
        let c = ctx("/proc/p1/workspace/projects/nexus/src/main.rs", "p_other");
        let err = hook.on_pre(&c).unwrap_err();
        assert!(err.contains("EPERM"));
        assert!(
            err.contains("owner-agent"),
            "the error must name the OWNER, not the pid the caller cannot act on: {err}"
        );
        assert!(err.contains("p_other"));
        assert!(
            err.contains("/agents/p_other/conversations/"),
            "the error must point the caller at its own chat list: {err}"
        );
    }

    #[test]
    fn read_path_does_not_trigger_boundary() {
        let hook = hook_with_p1();
        let read = HookContext::Read(ReadHookCtx {
            path: "/proc/p1/workspace/notes.md".to_string(),
            identity: HookIdentity {
                agent_id: "p_other".to_string(),
                user_id: "p_other".to_string(),
                zone_id: "root".to_string(),
                is_admin: false,
            },
            content: None,
            content_id: None,
        });
        assert!(hook.on_pre(&read).is_ok());
    }

    #[test]
    fn empty_caller_passes_through() {
        // Internal dispatchers without an authenticated caller must not
        // be blocked by the boundary check (kernel writes, recovery, …).
        let hook = hook_with_p1();
        let c = ctx("/proc/p1/workspace/notes.md", "");
        assert!(hook.on_pre(&c).is_ok());
    }
}
