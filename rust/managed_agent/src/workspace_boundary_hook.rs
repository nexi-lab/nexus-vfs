//! WorkspaceBoundaryHook — INTERCEPT pre-write hook that enforces the
//! "you cannot write into another agent's workspace" convention.
//!
//! Path layout (sudowork/docs/tech/nexus-integration-architecture.md §3.4):
//!
//! ```text
//! /proc/{owner_pid}/workspace/...   ← owned by the pid named in the path
//! ```
//!
//! When a write target falls under that prefix, the hook compares the
//! workspace owner pid (extracted from the path) against the caller's
//! `agent_id`. On mismatch the hook returns `Err` with a structured
//! teaching payload pointing at where messages DO go, so the caller (an
//! LLM) learns the convention from the error itself rather than from its
//! system prompt or memory.
//!
//! There is no longer a mailbox inside a workspace to carve an exception
//! for: messages are addressed by agent name, in the conversation the two
//! participants share, which lives outside every workspace.

use contracts::is_system_path;
use kernel::core::dispatch::{HookContext, HookOutcome, NativeInterceptHook};

/// Path prefix that scopes this hook. Anything under `/proc/{pid}/workspace/`
/// is governed by the workspace boundary check. Other paths short-circuit
/// in `is_workspace_path` so the hook is zero-cost outside its scope.
const WORKSPACE_PREFIX: &str = "/proc/";
const WORKSPACE_SEGMENT: &str = "/workspace/";

/// INTERCEPT pre-write hook scoped to `/proc/{pid}/workspace/`.
///
/// Stateless — the hook reads the workspace owner from the path and the
/// caller from the dispatch context, so a single instance covers every
/// workspace in the kernel.
pub(crate) struct WorkspaceBoundaryHook;

impl WorkspaceBoundaryHook {
    pub(crate) fn new() -> Self {
        Self
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
    /// It names the caller's own chat list rather than a message path,
    /// because the path depends on WHO the owner is and this hook only
    /// knows its pid. A `readdir` there answers the question the caller
    /// actually has, in one step it can take from inside the error.
    fn teaching_error(path: &str, owner_pid: &str, caller_agent_id: &str) -> String {
        format!(
            "EPERM at {path}: this workspace belongs to pid '{owner_pid}' and is private. \
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

        let caller = &ctx.identity().agent_id;
        if caller == owner_pid || caller.is_empty() {
            return Ok(HookOutcome::Pass);
        }

        Err(Self::teaching_error(path, owner_pid, caller))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::core::dispatch::{HookIdentity, ReadHookCtx, WriteHookCtx};

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

    #[test]
    fn passes_when_caller_owns_workspace() {
        let hook = WorkspaceBoundaryHook::new();
        let c = ctx("/proc/p1/workspace/notes.md", "p1");
        assert!(hook.on_pre(&c).is_ok());
    }

    /// A stranger gets no write into someone else's workspace, with no
    /// carve-out. There used to be one: the per-pid mailbox and its
    /// in-workspace link were the advertised way to reach an agent, so the
    /// hook had to let a non-owner write them. Messages are addressed by name
    /// now, in a conversation that lives outside every workspace, so the
    /// boundary has no exception left to make.
    #[test]
    fn rejects_a_stranger_everywhere_inside_the_workspace() {
        let hook = WorkspaceBoundaryHook::new();
        for path in [
            "/proc/p1/workspace/notes.md",
            "/proc/p1/workspace/chat-with-me",
        ] {
            assert!(
                hook.on_pre(&ctx(path, "stranger")).is_err(),
                "{path} must not be writable by a non-owner"
            );
        }
    }

    #[test]
    fn passes_for_paths_outside_workspace_namespace() {
        let hook = WorkspaceBoundaryHook::new();
        let c = ctx("/agents/scode-standard/config.toml", "stranger");
        assert!(hook.on_pre(&c).is_ok());
    }

    #[test]
    fn passes_for_pid_namespace_outside_workspace_segment() {
        // /proc/{pid}/agent and /proc/{pid}/sessions/ are runtime metadata
        // paths owned by their pid but not workspace files; the hook only
        // governs the workspace segment.
        let hook = WorkspaceBoundaryHook::new();
        let c = ctx("/proc/p1/sessions/foo.jsonl", "stranger");
        assert!(hook.on_pre(&c).is_ok());
    }

    #[test]
    fn rejects_cross_owner_write_with_teaching_payload() {
        let hook = WorkspaceBoundaryHook::new();
        let c = ctx("/proc/p1/workspace/projects/nexus/src/main.rs", "p_other");
        let err = hook.on_pre(&c).unwrap_err();
        assert!(err.contains("EPERM"));
        assert!(err.contains("p1"));
        assert!(err.contains("p_other"));
        assert!(
            err.contains("/agents/p_other/conversations/"),
            "the error must point the caller at its own chat list: {err}"
        );
    }

    #[test]
    fn read_path_does_not_trigger_boundary() {
        let hook = WorkspaceBoundaryHook::new();
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
        let hook = WorkspaceBoundaryHook::new();
        let c = ctx("/proc/p1/workspace/notes.md", "");
        assert!(hook.on_pre(&c).is_ok());
    }
}
