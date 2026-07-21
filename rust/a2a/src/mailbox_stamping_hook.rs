//! `MailboxStampingHook` — INTERCEPT pre-write hook that rewrites the
//! envelope's `from` field on chat-with-me writes.
//!
//! The kernel side is intentionally thin: this struct exists so the
//! dispatch system has a registered `NativeInterceptHook`, and its
//! `mutating_path_suffix` declaration drives the content-clone bypass
//! at the sys_write call site (only `*/chat-with-me` writes pay the
//! clone). The actual rewriting policy lives in the sibling
//! [`crate::mailbox_stamping_policy::maybe_stamp_chat_envelope`] — kernel
//! owns "how to be a hook" (dispatch wiring), policy owns "what to
//! rewrite" (envelope schema, identity guarantee).
//!
//! The hook is armed at cluster boot by [`crate::install_a2a`], which
//! binds it to the `a2a` hook-only service. It is `pub` so both the
//! boot wiring and consumer frontends (e.g. the matrix adapter's test
//! fixtures) that ride the same substrate can register it.

use crate::mailbox_stamping_policy;
use contracts::is_system_path;
use kernel::core::dispatch::{HookContext, HookOutcome, NativeInterceptHook};

/// Path suffix the dispatcher consults to decide when to clone write
/// content into `WriteHookCtx`. Kept as a constant so the suffix
/// declared by the trait method matches the one mailbox stamping
/// itself recognises.
const CHAT_WITH_ME_SUFFIX: &str = "/chat-with-me";

pub struct MailboxStampingHook {
    /// When true, a mailbox write with no caller `agent_id` is REJECTED
    /// (the write aborts with a permission error) instead of passing
    /// through unstamped. Meaningful only when auth is armed — the
    /// composition root sets it from the auth posture so a NoAuth
    /// bring-up (every write has an empty `agent_id`) stays fail-open.
    /// The default constructor keeps fail-open so frontend consumers
    /// (matrix, managed_agent) are unaffected.
    fail_closed: bool,
}

impl MailboxStampingHook {
    /// Fail-open hook: an empty `agent_id` mailbox write passes through
    /// unstamped. This is the behaviour every existing consumer relies on
    /// (NoAuth bring-up, matrix/managed_agent frontends).
    pub fn new() -> Self {
        Self { fail_closed: false }
    }

    /// Hook with an explicit fail-closed posture. `fail_closed=true` makes
    /// a mailbox write REQUIRE an authenticated agent identity — an empty
    /// `agent_id` write is rejected. The daemon arms this from the auth
    /// posture via [`crate::install_a2a_stamp_hook`].
    pub fn new_fail_closed(fail_closed: bool) -> Self {
        Self { fail_closed }
    }
}

impl Default for MailboxStampingHook {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeInterceptHook for MailboxStampingHook {
    fn name(&self) -> &str {
        "mailbox_stamping"
    }

    fn mutating_path_suffix(&self) -> Option<&'static str> {
        Some(CHAT_WITH_ME_SUFFIX)
    }

    fn on_pre(&self, ctx: &HookContext) -> Result<HookOutcome, String> {
        // Native (unnamed) hook contract — short-circuit kernel-internal
        // paths so any future sys_read/sys_write inside this hook body
        // cannot recurse. Mirrors PermissionHook._is_system_path() in
        // Python (see `contracts::SYSTEM_PATH_PREFIX`). Today the
        // mailbox stamping logic is content-only and `/__sys__/` paths
        // naturally pass through, but the explicit check is the
        // contract every native hook follows.
        if is_system_path(ctx.path()) {
            return Ok(HookOutcome::Pass);
        }
        let HookContext::Write(c) = ctx else {
            // Non-write contexts never carry mailbox content; ignore.
            return Ok(HookOutcome::Pass);
        };
        // Other accept/reject hooks declared no mutating suffix, so the
        // dispatcher keeps `c.content = vec![]` for them. We only see
        // real bytes when the dispatcher matched OUR suffix and cloned.
        // Defensive empty-content check covers the case where the path
        // matched some other future mutating hook's suffix but not ours.
        if c.content.is_empty() {
            return Ok(HookOutcome::Pass);
        }
        let caller = if c.identity.agent_id.is_empty() {
            None
        } else {
            Some(c.identity.agent_id.as_str())
        };
        // Fail-closed: an unforgeable `from` requires a real agent identity,
        // so a mailbox write with no caller `agent_id` is rejected rather than
        // passed through unstamped. Gated on `fail_closed` (set from the auth
        // posture at install) so a NoAuth bring-up — where every write has an
        // empty `agent_id` — stays fail-open. A pre-hook `Err` aborts the write
        // as a permission error (see `HookOutcome` docs). Scoped to genuine
        // mailbox paths via the policy SSOT predicate so a non-mailbox write
        // that merely shares a future hook's suffix is never rejected here.
        if self.fail_closed && caller.is_none() && mailbox_stamping_policy::is_mailbox_path(&c.path)
        {
            return Err(format!(
                "fail-closed: mailbox write to {} requires an authenticated agent \
                 identity (no agent_id on the caller)",
                c.path
            ));
        }
        match mailbox_stamping_policy::maybe_stamp_chat_envelope(&c.path, caller, &c.content) {
            Some(rewritten) => Ok(HookOutcome::Replace(rewritten.into_owned())),
            None => Ok(HookOutcome::Pass),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::core::dispatch::{HookIdentity, ReadHookCtx, WriteHookCtx};

    fn write_ctx(path: &str, agent_id: &str, content: Vec<u8>) -> HookContext {
        HookContext::Write(WriteHookCtx {
            path: path.to_string(),
            identity: HookIdentity {
                user_id: "user1".to_string(),
                zone_id: "root".to_string(),
                agent_id: agent_id.to_string(),
                is_admin: false,
            },
            content,
            is_new_file: false,
            content_id: None,
            new_version: 0,
            size_bytes: None,
        })
    }

    #[test]
    fn declares_chat_with_me_suffix() {
        let h = MailboxStampingHook::new();
        assert_eq!(h.mutating_path_suffix(), Some("/chat-with-me"));
    }

    #[test]
    fn replaces_envelope_when_chat_path_with_real_content() {
        let h = MailboxStampingHook::new();
        let ctx = write_ctx(
            "/proc/p1/chat-with-me",
            "agent-real",
            br#"{"to":"agent-b","body":"hi"}"#.to_vec(),
        );
        let outcome = h.on_pre(&ctx).expect("hook must accept");
        match outcome {
            HookOutcome::Replace(bytes) => {
                let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(v["from"], "agent-real");
            }
            HookOutcome::Pass => panic!("expected Replace, got Pass"),
        }
    }

    #[test]
    fn passes_when_content_empty_even_on_chat_path() {
        // Defensive: dispatcher can in principle match a different
        // mutating hook's suffix and skip cloning for ours. We must
        // not blow up — empty content means "not for us".
        let h = MailboxStampingHook::new();
        let ctx = write_ctx("/proc/p1/chat-with-me", "agent-a", Vec::new());
        let outcome = h.on_pre(&ctx).unwrap();
        assert!(matches!(outcome, HookOutcome::Pass));
    }

    #[test]
    fn passes_when_caller_agent_id_empty() {
        let h = MailboxStampingHook::new();
        let ctx = write_ctx("/proc/p1/chat-with-me", "", br#"{"to":"agent-b"}"#.to_vec());
        let outcome = h.on_pre(&ctx).unwrap();
        assert!(matches!(outcome, HookOutcome::Pass));
    }

    #[test]
    fn passes_for_non_write_contexts() {
        let h = MailboxStampingHook::new();
        let ctx = HookContext::Read(ReadHookCtx {
            path: "/proc/p1/chat-with-me".to_string(),
            identity: HookIdentity {
                user_id: "user".to_string(),
                zone_id: "root".to_string(),
                agent_id: "agent-a".to_string(),
                is_admin: false,
            },
            content: None,
            content_id: None,
        });
        assert!(matches!(h.on_pre(&ctx).unwrap(), HookOutcome::Pass));
    }

    #[test]
    fn passes_for_non_chat_path_with_content() {
        // The dispatcher only clones when our suffix matches, so this
        // shape shouldn't occur in practice; but if it does, the policy
        // function sees the non-chat path and returns None, which we
        // surface as Pass.
        let h = MailboxStampingHook::new();
        let ctx = write_ctx(
            "/workspace/notes.md",
            "agent-a",
            br#"{"to":"agent-b"}"#.to_vec(),
        );
        let outcome = h.on_pre(&ctx).unwrap();
        assert!(matches!(outcome, HookOutcome::Pass));
    }

    #[test]
    fn fail_closed_rejects_empty_agent_id_mailbox_write() {
        // Auth-armed posture: a mailbox write with no caller agent_id is
        // rejected (Err aborts the write) so `from` cannot be forged by an
        // unauthenticated writer.
        let h = MailboxStampingHook::new_fail_closed(true);
        let ctx = write_ctx("/proc/p1/chat-with-me", "", br#"{"to":"agent-b"}"#.to_vec());
        assert!(
            h.on_pre(&ctx).is_err(),
            "fail-closed must reject an empty-agent_id mailbox write"
        );
    }

    #[test]
    fn fail_closed_still_stamps_authenticated_write() {
        let h = MailboxStampingHook::new_fail_closed(true);
        let ctx = write_ctx(
            "/proc/p1/chat-with-me",
            "agent-real",
            br#"{"from":"impostor","to":"agent-b"}"#.to_vec(),
        );
        match h.on_pre(&ctx).expect("authenticated write accepted") {
            HookOutcome::Replace(bytes) => {
                let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(v["from"], "agent-real");
            }
            HookOutcome::Pass => panic!("expected Replace, got Pass"),
        }
    }

    #[test]
    fn fail_closed_does_not_reject_non_mailbox_write() {
        // Scoping: fail-closed rejects only genuine mailbox paths. A
        // non-chat-with-me write with an empty agent_id must pass, never
        // be caught by the identity gate.
        let h = MailboxStampingHook::new_fail_closed(true);
        let ctx = write_ctx("/workspace/notes.md", "", br#"{"to":"agent-b"}"#.to_vec());
        assert!(
            matches!(
                h.on_pre(&ctx).expect("non-mailbox write accepted"),
                HookOutcome::Pass
            ),
            "fail-closed must not reject a non-mailbox write"
        );
    }
}
