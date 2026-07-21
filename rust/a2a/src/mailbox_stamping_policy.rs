//! Mailbox envelope stamping — overwrites the `from` field of a message
//! envelope with the caller's `agent_id` before the write reaches the
//! backend.
//!
//! Lives in the `a2a` messaging substrate because the policy (which
//! paths count as mailboxes, what the envelope schema looks like, the
//! identity guarantee) is A2A behaviour layered on top of the kernel
//! write primitive. The kernel calls into this from `sys_write` so the
//! rewrite runs before any backend touches the bytes; that integration
//! site is the only kernel awareness of mailbox semantics.
//!
//! Path policy: any `sys_write` whose target ends in `/chat-with-me`
//! (the canonical mailbox path documented in the sudowork integration
//! design `docs/tech/nexus-integration-architecture.md` §3.3) is
//! parsed as a JSON envelope; the `from` field is stamped with
//! `caller_agent_id` regardless of what the LLM authored. Receivers
//! see who actually wrote the message, not who claimed to.
//!
//! Non-mailbox paths and writes without a caller agent_id short-circuit
//! at the path test, so the steady-state cost on the hot path is one
//! `str::ends_with` call.

use std::borrow::Cow;

/// The mailbox path suffix. SSOT for the `/chat-with-me` convention — the
/// stamp hook's `mutating_path_suffix()` (which drives the write-content
/// clone) and these path predicates MUST agree on it, so it is defined once
/// here and referenced by the hook rather than re-declared.
pub const CHAT_WITH_ME_SUFFIX: &str = "/chat-with-me";

/// The node-local managed-agent mailbox pipe prefix —
/// `/proc/{pid}/chat-with-me` (a DT_PIPE, intra-node, NOT replicated). It
/// shares the `/chat-with-me` suffix with the replicated A2A mailbox but is
/// exempt from the *cross-machine* fail-closed identity gate. `/proc` is a
/// stable kernel convention for the process tree, not an operator-set mount.
const NODE_LOCAL_MAILBOX_PREFIX: &str = "/proc/";

/// Whether `path` ends in the mailbox suffix (`*/chat-with-me`).
///
/// This is the **stamp** scope: the `from`-guarantee applies to every
/// mailbox-shaped write, including the local managed-agent pipe
/// (`/proc/{pid}/chat-with-me`) it was originally built for. Used by
/// [`maybe_stamp_chat_envelope`].
pub fn is_mailbox_path(path: &str) -> bool {
    path.ends_with(CHAT_WITH_ME_SUFFIX)
}

/// Whether `path` is a *cross-machine* mailbox subject to fail-closed.
///
/// The **fail-closed** scope, narrower than [`is_mailbox_path`]: rejecting an
/// unauthenticated write is a security requirement for a mailbox whose writes
/// reach other machines (untrusted remote peers). It must NOT catch the local
/// managed-agent pipe (`/proc/{pid}/chat-with-me`), which legitimately uses a
/// system/bare ctx and is not replicated. The stamp still runs on the local
/// pipe via [`is_mailbox_path`] — it is just never *rejected*.
///
/// FAIL-SAFE + mount-independent by construction: every `*/chat-with-me`
/// EXCEPT the node-local `/proc/` pipe. Deliberately NOT keyed off the A2A
/// mount point (`/agents`, operator-configurable via `NEXUS_FEDERATION_MOUNTS`)
/// — keying on the mount would fail UNSAFE, silently skipping the gate for a
/// mailbox under a differently-named mount. Excluding the one stable
/// node-local convention instead gates a replicated mailbox wherever it is
/// mounted. (Over-including an oddly-placed non-mailbox file named
/// `chat-with-me` is the safe direction for a security gate.)
///
/// NOTE: the precise mailbox-path structure is finalized by §F (per-sender
/// lanes vs one shared inbox — see the multi-writer seq contract); this is
/// the fail-safe interim until then.
pub fn is_a2a_mailbox_path(path: &str) -> bool {
    is_mailbox_path(path) && !path.starts_with(NODE_LOCAL_MAILBOX_PREFIX)
}

/// Rewrite the envelope's `from` field to the caller's `agent_id` when
/// the write target is a mailbox path. Returns the rewritten bytes, or
/// `None` if no rewrite was needed (non-mailbox path, no caller agent,
/// non-JSON content, or the existing `from` already matches).
///
/// JSON parsing failures are treated as "leave it alone" rather than
/// rejected — the kernel does not police the envelope schema, only the
/// `from` field. A non-JSON payload is forwarded to the backend
/// untouched and the receiver decides whether to accept it.
pub fn maybe_stamp_chat_envelope<'a>(
    path: &str,
    caller_agent_id: Option<&str>,
    content: &'a [u8],
) -> Option<Cow<'a, [u8]>> {
    if !is_mailbox_path(path) {
        return None;
    }
    let caller = caller_agent_id?;
    if caller.is_empty() {
        return None;
    }

    let mut value: serde_json::Value = serde_json::from_slice(content).ok()?;
    let obj = value.as_object_mut()?;

    // No-op if the field is already correct — preserves the borrow path
    // even when the caller already wrote `from` themselves with the
    // right value (rare, but cheap to check).
    if let Some(existing) = obj.get("from").and_then(|v| v.as_str()) {
        if existing == caller {
            return None;
        }
    }

    obj.insert(
        "from".to_string(),
        serde_json::Value::String(caller.to_string()),
    );
    let rewritten = serde_json::to_vec(&value).ok()?;
    Some(Cow::Owned(rewritten))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).expect("rewritten content must be valid JSON")
    }

    #[test]
    fn stamps_from_field_on_chat_with_me_write() {
        let original = br#"{"to":"agent-b","body":"hi"}"#;
        let out =
            maybe_stamp_chat_envelope("/proc/p1/chat-with-me", Some("agent-a"), original).unwrap();
        let v = parse(&out);
        assert_eq!(v["from"], "agent-a");
        assert_eq!(v["to"], "agent-b");
        assert_eq!(v["body"], "hi");
    }

    #[test]
    fn overwrites_caller_supplied_from_field() {
        // LLM tries to spoof a from field; the kernel overwrites it.
        let original = br#"{"from":"agent-fake","to":"agent-b","body":"x"}"#;
        let out = maybe_stamp_chat_envelope(
            "/proc/p1/workspace/chat-with-me",
            Some("agent-real"),
            original,
        )
        .unwrap();
        let v = parse(&out);
        assert_eq!(v["from"], "agent-real");
    }

    #[test]
    fn passes_through_when_caller_already_correct() {
        let original = br#"{"from":"agent-a","to":"agent-b"}"#;
        let out = maybe_stamp_chat_envelope("/proc/p1/chat-with-me", Some("agent-a"), original);
        assert!(out.is_none(), "no rewrite when from field already matches");
    }

    #[test]
    fn ignores_non_mailbox_paths() {
        let original = br#"{"from":"liar","body":"x"}"#;
        let out = maybe_stamp_chat_envelope("/workspace/notes.md", Some("agent-a"), original);
        assert!(
            out.is_none(),
            "rewriter must not touch ordinary file writes"
        );
    }

    #[test]
    fn ignores_when_caller_unset() {
        let original = br#"{"to":"agent-b"}"#;
        let out = maybe_stamp_chat_envelope("/proc/p1/chat-with-me", None, original);
        assert!(
            out.is_none(),
            "kernel-internal writes (no agent_id) walk through unmodified"
        );
    }

    #[test]
    fn ignores_when_caller_empty_string() {
        let original = br#"{"to":"agent-b"}"#;
        let out = maybe_stamp_chat_envelope("/proc/p1/chat-with-me", Some(""), original);
        assert!(out.is_none());
    }

    #[test]
    fn ignores_non_json_content() {
        let original = b"plain text body, not an envelope";
        let out = maybe_stamp_chat_envelope("/proc/p1/chat-with-me", Some("agent-a"), original);
        assert!(
            out.is_none(),
            "non-JSON content is forwarded untouched — receiver decides"
        );
    }

    #[test]
    fn ignores_json_array_top_level() {
        // Stamping is defined for envelope objects; anything else is left
        // alone so the kernel doesn't accidentally corrupt valid wire
        // formats it doesn't know about.
        let original = br#"["msg1","msg2"]"#;
        let out = maybe_stamp_chat_envelope("/proc/p1/chat-with-me", Some("agent-a"), original);
        assert!(out.is_none());
    }

    #[test]
    fn mailbox_predicate_scopes() {
        // Stamp scope (broad): any `*/chat-with-me`, incl. the local pipe.
        assert!(is_mailbox_path("/agents/win-ai/chat-with-me"));
        assert!(is_mailbox_path("/proc/p1/chat-with-me"));
        assert!(!is_mailbox_path("/workspace/notes.md"));

        // Fail-closed scope: any mailbox EXCEPT the node-local /proc pipe.
        assert!(is_a2a_mailbox_path("/agents/win-ai/chat-with-me"));
        assert!(
            !is_a2a_mailbox_path("/proc/p1/chat-with-me"),
            "the node-local managed-agent pipe is exempt from the gate"
        );
        assert!(
            !is_a2a_mailbox_path("/agents/win-ai/notes.txt"),
            "a non-chat-with-me file is never a mailbox"
        );
        // Mount-independent: a mailbox under a DIFFERENTLY-named federation
        // mount is still gated (keying off `/agents` would fail unsafe).
        assert!(
            is_a2a_mailbox_path("/team-mailboxes/win-ai/chat-with-me"),
            "fail-safe: a mailbox under any mount is gated, not just /agents"
        );
    }
}
