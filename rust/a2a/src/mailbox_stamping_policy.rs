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

use serde::{Deserialize, Serialize};

/// The mailbox path suffix. SSOT for the `/chat-with-me` convention — the
/// stamp hook's `mutating_path_suffix()` (which drives the write-content
/// clone) and these path predicates MUST agree on it, so it is defined once
/// here and referenced by the hook rather than re-declared.
pub const CHAT_WITH_ME_SUFFIX: &str = "/chat-with-me";

/// io_profile waterfall for a `chat-with-me` mailbox DT_STREAM: `wal`
/// (raft-replicated, so a message survives its sender and reaches other
/// machines) when federation is up, else the node-local `memory` terminal.
/// SSOT for the mailbox backing — a2a owns "what a mailbox *is*"; the kernel
/// resolves the concrete backend from this preference order (see
/// `Kernel::install_stream_backend`). Every mailbox provisioner
/// ([`crate::ensure_mailbox_stream`], and via it the per-pid
/// `/proc/{pid}/chat-with-me` and the persistent `/agents/{name}/chat-with-me`)
/// goes through this one string rather than re-declaring `"wal,memory"`.
pub const MAILBOX_IO_PROFILE: &str = "wal,memory";

/// Capacity (cold-storage retention budget, in bytes) of a `chat-with-me`
/// mailbox DT_STREAM — the inode capacity threaded to
/// `Kernel::install_stream_backend`. Sized for the per-conversation message
/// flow (integration doc §3). SSOT shared by every mailbox provisioner.
pub const MAILBOX_STREAM_CAPACITY: usize = 65_536;

/// Mount base for persistent, per-identity A2A inboxes. An agent `name`'s
/// cross-machine inbox is `{A2A_INBOX_BASE}/{name}/chat-with-me`. SSOT for the
/// `/agents` convention the sudocode `Mailbox::A2aInbox` base and the
/// federation-mount default (`--cluster-init-mount /agents=<zone>`) must agree
/// on — kept next to [`CHAT_WITH_ME_SUFFIX`] so the whole A2A *address* lives
/// in one place, not hardcoded at each host call site.
pub const A2A_INBOX_BASE: &str = "/agents";

/// The persistent A2A inbox path for `agent_name`
/// (`/agents/{agent_name}/chat-with-me`), composed from the two address SSOTs
/// ([`A2A_INBOX_BASE`] + [`CHAT_WITH_ME_SUFFIX`]) — a host never hand-builds it.
#[must_use]
pub fn agent_inbox_path(agent_name: &str) -> String {
    format!("{A2A_INBOX_BASE}/{agent_name}{CHAT_WITH_ME_SUFFIX}")
}

/// The canonical A2A mailbox message schema — the content format written to
/// (and read from) any `*/chat-with-me` mailbox. This is the SSOT for the
/// envelope shape; every consumer (co-hosted sudocode agents, hydra, the
/// kickoff client) serialises/parses through this one definition rather than
/// hand-rolling the field names.
///
/// **Only `from` is enforced by the substrate.** [`maybe_stamp_chat_envelope`]
/// overwrites `from` with the authenticated caller's `agent_id` at the kernel
/// write hook, so a receiver sees who actually wrote the message, not who
/// claimed to. `to` and `body` are the application convention (documented
/// here) and are deliberately NOT policed by the kernel — a malformed or
/// partial payload is forwarded untouched and the receiver decides. Parsing
/// is therefore lenient (missing fields default to empty), and an empty
/// `from` is omitted on the wire so a writer may send `{to, body}` and let
/// the substrate stamp the sender.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MailboxEnvelope {
    /// Sender agent id. Authored by the writer but authoritatively stamped by
    /// the substrate — never trust a peer's self-claimed `from`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from: String,
    /// Recipient agent id (the mailbox owner this envelope is addressed to).
    #[serde(default)]
    pub to: String,
    /// The message text.
    #[serde(default)]
    pub body: String,
}

impl MailboxEnvelope {
    /// Serialise to the mailbox wire bytes (JSON).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Parse mailbox wire bytes into an envelope. Returns `None` on non-JSON
    /// content — matching the substrate's "don't police the schema" stance,
    /// the caller decides how to treat a payload that isn't an envelope.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// The node-local managed-agent mailbox prefix — `/proc/{pid}/chat-with-me` (a
/// DT_STREAM provisioned by `managed_agent::proc_entry` via
/// [`crate::ensure_mailbox_stream`], scoped to the pid's own node). It shares
/// the `/chat-with-me` suffix with the persistent A2A inbox but is exempt from
/// the *cross-machine* fail-closed identity gate. `/proc` is a stable kernel
/// convention for the process tree, not an operator-set mount.
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
    fn mailbox_envelope_round_trips_and_omits_empty_from() {
        // A writer sends {to, body} and lets the substrate stamp `from`:
        // empty `from` is omitted on the wire.
        let out = MailboxEnvelope {
            from: String::new(),
            to: "agent-b".into(),
            body: "hi".into(),
        };
        assert_eq!(
            parse(&out.to_bytes()),
            serde_json::json!({"to":"agent-b","body":"hi"})
        );

        // Round-trip with a stamped `from`.
        let stamped = MailboxEnvelope {
            from: "agent-a".into(),
            to: "agent-b".into(),
            body: "hi".into(),
        };
        assert_eq!(
            MailboxEnvelope::from_bytes(&stamped.to_bytes()),
            Some(stamped)
        );
    }

    #[test]
    fn mailbox_envelope_parses_leniently_and_rejects_non_json() {
        // Missing fields default to empty (don't police the schema).
        assert_eq!(
            MailboxEnvelope::from_bytes(br#"{"to":"agent-b"}"#),
            Some(MailboxEnvelope {
                from: String::new(),
                to: "agent-b".into(),
                body: String::new()
            })
        );
        // Extra fields the substrate forwarded are ignored by the typed view.
        assert_eq!(
            MailboxEnvelope::from_bytes(br#"{"from":"a","to":"b","body":"x","error":true}"#),
            Some(MailboxEnvelope {
                from: "a".into(),
                to: "b".into(),
                body: "x".into()
            })
        );
        // Non-JSON is `None` — the caller decides.
        assert_eq!(MailboxEnvelope::from_bytes(b"not json"), None);
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

    #[test]
    fn agent_inbox_path_is_the_a2a_convention() {
        assert_eq!(agent_inbox_path("mac-ai"), "/agents/mac-ai/chat-with-me");
        assert_eq!(agent_inbox_path("win-ai"), "/agents/win-ai/chat-with-me");
        // Composed from the two address SSOTs, not string literals.
        let p = agent_inbox_path("x");
        assert!(p.starts_with(A2A_INBOX_BASE));
        assert!(p.ends_with(CHAT_WITH_ME_SUFFIX));
        // Integration invariant: an inbox we provision MUST be recognized as a
        // cross-machine A2A mailbox by the fail-closed predicate — else the
        // `from`-guarantee would silently skip the very inboxes we create.
        assert!(is_a2a_mailbox_path(&p));
    }
}
