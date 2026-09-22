//! Mailbox envelope stamping — overwrites the `from` field of a message
//! envelope with the caller's `agent_id` before the write reaches the
//! backend.
//!
//! Lives in the `a2a` messaging substrate because the policy (which paths
//! count as message logs, what the envelope schema looks like, the identity
//! guarantee) is A2A behaviour layered on top of the kernel write primitive.
//! The kernel calls into this from `sys_write` so the rewrite runs before any
//! backend touches the bytes; that integration site is the only kernel
//! awareness of mailbox semantics.
//!
//! Path policy: any `sys_write` whose target is an A2A message log — a
//! conversation transcript, or a legacy `*/chat-with-me` mailbox during the
//! rename window — is parsed as a JSON envelope and its `from` field stamped
//! with `caller_agent_id` regardless of what the LLM authored. Receivers see
//! who actually wrote the message, not who claimed to.
//!
//! Non-mailbox paths and writes without a caller agent_id short-circuit at the
//! path test, so the steady-state cost on the hot path is one `str::ends_with`
//! plus (for the transcript arm) one `str::contains`.
//!
//! The ADDRESSES themselves live in [`crate::addresses`]; this module only
//! asks questions about them. The dependency runs one way — stamping imports
//! addressing, never the reverse.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::addresses::{is_conversation_transcript_path, TRANSCRIPT_LEAF};

/// Write-content suffixes the A2A stamp hook claims.
///
/// A slice, not a single value, because a rename here spans repos: the writers
/// live in sudocode, which pins THIS repo by revision, so a new leaf must be
/// honoured here BEFORE sudocode may write it and the old one must keep being
/// honoured until the release chain (nexus-vfs tag → sudocode pin → nexus
/// assembly tag) has carried the change to every writer. Dropping a suffix
/// early un-stamps its writers SILENTLY — no compile error, no runtime error,
/// just a forgeable `from` — so a suffix leaves this list only once no
/// supported consumer writes it.
pub const MAILBOX_WRITE_SUFFIXES: &[&str] = &[TRANSCRIPT_LEAF];

/// The canonical A2A mailbox message schema — the content format written to
/// (and read from) any A2A message log. This is the SSOT for the
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

/// Whether `path` is an A2A message log — a conversation transcript
/// (`…/conversations/<cid>/transcript`).
///
/// ONE predicate, for both the stamp and the fail-closed gate. There used to be
/// two: the node-local `/proc/{pid}/chat-with-me` pipe was stamped but never
/// *rejected*, because an unauthenticated write to it could not reach another
/// machine. That pipe is gone, every message log is replicated, and a
/// distinction with nothing left on one side of it is a trap — the next reader
/// has to work out that the two are coextensive before trusting either.
///
/// It MUST stay in agreement with the hook's declared suffixes
/// ([`MAILBOX_WRITE_SUFFIXES`]): a path the hook does not claim is never
/// cloned, so the stamp never runs on it and `from` becomes whatever the writer
/// typed.
///
/// FAIL-SAFE and mount-independent by construction. Deliberately NOT keyed off
/// the A2A mount point (`/agents`, operator-configurable via
/// `NEXUS_FEDERATION_MOUNTS`) — keying on the mount would fail UNSAFE, silently
/// skipping the gate for a log under a differently-named mount. Over-including
/// an oddly-placed non-mailbox file is the safe direction for a security gate.
///
/// This is ALSO the entire allow-list [`crate::foreign_containment`] confines a
/// cross-org caller to, which is why [`is_conversation_transcript_path`] tests
/// for the `/conversations/` segment rather than the `/transcript` leaf alone:
/// a bare leaf test would hand a foreign agent every path in the tree that
/// happens to end that way.
pub fn is_mailbox_path(path: &str) -> bool {
    is_conversation_transcript_path(path)
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
    use crate::addresses::{
        conversation_id, conversation_reader_path, conversation_transcript_path,
        is_conversation_reader_path,
    };

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
    fn stamps_from_field_on_transcript_write() {
        let original = br#"{"to":"agent-b","body":"hi"}"#;
        let path = conversation_transcript_path(&conversation_id("agent-a", "agent-b"));
        let out = maybe_stamp_chat_envelope(&path, Some("agent-a"), original).unwrap();
        let v = parse(&out);
        assert_eq!(v["from"], "agent-a");
        assert_eq!(v["to"], "agent-b");
        assert_eq!(v["body"], "hi");
    }

    #[test]
    fn overwrites_caller_supplied_from_field() {
        // LLM tries to spoof a from field; the kernel overwrites it.
        let original = br#"{"from":"agent-fake","to":"agent-b","body":"x"}"#;
        let path = conversation_transcript_path(&conversation_id("agent-real", "agent-b"));
        let out = maybe_stamp_chat_envelope(&path, Some("agent-real"), original).unwrap();
        let v = parse(&out);
        assert_eq!(v["from"], "agent-real");
    }

    /// A transcript path, so the `None` results below come from the reason
    /// each test names and not from the path simply not being a mailbox.
    fn mbox() -> String {
        conversation_transcript_path(&conversation_id("agent-a", "agent-b"))
    }

    #[test]
    fn passes_through_when_caller_already_correct() {
        let original = br#"{"from":"agent-a","to":"agent-b"}"#;
        let out = maybe_stamp_chat_envelope(&mbox(), Some("agent-a"), original);
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
        let out = maybe_stamp_chat_envelope(&mbox(), None, original);
        assert!(
            out.is_none(),
            "kernel-internal writes (no agent_id) walk through unmodified"
        );
    }

    #[test]
    fn ignores_when_caller_empty_string() {
        let original = br#"{"to":"agent-b"}"#;
        let out = maybe_stamp_chat_envelope(&mbox(), Some(""), original);
        assert!(out.is_none());
    }

    #[test]
    fn ignores_non_json_content() {
        let original = b"plain text body, not an envelope";
        let out = maybe_stamp_chat_envelope(&mbox(), Some("agent-a"), original);
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
        let out = maybe_stamp_chat_envelope(&mbox(), Some("agent-a"), original);
        assert!(out.is_none());
    }

    /// What the predicate admits, and what it must refuse.
    ///
    /// One predicate now drives both the stamp and the fail-closed gate, so
    /// every path it admits is one an unauthenticated write is REJECTED on.
    /// Widening it is therefore not a cosmetic change.
    #[test]
    fn mailbox_predicate_scope() {
        let cid = conversation_id("win-ai", "mac-ai");
        let transcript = conversation_transcript_path(&cid);
        assert!(is_mailbox_path(&transcript), "{transcript}");

        // Mount-independent: the A2A mount point is operator-configurable, so
        // keying on `/agents` would fail UNSAFE — a log under a differently
        // named mount would silently skip the gate.
        assert!(
            is_mailbox_path(&format!("/zone-x/conversations/{cid}/transcript")),
            "a transcript under any mount is gated, not just the default one"
        );

        assert!(!is_mailbox_path("/workspace/notes.md"));
        assert!(
            !is_mailbox_path("/agents/win-ai/notes.txt"),
            "an ordinary file under the agent presence is not a message log"
        );
    }

    /// The `/conversations/` segment is load-bearing, not decoration.
    ///
    /// [`is_mailbox_path`] is the ENTIRE allow-list a cross-org caller is
    /// confined to (`crate::foreign_containment`), and `/transcript` is not a
    /// leaf that is safe to test for on its own — a session transcript, an
    /// audit transcript, anything a user names that way would land inside a
    /// foreign agent's reach. So the predicate is structural, and this pins
    /// it.
    #[test]
    fn a_bare_transcript_leaf_is_not_a_mailbox() {
        for path in [
            "/workspace/transcript",
            "/sessions/sid-42/transcript",
            "/agents/win-ai/transcript",
        ] {
            assert!(
                !is_mailbox_path(path),
                "{path} must NOT be a mailbox — it carries no /conversations/ segment"
            );
        }
    }

    /// A reader register is readable by a peer but must never be WRITABLE by a
    /// foreign one, so it must fall OUTSIDE the mailbox predicates.
    ///
    /// [`is_mailbox_path`] grants a cross-org caller read AND write. Moving
    /// someone else's read position steps over their inbound messages with no
    /// error, no trace, and the sender still told "delivered" — so the register
    /// gets its own predicate, admitted for reads only.
    #[test]
    fn reader_register_is_outside_the_foreign_write_scope() {
        let cid = conversation_id("win-ai", "mac-ai");
        let reader = conversation_reader_path(&cid, "win-ai");

        assert!(is_conversation_reader_path(&reader), "{reader}");
        assert!(
            !is_mailbox_path(&reader),
            "a reader register must not be inside the foreign agent's write scope: {reader}"
        );
        // And a transcript is not a reader register.
        assert!(!is_conversation_reader_path(&conversation_transcript_path(
            &cid
        )));
    }
}
