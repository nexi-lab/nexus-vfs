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
/// stamp hook's `mutating_path_suffixes()` (which drives the write-content
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

/// Suffix of an agent's replicated attention-state stream — sibling to
/// [`CHAT_WITH_ME_SUFFIX`] under the same `{A2A_INBOX_BASE}/{name}` presence.
pub const AGENT_STATE_SUFFIX: &str = "/state";

/// Address of `agent_name`'s attention-state stream
/// (`/agents/{agent_name}/state`) — sibling to [`agent_inbox_path`]. The host
/// publishes `AwaitingInput` enter/exit here; because it routes into the same
/// replicated `/agents/{name}` presence, any node reads "is this agent waiting?"
/// with a plain `sys_read` (and, riding the same stream-wakeup primitive as the
/// inbox, is woken the instant it changes). NOT a `*/chat-with-me` path, so it
/// carries no `from`-stamping.
#[must_use]
pub fn agent_state_path(agent_name: &str) -> String {
    format!("{A2A_INBOX_BASE}/{agent_name}{AGENT_STATE_SUFFIX}")
}

// ── Conversations ──────────────────────────────────────────────────────
//
// A conversation, not a pair of inboxes. `/agents/{name}/chat-with-me` made
// "where has this agent read to" a property of whichever machine ran it, and
// two inboxes that never merge cannot express "has my peer read this" — there
// is no shared offset space to point at. One append-only transcript both
// parties write, plus one reader register per participant, answers both.
//
// The leaf is `transcript`, singular, because it IS one object (a DT_STREAM
// here, one JSONL file on a host backend) sitting next to a real `readers/`
// directory — a plural leaf there reads as a directory you could list. It is
// deliberately NOT `inbox` or `chat-with-me`: both name a per-recipient,
// receive-only mailbox, and this log is bidirectional (A's message and B's
// reply are the same stream, each side filtering its own writes). Naming it
// for one endpoint would reinstate the very model this replaces.

/// Root of the conversation store. Flat and cid-keyed: a conversation belongs
/// to its participants, not to either one's subtree, so it cannot live under
/// `/agents/{name}`. Each participant reaches it through a DT_LINK
/// ([`agent_conversation_link_path`]) — the same shape sessions already use,
/// where `/agents/{name}/sessions/<sid>` indexes into a flat `/sessions` store.
pub const CONVERSATIONS_BASE: &str = "/conversations";

/// Leaf of a conversation's append-only message log — the offset-addressed
/// transcript both participants append to. SSOT for the leaf name; the stamp
/// hook's [`MAILBOX_WRITE_SUFFIXES`] and the path predicates below all read it
/// from here rather than re-spelling it.
pub const TRANSCRIPT_LEAF: &str = "/transcript";

/// Path segment introducing a conversation id. Used by the STRUCTURAL
/// predicates: a bare `ends_with("/transcript")` would be a far weaker test
/// than the old `/chat-with-me` (which nothing else in the tree is named), and
/// [`is_a2a_mailbox_path`] is the ENTIRE allow-list a cross-org caller is
/// confined to — see `crate::foreign_containment`. Requiring the
/// `/conversations/` segment keeps that gate exactly as narrow as it was.
const CONVERSATIONS_SEGMENT: &str = "/conversations/";

/// Path segment introducing a conversation's per-participant reader registers.
const READERS_SEGMENT: &str = "/readers/";

/// Segment under an agent's presence holding its conversation DT_LINKs, so
/// `readdir("{A2A_INBOX_BASE}/{name}/conversations")` is that agent's chat list.
pub const AGENT_CONVERSATIONS_SEGMENT: &str = "/conversations";

/// Write-content suffixes the A2A stamp hook claims, newest first.
///
/// TWO entries for the duration of the rename, and that is the whole reason
/// `NativeInterceptHook::mutating_path_suffixes` returns a slice. The writers
/// live in the sudocode repo, which pins THIS repo by revision, so the new leaf
/// cannot appear on both sides at once: this repo must honour the new path
/// BEFORE sudocode may write it, and must keep honouring the old one until the
/// release chain (nexus-vfs tag → sudocode pin → nexus assembly tag) has
/// carried the change to every writer. Dropping `CHAT_WITH_ME_SUFFIX` early
/// un-stamps every in-flight writer SILENTLY — no compile error, no runtime
/// error, just a forgeable `from`. Delete it only once no supported consumer
/// writes the old path.
pub const MAILBOX_WRITE_SUFFIXES: &[&str] = &[TRANSCRIPT_LEAF, CHAT_WITH_ME_SUFFIX];

/// VFS prefixes whose contents MUST be raft-replicated for A2A to work at all.
///
/// A2A's entire promise is that a message reaches an agent on ANOTHER machine.
/// That holds only if the paths it writes route into a federation zone: an
/// unmounted prefix falls back to this node's own SOLO `root` zone (the
/// fallback in `VFSRouter::route`), where the write succeeds, a local read
/// returns it, and the peer never sees it. Nothing errors — the operator finds
/// out from a conversation that silently never arrives.
///
/// Declared HERE, by the subsystem that owns the addresses, rather than left to
/// each deployment's `--cluster-init-mount` line. "Which prefixes A2A needs
/// replicated" is a2a's knowledge and nobody else's; making the operator
/// restate it is how it gets forgotten, and forgetting it fails silently. The
/// composition root reads this list and mounts them automatically, so declaring
/// a federation zone is enough to get a working A2A.
///
/// Adding a prefix here is a DEPLOYMENT-AFFECTING change: it starts being
/// mounted on the next founder boot. That is the intent — a new A2A path that
/// needs replication should arrive already replicated — but it means this list
/// is a contract, not a convenience.
pub const REPLICATED_PREFIXES: &[&str] = &[A2A_INBOX_BASE, CONVERSATIONS_BASE];

/// The conversation id for an unordered pair of agent names.
///
/// Deterministic and order-free: both sides compute the same id from the names
/// alone, with no coordination and no registry lookup, so `send(to = "bob")`
/// resolves to a conversation without either party having run first. Sorting
/// the pair is what makes it unordered — `f(a, b) == f(b, a)` — which is what
/// gives 1:1 chat-app semantics: exactly ONE thread per pair, created
/// idempotently by whoever writes first.
///
/// This uniqueness rule is load-bearing beyond convenience. It is what keeps
/// `to = <name>` unambiguous, so that adding group conversations later (an
/// explicitly minted cid addressed as `conversation = <cid>`) does not change
/// what `to` means for the 1:1 case.
///
/// The names are separated by a NUL rather than a printable character because
/// agent names are user-chosen: with a `-` separator the pairs `("a-b", "c")`
/// and `("a", "b-c")` hash identically, silently merging two conversations.
/// NUL cannot occur in a name that is usable as a path segment.
///
/// BLAKE3 (the hash this repo already uses for content addressing) truncated to
/// 32 hex chars = 128 bits — collision-negligible for a name space this size,
/// and short enough to stay readable in a path.
#[must_use]
pub fn conversation_id(a: &str, b: &str) -> String {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = blake3::Hasher::new();
    hasher.update(first.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(second.as_bytes());
    hasher.finalize().to_hex()[..32].to_string()
}

/// The append-only transcript of conversation `cid`
/// (`/conversations/{cid}/transcript`).
#[must_use]
pub fn conversation_transcript_path(cid: &str) -> String {
    format!("{CONVERSATIONS_BASE}/{cid}{TRANSCRIPT_LEAF}")
}

/// `agent`'s reader register in conversation `cid`
/// (`/conversations/{cid}/readers/{agent}`) — the mutable
/// `{holder, lease_expires_at, read_offset}` record.
///
/// A register rather than frames in the transcript: a read position is mutable
/// state with one current value, while the transcript is an append-only log.
/// Welding them would mean recovering a position by scanning BACKWARD for your
/// own last receipt, and a DT_STREAM is forward offset-addressed — O(tail scan)
/// where a register is O(1).
///
/// It lives beside the transcript, in the conversation, so the position is a
/// property of the agent rather than of whichever machine happened to run it.
/// That is what lets a peer observe readiness directly, and what makes a lost
/// client config home a non-event instead of an agent that looks brand new.
#[must_use]
pub fn conversation_reader_path(cid: &str, agent_name: &str) -> String {
    format!("{CONVERSATIONS_BASE}/{cid}{READERS_SEGMENT}{agent_name}")
}

/// `agent`'s DT_LINK to conversation `cid`
/// (`/agents/{agent}/conversations/{cid}`) — the chat-list index entry.
///
/// A pointer, not the bytes: `readdir("/agents/{name}")` still lists that
/// agent's presence, and `readdir("/agents/{name}/conversations")` is its chat
/// list, while the conversation itself stays single-instance under
/// [`CONVERSATIONS_BASE`] so both participants read and write the same log.
#[must_use]
pub fn agent_conversation_link_path(agent_name: &str, cid: &str) -> String {
    format!("{A2A_INBOX_BASE}/{agent_name}{AGENT_CONVERSATIONS_SEGMENT}/{cid}")
}

/// Whether `path` is a conversation transcript
/// (`…/conversations/<cid>/transcript`).
///
/// Structural, not a bare suffix test — see [`CONVERSATIONS_SEGMENT`].
#[must_use]
pub fn is_conversation_transcript_path(path: &str) -> bool {
    path.ends_with(TRANSCRIPT_LEAF) && path.contains(CONVERSATIONS_SEGMENT)
}

/// Whether `path` is a conversation reader register
/// (`…/conversations/<cid>/readers/<agent>`).
///
/// Separate from [`is_a2a_mailbox_path`] ON PURPOSE. A reader register is
/// readable by a peer — that is how readiness is observed without a relay — but
/// it must never fall inside a foreign agent's WRITE scope: moving someone
/// else's read position silently skips their inbound messages, which is a
/// denial of delivery that leaves no trace. `crate::foreign_containment` admits
/// this predicate for reads only.
#[must_use]
pub fn is_conversation_reader_path(path: &str) -> bool {
    path.contains(CONVERSATIONS_SEGMENT) && path.contains(READERS_SEGMENT)
}

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

/// The node-local managed-agent mailbox prefix — `/proc/{pid}/chat-with-me` (a
/// DT_STREAM provisioned by `managed_agent::proc_entry` via
/// [`crate::ensure_mailbox_stream`], scoped to the pid's own node). It shares
/// the `/chat-with-me` suffix with the persistent A2A inbox but is exempt from
/// the *cross-machine* fail-closed identity gate. `/proc` is a stable kernel
/// convention for the process tree, not an operator-set mount.
const NODE_LOCAL_MAILBOX_PREFIX: &str = "/proc/";

/// Whether `path` is an A2A message log — a conversation transcript
/// (`…/conversations/<cid>/transcript`) or, for the duration of the rename, a
/// legacy `*/chat-with-me` mailbox.
///
/// This is the **stamp** scope: the `from`-guarantee applies to every
/// mailbox-shaped write, including the local managed-agent pipe
/// (`/proc/{pid}/chat-with-me`) it was originally built for. Used by
/// [`maybe_stamp_chat_envelope`].
///
/// Both shapes are accepted because the rename spans repos — see
/// [`MAILBOX_WRITE_SUFFIXES`] for why the window exists and when the legacy arm
/// may be deleted. The two predicates and the hook's declared suffixes MUST
/// stay in agreement: a path the hook does not claim is never cloned, so the
/// stamp never runs on it and `from` becomes whatever the writer typed.
pub fn is_mailbox_path(path: &str) -> bool {
    is_conversation_transcript_path(path) || path.ends_with(CHAT_WITH_ME_SUFFIX)
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
/// FAIL-SAFE + mount-independent by construction: every A2A message log EXCEPT
/// the node-local `/proc/` pipe. Deliberately NOT keyed off the A2A mount point
/// (`/agents`, operator-configurable via `NEXUS_FEDERATION_MOUNTS`) — keying on
/// the mount would fail UNSAFE, silently skipping the gate for a log under a
/// differently-named mount. Excluding the one stable node-local convention
/// instead gates a replicated log wherever it is mounted. (Over-including an
/// oddly-placed non-mailbox file is the safe direction for a security gate.)
///
/// This is ALSO the entire allow-list `crate::foreign_containment` confines a
/// cross-org caller to, which is why [`is_conversation_transcript_path`] tests
/// for the `/conversations/` segment rather than the `/transcript` leaf alone:
/// a bare leaf test would hand a foreign agent every path in the tree that
/// happens to end that way.
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

    /// A conversation transcript is a mailbox on both scopes, wherever mounted.
    #[test]
    fn conversation_transcript_is_a_mailbox_on_both_scopes() {
        let cid = conversation_id("win-ai", "mac-ai");
        let transcript = conversation_transcript_path(&cid);

        assert!(is_mailbox_path(&transcript), "{transcript}");
        assert!(is_a2a_mailbox_path(&transcript), "{transcript}");
        // Mount-independent, same as the legacy shape.
        assert!(is_a2a_mailbox_path(&format!(
            "/zone-x/conversations/{cid}/transcript"
        )));
    }

    /// The `/conversations/` segment is load-bearing, not decoration.
    ///
    /// `is_a2a_mailbox_path` is the ENTIRE allow-list a cross-org caller is
    /// confined to (`crate::foreign_containment`). The legacy `/chat-with-me`
    /// leaf was safe as a bare suffix because nothing else in the tree is named
    /// that; `/transcript` is not — a session transcript, an audit transcript,
    /// anything a user names that way would land inside a foreign agent's
    /// reach. So the predicate is structural, and this pins it.
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
            assert!(!is_a2a_mailbox_path(path), "{path}");
        }
    }

    /// A reader register is readable by a peer but must never be WRITABLE by a
    /// foreign one, so it must fall OUTSIDE the mailbox predicates.
    ///
    /// `is_a2a_mailbox_path` grants a cross-org caller read AND write. Moving
    /// someone else's read position steps over their inbound messages with no
    /// error, no trace, and the sender still told "delivered" — so the register
    /// gets its own predicate, admitted for reads only.
    #[test]
    fn reader_register_is_outside_the_foreign_write_scope() {
        let cid = conversation_id("win-ai", "mac-ai");
        let reader = conversation_reader_path(&cid, "win-ai");

        assert!(is_conversation_reader_path(&reader), "{reader}");
        assert!(
            !is_a2a_mailbox_path(&reader),
            "a reader register must not be inside the foreign agent's write scope: {reader}"
        );
        assert!(!is_mailbox_path(&reader), "{reader}");
        // And a transcript is not a reader register.
        assert!(!is_conversation_reader_path(&conversation_transcript_path(
            &cid
        )));
    }

    /// One conversation per unordered pair, derivable by either side alone.
    #[test]
    fn conversation_id_is_deterministic_and_order_free() {
        assert_eq!(
            conversation_id("win-ai", "mac-ai"),
            conversation_id("mac-ai", "win-ai"),
            "the pair is unordered — both sides must derive the same id with no coordination"
        );
        assert_eq!(conversation_id("a", "b"), conversation_id("a", "b"));
        assert_ne!(conversation_id("a", "b"), conversation_id("a", "c"));
        // Path-safe and stable in length.
        let cid = conversation_id("win-ai", "mac-ai");
        assert_eq!(cid.len(), 32);
        assert!(cid.chars().all(|c| c.is_ascii_hexdigit()), "{cid}");
    }

    /// The NUL separator is what stops two different pairs sharing one id.
    ///
    /// Agent names are user-chosen, so any printable separator can occur inside
    /// one. With a `-` join, `("a-b", "c")` and `("a", "b-c")` both hash
    /// `"a-b-c"` — two unrelated pairs silently merged into one conversation,
    /// each reading the other's messages.
    #[test]
    fn conversation_id_separator_prevents_pair_ambiguity() {
        assert_ne!(
            conversation_id("a-b", "c"),
            conversation_id("a", "b-c"),
            "a separator that can appear in a name would merge two distinct pairs"
        );
    }

    /// Every conversation path composes from the SSOTs, and the transcript a
    /// provisioner creates is recognised by the fail-closed predicate.
    #[test]
    fn conversation_paths_compose_from_the_ssots() {
        let cid = conversation_id("win-ai", "mac-ai");

        let transcript = conversation_transcript_path(&cid);
        assert_eq!(transcript, format!("/conversations/{cid}/transcript"));
        assert!(transcript.starts_with(CONVERSATIONS_BASE));
        assert!(transcript.ends_with(TRANSCRIPT_LEAF));

        assert_eq!(
            conversation_reader_path(&cid, "win-ai"),
            format!("/conversations/{cid}/readers/win-ai")
        );
        // The chat-list index lives under the agent's presence and points AT
        // the shared conversation — `readdir` on it is that agent's chat list.
        assert_eq!(
            agent_conversation_link_path("win-ai", &cid),
            format!("/agents/win-ai/conversations/{cid}")
        );
        // Integration invariant, mirroring `agent_inbox_path_is_the_a2a_convention`:
        // what we provision MUST be what the gate recognises, or the
        // `from`-guarantee silently skips the very logs we create.
        assert!(is_a2a_mailbox_path(&transcript));
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
