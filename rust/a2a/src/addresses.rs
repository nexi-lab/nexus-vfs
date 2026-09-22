//! A2A addressing — where agents and conversations LIVE in the VFS.
//!
//! This is the address SSOT: every path an A2A participant reads or writes is
//! composed here, so a host never hand-builds one and two call sites cannot
//! spell the same location differently. It also carries the stream contract a
//! message log is provisioned with ([`MAILBOX_IO_PROFILE`],
//! [`MAILBOX_STREAM_CAPACITY`]) — that is "what a mailbox IS", which belongs
//! with the address rather than with the policy that inspects writes to it.
//!
//! Split from `mailbox_stamping_policy` because they answer different
//! questions and only one direction of dependency exists: stamping asks "is
//! this path a message log" and therefore imports from here; nothing here
//! needs to know a stamp exists.
//!
//! Naming, decided with the kernel lead: a conversation's log is a
//! `transcript`, not an `inbox` or a `chat-with-me`. The latter two name a
//! per-recipient, receive-only mailbox, while this log is bidirectional — A's
//! message and B's reply are the same stream, each side filtering its own
//! writes. Naming it for one endpoint would reinstate the two-inbox model that
//! conversations replace.

/// io_profile waterfall for an A2A message-log DT_STREAM: `wal`
/// (raft-replicated, so a message survives its sender and reaches other
/// machines) when federation is up, else the node-local `memory` terminal.
/// SSOT for the mailbox backing — a2a owns "what a mailbox *is*"; the kernel
/// resolves the concrete backend from this preference order (see
/// `Kernel::install_stream_backend`). Every provisioner
/// ([`crate::ensure_mailbox_stream`], and via it the per-pid
/// `/proc/{pid}/chat-with-me` pipe and the conversation transcript) goes
/// through this one string rather than re-declaring `"wal,memory"`.
pub const MAILBOX_IO_PROFILE: &str = "wal,memory";

/// Capacity (cold-storage retention budget, in bytes) of an A2A message-log
/// DT_STREAM — the inode capacity threaded to `Kernel::install_stream_backend`.
/// SSOT shared by every provisioner.
///
/// Non-zero deliberately. A `wal,memory` stream created with capacity 0 is a
/// legal "keep forever" budget FOR WAL, but when the waterfall falls through to
/// `memory` it becomes a 0-byte ring that rejects every frame as `Oversized` —
/// a stream that exists, accepts a create, and can never hold a message. That
/// is how #276 lost mail.
pub const MAILBOX_STREAM_CAPACITY: usize = 65_536;

/// Mount base for persistent, per-identity agent presences. An agent `name`'s
/// presence is `{A2A_INBOX_BASE}/{name}/`. SSOT for the `/agents` convention
/// the sudocode mailbox base and the federation-mount default
/// (`--cluster-init-mount /agents=<zone>`) must agree on.
pub const A2A_INBOX_BASE: &str = "/agents";

/// Suffix of an agent's replicated attention-state stream — sibling to the
/// agent's other entries under the same `{A2A_INBOX_BASE}/{name}` presence.
pub const AGENT_STATE_SUFFIX: &str = "/state";

/// Address of `agent_name`'s attention-state stream
/// (`/agents/{agent_name}/state`). The host publishes `AwaitingInput`
/// enter/exit here; because it routes into the same replicated
/// `/agents/{name}` presence, any node reads "is this agent waiting?" with a
/// plain `sys_read` (and, riding the same stream-wakeup primitive as a message
/// log, is woken the instant it changes). NOT a message log, so it carries no
/// `from`-stamping.
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

/// Root of the conversation store. Flat and cid-keyed: a conversation belongs
/// to its participants, not to either one's subtree, so it cannot live under
/// `/agents/{name}`. Each participant reaches it through a DT_LINK
/// ([`agent_conversation_link_path`]) — the same shape sessions already use,
/// where `/agents/{name}/sessions/<sid>` indexes into a flat `/sessions` store.
pub const CONVERSATIONS_BASE: &str = "/conversations";

/// Leaf of a conversation's append-only message log — the offset-addressed
/// transcript both participants append to. SSOT for the leaf name; the stamp
/// hook's suffix list and the path predicates below all read it from here.
///
/// Singular because it IS one object (a DT_STREAM here, one JSONL file on a
/// host backend) sitting next to a real `readers/` directory — a plural leaf
/// there would read as a directory you could list.
pub const TRANSCRIPT_LEAF: &str = "/transcript";

/// Path segment introducing a conversation id. Used by the STRUCTURAL
/// predicates: a bare `ends_with("/transcript")` would be a far weaker test
/// than the old `/chat-with-me` (which nothing else in the tree is named), and
/// `crate::is_a2a_mailbox_path` is the ENTIRE allow-list a cross-org caller is
/// confined to — see `crate::foreign_containment`. Requiring the
/// `/conversations/` segment keeps that gate exactly as narrow as it was.
const CONVERSATIONS_SEGMENT: &str = "/conversations/";

/// Path segment introducing a conversation's per-participant reader registers.
const READERS_SEGMENT: &str = "/readers/";

/// Segment under an agent's presence holding its conversation DT_LINKs, so
/// `readdir("{A2A_INBOX_BASE}/{name}/conversations")` is that agent's chat list.
pub const AGENT_CONVERSATIONS_SEGMENT: &str = "/conversations";

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

/// `agent`'s DT_LINK to its conversation with `peer`
/// (`/agents/{agent}/conversations/{peer}`) — the chat-list index entry.
///
/// A pointer, not the bytes: `readdir("/agents/{name}")` still lists that
/// agent's presence, and `readdir("/agents/{name}/conversations")` is its chat
/// list, while the conversation itself stays single-instance under
/// [`CONVERSATIONS_BASE`] so both participants read and write the same log.
///
/// # Why the leaf is the PEER, not the cid
///
/// The cid is a BLAKE3 digest and therefore one-way: given
/// `/agents/win-ai/conversations/<32 hex>` there is no way back to "this is my
/// conversation with mac-ai". That breaks the index's whole purpose twice
/// over. A receiver discovers which transcripts to tail by listing this
/// directory, and with cid leaves it learns only that N conversations exist,
/// not who they are with — so it cannot derive a single transcript path.
/// And a human running `ls` sees a wall of hashes.
///
/// Keying by peer keeps the directory both machine- and human-readable, and
/// costs nothing: the cid is recomputed from the pair on demand
/// ([`conversation_id`]), which is exactly what makes it derivable rather than
/// allocated.
///
/// Group conversations, when they arrive, key by their minted cid instead —
/// unambiguous against this, since a 32-hex-char id cannot collide with an
/// agent name.
#[must_use]
pub fn agent_conversation_link_path(agent_name: &str, peer_name: &str) -> String {
    format!("{A2A_INBOX_BASE}/{agent_name}{AGENT_CONVERSATIONS_SEGMENT}/{peer_name}")
}

/// Whether `path` is an agent's chat list (`/agents/<name>/conversations`) or
/// one entry inside it.
///
/// Shape-checked rather than prefix-checked, because
/// [`crate::foreign_containment`] opens these to a foreign caller. A prefix
/// test would hand it the whole `/agents` subtree, and the shallower shapes
/// are indistinguishable from things that must stay closed: `/agents/<name>`
/// and `/agents/secrets.txt` are both two segments, so admitting the depth
/// admits the file.
///
/// A recipient's chat list already exists by the time anyone writes to it —
/// an agent announces itself by creating it before it starts listening — so
/// the entry is the only thing a sender needs to add.
#[must_use]
pub fn is_conversation_index_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(A2A_INBOX_BASE) else {
        return false;
    };
    // `/agentsfoo` strips to `foo`, which is not under `/agents` at all.
    if !(rest.is_empty() || rest.starts_with('/')) {
        return false;
    }
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    // `AGENT_CONVERSATIONS_SEGMENT` is `/conversations`; the leading slash is
    // gone once split, so compare against its trimmed form rather than
    // re-spelling the word.
    let index_dir = AGENT_CONVERSATIONS_SEGMENT.trim_start_matches('/');
    // Segments after `/agents`: [agent, "conversations"] is the chat list and
    // one more is an entry in it. Nothing shallower — see the note above on
    // why depth alone cannot tell a presence directory from a stray file.
    match segments.as_slice() {
        [_, dir] => *dir == index_dir,
        [_, dir, peer] => *dir == index_dir && !peer.is_empty(),
        _ => false,
    }
}

/// Whether `path` is a conversation transcript
/// (`…/conversations/<cid>/transcript`).
///
/// Structural rather than a bare suffix test, because `crate::is_a2a_mailbox_path`
/// builds on it and doubles as a cross-org allow-list — see the
/// `/conversations/` segment note above.
#[must_use]
pub fn is_conversation_transcript_path(path: &str) -> bool {
    path.ends_with(TRANSCRIPT_LEAF) && path.contains(CONVERSATIONS_SEGMENT)
}

/// Whether `path` is a conversation reader register
/// (`…/conversations/<cid>/readers/<agent>`).
///
/// Separate from `crate::is_a2a_mailbox_path` ON PURPOSE. A reader register is
/// readable by a peer — that is how readiness is observed without a relay — but
/// it must never fall inside a foreign agent's WRITE scope: moving someone
/// else's read position silently skips their inbound messages, which is a
/// denial of delivery that leaves no trace. `crate::foreign_containment` admits
/// this predicate for reads only.
#[must_use]
pub fn is_conversation_reader_path(path: &str) -> bool {
    path.contains(CONVERSATIONS_SEGMENT) && path.contains(READERS_SEGMENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox_stamping_policy::is_mailbox_path;

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
        //
        // Keyed by the PEER, not the cid: a BLAKE3 digest is one-way, so a
        // cid-named entry would tell a receiver that a conversation exists
        // without telling it with whom — and it could then derive no transcript
        // path at all. The cid is recomputed from the pair on demand.
        assert_eq!(
            agent_conversation_link_path("win-ai", "mac-ai"),
            "/agents/win-ai/conversations/mac-ai"
        );
        assert_eq!(
            agent_conversation_link_path("mac-ai", "win-ai"),
            "/agents/mac-ai/conversations/win-ai",
            "each side's entry names the other participant"
        );
        // Integration invariant: what we provision MUST be what the gate
        // recognises, or the `from`-guarantee silently skips the very logs we
        // create.
        assert!(is_mailbox_path(&transcript));
    }
}
