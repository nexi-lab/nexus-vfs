//! A2A messaging substrate — the kernel-tier capability that gives
//! agent-to-agent messaging an unforgeable `from`.
//!
//! # Role in the tier map
//!
//! `a2a` is the messaging **substrate**, not a frontend. It owns the
//! **`from` identity guarantee**: [`MailboxStampingHook`] rewrites the
//! envelope `from` to the caller's `agent_id` on every `*/chat-with-me`
//! write, so a frontend cannot forge a sender. The hook is armed ONCE at
//! the daemon by [`install_a2a_stamp_hook`], bound to the `a2a` hook-only
//! service.
//!
//! The **cross-machine delivery wake** is a separate, generic raft
//! primitive (`nexus_raft::stream_wakeup::install_stream_wakeup_observer`:
//! a replicated `AppendStreamEntry` wakes a reader parked on a replica —
//! both the DT_STREAM blocking tail and any `sys_watch` file-watcher on the
//! path). It is NOT a2a-specific — A2A's `chat-with-me` DT_STREAM
//! merely rides it — so it is armed per-zone by the composition root
//! (which holds the `Arc<Kernel>` the observer needs a `Weak` of, and the
//! federation-mount config that maps each zone's key to its caller-facing
//! path). Keeping it out of a2a leaves this crate a pure post-syscall
//! hook substrate (kernel + contracts + serde_json only — no raft).
//!
//! # Frontends / consumers
//!
//! Frontends ride on the substrate rather than re-implementing it:
//! `matrix_adapter` (Matrix C-S → humans, nexus services tier), the
//! `sudocode` runtime (agent runtime → AI), and `managed_agent`
//! (spawn/PCB → process). A frontend consumes [`MailboxStampingHook`];
//! only the daemon calls [`install_a2a_stamp_hook`].

pub mod addresses;
pub mod foreign_containment;
pub mod mailbox_stamping_hook;
pub mod mailbox_stamping_policy;

pub use foreign_containment::{install_foreign_agent_containment, ForeignAgentMailboxOnly};
pub use mailbox_stamping_hook::MailboxStampingHook;

// The crate root is the stable surface: consumers spell `a2a::X` and never name
// the module, so splitting addressing out of the stamping policy is invisible
// to them. Keep it that way — moving a symbol between these two lists is free,
// dropping one from the root is a breaking change for the other repo.
pub use addresses::{
    agent_conversation_link_path, agent_inbox_path, agent_state_path, conversation_id,
    conversation_reader_path, conversation_transcript_path, is_conversation_reader_path,
    is_conversation_transcript_path, A2A_INBOX_BASE, AGENT_CONVERSATIONS_SEGMENT,
    AGENT_STATE_SUFFIX, CHAT_WITH_ME_SUFFIX, CONVERSATIONS_BASE, MAILBOX_IO_PROFILE,
    MAILBOX_STREAM_CAPACITY, REPLICATED_PREFIXES, TRANSCRIPT_LEAF,
};
// `is_mailbox_path` / `is_a2a_mailbox_path` are re-exported because they ARE
// the public contract, not internals: the first is the stamp scope, the second
// is the entire allow-list a cross-org caller is confined to
// (`foreign_containment`). A consumer deciding whether a path is an A2A log
// must reach the same answer this crate does — re-exporting them is what keeps
// a second, drifting copy from being written elsewhere.
pub use mailbox_stamping_policy::{
    is_a2a_mailbox_path, is_mailbox_path, MailboxEnvelope, MAILBOX_WRITE_SUFFIXES,
};

use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::Kernel;

use kernel::meta_store::{DT_DIR, DT_LINK, DT_STREAM};

/// Provision `agent_name`'s persistent A2A inbox as a DT_STREAM, idempotently.
///
/// The A2A analogue of the per-pid `/proc/{pid}/chat-with-me` pipe: a2a owns
/// BOTH the address ([`agent_inbox_path`]) AND the stream contract
/// ([`ensure_mailbox_stream`]). A2A is host-agnostic — this is called by
/// whatever brings an agent online locally (today `managed_agent`, the sole
/// agent host; any future unmanaged host calls the same function). A REMOTE
/// agent's inbox is provisioned on its own host and replicated in, so a node
/// only ever provisions the inboxes of agents IT hosts.
pub fn ensure_agent_inbox<K: KernelSyscall>(kernel: &K, agent_name: &str) -> Result<(), String> {
    ensure_mailbox_stream(kernel, &agent_inbox_path(agent_name))
}

/// Provision `agent_name`'s attention-state stream as a DT_STREAM, idempotently
/// — the sibling of its inbox under the same replicated `/agents/{name}`
/// presence (see [`agent_state_path`]). Same host rule as the inbox: a node only
/// provisions the state streams of the agents IT hosts. Best-effort at the call
/// site — a std / non-stream deployment simply has no reader, and the agent runs
/// unaffected.
pub fn ensure_agent_state_stream<K: KernelSyscall>(
    kernel: &K,
    agent_name: &str,
) -> Result<(), String> {
    ensure_mailbox_stream(kernel, &agent_state_path(agent_name))
}

/// Provision the 1:1 conversation between `agent_name` and `peer_name`,
/// idempotently, and index it from BOTH participants' presences.
///
/// Creates the conversation's directory layer, its append-only transcript
/// DT_STREAM, and a DT_LINK under each agent's `/agents/{name}/conversations/`
/// chat list.
///
/// It deliberately does NOT create either side's reader register. A register
/// carries the holder and lease of whoever is actually consuming, which only
/// that process can fill in, so the consumer writes it on its first poll.
/// Nothing is lost by the absence: "no register" reads as offset 0, which is
/// exactly where a brand-new participant should start.
///
/// # Who calls this, and when
///
/// The SENDER, on send — NOT the agent host at mint. A cid is derived from a
/// PAIR ([`conversation_id`]), and at mint an agent knows only its own name, so
/// there is no conversation to provision yet. The sender knows both names,
/// which is the part that matters: it materialises the conversation itself
/// rather than depending on the recipient having run first.
///
/// That dependency is the defect this removes. A send to an agent that had
/// never run used to fail `StreamNotFound`, which made "the receiver must be up
/// BEFORE the peer sends" an operational rule that bit every cross-machine
/// round; a receiver starting late then seeked to the tail and stepped over
/// whatever had landed meanwhile. Now the first send materialises the
/// conversation, and a late receiver still reads it from 0.
///
/// Idempotent throughout and safe to race: the cid is derived rather than
/// allocated, so both hosts converge on the SAME conversation with no
/// coordination — whichever arrives first creates it, and the other's
/// `sys_setattr` is a matching no-op.
pub fn ensure_conversation<K: KernelSyscall>(
    kernel: &K,
    agent_name: &str,
    peer_name: &str,
) -> Result<(), String> {
    let cid = conversation_id(agent_name, peer_name);
    let conversation_root = format!("{CONVERSATIONS_BASE}/{cid}");
    let transcript = conversation_transcript_path(&cid);

    // Steady-state exit: ONE `sys_stat` instead of the eleven `sys_setattr`
    // round trips below. A sender calls this on every send, and every call
    // below is individually idempotent — so without this check the hot path
    // pays eleven syscalls per message to re-establish what the first send
    // already built.
    //
    // The transcript is created LAST on purpose, which is what makes it a
    // sound completion sentinel: if it exists, every directory and both
    // chat-list links exist too. Creating it earlier (the obvious order, since
    // it is the point of the conversation) would let a run interrupted between
    // the stream and the links leave a transcript with no index, and this
    // early return would then skip repairing it forever.
    if kernel
        .sys_stat(&transcript, contracts::ROOT_ZONE_ID)
        .is_some()
    {
        return Ok(());
    }

    // Dirent layer first — children attach below it. `setattr_create_link`
    // validates the target and puts the row; it does NOT materialise parents.
    // Without this the chat-list DT_LINK lands under a directory nothing can
    // `readdir`, and the chat list is the entire point of the index. Same
    // ordering `managed_agent::proc_entry` uses when it stamps `/proc`.
    ensure_dir(kernel, CONVERSATIONS_BASE)?;
    ensure_dir(kernel, &conversation_root)?;
    ensure_dir(kernel, A2A_INBOX_BASE)?;

    // Both participants get a chat-list entry. A conversation is not owned by
    // whoever provisioned it, so indexing only the local agent would leave the
    // peer unable to find it by listing.
    for name in [agent_name, peer_name] {
        ensure_dir(kernel, &format!("{A2A_INBOX_BASE}/{name}"))?;
        ensure_dir(
            kernel,
            &format!("{A2A_INBOX_BASE}/{name}{AGENT_CONVERSATIONS_SEGMENT}"),
        )?;
        link_conversation(
            kernel,
            &agent_conversation_link_path(name, &cid),
            &conversation_root,
        )
        .map_err(|e| format!("index conversation {cid} for {name}: {e}"))?;
    }

    // Last — see the completion-sentinel note above.
    ensure_mailbox_stream(kernel, &transcript)
}

/// Create `path` as a DT_DIR, idempotently.
///
/// `setattr_create_dir` treats an existing DT_DIR — or a DT_MOUNT, which is
/// directory-like — as a no-op, so this is safe to call on a federation mount
/// point such as `/agents`.
fn ensure_dir<K: KernelSyscall>(kernel: &K, path: &str) -> Result<(), String> {
    metadata_setattr(kernel, path, DT_DIR, None).map_err(|e| format!("ensure dir {path}: {e}"))
}

/// Point `alias` at `target` as a DT_LINK (the chat-list index entry).
fn link_conversation<K: KernelSyscall>(
    kernel: &K,
    alias: &str,
    target: &str,
) -> Result<(), String> {
    metadata_setattr(kernel, alias, DT_LINK, Some(target))
}

/// The shared `sys_setattr` shape for a2a's metadata-only entries — 21
/// positional arguments are worth naming once rather than at each call site,
/// where a misplaced `None` is invisible.
fn metadata_setattr<K: KernelSyscall>(
    kernel: &K,
    path: &str,
    entry_type: u8,
    link_target: Option<&str>,
) -> Result<(), String> {
    kernel
        .sys_setattr(
            path,
            // `kernel::meta_store` types these as `u8`; the syscall arg is
            // `i32`. Widening HERE keeps every call site spelling the named
            // constant instead of an integer literal — which is exactly what
            // those constants are `pub` for.
            i32::from(entry_type),
            /* backend_name */ "",
            /* backend */ None,
            /* metastore */ None,
            /* raft_backend */ None,
            /* io_profile */ "",
            /* zone_id */ contracts::ROOT_ZONE_ID,
            /* is_external */ false,
            /* capacity */ 0,
            /* read_fd */ None,
            /* write_fd */ None,
            /* mime_type */ None,
            /* modified_at_ms */ None,
            /* content_id */ None,
            /* size */ None,
            /* version */ None,
            /* created_at_ms */ None,
            link_target,
            /* source */ None,
            /* remote_metastore */ None,
        )
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

/// Provision the `chat-with-me` mailbox at `path` as a DT_STREAM, idempotently.
///
/// This is the ONE place that turns the a2a mailbox contract
/// ([`MAILBOX_IO_PROFILE`] + [`MAILBOX_STREAM_CAPACITY`]) into a real inode, so
/// every mailbox — the node-local `/proc/{pid}/chat-with-me` pipe AND the
/// persistent, replicated `/agents/{name}/chat-with-me` inbox — is the SAME
/// kind of stream. Provisioning is a2a's job because a2a owns "what a mailbox
/// is"; the *lifecycle* owner (`managed_agent`) decides *when* and *for whom*
/// to call this.
///
/// The `io_profile` waterfall lets the KERNEL pick the backing — `wal`
/// (raft-replicated) when the path routes into a federated zone, else
/// node-local `memory` — so the caller never has to read federation state.
/// Idempotent: `sys_setattr` treats a matching existing DT_STREAM as a
/// successful no-op, so re-spawns / restarts are safe. The provisioning ctx is
/// the root zone; routing resolves the mount's real zone for the wal backend
/// (the `routed_zone_id` SSOT), so a `/agents=<zone>` federation mount lands
/// the stream in `<zone>` without the caller naming it.
///
/// Generic over [`KernelSyscall`] (not `&Kernel`) so the services rlib can call
/// it without monomorphising against a concrete kernel.
pub fn ensure_mailbox_stream<K: KernelSyscall>(kernel: &K, path: &str) -> Result<(), String> {
    kernel
        .sys_setattr(
            path,
            i32::from(DT_STREAM),
            /* backend_name */ "",
            /* backend */ None,
            /* metastore */ None,
            /* raft_backend */ None,
            MAILBOX_IO_PROFILE,
            /* zone_id */ contracts::ROOT_ZONE_ID,
            /* is_external */ false,
            MAILBOX_STREAM_CAPACITY,
            /* read_fd */ None,
            /* write_fd */ None,
            /* mime_type */ None,
            /* modified_at_ms */ None,
            /* content_id */ None,
            /* size */ None,
            /* version */ None,
            /* created_at_ms */ None,
            /* link_target */ None,
            /* source */ None,
            /* remote_metastore */ None,
        )
        .map(|_| ())
        .map_err(|e| {
            format!("ensure_mailbox_stream({path}) io_profile={MAILBOX_IO_PROFILE:?}: {e:?}")
        })
}

/// Arm the A2A `from`-stamp hook. Call once at daemon boot.
///
/// Enlists the `a2a` hook-only service and registers
/// [`MailboxStampingHook`] on it (the ServiceRegistry ownership path, so
/// the hook load/unloads with the service). Every `*/chat-with-me` write
/// then passes through it and the envelope `from` is rewritten to the
/// caller's `agent_id`.
///
/// `fail_closed` sets the identity-enforcement posture and MUST be derived
/// from the auth posture (true iff an auth provider is armed):
/// - `false` (NoAuth / trusted-local): an empty-`agent_id` write passes
///   through unstamped — behaviour-preserving for the current bring-up.
/// - `true` (auth armed): a mailbox write with no caller `agent_id` is
///   REJECTED, so `from` cannot be forged by an unauthenticated writer.
///   Meaningful only once auth populates `agent_id` — hence gated here,
///   not defaulted on.
///
/// Takes `&Kernel` (not `Arc`) because the hook captures no kernel
/// reference — it operates purely on the `HookContext` handed to it.
pub fn install_a2a_stamp_hook(kernel: &Kernel, fail_closed: bool) -> Result<(), String> {
    let handle = kernel.enlist_hook_only_service("a2a")?;
    kernel.register_service_hook(
        &handle,
        Box::new(MailboxStampingHook::new_fail_closed(fail_closed)),
    );
    Ok(())
}

/// The `a2a` service as a boot declaration for
/// [`kernel::kernel::Kernel::bring_up_services`] — the uniform path by
/// which the composition layer hands services to the kernel (instead of
/// boot code hand-calling installs). Thin wrapper over
/// [`install_a2a_stamp_hook`]; `fail_closed` is boot-derived (true iff an
/// auth provider is armed) and supplied by the composition from the boot
/// context.
pub fn service_decl(fail_closed: bool) -> kernel::kernel::ServiceDecl {
    kernel::kernel::ServiceDecl {
        name: "a2a".to_string(),
        install: Box::new(move |kernel| install_a2a_stamp_hook(kernel, fail_closed)),
    }
}
