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

pub mod foreign_containment;
pub mod mailbox_stamping_hook;
pub mod mailbox_stamping_policy;

pub use foreign_containment::{install_foreign_agent_containment, ForeignAgentMailboxOnly};
pub use mailbox_stamping_hook::MailboxStampingHook;
pub use mailbox_stamping_policy::{
    agent_inbox_path, MailboxEnvelope, A2A_INBOX_BASE, CHAT_WITH_ME_SUFFIX, MAILBOX_IO_PROFILE,
    MAILBOX_STREAM_CAPACITY,
};

use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::Kernel;

/// DT_STREAM entry-type discriminant for `sys_setattr` (mirrors
/// `kernel::meta_store::DT_STREAM`, which is `u8`; the setattr arg is `i32`).
const DT_STREAM: i32 = 4;

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
            DT_STREAM,
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
