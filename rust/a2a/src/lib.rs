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
//! a replicated `AppendStreamEntry` wakes a `sys_watch` parked on a
//! replica). It is NOT a2a-specific — A2A's `chat-with-me` DT_STREAM
//! merely rides it — so it is armed per-zone by the composition root
//! (which holds the `Arc<Kernel>` the observer needs a `Weak` of, and the
//! federation-mount config that maps each zone's key to its caller-facing
//! path). Keeping it out of a2a leaves this crate a pure post-syscall
//! hook substrate (kernel + contracts + serde_json only — no raft).
//!
//! # Frontends / consumers
//!
//! Frontends ride on the substrate rather than re-implementing it:
//! `matrix_adapter` (Matrix C-S → humans, nexus services tier),
//! `sudocode-host` (agent runtime → AI), and `managed_agent` (spawn/PCB
//! → process). A frontend consumes [`MailboxStampingHook`]; only the
//! daemon calls [`install_a2a_stamp_hook`].

pub mod mailbox_stamping_hook;
pub mod mailbox_stamping_policy;

pub use mailbox_stamping_hook::MailboxStampingHook;

use kernel::kernel::Kernel;

/// Arm the A2A `from`-stamp hook. Call once at daemon boot.
///
/// Enlists the `a2a` hook-only service and registers
/// [`MailboxStampingHook`] on it (the ServiceRegistry ownership path, so
/// the hook load/unloads with the service). Every `*/chat-with-me` write
/// then passes through it and the envelope `from` is rewritten to the
/// caller's `agent_id`. Behaviour-preserving under NoAuth: an empty
/// `agent_id` makes the policy return `None`, so nothing is rewritten.
///
/// Takes `&Kernel` (not `Arc`) because the hook captures no kernel
/// reference — it operates purely on the `HookContext` handed to it.
pub fn install_a2a_stamp_hook(kernel: &Kernel) -> Result<(), String> {
    let handle = kernel.enlist_hook_only_service("a2a")?;
    kernel.register_service_hook(&handle, Box::new(MailboxStampingHook::new()));
    Ok(())
}
