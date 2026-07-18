//! A2A messaging substrate — the kernel-tier capability that gives
//! agent-to-agent messaging an unforgeable `from` and a cross-machine
//! delivery wake.
//!
//! # Role in the tier map
//!
//! `a2a` is the messaging **substrate**, not a frontend. It owns the two
//! guarantees every mailbox writer must inherit, and arms them ONCE at
//! the daemon:
//!
//! * the **`from` identity guarantee** — [`MailboxStampingHook`] rewrites
//!   the envelope `from` to the caller's `agent_id` on every
//!   `*/chat-with-me` write, so a frontend cannot forge a sender;
//! * the **cross-machine wakeup** — a replicated `AppendStreamEntry`
//!   wakes a `sys_watch` parked on a replica (the §A stream-wakeup
//!   observer, armed by [`install_a2a`]).
//!
//! Frontends / consumers ride on this substrate rather than
//! re-implementing it: `matrix_adapter` (Matrix C-S protocol → humans,
//! nexus services tier), `sudocode-host` (agent runtime → AI), and
//! `managed_agent` (spawn/PCB → process). The `from` guarantee lives
//! here — not in a frontend — because it must hold for EVERY writer,
//! so it is enforced once at the substrate.
//!
//! # Crate footprint
//!
//! The core (hook + policy) depends only on `kernel` + `contracts` +
//! `serde_json`. The raft-backed boot wiring ([`install_a2a`]) is gated
//! behind the `install` feature so consumers that need only the stamp
//! hook never link raft — they reach raft through `kernel.sys_*` like
//! every other peer crate (`services ⊥ raft`, KERNEL-ARCHITECTURE §6.1).

pub mod mailbox_stamping_hook;
pub mod mailbox_stamping_policy;

pub use mailbox_stamping_hook::MailboxStampingHook;

#[cfg(feature = "install")]
mod install;
#[cfg(feature = "install")]
pub use install::install_a2a;
