//! A2A cross-machine stream-wakeup — the apply-side observer that lets a
//! replicated `AppendStreamEntry` wake a `sys_watch` parked on a replica.
//!
//! ## Why this exists
//!
//! A2A's cross-machine interrupt primitive is `sys_watch` /
//! `FileWatchRegistry`, not the node-local `StreamManager` condvar. On the
//! node that runs the write, `Kernel::dispatch_observers` already fires the
//! watcher inline. On a **replica** the local syscall path never ran for
//! that entry — the mutation arrived over the raft log and was materialised
//! by the apply loop — so nothing wakes a parked watcher. This observer is
//! the missing subscriber that closes that gap: it rides the unified
//! apply-observer spine (the same seam DCache invalidation, federation-mount
//! wiring, and auth-cache eviction subscribe to) and, for every applied
//! `AppendStreamEntry`, calls `Kernel::wake_file_watch` for the entry's
//! caller-facing path.
//!
//! ## Raft usage contract (must hold 100%)
//!
//! The apply spine invokes registered observers AFTER the entry is durably
//! applied, under `catch_unwind`. This observer honours the contract:
//! * **side-effect only** — never mutates state-machine state, so apply
//!   stays deterministic across replicas;
//! * **non-blocking** — `wake_file_watch` is a single `condvar.notify_one`
//!   behind an RwLock read;
//! * **cheap when idle** — a non-`AppendStreamEntry` command returns
//!   immediately, and a wake with no matching watcher is one RwLock read
//!   plus an iterator filter.
//!
//! ## Ownership
//!
//! The kernel is captured as a `Weak` on purpose. In production the kernel
//! transitively owns the consensus (kernel → coordinator → zone → consensus
//! → state machine → this observer), so capturing an `Arc` would form a
//! reference cycle and leak the kernel for the process lifetime. The `Weak`
//! upgrade also makes the observer a no-op once the kernel is torn down,
//! which is the correct behaviour during shutdown.
//!
//! ## Scope (§A vs §F)
//!
//! This is the reusable trigger seam. §F arms it per zone from the
//! zone-open path, supplying a `to_global` that maps the zone-relative
//! stream key to the mailbox path convention it owns (mirroring
//! `ZoneMetaStore::to_global_path`). §A only validates the mechanism, so
//! its test passes an identity translation.

use std::sync::{Arc, Weak};

use kernel::kernel::Kernel;

use crate::prelude::{AppliedEntry, Command, FullStateMachine, ZoneConsensus};

/// Register the A2A stream-wakeup observer on `consensus`.
///
/// For every applied `AppendStreamEntry`, wakes any `sys_watch` parked on
/// `to_global(key)` via `Kernel::wake_file_watch`. All other commands are
/// ignored. See the module docs for the raft usage contract and the reason
/// the kernel is held weakly.
///
/// Anonymous registration (accumulate): one observer per zone consensus is
/// correct, matching the DCache-invalidator precedent. A distinct zone has
/// a distinct consensus and state machine, so there is nothing to dedup
/// against within a single consensus's lifetime.
pub fn install_stream_wakeup_observer<F>(
    consensus: &ZoneConsensus<FullStateMachine>,
    kernel: Weak<Kernel>,
    to_global: F,
) where
    F: Fn(&str) -> String + Send + Sync + 'static,
{
    consensus.register_apply_observer(Arc::new(move |entry: &AppliedEntry| {
        if let Command::AppendStreamEntry { key, .. } = entry.command {
            if let Some(kernel) = kernel.upgrade() {
                kernel.wake_file_watch(&to_global(key));
            }
        }
    }));
}
