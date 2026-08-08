//! A2A cross-machine stream-wakeup — the apply-side observer that lets a
//! replicated `AppendStreamEntry` wake a reader parked on a replica.
//!
//! ## Why this exists
//!
//! A2A has TWO cross-machine wait primitives, and a parked reader on a
//! replica is woken by neither on its own:
//!
//! * **DT_STREAM tail (PRIMARY)** — `stream_read_at_blocking` →
//!   `StreamManager::read_at_blocking`, the primitive the A2A mailbox tail
//!   and hydra's `watch` use. It parks on the StreamManager per-path condvar,
//!   signalled only by the node-local write path (`write_nowait`).
//! * **`sys_watch` file-watch** — `FileWatchRegistry`, an inotify-style
//!   watcher that may be parked on the same mailbox path.
//!
//! On the node that runs the write, the local syscall path signals both
//! inline (the StreamManager condvar via `write_nowait`; the file-watch via
//! `dispatch_observers`). On a **replica** the local syscall path never ran
//! for that entry — the mutation arrived over the raft log and was
//! materialised by the apply loop into the durable WAL — so neither condvar
//! is signalled and a parked reader hangs until its long-poll times out.
//! This observer is the missing subscriber that closes that gap: it rides the
//! unified apply-observer spine (the same seam DCache invalidation,
//! federation-mount wiring, and auth-cache eviction subscribe to) and, for
//! every applied `AppendStreamEntry`, wakes BOTH primitives parked on the
//! entry's file path — `Kernel::wake_stream_waiters` (the DT_STREAM tail) and
//! `Kernel::wake_file_watch` (the `sys_watch` file-watch).
//!
//! ## Key format — why no per-zone `to_global`
//!
//! A wal DT_STREAM keys every raft entry
//! `/__wal_stream__/{path}/{seq}` (see `WalStreamCore::new`), where `{path}`
//! is the DT_STREAM's own path — exactly what a `sys_watch` is parked on,
//! and identical on every replica (the mount point is the same across zone
//! members). So the observer recovers the watch path with a fixed parse
//! ([`kernel::core::stream::wal::watch_path_from_wal_stream_key`], the SSOT
//! for the key format) — NOT a mount-point translation. `ZoneMetaStore`
//! deliberately does not zone-relative-translate stream keys, so there is
//! no zone-relative→global mapping to apply here.
//!
//! ## Raft usage contract (must hold 100%)
//!
//! The apply spine invokes registered observers AFTER the entry is durably
//! applied, under `catch_unwind`. This observer honours the contract:
//! * **side-effect only** — never mutates state-machine state, so apply
//!   stays deterministic across replicas;
//! * **non-blocking** — each wake is a single `condvar.notify` behind a
//!   `DashMap`/RwLock read;
//! * **cheap when idle** — a non-`AppendStreamEntry` command returns
//!   immediately; a non-stream (pipe) key parses to `None`; a wake with no
//!   parked reader is one lookup that finds nothing.
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
//! ## Scope
//!
//! The composition root arms this on every zone whose DT_STREAMs must wake
//! readers cross-machine — root plus each federation mount (a chat-with-me
//! in a shared `/agents` zone replicates across members, and this observer
//! wakes the peer's parked mailbox tail on apply).

use std::sync::{Arc, Weak};

use kernel::core::stream::wal::watch_path_from_wal_stream_key;
use kernel::kernel::Kernel;

use crate::prelude::{AppliedEntry, Command, FullStateMachine, ZoneConsensus};

/// Register the A2A stream-wakeup observer on `consensus`.
///
/// For every applied `AppendStreamEntry`, wakes BOTH cross-machine wait
/// primitives parked on the stream's file path — the DT_STREAM tail
/// (`Kernel::wake_stream_waiters`, the primitive the A2A mailbox tail uses)
/// and any `sys_watch` file-watcher (`Kernel::wake_file_watch`). The command
/// carries the stream PREFIX (`/__wal_stream__/<path>/`);
/// `watch_path_from_wal_stream_key` recovers the watched `<path>`. Non-stream
/// commands are ignored. See the module docs for the raft usage contract and
/// why the kernel is held weakly.
///
/// Anonymous registration (accumulate): one observer per zone consensus is
/// correct, matching the DCache-invalidator precedent. A distinct zone has
/// a distinct consensus and state machine, so there is nothing to dedup
/// against within a single consensus's lifetime.
pub fn install_stream_wakeup_observer(
    consensus: &ZoneConsensus<FullStateMachine>,
    kernel: Weak<Kernel>,
) {
    consensus.register_apply_observer(Arc::new(move |entry: &AppliedEntry| {
        if let Command::AppendStreamEntry { stream_prefix, .. } = &entry.command {
            if let Some(path) = watch_path_from_wal_stream_key(stream_prefix) {
                if let Some(kernel) = kernel.upgrade() {
                    // Wake BOTH cross-machine wait primitives parked on this
                    // path. The A2A mailbox tail (`stream_read_at_blocking`,
                    // used by hydra `watch` and every DT_STREAM follower) parks
                    // on the StreamManager per-path condvar — the PRIMARY
                    // primitive, and the one a replica apply otherwise never
                    // signals. A `sys_watch` file-watcher on the same path
                    // parks on the `FileWatchRegistry` instead; wake it too so
                    // an inotify-style watcher on the mailbox path also fires.
                    kernel.wake_stream_waiters(path);
                    kernel.wake_file_watch(path);
                }
            }
        }
    }));
}
