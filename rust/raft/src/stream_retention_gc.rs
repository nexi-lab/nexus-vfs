//! DT_STREAM retention GC — the apply-side observer that reclaims a trimmed
//! stream's cold-segment blobs (P3 of the unbounded DT_STREAM).
//!
//! ## Why this exists
//!
//! A wal DT_STREAM created with a non-zero retention budget trims its oldest
//! cold segments once the sealed cold storage exceeds the budget. Trimming is
//! a replicated `TrimStreamSegment` raft command: it drops the segment INDEX
//! entries and advances `earliest` deterministically on every replica — but it
//! deliberately does NOT delete the segment BLOBS. A blob's bytes are
//! path/content-addressed storage that physically lives on the node that
//! sealed it (its `origin`), so only that node can reclaim the space. This
//! observer is the subscriber that, on every node, deletes the trimmed blobs
//! THIS node owns.
//!
//! ## Why an apply-observer, not inline in the trimmer
//!
//! The trimmer (`WalStreamCore::maybe_trim`) runs on ONE node — the seal
//! thread that proposed the trim. Its peers never ran it, so an inline delete
//! there would reclaim only the proposer's blobs and orphan every other
//! origin's. Riding the apply spine instead fires the GC on EVERY replica as
//! the command applies, and the `origin == self` filter (in
//! `Kernel::gc_trimmed_cold_segments`) makes each node reclaim exactly its own
//! blobs — one delete per blob, cluster-wide, with no cross-node race. Single-
//! and multi-origin streams reclaim uniformly.
//!
//! ## Raft usage contract (must hold 100%)
//!
//! Same posture as `stream_wakeup`: the observer is a SIDE EFFECT only (never
//! mutates state-machine state, so apply stays deterministic across replicas)
//! and must not block the apply thread. Blob deletion is disk I/O, so — unlike
//! the per-append wakeup's cheap inline condvar notify — it is offloaded to
//! `runtime.spawn_blocking`. A non-`TrimStreamSegment` command returns
//! immediately; a trim with no own-origin blobs does no I/O.
//!
//! ## Ownership
//!
//! The kernel is captured `Weak` for the same reason as `stream_wakeup`:
//! production has kernel → coordinator → zone → consensus → state machine →
//! this observer, so an `Arc` would form a cycle and leak the kernel for the
//! process lifetime; the `Weak` upgrade also makes the GC a no-op during
//! shutdown.

use std::sync::{Arc, Weak};

use kernel::core::stream::wal::watch_path_from_wal_stream_key;
use kernel::kernel::Kernel;

use crate::prelude::{AppliedEntry, Command, FullStateMachine, ZoneConsensus};

/// Register the DT_STREAM retention-GC observer on `consensus`.
///
/// For every applied `TrimStreamSegment`, deletes — off the apply thread — the
/// trimmed segments' blobs this node sealed (`origin == self`). The command
/// carries the stream PREFIX (`/__wal_stream__/<path>/`) plus the dropped
/// blobs' `(origin, content_id)` refs; `watch_path_from_wal_stream_key`
/// recovers the `<path>` the kernel resolves the content backend for. Other
/// commands are ignored. See the module docs for the raft usage contract and
/// why the kernel is held weakly / the work is offloaded.
///
/// Anonymous registration (accumulate), matching `install_stream_wakeup_observer`:
/// one observer per zone consensus, each keying off the variants it cares about.
pub fn install_stream_trim_gc_observer(
    consensus: &ZoneConsensus<FullStateMachine>,
    kernel: Weak<Kernel>,
    runtime: tokio::runtime::Handle,
) {
    consensus.register_apply_observer(Arc::new(move |entry: &AppliedEntry| {
        let Command::TrimStreamSegment {
            stream_prefix,
            trimmed,
            ..
        } = &entry.command
        else {
            return;
        };
        let Some(path) = watch_path_from_wal_stream_key(stream_prefix) else {
            return;
        };
        let Some(kernel) = kernel.upgrade() else {
            return;
        };
        // Blob deletion is disk I/O — offload it so the apply thread (which
        // drives this observer synchronously) never blocks on a filesystem
        // unlink. A brief lag between the index trim and the blob reclaim is
        // fine: the index no longer references the blob, so a reader can never
        // reach it — this only reclaims the space.
        let path = path.to_string();
        let trimmed = trimmed.clone();
        runtime.spawn_blocking(move || {
            kernel.gc_trimmed_cold_segments(&path, &trimmed);
        });
    }));
}
