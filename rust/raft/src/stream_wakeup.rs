//! Wake stream readers after a Raft append has been applied.
//!
//! The consensus supplies the owning zone; the WAL key supplies the path
//! within it. Kernel routing may expose that resource through different
//! mounts on different nodes, but its notification identity stays the same.
//!
//! The apply callback only notifies in-memory waiters. It never reads the
//! metastore, proposes a command, performs I/O or holds a strong Kernel
//! reference. In particular, resolving mounts through metadata here would
//! re-enter the state-machine lock already held by apply.

use std::sync::{Arc, Weak};

use kernel::core::stream::wal::watch_path_from_wal_stream_key;
use kernel::kernel::Kernel;

use crate::prelude::{AppliedEntry, Command, FullStateMachine, ZoneConsensus};

/// Install one keyed observer per zone consensus. Reinstallation replaces
/// the observer; different zones have independent consensus instances.
pub fn install_stream_wakeup_observer(
    consensus: &ZoneConsensus<FullStateMachine>,
    kernel: Weak<Kernel>,
    zone_id: &str,
) {
    let zone_id = zone_id.to_owned();
    // Keyed: arming is now driven by zone materialization, which can also
    // re-fire for a zone that boot already armed, and an accumulating observer
    // would notify the same waiter once per install.
    consensus.register_keyed_apply_observer(
        "a2a_stream_wakeup",
        Arc::new(move |entry: &AppliedEntry| {
            if let Command::AppendStreamEntry { stream_prefix, .. } = &entry.command {
                if let Some(path) = watch_path_from_wal_stream_key(stream_prefix) {
                    if let Some(kernel) = kernel.upgrade() {
                        kernel.wake_stream_waiters_in_zone(path, &zone_id);
                        kernel.wake_file_watch(path);
                    }
                }
            }
        }),
    );
}
