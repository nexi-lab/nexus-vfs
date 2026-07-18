//! Boot wiring for the A2A messaging substrate (the `install` feature).
//!
//! Kept in a feature-gated module so the raft dependency it needs — for
//! `ZoneConsensus` and the stream-wakeup observer — is pulled in ONLY by
//! the profile binaries that arm the substrate at boot. Consumers that
//! use just [`crate::MailboxStampingHook`] leave the feature off and
//! never link raft.

use std::sync::Arc;

use kernel::kernel::Kernel;
use nexus_raft::prelude::{FullStateMachine, ZoneConsensus};
use nexus_raft::stream_wakeup::install_stream_wakeup_observer;

use crate::MailboxStampingHook;

/// Arm the A2A messaging substrate on `root_consensus`. Call once at
/// cluster boot, after the root zone is open.
///
/// Two effects:
///
/// 1. **Unforgeable `from`.** Registers [`MailboxStampingHook`] on the
///    `a2a` hook-only service (the ServiceRegistry ownership path, so
///    the hook load/unloads with the service). Every `*/chat-with-me`
///    write then passes through it and the envelope `from` is rewritten
///    to the caller's `agent_id`. Behaviour-preserving under NoAuth: an
///    empty `agent_id` makes the policy return `None`, so nothing is
///    rewritten. This is the FIRST boot-enlisted service — it
///    establishes the pattern.
///
/// 2. **Cross-machine delivery wake.** Registers the §A stream-wakeup
///    observer so a replicated `AppendStreamEntry` wakes a `sys_watch`
///    parked on this replica. The kernel is captured weakly to avoid a
///    reference cycle (kernel → coordinator → zone → consensus → state
///    machine → observer would otherwise leak the kernel for the process
///    lifetime).
///
/// Wired on the ROOT zone consensus, whose mount point is `/`, so the
/// zone-relative stream key already IS the caller-facing path and the
/// `to_global` translation is the identity. §F arms additional zones
/// from the zone-open path with their real mount-point mappings
/// (mirroring `ZoneMetaStore::to_global_path`).
pub fn install_a2a(
    kernel: &Arc<Kernel>,
    root_consensus: &ZoneConsensus<FullStateMachine>,
) -> Result<(), String> {
    let handle = kernel.enlist_hook_only_service("a2a")?;
    kernel.register_service_hook(&handle, Box::new(MailboxStampingHook::new()));

    install_stream_wakeup_observer(
        root_consensus,
        Arc::downgrade(kernel),
        // Root zone mounts at `/`; the zone-relative key equals the
        // caller-facing path, so translation is the identity here.
        |key: &str| key.to_string(),
    );
    Ok(())
}
