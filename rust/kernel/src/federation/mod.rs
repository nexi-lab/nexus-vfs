//! Federation domain — kernel-side wiring + consumer dispatch for the
//! `DistributedCoordinator` and `FederationPeerClient` §3.B HAL surfaces.
//!
//! Promoted from `kernel/src/kernel/federation.rs` to a top-level
//! sibling of `hal/`, `abc/`, `core/`, `kernel/` because the file was
//! always a *domain* (federation), not a per-syscall family submodule
//! of `kernel/`.  The name `federation.rs` nested under `kernel/`
//! falsely suggested the federation IMPL lived here — the actual
//! impls live in `rust/raft/` (`RaftDistributedCoordinator`) and
//! `rust/transport/` (`FederationClient`).  This module owns ONLY the
//! kernel-side concerns:
//!
//! * **§3.B.1 `DistributedCoordinator` wiring** ([`coordinator_wiring`]) —
//!   slot accessors plus `/__sys__/zones/` procfs synthesisers.
//! * **§3.B.X `FederationPeerClient` wiring** ([`peer_dispatch`]) — slot
//!   accessors, the generic `dispatch_federation_peer` convention, and
//!   per-syscall thin wrappers (`federation_peer_readdir` / `_stat` /
//!   `_write` / `_delete_file` / `_mkdir` / `_rename` / `_setattr`).
//! * **Blob-fetcher slot plumbing** ([`blob_fetcher_slot`]) — boot-time
//!   stash for the raft-tier handler to drain.
//!
//! All methods stay members of [`crate::kernel::Kernel`] via
//! `impl Kernel { ... }` blocks — the file split is a code-organization
//! change, not an API change.  Per-syscall short-circuits in
//! `kernel/src/kernel/io.rs` / `mod.rs` continue to call the same
//! `Kernel::federation_peer_X` method names.

mod blob_fetcher_slot;
mod coordinator_wiring;
mod peer_dispatch;
