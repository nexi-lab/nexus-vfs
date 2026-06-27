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
//! * **§3.B.1 `DistributedCoordinator` wiring** — slot accessors
//!   + `/__sys__/zones/` procfs synthesisers
//!   ([`coordinator_wiring`]).
//! * **§3.B.X `FederationPeerClient` wiring** — slot accessors +
//!   generic [`dispatch_federation_peer`](peer_dispatch::Kernel::dispatch_federation_peer)
//!   convention + per-syscall thin wrappers (`federation_peer_readdir`
//!   / `_stat` / `_write` / `_delete_file` / `_mkdir` / `_rename` /
//!   `_setattr`) ([`peer_dispatch`]).
//! * **Blob-fetcher slot plumbing** — boot-time stash for the raft-tier
//!   handler to drain ([`blob_fetcher_slot`]).
//!
//! All methods stay members of [`crate::kernel::Kernel`] via
//! `impl Kernel { ... }` blocks — the file split is a code-organization
//! change, not an API change.  Per-syscall short-circuits in
//! `kernel/src/kernel/io.rs` / `mod.rs` continue to call the same
//! `Kernel::federation_peer_X` method names.

mod blob_fetcher_slot;
mod coordinator_wiring;
mod peer_dispatch;
