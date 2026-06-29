//! Kernel-routing federation outcome types.
//!
//! The HAL trait [`crate::hal::distributed_coordinator::DistributedCoordinator`]
//! exposes per-syscall `peer_*` dispatch methods that return `Option<T>` or
//! `bool` — the trait answers "did the SSOT peer have it" given that
//! the caller has already decided this route IS a federation-peer-mount.
//!
//! Kernel routing layers (`RouteResult::supplement_*` /
//! `via_federation_*`) need ONE more state — "this route is not a
//! federation-peer-mount; the caller should fall through to its
//! local handling" — that the HAL trait does not model (and should
//! not model, because the routing decision is the kernel's, not the
//! coordinator impl's).  This module owns the wrapper types that add
//! that state on top of the HAL trait's return.
//!
//! `sys_read` / `sys_stat` / `sys_readdir` / `sys_unlink` collapse the
//! routing decision into `Option<T>` because their "miss" arm IS the
//! same shape as "not a federation route" (both fall through to
//! local-not-found semantics).  Only `sys_write` needs the explicit
//! three-state distinction encoded in [`FederationWriteOutcome`] —
//! federation-peer-mounts have no local backend to fall back on, so
//! the kernel cannot transparently treat "dispatch missed" as "fall
//! through to local".
//!
//! ## Where this file lives
//!
//! Federation is the §3.B.1 Control-Plane HAL abstraction; concrete
//! impl lives below the HAL boundary in the raft crate.  Kernel-side
//! wiring for the federation domain lives in `kernel/src/federation/`
//! (siblings: `coordinator_wiring`, `grpc_ops`, `blob_fetcher_slot`).
//! Per `docs/KERNEL-ARCHITECTURE.md` §3/§4, `kernel/src/core/` is
//! reserved for §4 kernel primitives (VFSRouter, LockManager,
//! KernelDispatch, …) — federation-domain types like this enum do
//! NOT belong there.

use crate::abc::object_store::WriteResult;

/// Outcome of dispatching a write to the federation SSOT peer.
///
/// Three states because federation-peer-mounts have no local backend
/// fallback — the syscall layer cannot transparently treat "dispatch
/// missed" as "fall through to local write".  Sister read / stat /
/// list_dir / unlink methods use `Option<T>` because their "miss"
/// arm IS the same shape as "not a federation route" (both fall
/// through to local-not-found semantics); only `write` needs the
/// three-state distinction.
///
/// The Hit variant carries the peer's canonical `(content_id, size)`
/// from `WriteResult` so the caller's OBSERVE event + native POST
/// hook fire with the SSOT-side authoritative values.
#[derive(Debug)]
pub enum FederationWriteOutcome {
    /// Route is not a federation-peer-mount.  Caller falls through
    /// to its normal local write path.
    NotPeer,
    /// Federation-peer-mount route, but dispatch missed (peer
    /// unreachable, coordinator without an installed grpc_ops,
    /// observability warns fire on the coordinator side).
    /// Caller MUST return a miss-shaped result WITHOUT attempting
    /// any local fallback — federation-peer-mounts have no local
    /// backend, and surfacing the failure as `KernelError::IOError`
    /// breaks the cc-tasks-share retry contract that legitimately
    /// expects `hit=false` on transient peer unreachability.
    DispatchMissed,
    /// Federation-peer-mount route + dispatch hit.  Caller
    /// short-circuits with `wr`.
    Hit(WriteResult),
}
