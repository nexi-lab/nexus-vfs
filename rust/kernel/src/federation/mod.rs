//! Federation domain — kernel-side wiring for the
//! `DistributedCoordinator` §3.B.1 HAL surface plus the
//! `FederationGrpcOps` internal DI trait that backs cross-node typed
//! RPC dispatch.
//!
//! Promoted from `kernel/src/kernel/federation.rs` to a top-level
//! sibling of `hal/`, `abc/`, `core/`, `kernel/` because the file was
//! always a *domain* (federation), not a per-syscall family submodule
//! of `kernel/`.  The name `federation.rs` nested under `kernel/`
//! falsely suggested the federation IMPL lived here — the actual
//! impls live in `rust/raft/` (`RaftDistributedCoordinator`) and
//! `rust/transport/` (`FederationClient`).  This module owns:
//!
//! * **§3.B.1 `DistributedCoordinator` wiring** ([`coordinator_wiring`]) —
//!   slot accessors plus `/__sys__/zones/` procfs synthesisers.
//!   Cross-node typed-RPC dispatch (`peer_read` / `peer_stat` /
//!   `peer_list_dir` / `peer_delete_file` / `peer_rmdir` /
//!   `peer_write` / `peer_mkdir` / `peer_rename` / `peer_setattr`)
//!   is part of this trait; the iteration loop + PR #94 silent-miss
//!   observability lives in the raft-tier impl.
//! * **[`grpc_ops`] DI seam** — `FederationGrpcOps` trait that the
//!   raft-tier coordinator consumes and the transport-tier
//!   `FederationClient` produces.  Lives here (not in `hal/`)
//!   because it is an internal DI boundary, not a kernel HAL —
//!   kernel callers reach federation peers only through
//!   `kernel.distributed_coordinator().peer_*(...)`.
//! * **Blob-fetcher slot plumbing** ([`blob_fetcher_slot`]) — boot-time
//!   stash for the raft-tier handler to drain.
//!
//! Syscall sites in `kernel/io.rs` / `kernel/mod.rs` reach federation
//! peers through `RouteResult::supplement_*` / `via_federation_*`
//! behavior methods (in `core/vfs_router.rs`) rather than naming the
//! coordinator directly — the `is_federation_peer_mount()` predicate
//! is encapsulated inside those methods.

mod blob_fetcher_slot;
mod coordinator_wiring;
pub mod grpc_ops;
