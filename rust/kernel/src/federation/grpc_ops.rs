//! Internal DI seam — `FederationGrpcOps` trait.
//!
//! NOT a kernel HAL surface (not in `crate::hal::`).  This trait is
//! the wire-shape contract for the per-peer gRPC calls that back the
//! `DistributedCoordinator::peer_*` methods.  Two roles:
//!
//! * **Producer** — `transport::FederationClient` implements it
//!   (each method is a tonic `NexusVFSService.*` call against a
//!   per-peer Channel).
//! * **Consumer** — `RaftDistributedCoordinator` holds an
//!   `Arc<dyn FederationGrpcOps>` it receives via constructor DI;
//!   its `peer_*` impls iterate `zone_peers` and dispatch each
//!   non-self peer through this trait.
//!
//! Kernel-side callers (syscall sites in `kernel/io.rs` /
//! `kernel/mod.rs`) NEVER name this trait — they reach the SSOT
//! peer through `kernel.distributed_coordinator().peer_*(...)`
//! (the only federation HAL).  This file lives in `federation/`,
//! not `hal/`, to signal that distinction.
//!
//! ## Crate-dep layering
//!
//! `kernel` is the base crate; `transport` and `raft` depend on it.
//! Defining the trait here lets both `RaftDistributedCoordinator`
//! (in raft) and `FederationClient` (in transport) reference the
//! same type without either crate depending on the other — exactly
//! the constraint the user enforced when we collapsed
//! `FederationPeerClient` into `DistributedCoordinator`.

use crate::abc::object_store::BackendStat;

/// Result type for per-peer gRPC RPCs.  String errors carry the
/// underlying tonic status / timeout message verbatim so the
/// coordinator's iteration loop can log them at warn-level when
/// every voter fails (the PR #94 observability path).
pub type FederationPeerResult<T> = Result<T, String>;

/// Per-peer typed VFS RPC surface — one address per call.
///
/// `Send + Sync` so `Arc<dyn FederationGrpcOps>` can travel through
/// the raft coordinator's async tasks and the kernel's tokio worker
/// pool without per-call cloning.
///
/// `pub(crate)` until [`Kernel`] gains a non-test reason to expose
/// it — kept private right now because callers in raft + transport
/// reach it via the published [`crate::federation::grpc_ops`] path
/// regardless of visibility.
pub trait FederationGrpcOps: Send + Sync {
    /// Fetch file bytes via `NexusVFSService.Read`.
    fn read(&self, addr: &str, path: &str, offset: u64) -> FederationPeerResult<Vec<u8>>;

    // `write` removed under the uniform local-first sys_write contract
    // (PR #98).  Every voter writes through its own kernel-global
    // federation-cache backend; cross-peer reads use `read` on the
    // writer's address (resolved via `FileMetadata.last_writer_address`).
    // No syscall site dispatches a write to a peer anymore.

    /// Stat one path via `NexusVFSService.Stat`.  Returns `Ok(None)`
    /// when the peer reports the path is not found (in-band
    /// `found = false`); transport errors surface as `Err`.
    fn stat(&self, addr: &str, path: &str) -> FederationPeerResult<Option<BackendStat>>;

    /// List immediate children via `NexusVFSService.Readdir`.  Each
    /// child is `(name, entry_type)`; names are bare filenames.
    fn list_dir(&self, addr: &str, path: &str) -> FederationPeerResult<Vec<(String, u8)>>;

    /// Delete a regular file via `NexusVFSService.Delete`.
    fn delete_file(&self, addr: &str, path: &str) -> FederationPeerResult<()>;

    /// Remove a directory via `NexusVFSService.Delete` with the
    /// `recursive` bit set per `DRIVER_RMDIR` ABI v5.
    fn rmdir(&self, addr: &str, path: &str, recursive: bool) -> FederationPeerResult<()>;

    /// Create a directory via `NexusVFSService.Mkdir`.
    fn mkdir(
        &self,
        addr: &str,
        path: &str,
        parents: bool,
        exist_ok: bool,
    ) -> FederationPeerResult<()>;

    /// Rename a file or directory via `NexusVFSService.Rename`.
    fn rename(&self, addr: &str, old_path: &str, new_path: &str) -> FederationPeerResult<()>;

    /// Update DT_REG metadata via `NexusVFSService.Setattr`.
    /// Restricted to DT_REG; other entry types are node-local.
    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        addr: &str,
        path: &str,
        mime_type: Option<&str>,
        content_id: Option<&str>,
        modified_at_ms: Option<i64>,
        created_at_ms: Option<i64>,
        size: Option<u64>,
        version: Option<u32>,
    ) -> FederationPeerResult<()>;
}
