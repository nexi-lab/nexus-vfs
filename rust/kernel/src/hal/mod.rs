//! Kernel HAL — Control-Plane HAL §3.B (runtime DI surfaces).
//!
//! Companion to `crate::abc::*` (Storage HAL §3.A — the 3 ABC pillars).
//! Where `abc/` declares persistent-data driver contracts, `hal/`
//! declares runtime DI surfaces: capabilities the kernel needs but
//! does not own. Same DI shape across both members:
//!
//! * Trait declared here in the kernel crate.
//! * Concrete impl in the owner crate (raft, backends).
//! * `OnceLock` / `RwLock<Arc<dyn Trait>>` slot that the host binary
//!   wires at startup, before any syscall fires.
//!
//! Members:
//!
//! * [`distributed_coordinator`] — `DistributedCoordinator` trait
//!   (§3.B.1). Per-node distributed-namespace topology: zones, mounts,
//!   share registry, leader/voter introspection, per-zone metastore +
//!   locks, **and** per-syscall cross-node peer dispatch (`peer_read`,
//!   `peer_stat`, `peer_list_dir`, `peer_delete_file`, `peer_rmdir`,
//!   `peer_write`, `peer_mkdir`, `peer_rename`, `peer_setattr`).
//!   Concrete impl in `nexus_raft::distributed_coordinator`; the
//!   raft-tier impl holds an `Arc<dyn FederationGrpcOps>`
//!   (`kernel::federation::grpc_ops`) for the actual gRPC plumbing —
//!   that trait is an internal DI seam, not a kernel HAL.
//! * [`object_store_provider`] — `ObjectStoreProvider` trait (§3.B.2).
//!   Constructs `Arc<dyn ObjectStore>` for backend types
//!   (anthropic / openai / s3 / gcs / …) without the kernel naming
//!   `backends::*`. Concrete impl lives in the `backends` crate and
//!   is registered by the host binary at startup.
//! * [`peer`] — re-export of `lib::transport_primitives::PeerBlobClient`.
//!   The trait declaration lives in the tier-neutral `lib` crate's
//!   `transport_primitives` module so raft (server-side fetcher) and
//!   transport (client-side fetcher) reach it without depending on
//!   each other.
//!
//! ObjectStore extension hooks like [`crate::llm_streaming::LlmStreamingBackend`]
//! live at the kernel crate root, not under `hal/` — they extend a
//! §3.A storage pillar rather than declare a §3.B DI surface.
//!
//! ## What's intentionally **not** here
//!
//! The CAS primitives — `cas_engine`, `cas_chunking`, `cas_remote`
//! (incl. `RemoteChunkFetcher` + `GrpcChunkFetcher`), `cas_transport`
//! (`LocalCASTransport`) — stay in the kernel crate. Linux precedent:
//! the kernel-VFS-equivalent storage primitive (CAS engine for our
//! content-addressed pillar) belongs in the kernel; backends consume
//! it through `Arc<CASEngine>` to compose `ObjectStore` impls
//! (`CasLocalBackend` etc.). Moving the CAS primitives out would
//! require either a runtime-dispatched `CasOps` trait (perf hit on
//! the hot CAS read path) or an ABI-breaking move of the entire
//! `Kernel::cas_*` family — neither pays its way given the CAS
//! engine is conceptually a kernel primitive.
//!
//! Directory layout enforces the §3.A / §3.B split: `abc/` holds the
//! 3 §3.A pillar trait files, `hal/` holds the §3.B Control-Plane HAL
//! traits. Kernel primitives (§4) live in `kernel/src/core/` as
//! concrete types.

pub mod distributed_coordinator;
pub mod object_store_provider;

// `PeerBlobClient` lives in `lib::transport_primitives` — the
// tier-neutral transport-layer abstraction shared between the raft
// server-side fetcher and the transport-tier client-side fetcher.
// Re-exported here so `kernel::hal::peer::PeerBlobClient` callers
// keep their canonical import path.
pub mod peer {
    pub use lib::transport_primitives::{NoopPeerBlobClient, PeerBlobClient, PeerBlobResult};
}
