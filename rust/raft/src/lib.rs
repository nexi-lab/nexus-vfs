//! Nexus Raft: Embedded Storage and Consensus for Nexus
//!
//! This crate provides:
//!
//! 1. **Embedded Storage** ([`storage`]): General-purpose embedded KV database
//!    using redb (stable, pure Rust). Reusable for caching, queues, and more.
//!
//! 2. **State Machine** ([`raft`]): Metadata and lock operations with
//!    snapshot/restore support.
//!
//! 3. **Raft Consensus** (behind `consensus` flag): Distributed consensus using
//!    tikv/raft-rs. EXPERIMENTAL — not used in production.
//!
//! 4. **gRPC Transport** (behind `grpc` flag): Network transport for Raft
//!    messages. EXPERIMENTAL — not used in production.
//!
//! # Feature Flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `consensus` | off | Raft consensus via tikv/raft-rs (experimental) |
//! | `grpc` | off | gRPC transport for Raft messages (experimental) |
//! | `async` | off | Tokio async runtime |
//! | `full` | off | All features |
//!
//! # Quick Start
//!
//! ## Embedded Storage
//!
//! ```rust,ignore
//! use nexus_raft::storage::RedbStore;
//!
//! let store = RedbStore::open("/var/lib/nexus/data").unwrap();
//! let cache = store.tree("cache").unwrap();
//! cache.set(b"key", b"value").unwrap();
//! ```
//!
//! # Storage Backend
//!
//! Uses **redb** — stable, pure Rust embedded KV database.
//!
//! # Issue Reference
//!
//! Part of Issue #1159: P2P Federation and Consensus Zones

// The mimalloc `#[global_allocator]` lives in the final binary
// (nexus-cluster / nexusd / vault). An rlib cannot declare a global
// allocator — only the final binary can.

pub mod storage;

/// Raft consensus module for STRONG_HA zones.
///
/// Provides distributed consensus using tikv/raft-rs for linearizable
/// metadata and lock operations. Requires `consensus` feature for
/// full ZoneConsensus support (leader election, log replication).
pub mod raft;

/// Federation orchestration layer — cross-node zone share / join
/// flows and the TOFU peer-CA trust store. See [`federation`] for
/// the sub-module layout.
#[cfg(feature = "grpc")]
pub mod federation;

/// Pure-Rust zone handle — kernel-internal.
#[cfg(all(feature = "grpc", has_protos))]
pub mod zone_handle;

/// Pure-Rust zone manager — kernel-internal.
#[cfg(all(feature = "grpc", has_protos))]
pub mod zone_manager;

/// BlobFetcher trait — lets the raft gRPC server serve peer-facing
/// `ReadBlob` without depending on kernel types. The kernel crate
/// installs the impl at bootstrap. See [`blob_fetcher`] module.
#[cfg(all(feature = "grpc", has_protos))]
pub mod blob_fetcher;

#[cfg(all(feature = "grpc", has_protos))]
pub use zone_handle::{Consistency, ZoneHandle};

#[cfg(all(feature = "grpc", has_protos))]
pub use zone_manager::{
    join_cluster_and_provision_tls, ClusterStatus, TlsFiles, ZoneLoadPolicy, ZoneManager,
};

/// gRPC transport layer (requires `grpc` feature).
///
/// This module provides network transport for Raft messages using gRPC.
/// It is also reusable for webhook streaming and real-time events.
///
/// Enable with:
/// ```toml
/// [dependencies]
/// nexus_raft = { version = "0.1", features = ["grpc"] }
/// ```
#[cfg(feature = "grpc")]
pub mod transport;

// Driver-layer impls of kernel HAL surfaces:
//
//   distributed_coordinator.rs — `RaftDistributedCoordinator` impl of the
//                                Control-Plane HAL §3.B.1 trait
//   zone_meta_store.rs         — Raft-backed `kernel::abc::MetaStore` impl
//   auth_key_store.rs          — Raft-backed `kernel::hal::AuthKeyStore` impl
//   blob_fetcher_handler.rs    — `KernelBlobFetcher` server-side handler
//                                co-located with `ZoneApiService` on the
//                                raft port; reaches kernel data plane
//                                through `VFSRouter` + `DCache`
//
// Distributed state (`ZoneManager`, `ZoneRaftRegistry`, tokio runtime,
// cross-zone mounts reverse index) lives on the coordinator. WAL stream
// / pipe backends live in `kernel::core::stream::wal` / `kernel::core::pipe::wal`
// — kernel primitives that compose whatever distributed `MetaStore` impl
// the coordinator DI's (typically `ZoneMetaStore` below).
#[cfg(all(feature = "grpc", has_protos))]
pub mod auth_key_store;
#[cfg(all(feature = "grpc", has_protos))]
pub mod blob_fetcher_handler;
#[cfg(all(feature = "grpc", has_protos))]
pub mod distributed_coordinator;
// A2A cross-machine stream-wakeup: the apply-side observer that wakes a
// replica's parked `sys_watch` when a peer's `AppendStreamEntry` replicates
// in (§A). Bridges the raft apply spine to the kernel's file-watch wake.
#[cfg(all(feature = "grpc", has_protos))]
pub mod stream_wakeup;

/// Sync-façade → async-core bridge shared by every raft-backed store
/// that exposes a synchronous API over the async consensus core.
#[cfg(all(feature = "grpc", has_protos))]
pub(crate) mod runtime_bridge;

/// Node-bound peer address book persistence — `identity.json` at a
/// platform-native user-data location.  Survives `<NEXUS_DATA_DIR>`
/// wipes so cold-boot does not need operator re-specifying `--peers`.
/// Deliberately narrow: peer list only, no `node_id` (raft's
/// per-Progress heartbeat invariant requires wipe = id-rotation; see
/// `docs/federation-architecture.md` § 6.3.1).
#[cfg(all(feature = "grpc", has_protos))]
pub mod identity;

/// Boot-time federation-branch decision layer for the cluster binary
/// (S3 完全体 unified bring-up).  Pure decision function on a typed
/// [`bootstrap::BootConfig`] → [`bootstrap::BootAction`]; no env vars,
/// no I/O, no ZoneManager coupling.  See module docs for the full
/// matrix.
#[cfg(all(feature = "grpc", has_protos))]
pub mod bootstrap;
// WAL stream / pipe backends moved into the kernel crate
// (`kernel::core::stream::wal`, `kernel::core::pipe::wal`) — they
// are kernel primitives that compose whatever distributed `MetaStore`
// federation has DI'd (typically `ZoneMetaStore` below).  Raft no
// longer ships its own `WalConsensus` trait; the kernel-side
// `MetaStore::{append_stream_entry, get_stream_entry}` methods are
// the abstraction.
#[cfg(all(feature = "grpc", has_protos))]
pub mod zone_meta_store;

// Stub module when grpc feature is disabled
#[cfg(not(feature = "grpc"))]
pub mod transport {
    //! gRPC transport (requires `grpc` feature).
    //!
    //! Enable the `grpc` feature to use this module:
    //!
    //! ```toml
    //! [dependencies]
    //! nexus_raft = { version = "0.1", features = ["grpc"] }
    //! ```

    /// Transport error types.
    #[derive(Debug, thiserror::Error)]
    pub enum TransportError {
        /// gRPC feature not enabled.
        #[error("gRPC feature not enabled. Add `features = [\"grpc\"]` to Cargo.toml")]
        FeatureNotEnabled,
    }
}

/// Re-export commonly used types for convenience.
pub mod prelude {
    pub use crate::storage::{RedbBatch, RedbStore, RedbTree, RedbTreeBatch, StorageError};

    pub use crate::raft::{
        AppliedEntry, ApplyObserver, Command, CommandResult, FullStateMachine, HolderInfo,
        LockAcquireResult, LockEntry, LockInfo, LockState, RaftError, StateMachine,
        WitnessStateMachine,
    };

    #[cfg(feature = "consensus")]
    pub use crate::raft::{RaftConfig, RaftStorage, ZoneConsensus};

    #[cfg(all(feature = "grpc", has_protos))]
    pub use crate::transport::{
        ClientConfig, NodeAddress, RaftClient, RaftClientPool, RaftGrpcServer, ServerConfig,
        TransportError as GrpcError,
    };
}
