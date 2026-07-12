//! Kernel ABC pillars — the canonical "Linux `struct file_operations`"
//! analogues from `docs/architecture/KERNEL-ARCHITECTURE.md` §3.
//!
//! Strict split: this directory holds **only** the §3.A pillar
//! trait declarations that any compliant driver impl must satisfy.
//! §3.B Control-Plane HAL DI surfaces (`DistributedCoordinator`,
//! `ObjectStoreProvider`) live in `crate::hal::*`. Opt-in ObjectStore
//! extension traits (`LlmStreamingBackend`, `ObserverBackend`) live in
//! `crate::extensions::*` — they extend a §3.A pillar through an
//! `ObjectStore::as_*()` downcast rather than being one of the
//! mandatory pillars every backend implements. Peer-blob fetch
//! (`crate::hal::peer::PeerBlobClient`) is a transport-layer
//! abstraction reached through the kernel's peer_client slot. Kernel
//! primitives (vfs_router, dlc, dcache, locks, dispatch, procfs, …) live
//! in `crate::core::*`; the traits they declare are the registration
//! interfaces their own registries dispatch through
//! (`NativeInterceptHook`, `ProcfsProvider`, …), never a §3 HAL surface.
//!
//! The three pillars — `ObjectStore`, `MetaStore`, `CacheStore` — are
//! co-equal: each is its own trait file and travels with its associated
//! error / result types so dependent crates can import a pillar with a
//! single `use` line. Concrete impls live in their respective parallel
//! crate (`backends/` for object stores, kernel-internal for the
//! in-memory reference metastore, …).
//!
//! Doc invariant — anything inside `abc/` is one of the three §3
//! mandatory storage pillars; nothing else qualifies. Opt-in pillar
//! extensions belong in `crate::extensions/`.

pub mod cache_store;
pub mod meta_store;
pub mod object_store;
