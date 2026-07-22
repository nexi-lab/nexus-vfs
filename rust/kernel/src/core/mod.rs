//! Kernel `core/` — kernel primitives only (§4 of
//! `docs/architecture/KERNEL-ARCHITECTURE.md`).
//!
//! Strict split inside `kernel/src/`:
//!
//! * `crate::abc::*` — §3.A Storage HAL pillars (`ObjectStore`,
//!   `MetaStore`, `CacheStore`).
//! * `crate::hal::*` — §3.B Control-Plane HAL DI surfaces
//!   (`DistributedCoordinator`, `ObjectStoreProvider`,
//!   `PeerBlobClient`).
//! * `crate::core::*` — §4 kernel primitives (this module): the runtime
//!   mechanisms the syscall layer needs (vfs_router, dlc, locks,
//!   dispatch, procfs, plus the in-memory reference impls of the §3.A
//!   pillars that are too small to justify their own crate). A primitive
//!   may declare the registration interface its own registry dispatches
//!   through — `NativeInterceptHook`, `MutationObserver`, `StreamBackend`,
//!   `ProcfsProvider`. What does NOT belong here is a §3 HAL surface:
//!   those are declared in `abc/` (§3.A pillars) and `hal/` (§3.B DI).
//!
//! The `lib.rs` crate root re-exposes the flat names
//! (`crate::vfs_router::*`, `crate::pipe::*`, `crate::stream::*`, …)
//! via `pub use core::… as <flat>` shims, so callers can name a single
//! canonical path regardless of the internal `core/` nesting.

// Agent table SSOT (§1 Service Lifecycle).
pub mod agents;

// VFS routing + DLC mount lifecycle.
pub mod dlc;
// Kernel-side metadata reconcile for out-of-band backends (armed by DLC
// when a mount opts in). Generic over ObjectStore so it works across the
// dylib C-ABI — see the module docs.
pub(crate) mod metadata_sync;
pub mod vfs_router;

// File-watch waiters + kernel-owned service registry.
pub mod file_watch;

/// Procfs registry — read-only `/__sys__/…` views over kernel-internal
/// primitives that deliberately are not files (locks, zones, credential
/// hashes). Linux `proc_create()`.
pub mod procfs;
pub mod service_registry;

// Unified locking — I/O lock + advisory lock (§4.1).
pub mod lock;

// VFS dispatch + hook/observer registry (§2.4).
pub mod dispatch;

// Permission lease cache moved to the `permission` rlib at the
// 2026-07-23 refactor — the cache is a *provider* implementation
// detail (used inside `permission::ZonePermsProvider`), not a
// kernel primitive.  The kernel now holds only the
// `Arc<dyn PermissionProvider>` slot and the two-line gate that
// delegates to it; see `kernel/dispatch.rs::check_permission`.

// MetaStore primitive impls — LocalMetaStore + remote proxy.
// The trait declaration lives in `crate::abc::meta_store` (§3.A.1);
// this module only holds the kernel-internal concrete impls.
pub mod meta_store;

// DT_PIPE / DT_STREAM IPC pillars (§4.2).
pub mod pipe;
pub mod stream;

// Content-addressable storage primitive — `CASEngine`, CDC chunking,
// scatter-gather remote fetcher, local blob transport (§4 CAS row).
pub mod cas;

// Out-bound VFS gRPC client — backs `RemoteMetaStore` and the
// `Remote{Pipe,Stream}Backend` wrappers in `core/meta_store/`,
// `core/pipe/`, `core/stream/`.
pub mod rpc_transport;

// Shared mmap header accessors used by both pipe/shm and stream/shm.
#[cfg(unix)]
pub(crate) mod shm_header;

// File-descriptor table — pre-opened fds for PAS fast-path reads
// (§4 PermissionGate row's FileDescriptorTable peer).
pub mod fdt;

// dylib plugin loader — moved to kernel/plugins/loader.rs (§10).
// `PluginLoader` is an implementation detail of kernel plugin management,
// not a shared core primitive.
