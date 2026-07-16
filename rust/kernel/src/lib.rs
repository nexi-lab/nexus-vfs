#![allow(clippy::useless_conversion)]

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Canonical root zone identifier — re-exported from the ``contracts``
/// crate (the Rust mirror of ``nexus.contracts.constants``) so kernel
/// users can reach it via ``kernel::ROOT_ZONE_ID`` without pulling
/// another workspace dep. Prefer this constant over hardcoded ``"root"``
/// literals.
pub use contracts::ROOT_ZONE_ID;

// ── §3 / §4 / HAL surface ────────────────────────────────────────────
// Four tier-directories inside the kernel crate (see
// `docs/architecture/KERNEL-ARCHITECTURE.md` §3 / §4 / §6.1):
//   * `crate::abc`        — §3.A Storage HAL pillars (ObjectStore /
//                           MetaStore / CacheStore). Mandatory trait
//                           declarations, one file each.
//   * `crate::extensions` — §3.A.2 opt-in ObjectStore extension traits
//                           (LlmStreamingBackend), each reached via an
//                           ObjectStore::as_*() downcast. Declarations
//                           only. (Note: capabilities that must cross
//                           the dylib C-ABI cannot be as_*() downcasts —
//                           e.g. metadata_sync is a core/ primitive.)
//   * `crate::hal`        — §3.B Control-Plane HAL DI surfaces
//                           (DistributedCoordinator, ObjectStoreProvider).
//   * `crate::core`       — §4 kernel primitives (vfs_router, dlc,
//                           locks, dispatch, in-memory reference impls
//                           of the §3.A pillars).
pub mod abc;
pub mod auth;
pub mod core;
pub mod extensions;
pub mod federation;
pub mod hal;

// ── Flat re-exports of `core::*` ─────────────────────────────────────
pub(crate) use core::dispatch;
pub(crate) use core::dlc;
pub(crate) use core::file_watch;

// Types needed by peer crates (services, transport) and integration
// tests to implement / register NativeInterceptHook / MutationObserver
// without reaching into the `pub(crate)` dispatch flat alias.
pub use core::dispatch::{
    DeleteHookCtx, FileEvent, FileEventType, HookContext, HookIdentity, HookOutcome,
    MutationObserver, NativeInterceptHook, ReadHookCtx, RenameHookCtx, WriteHookCtx,
};
pub use core::lock as lock_manager;
pub use core::lock::locks;
pub use core::meta_store;
pub(crate) use core::pipe;
pub(crate) use core::pipe::manager as pipe_manager;
pub use core::vfs_router;

// `acp` and `managed_agent` modules used to live here; both moved to
// the `services` crate (`rust/services/src/{acp,managed_agent}/`) so
// the kernel↔services dep direction stays one-way (services depends
// on kernel, never the reverse).

pub(crate) use core::fdt;
#[cfg(unix)]
pub(crate) use core::pipe::shm as shm_pipe;
#[cfg(unix)]
pub(crate) use core::pipe::stdio as stdio_pipe;
pub use core::service_registry;
pub use core::stream;
pub use core::stream::manager as stream_manager;
#[cfg(unix)]
pub(crate) use core::stream::shm as shm_stream;

// ── Kernel-owned primitives ──────────────────────────────────────────
// CAS (content-addressed storage) — the kernel's storage primitive
// (Linux-VFS analogue). Implementation lives in `core::cas/` per §4;
// re-exported under the historical `kernel::cas_*` flat names so
// `backends::storage::cas_local` (and other external consumers) keep
// their existing import paths. See
// `docs/architecture/KERNEL-ARCHITECTURE.md` §4 for the rationale.
pub use core::cas::chunking as cas_chunking;
pub use core::cas::engine as cas_engine;
pub use core::cas::remote as cas_remote;
pub use core::cas::transport as cas_transport;

// Kernel struct + syscalls.  `pub` so peer crates (`services`,
// `transport`, `backends`) hold `&kernel::Kernel` and call the
// in-tree Rust API directly (`register_native_hook`,
// `prepare_audit_stream`, `sys_*`).
pub mod kernel;

// `KernelSyscall` trait — generic-over-K syscall surface that every
// Rust service uses to reach the kernel. `impl KernelSyscall for Kernel`
// is a pure forwarder; production binaries monomorphise `K = Kernel`
// at link time so service code paths inline back to direct inherent
// calls (no vtable, no perf cost vs holding `Arc<Kernel>` directly).
//
// The trait definition lives in `kernel::kernel::syscall` (moved from
// the old top-level `kernel::abi`). The `abi` module below is a
// backward-compat re-export so downstream crates that import
// `kernel::abi::KernelAbi` continue to compile without changes.
pub mod abi {
    pub use crate::kernel::syscall::KernelSyscall;
    /// Backward-compat re-export — downstream code importing
    /// `kernel::abi::KernelAbi` keeps compiling while migrating to
    /// `KernelSyscall`.
    pub use crate::kernel::syscall::KernelSyscall as KernelAbi;
}

// kernel↔raft Cargo edge direction: `raft → kernel`. Raft state-machine
// impls (zone_meta_store) and the
// `RaftDistributedCoordinator` trait impl live in the raft crate.
// Kernel reaches them through the
// `kernel::hal::distributed_coordinator::DistributedCoordinator`
// trait dispatch installed by the binary boot path.

// Client-side RPC transport for `RemoteBackend` (the
// `backends::storage::remote::RemoteBackend` ObjectStore impl that
// proxies all syscalls over gRPC to a remote `nexusd`). Implementation
// lives in `core::rpc_transport` per §4 alongside the kernel-internal
// `RemoteMetaStore` / `Remote{Pipe,Stream}Backend` wrappers that wrap
// it; re-exported here under the historical flat name so peer crates
// (`transport`, `backends`) keep their existing import paths.
pub use core::rpc_transport;
