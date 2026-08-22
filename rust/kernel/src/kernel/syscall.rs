//! Tier 1 CONTRACTS — implementations in `syscall_impl.rs`.
//!
//! `KernelSyscall` — the canonical Rust syscall surface that every
//! in-process Rust service uses to reach the kernel.
//!
//! All Rust services (in-tree `services::*` and any future
//! managed-agent runtime that lives alongside them) reach kernel
//! syscalls through `K: KernelSyscall` instead of holding a concrete
//! `Arc<Kernel>`. The same generic codepath compiles for production
//! (`K = Kernel`, monomorphised at link time → identical perf to a
//! direct inherent call) and for unit tests (`K = MockKernel`).
//!
//! Layered against KERNEL-ARCHITECTURE.html §6.1: the analogue of
//! Linux's `include/linux/` syscall ABI surface, lifted into Rust as
//! a single trait. The trait declaration lives in
//! `kernel::kernel::syscall` rather than in the `contracts` crate to
//! keep the kernel-internal result types (`SysReadResult`,
//! `KernelError`, …) on their existing module path.
//!
//! ## Surface scope
//!
//! Trait methods correspond to the inherent `Kernel::sys_*` syscalls.
//! Vectored syscalls (sys_read, sys_write, sys_unlink) expose
//! single-path convenience wrappers here; the inherent methods accept
//! `&[ReadRequest]` / `&[WriteRequest]` / `&[UnlinkRequest]` for
//! batch callers. No invented syscalls. No
//! kernel-internal struct accessors (`vfs_router_arc`,
//! `agent_registry`, `distributed_coordinator`, …); services that
//! need those reach them through the production-only
//! `impl ManagedAgentService<Kernel>` install paths or through
//! syscalls (a future `/__sys__/agents/{pid}/...` metadata-syscall
//! migration tracks the AgentRegistry case).
//!
//! Non-syscall surfaces live elsewhere: the install-time control
//! plane (`register_service_hook`, `enlist_hook_only_service`, …) stays
//! on the inherent `Kernel` impl, and federation-readiness is resolved
//! by the kernel itself inside `setattr_stream` (the `io_profile`
//! waterfall) rather than probed by services — neither belongs on this
//! Tier-1 syscall contract.

use std::sync::Arc;

use contracts::OperationContext;

use crate::core::dispatch::FileEvent;
use crate::kernel::{
    KernelError, StatResult, SysCopyResult, SysReadResult, SysRenameResult, SysSetAttrResult,
    SysUnlinkResult, SysWriteResult,
};

/// Options for [`KernelSyscall::sys_readdir`]. `Default` = single-level,
/// unbounded — the classic `readdir(3)` behaviour, so an unchanged caller
/// reads exactly as before.
///
/// `recursive` makes the ONE enumeration primitive list the whole subtree in
/// a single call (the metastore's native `list(prefix)` range-scan — one
/// ordered pass) instead of forcing a caller to compose N single-level calls
/// across the boundary. For a tree walk that is the difference between one
/// round-trip and O(directories); it is why `glob`/`grep` must ride this
/// syscall rather than client-side composition (see `docs/syscall-design.md`).
/// A separate `sys_glob` would overlap this same "enumerate namespace" axis,
/// so recursion is a mode of `sys_readdir`, not a new syscall.
///
/// NOTE (scope): recursion spans the routed zone's metastore namespace AND
/// descends across nested LOCAL mount boundaries (`sys_readdir` scans each
/// visible child mount too — a mount's metastore holds only its own entries).
/// Remaining follow-ups: recursive descent INTO a federation PEER mount stays
/// single-level (the peer probe is single-level by construction; a recursive
/// peer result would be mis-rebased one directory level per hop), deep
/// enumeration of connector-backed content is bounded by what the metastore has
/// seeded on-access, and `limit` truncates post-scan rather than bounding the
/// underlying scan.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReaddirOpts {
    /// List the whole subtree under `parent_path`, not just direct children.
    pub recursive: bool,
    /// Cap the number of returned entries (`None` = unbounded).
    pub limit: Option<usize>,
}

/// Canonical syscall surface that every Rust service uses to reach
/// the kernel.
///
/// Bounds: `Send + Sync + 'static` so consumers can pass `Arc<K>`
/// across thread boundaries (the managed-agent runtime spawns OS
/// threads that hold a kernel handle).
pub trait KernelSyscall: Send + Sync + 'static {
    // ── Syscalls (1:1 with inherent `Kernel::sys_*`) ────────────────

    fn sys_read(
        &self,
        path: &str,
        ctx: &OperationContext,
        timeout_ms: u64,
        offset: u64,
    ) -> Result<SysReadResult, KernelError>;

    fn sys_write(
        &self,
        path: &str,
        ctx: &OperationContext,
        content: &[u8],
        offset: u64,
    ) -> Result<SysWriteResult, KernelError>;

    fn sys_unlink(
        &self,
        path: &str,
        ctx: &OperationContext,
        recursive: bool,
    ) -> Result<SysUnlinkResult, KernelError>;

    /// Full inherent `sys_setattr` signature (21 params). Kernel-internal
    /// types (`Arc<dyn ObjectStore>`, `Arc<dyn MetaStore>`, `Box<dyn
    /// Any + Send + Sync>`) appear here because the trait lives in
    /// the kernel crate. Service callers that don't touch DT_MOUNT
    /// pass `""` / `None` for the mount-only params; production
    /// labelling (`/* backend */ None`, `/* metastore */ None`, …)
    /// keeps callsites readable.
    #[allow(clippy::too_many_arguments)]
    fn sys_setattr(
        &self,
        path: &str,
        entry_type: i32,
        backend_name: &str,
        backend: Option<Arc<dyn crate::abc::object_store::ObjectStore>>,
        metastore: Option<Arc<dyn crate::meta_store::MetaStore>>,
        raft_backend: Option<Box<dyn std::any::Any + Send + Sync>>,
        io_profile: &str,
        zone_id: &str,
        is_external: bool,
        capacity: usize,
        read_fd: Option<i32>,
        write_fd: Option<i32>,
        mime_type: Option<&str>,
        modified_at_ms: Option<i64>,
        content_id: Option<&str>,
        size: Option<u64>,
        version: Option<u32>,
        created_at_ms: Option<i64>,
        link_target: Option<&str>,
        source: Option<&str>,
        remote_metastore: Option<Arc<dyn crate::meta_store::MetaStore>>,
    ) -> Result<SysSetAttrResult, KernelError>;

    fn sys_stat(&self, path: &str, zone_id: &str) -> Option<StatResult>;

    fn sys_rename(
        &self,
        old_path: &str,
        new_path: &str,
        ctx: &OperationContext,
    ) -> Result<SysRenameResult, KernelError>;

    fn sys_copy(
        &self,
        src_path: &str,
        dst_path: &str,
        ctx: &OperationContext,
    ) -> Result<SysCopyResult, KernelError>;

    // ── Locks ────────────────────────────────────────────────────────

    /// Acquire or create a lock on `path`. Returns the lock_id on
    /// success (generated if `lock_id` is empty), or `None` if the lock
    /// could not be acquired (contention).
    ///
    /// `max_holders` parametrizes the lock shape: `1` is a mutex,
    /// `> 1` is a counting semaphore.
    fn sys_lock(
        &self,
        path: &str,
        lock_id: &str,
        max_holders: u32,
        ttl_secs: u64,
        holder_info: &str,
    ) -> Result<Option<String>, KernelError>;

    /// Release a lock. If `force` is true, unconditionally removes the
    /// lock regardless of holder identity. Returns true if the lock was
    /// actually released.
    fn sys_unlock(&self, path: &str, lock_id: &str, force: bool) -> Result<bool, KernelError>;

    /// Directory listing with metastore + backend merge. Returns
    /// Vec<(child_path, entry_type)>. Handles synthetic-view intercepts
    /// (e.g. `/__sys__/zones/`). `opts` selects single-level (default) vs a
    /// recursive whole-subtree scan and an optional entry cap — see
    /// [`ReaddirOpts`]; a traversal is one server-side call, never client-side
    /// composition of N single-level reads.
    fn sys_readdir(
        &self,
        parent_path: &str,
        zone_id: &str,
        is_admin: bool,
        opts: ReaddirOpts,
    ) -> Vec<(String, u8)>;

    // ── Event watch (inotify equivalent) ──────────────────────────

    /// Block until a file event matching `pattern` fires, or timeout.
    /// Returns `None` on timeout or when `timeout_ms == 0` (non-blocking
    /// try). Callers re-arm by calling again with a new `sys_watch`.
    ///
    /// Used by managed-agent runtimes to replace polling with
    /// event-driven blocking on `/proc/{pid}/chat-with-me` mailboxes.
    fn sys_watch(&self, pattern: &str, timeout_ms: u64) -> Option<FileEvent>;
}

// ── `impl KernelSyscall for Kernel` ──────────────────────────────────────
//
// Pure forwarder — every method delegates to the inherent fn of the
// same name on `Kernel`. Monomorphisation at the binary link site
// inlines through the trait dispatch back to the inherent call,
// recovering 100% of the direct-call perf.

impl KernelSyscall for crate::kernel::Kernel {
    fn sys_read(
        &self,
        path: &str,
        ctx: &OperationContext,
        timeout_ms: u64,
        offset: u64,
    ) -> Result<SysReadResult, KernelError> {
        self.sys_read_single(path, ctx, 1, timeout_ms, offset)
    }

    fn sys_write(
        &self,
        path: &str,
        ctx: &OperationContext,
        content: &[u8],
        offset: u64,
    ) -> Result<SysWriteResult, KernelError> {
        self.sys_write_with_link_depth(path, ctx, content, offset, 1)
    }

    fn sys_unlink(
        &self,
        path: &str,
        ctx: &OperationContext,
        recursive: bool,
    ) -> Result<SysUnlinkResult, KernelError> {
        self.sys_unlink_single(path, ctx, recursive)
    }

    fn sys_setattr(
        &self,
        path: &str,
        entry_type: i32,
        backend_name: &str,
        backend: Option<Arc<dyn crate::abc::object_store::ObjectStore>>,
        metastore: Option<Arc<dyn crate::meta_store::MetaStore>>,
        raft_backend: Option<Box<dyn std::any::Any + Send + Sync>>,
        io_profile: &str,
        zone_id: &str,
        is_external: bool,
        capacity: usize,
        read_fd: Option<i32>,
        write_fd: Option<i32>,
        mime_type: Option<&str>,
        modified_at_ms: Option<i64>,
        content_id: Option<&str>,
        size: Option<u64>,
        version: Option<u32>,
        created_at_ms: Option<i64>,
        link_target: Option<&str>,
        source: Option<&str>,
        remote_metastore: Option<Arc<dyn crate::meta_store::MetaStore>>,
    ) -> Result<SysSetAttrResult, KernelError> {
        Self::sys_setattr(
            self,
            path,
            entry_type,
            backend_name,
            backend,
            metastore,
            raft_backend,
            io_profile,
            zone_id,
            is_external,
            capacity,
            read_fd,
            write_fd,
            mime_type,
            modified_at_ms,
            content_id,
            size,
            version,
            created_at_ms,
            link_target,
            source,
            remote_metastore,
        )
    }

    fn sys_stat(&self, path: &str, zone_id: &str) -> Option<StatResult> {
        Self::sys_stat(self, path, zone_id)
    }

    fn sys_rename(
        &self,
        old_path: &str,
        new_path: &str,
        ctx: &OperationContext,
    ) -> Result<SysRenameResult, KernelError> {
        Self::sys_rename(self, old_path, new_path, ctx)
    }

    fn sys_copy(
        &self,
        src_path: &str,
        dst_path: &str,
        ctx: &OperationContext,
    ) -> Result<SysCopyResult, KernelError> {
        Self::sys_copy(self, src_path, dst_path, ctx)
    }

    fn sys_lock(
        &self,
        path: &str,
        lock_id: &str,
        max_holders: u32,
        ttl_secs: u64,
        holder_info: &str,
    ) -> Result<Option<String>, KernelError> {
        Self::sys_lock(self, path, lock_id, max_holders, ttl_secs, holder_info)
    }

    fn sys_unlock(&self, path: &str, lock_id: &str, force: bool) -> Result<bool, KernelError> {
        Self::sys_unlock(self, path, lock_id, force)
    }

    fn sys_readdir(
        &self,
        parent_path: &str,
        zone_id: &str,
        is_admin: bool,
        opts: ReaddirOpts,
    ) -> Vec<(String, u8)> {
        Self::sys_readdir(self, parent_path, zone_id, is_admin, opts)
    }

    fn sys_watch(&self, pattern: &str, timeout_ms: u64) -> Option<FileEvent> {
        Self::sys_watch(self, pattern, timeout_ms)
    }
}
