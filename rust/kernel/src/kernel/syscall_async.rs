//! Async wrappers for I/O syscalls — `spawn_blocking` blanket impl.
//!
//! `KernelSyscallAsync` is automatically implemented for every
//! `T: KernelSyscall`.  Each method clones `Arc<Self>` into a
//! `spawn_blocking` closure so the blocking kernel call runs on
//! tokio's blocking thread pool instead of a worker thread.
//!
//! **Zero cost when unused**: the blanket impl is generic and
//! `#[inline]` — the compiler monomorphises and inlines the outer
//! future setup, so there is no vtable, no Box, and no allocation
//! beyond the `Arc::clone` (~10ns atomic increment).
//!
//! Only I/O syscalls are wrapped (read, write, stat, readdir, unlink,
//! rename, copy).  Control-plane methods (register_*, install_*) are
//! called once at boot and don't need async variants.

use std::future::Future;
use std::sync::Arc;

use super::syscall::KernelSyscall;
use super::{KernelError, OperationContext, StatResult};
use super::{SysCopyResult, SysReadResult, SysRenameResult, SysUnlinkResult, SysWriteResult};

/// Async projection of the I/O subset of [`KernelSyscall`].
///
/// Blanket-implemented for all `T: KernelSyscall`.  Callers hold
/// `Arc<K>` and call `k.sys_read_async(...)`.await — the blocking
/// syscall body runs on `spawn_blocking`, freeing the tokio worker.
pub trait KernelSyscallAsync: KernelSyscall {
    #[inline]
    fn sys_read_async(
        self: &Arc<Self>,
        path: String,
        ctx: OperationContext,
        timeout_ms: u64,
        offset: u64,
    ) -> impl Future<Output = Result<SysReadResult, KernelError>> + Send {
        let k = Arc::clone(self);
        async move {
            tokio::task::spawn_blocking(move || k.sys_read(&path, &ctx, timeout_ms, offset))
                .await
                .unwrap_or_else(|e| {
                    Err(KernelError::IOError(format!(
                        "spawn_blocking join failed: {e}"
                    )))
                })
        }
    }

    #[inline]
    fn sys_write_async(
        self: &Arc<Self>,
        path: String,
        ctx: OperationContext,
        content: Vec<u8>,
        offset: u64,
    ) -> impl Future<Output = Result<SysWriteResult, KernelError>> + Send {
        let k = Arc::clone(self);
        async move {
            tokio::task::spawn_blocking(move || k.sys_write(&path, &ctx, &content, offset))
                .await
                .unwrap_or_else(|e| {
                    Err(KernelError::IOError(format!(
                        "spawn_blocking join failed: {e}"
                    )))
                })
        }
    }

    #[inline]
    fn sys_stat_async(
        self: &Arc<Self>,
        path: String,
        zone_id: String,
    ) -> impl Future<Output = Option<StatResult>> + Send {
        let k = Arc::clone(self);
        async move {
            tokio::task::spawn_blocking(move || k.sys_stat(&path, &zone_id))
                .await
                .unwrap_or(None)
        }
    }

    #[inline]
    fn sys_readdir_async(
        self: &Arc<Self>,
        parent_path: String,
        zone_id: String,
        is_admin: bool,
    ) -> impl Future<Output = Vec<(String, u8)>> + Send {
        let k = Arc::clone(self);
        async move {
            tokio::task::spawn_blocking(move || k.sys_readdir(&parent_path, &zone_id, is_admin))
                .await
                .unwrap_or_default()
        }
    }

    #[inline]
    fn sys_unlink_async(
        self: &Arc<Self>,
        path: String,
        ctx: OperationContext,
        recursive: bool,
    ) -> impl Future<Output = Result<SysUnlinkResult, KernelError>> + Send {
        let k = Arc::clone(self);
        async move {
            tokio::task::spawn_blocking(move || k.sys_unlink(&path, &ctx, recursive))
                .await
                .unwrap_or_else(|e| {
                    Err(KernelError::IOError(format!(
                        "spawn_blocking join failed: {e}"
                    )))
                })
        }
    }

    #[inline]
    fn sys_rename_async(
        self: &Arc<Self>,
        old_path: String,
        new_path: String,
        ctx: OperationContext,
    ) -> impl Future<Output = Result<SysRenameResult, KernelError>> + Send {
        let k = Arc::clone(self);
        async move {
            tokio::task::spawn_blocking(move || k.sys_rename(&old_path, &new_path, &ctx))
                .await
                .unwrap_or_else(|e| {
                    Err(KernelError::IOError(format!(
                        "spawn_blocking join failed: {e}"
                    )))
                })
        }
    }

    #[inline]
    fn sys_copy_async(
        self: &Arc<Self>,
        src_path: String,
        dst_path: String,
        ctx: OperationContext,
    ) -> impl Future<Output = Result<SysCopyResult, KernelError>> + Send {
        let k = Arc::clone(self);
        async move {
            tokio::task::spawn_blocking(move || k.sys_copy(&src_path, &dst_path, &ctx))
                .await
                .unwrap_or_else(|e| {
                    Err(KernelError::IOError(format!(
                        "spawn_blocking join failed: {e}"
                    )))
                })
        }
    }
}

/// Blanket impl — every `KernelSyscall` impl gets async variants for free.
impl<T: KernelSyscall> KernelSyscallAsync for T {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time proof that the blanket impl produces `Send` futures
    /// (required by `tokio::spawn`).
    fn _assert_send<F: Future + Send>(_f: F) {}

    /// Dummy check — we can't easily construct a Kernel in a unit test,
    /// but we can verify the trait is object-safe enough that the
    /// blanket impl compiles and the futures are Send.
    #[allow(dead_code)]
    fn _prove_send_futures(k: &Arc<super::super::Kernel>) {
        let ctx = OperationContext::new("", "root", true, None, true);
        _assert_send(k.sys_read_async("/x".into(), ctx.clone(), 0, 0));
        _assert_send(k.sys_write_async("/x".into(), ctx.clone(), vec![], 0));
        _assert_send(k.sys_stat_async("/x".into(), "root".into()));
        _assert_send(k.sys_readdir_async("/".into(), "root".into(), false));
        _assert_send(k.sys_unlink_async("/x".into(), ctx.clone(), false));
        _assert_send(k.sys_rename_async("/a".into(), "/b".into(), ctx.clone()));
        _assert_send(k.sys_copy_async("/a".into(), "/b".into(), ctx));
    }
}
