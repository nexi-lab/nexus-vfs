//! IPC syscalls — pipe + stream manager delegation.
//!
//! Every method stays a member of [`Kernel`] via this submodule's
//! `impl Kernel { ... }` block.

use std::sync::Arc;

use crate::extensions::llm_streaming::StreamSink;
use crate::meta_store::{DT_PIPE, DT_STREAM};

use super::{pipe_mgr_err, stream_mgr_err, Kernel, KernelError, OperationContext};

impl Kernel {
    // ── IPC Registry — Pipe methods (delegates to PipeManager) ──────────

    /// Create a pipe buffer in the IPC registry.
    ///
    /// PipeManager owns the buffer; Kernel persists DT_PIPE inode so
    /// sys_read/sys_write dispatch to IPC fast-path.
    pub fn create_pipe(&self, path: &str, capacity: usize) -> Result<(), KernelError> {
        self.pipe_manager
            .create(path, capacity)
            .map_err(pipe_mgr_err)?;

        let meta = self.build_metadata(
            path,
            contracts::ROOT_ZONE_ID,
            DT_PIPE,
            capacity as u64,
            None,
            0,
            1,
            None,
            None,
            None,
        );
        self.metastore_put(path, meta)?;

        Ok(())
    }

    /// Destroy a pipe buffer.
    pub fn destroy_pipe(&self, path: &str) -> Result<(), KernelError> {
        self.pipe_manager.destroy(path).map_err(pipe_mgr_err)?;

        self.metastore_delete(path)?;

        Ok(())
    }

    /// Close a pipe (signal close, keep in registry for drain).
    pub fn close_pipe(&self, path: &str) -> Result<(), KernelError> {
        self.pipe_manager.close(path).map_err(pipe_mgr_err)
    }

    /// Check if a pipe exists.
    pub fn has_pipe(&self, path: &str) -> bool {
        self.pipe_manager.has(path)
    }

    /// Queued bytes pending in a DT_PIPE.
    ///
    /// Returns `KernelError::FileNotFound` if no pipe is registered at
    /// `path`. `Ok(0)` means the pipe exists but has nothing to pop.
    /// Kernel-internal helper: read-only probe, no syscall dispatch.
    pub fn pipe_size(&self, path: &str) -> Result<usize, KernelError> {
        self.pipe_manager
            .size(path)
            .ok_or_else(|| KernelError::FileNotFound(path.to_string()))
    }

    /// Non-blocking write to a pipe. Returns bytes written.
    ///
    /// Runs mutating pre-hooks first via the shared
    /// [`Kernel::apply_mutating_write_hooks`] seam, so a DT_PIPE mailbox
    /// (`/proc/{pid}/transcript`) gets the same `from`-stamp as every other
    /// write path.
    pub fn pipe_write_nowait(
        &self,
        path: &str,
        data: &[u8],
        ctx: &OperationContext,
    ) -> Result<usize, KernelError> {
        let replacement = self.apply_mutating_write_hooks(path, ctx, data)?;
        let effective: &[u8] = replacement.as_deref().unwrap_or(data);
        self.pipe_manager
            .write_nowait(path, effective)
            .map_err(pipe_mgr_err)
    }

    /// Non-blocking read from a pipe. Returns data or None if empty.
    pub fn pipe_read_nowait(&self, path: &str) -> Result<Option<Vec<u8>>, KernelError> {
        self.pipe_manager.read_nowait(path).map_err(pipe_mgr_err)
    }

    /// List all pipes with their paths.
    pub fn list_pipes(&self) -> Vec<String> {
        self.pipe_manager.list()
    }

    /// Blocking read — Condvar wait.
    ///
    /// Kernel-side surface for Rust services that need to wait on
    /// a pipe; the underlying `PipeManager::read_blocking` parks
    /// the caller on a Condvar until data arrives or `timeout_ms`
    /// elapses.
    #[allow(dead_code)]
    pub fn pipe_read_blocking(&self, path: &str, timeout_ms: u64) -> Result<Vec<u8>, KernelError> {
        self.pipe_manager
            .read_blocking(path, timeout_ms)
            .map_err(pipe_mgr_err)
    }

    /// Close all pipes (shutdown).
    pub fn close_all_pipes(&self) {
        self.pipe_manager.close_all();
    }

    // ── IPC Registry — Stream methods (delegates to StreamManager) ────

    /// Create a stream buffer in the IPC registry.
    pub fn create_stream(&self, path: &str, capacity: usize) -> Result<(), KernelError> {
        self.stream_manager
            .create(path, capacity)
            .map_err(stream_mgr_err)?;

        let meta = self.build_metadata(
            path,
            contracts::ROOT_ZONE_ID,
            DT_STREAM,
            capacity as u64,
            None,
            0,
            1,
            None,
            None,
            None,
        );
        self.metastore_put(path, meta)?;

        Ok(())
    }

    /// Destroy a stream buffer.
    pub fn destroy_stream(&self, path: &str) -> Result<(), KernelError> {
        self.stream_manager.destroy(path).map_err(stream_mgr_err)?;

        self.metastore_delete(path)?;

        Ok(())
    }

    /// Close a stream (signal close, keep in registry for drain), waking
    /// every blocked reader.
    ///
    /// The producer's half of the DT_STREAM lifecycle, and the reason a
    /// producer outside this crate needs nothing from `StreamManager`: with
    /// [`Self::create_stream`], [`Self::stream_write_nowait`] and this, the
    /// whole producer path is Kernel surface, so the hook-bearing write is
    /// the only write there is. Closing carries no content, so no hook runs —
    /// unlike the write, there is nothing here to inspect or rewrite.
    pub fn close_stream(&self, path: &str) -> Result<(), KernelError> {
        self.stream_manager.close(path).map_err(stream_mgr_err)
    }

    /// Check if a stream exists.
    pub fn has_stream(&self, path: &str) -> bool {
        self.stream_manager.has(path)
    }

    /// Current tail (write offset) of a DT_STREAM.
    ///
    /// Returns `KernelError::FileNotFound` if no stream is registered at
    /// `path`. Callers use this for the seek-to-end pattern: read the
    /// tail, then pass it as the offset to `stream_read_at_blocking`
    /// to skip history and block until new data arrives. Kernel-internal
    /// helper: read-only probe, no syscall dispatch.
    pub fn stream_tail(&self, path: &str) -> Result<usize, KernelError> {
        self.stream_manager
            .tail(path)
            .ok_or_else(|| KernelError::FileNotFound(path.to_string()))
    }

    /// Non-blocking write to a stream. Returns byte offset.
    ///
    /// Runs mutating pre-hooks first via the shared
    /// [`Kernel::apply_mutating_write_hooks`] seam, so a DT_STREAM mailbox
    /// write gets the same `from`-stamp / fail-closed guarantee `sys_write`
    /// does. The A2A mailbox IS a DT_STREAM, so this is the path its `from`
    /// unforgeability actually depends on — it must not be bypassable by
    /// choosing the stream RPC over `sys_write`.
    pub fn stream_write_nowait(
        &self,
        path: &str,
        data: &[u8],
        ctx: &OperationContext,
    ) -> Result<usize, KernelError> {
        let replacement = self.apply_mutating_write_hooks(path, ctx, data)?;
        let effective: &[u8] = replacement.as_deref().unwrap_or(data);
        self.stream_manager
            .write_nowait(path, effective)
            .map_err(stream_mgr_err)
    }

    /// A [`StreamSink`] that appends as `ctx`, for a producer outside this
    /// crate.
    ///
    /// Binding the identity here rather than passing it per-append is
    /// deliberate: a producer that could choose an identity per frame could
    /// choose the wrong one, and a streaming backend pumps frames from a
    /// spawned task where the ambient caller is long gone. One handle, one
    /// principal, decided where the handle is made.
    pub fn stream_sink(self: &Arc<Self>, ctx: OperationContext) -> Arc<dyn StreamSink> {
        Arc::new(KernelStreamSink {
            kernel: Arc::clone(self),
            ctx,
        })
    }

    /// Read one message at byte offset. Returns (data, next_offset) or None if empty.
    pub fn stream_read_at(
        &self,
        path: &str,
        offset: usize,
    ) -> Result<Option<(Vec<u8>, usize)>, KernelError> {
        self.stream_manager
            .read_at(path, offset)
            .map_err(stream_mgr_err)
    }

    /// Read up to `count` messages starting from byte offset.
    pub fn stream_read_batch(
        &self,
        path: &str,
        offset: usize,
        count: usize,
    ) -> Result<(Vec<Vec<u8>>, usize), KernelError> {
        self.stream_manager
            .read_batch(path, offset, count)
            .map_err(stream_mgr_err)
    }

    /// Collect all stream payloads from offset 0, concatenated.
    ///
    /// One kernel call returns the whole stream, so LLM-backend
    /// callers can replace a per-frame `read_at` loop with a single
    /// drain. Pure mechanism — the §13 read gate is the dispatch layer's
    /// job (`sys_read` for offset reads; the external RPC handler invokes
    /// `check_permission(Read)` for this whole-stream variant), never here.
    pub fn stream_collect_all(&self, path: &str) -> Result<Vec<u8>, KernelError> {
        self.stream_manager
            .collect_all_payloads(path)
            .map_err(stream_mgr_err)
    }

    /// List all streams with their paths.
    pub fn list_streams(&self) -> Vec<String> {
        self.stream_manager.list()
    }

    /// Blocking read at offset — Condvar wait.
    ///
    /// Kernel-side surface for Rust services that need to wait on
    /// a stream's tail to advance past `offset`; the underlying
    /// `StreamManager::read_at_blocking` parks the caller on a
    /// Condvar until a frame whose `offset_in >= offset` arrives
    /// or `timeout_ms` elapses.
    #[allow(dead_code)]
    pub fn stream_read_at_blocking(
        &self,
        path: &str,
        offset: usize,
        timeout_ms: u64,
    ) -> Result<(Vec<u8>, usize), KernelError> {
        self.stream_manager
            .read_at_blocking(path, offset, timeout_ms)
            .map_err(stream_mgr_err)
    }

    /// Close all streams (shutdown).
    pub fn close_all_streams(&self) {
        self.stream_manager.close_all();
    }
}

/// The only [`StreamSink`] there is: every append goes through
/// [`Kernel::stream_write_nowait`], so every append runs the write hooks.
///
/// Holding the `Arc<Kernel>` is what lets a backend outlive the call that
/// made it — a streaming pump appends from a spawned task, long after the
/// request that started it returned.
struct KernelStreamSink {
    kernel: Arc<Kernel>,
    ctx: OperationContext,
}

impl StreamSink for KernelStreamSink {
    fn append(&self, path: &str, data: &[u8]) -> Result<usize, String> {
        self.kernel
            .stream_write_nowait(path, data, &self.ctx)
            .map_err(|e| format!("{e:?}"))
    }

    fn close(&self, path: &str) -> Result<(), String> {
        self.kernel.close_stream(path).map_err(|e| format!("{e:?}"))
    }
}

#[cfg(test)]
mod stream_sink_tests {
    use super::*;
    use crate::core::dispatch::{HookContext, HookOutcome, NativeInterceptHook};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const STREAM: &str = "/llm/reply.stream";

    /// Counts what it saw and refuses anything containing `veto`.
    ///
    /// Both halves matter: a hook that only counts proves the seam is reached,
    /// and a hook that refuses proves the write actually depends on the
    /// answer — a seam that is consulted and ignored is not a seam.
    struct Watcher {
        seen: Arc<AtomicUsize>,
    }

    impl NativeInterceptHook for Watcher {
        fn name(&self) -> &str {
            "watcher"
        }
        fn mutating_path_suffixes(&self) -> &'static [&'static str] {
            &[".stream"]
        }
        fn on_pre(&self, ctx: &HookContext) -> Result<HookOutcome, String> {
            if let HookContext::Write(w) = ctx {
                self.seen.fetch_add(1, Ordering::SeqCst);
                if w.content.windows(4).any(|c| c == b"veto") {
                    return Err("refused by watcher".to_string());
                }
            }
            Ok(HookOutcome::Pass)
        }
    }

    fn kernel_with_watcher() -> (Arc<Kernel>, Arc<AtomicUsize>) {
        let k = Arc::new(Kernel::new());
        let seen = Arc::new(AtomicUsize::new(0));
        k.register_native_hook(Box::new(Watcher {
            seen: Arc::clone(&seen),
        }));
        k.create_stream(STREAM, 64 * 1024).unwrap();
        (k, seen)
    }

    fn ctx() -> OperationContext {
        OperationContext::new("test", "root", false, None, false)
    }

    /// The whole point of the change. A producer outside this crate used to
    /// hold a `StreamManager` and append straight into the buffer, so its
    /// output was the one write no hook could see. Going through the sink,
    /// the hook sees it.
    #[test]
    fn a_sink_append_is_seen_by_write_hooks() {
        let (k, seen) = kernel_with_watcher();
        let sink = k.stream_sink(ctx());

        sink.append(STREAM, b"hello from the model").unwrap();

        assert_eq!(
            seen.load(Ordering::SeqCst),
            1,
            "the hook must see a sink append; if this is 0 the write went \
             around the seam"
        );
    }

    /// And the hook's answer is binding: a refusal means the bytes are not in
    /// the stream, not merely that something was logged.
    #[test]
    fn a_hook_can_refuse_a_sink_append() {
        let (k, _seen) = kernel_with_watcher();
        let sink = k.stream_sink(ctx());

        sink.append(STREAM, b"fine").unwrap();
        let err = sink
            .append(STREAM, b"please veto this")
            .expect_err("a refusing hook must fail the append");
        assert!(err.contains("refused"), "err was: {err}");

        let landed = k.stream_collect_all(STREAM).unwrap();
        assert_eq!(
            landed, b"fine",
            "the refused bytes must not be in the stream"
        );
    }

    /// The sink appends as the principal it was built with, so a hook is
    /// deciding about a caller rather than about an anonymous write. This is
    /// what makes the identity binding at `stream_sink` load-bearing.
    #[test]
    fn a_sink_appends_as_the_identity_it_was_built_with() {
        struct Recorder {
            who: Arc<std::sync::Mutex<Vec<String>>>,
        }
        impl NativeInterceptHook for Recorder {
            fn name(&self) -> &str {
                "recorder"
            }
            fn mutating_path_suffixes(&self) -> &'static [&'static str] {
                &[".stream"]
            }
            fn on_pre(&self, ctx: &HookContext) -> Result<HookOutcome, String> {
                if let HookContext::Write(w) = ctx {
                    self.who.lock().unwrap().push(w.identity.user_id.clone());
                }
                Ok(HookOutcome::Pass)
            }
        }

        let k = Arc::new(Kernel::new());
        let who = Arc::new(std::sync::Mutex::new(Vec::new()));
        k.register_native_hook(Box::new(Recorder {
            who: Arc::clone(&who),
        }));
        k.create_stream(STREAM, 64 * 1024).unwrap();

        let sink = k.stream_sink(OperationContext::new("alice", "root", false, None, false));
        sink.append(STREAM, b"x").unwrap();

        assert_eq!(
            who.lock().unwrap().as_slice(),
            &["alice".to_string()],
            "the hook must see the sink's bound principal"
        );
    }
}
