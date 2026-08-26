//! Runtime-context bridge — run an async future to completion from a
//! **synchronous** caller, correct for **any** ambient tokio runtime flavor.
//!
//! # The hazard this centralizes
//!
//! A "sync façade over an async core" must block the calling thread until the
//! future completes. The tokio primitive for that depends on the *caller's*
//! context, and the rules are sharp:
//!
//! * `Handle::block_on` **panics** if called from *within* any runtime
//!   ("Cannot block the current thread from within a runtime").
//! * `tokio::task::block_in_place` is legal **only** on a *multi-thread*
//!   runtime worker; on a current-thread runtime it panics ("can call
//!   blocking only when running on the multi-threaded runtime").
//!
//! Every bridge site in the tree re-derived this — the raft stores
//! (`bridge_block_on`), the kernel peer-RPC transport, and sudocode's
//! bash / MCP / VLM tool bridges — and several drifted into an
//! "ambient runtime ⇒ multi-thread" assumption that panics the moment the
//! caller is a *current-thread* runtime (the co-host managed-agent LLM runtime,
//! `sudocode spawn_task`). One helper, one set of rules, so the reasoning can
//! never drift per site again.
//!
//! The `KernelSyscall` contract is "callable from any thread" (see
//! `kernel/src/kernel/syscall.rs`); this module is what makes that true.

use tokio::runtime::{Builder, Handle, RuntimeFlavor};

/// Dispatch a `block_on`-style closure correctly for the ambient runtime:
///
/// * **no ambient runtime** → call it inline (it parks this thread);
/// * **multi-thread worker** → `block_in_place`, so work-stealing keeps the
///   pool live while this worker parks;
/// * **current-thread (or any non-multi-thread) runtime** → run it on a scratch
///   OS thread that has no ambient runtime, since `block_in_place` is illegal
///   and a direct `block_on` would deadlock the sole worker.
///
/// The scratch-thread hop is paid **only** on the current-thread branch (rare —
/// an in-process managed agent crossing into async work); the hot multi-thread
/// path keeps the zero-alloc `block_in_place`.
fn dispatch<T, Op>(block_on: Op) -> T
where
    Op: FnOnce() -> T + Send,
    T: Send,
{
    match Handle::try_current() {
        Err(_) => block_on(),
        Ok(current) => match current.runtime_flavor() {
            RuntimeFlavor::MultiThread => tokio::task::block_in_place(block_on),
            _ => std::thread::scope(|s| {
                s.spawn(block_on)
                    .join()
                    .expect("rt::dispatch scratch thread panicked")
            }),
        },
    }
}

/// Bridge a sync façade onto an **owned inner runtime** (`handle`) from any
/// context — the future runs on `handle`'s runtime. Use when the future's async
/// work depends on tasks driven by that specific runtime (raft consensus stores
/// whose `propose` awaits the transport loop; the kernel peer-RPC transport).
pub fn block_on_via<F>(handle: &Handle, fut: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    dispatch(move || handle.block_on(fut))
}

/// Run a **self-contained** future to completion from any context, without
/// owning a runtime: reuse the ambient one when it is multi-thread, else drive
/// it on an ephemeral current-thread runtime. Use for tool bridges
/// (bash / MCP / VLM) whose future needs *some* executor but not a specific one.
pub fn block_on_portable<F>(fut: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    dispatch(move || match Handle::try_current() {
        Ok(handle) => handle.block_on(fut),
        Err(_) => Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt::block_on_portable ephemeral runtime")
            .block_on(fut),
    })
}

#[cfg(test)]
mod tests {
    use super::{block_on_portable, block_on_via};

    fn inner() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("inner runtime")
    }

    // block_on_via — the owned-inner-runtime bridge — across all three contexts.
    #[test]
    fn via_no_ambient_runtime() {
        let rt = inner();
        assert_eq!(block_on_via(rt.handle(), async { 40 + 2 }), 42);
    }

    #[test]
    fn via_multi_thread_ambient() {
        let rt = inner();
        let outer = inner();
        assert_eq!(
            outer.block_on(async { block_on_via(rt.handle(), async { 6 * 7 }) }),
            42
        );
    }

    #[test]
    fn via_current_thread_ambient_does_not_panic() {
        // THE REGRESSION: the co-host managed-agent (current-thread) runtime
        // reaching a federated kernel op. Pre-fix this panicked.
        let rt = inner();
        let agent = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(
            agent.block_on(async { block_on_via(rt.handle(), async { 21 + 21 }) }),
            42
        );
    }

    // block_on_portable — the self-contained tool-bridge form — same matrix.
    #[test]
    fn portable_no_ambient_runtime() {
        assert_eq!(block_on_portable(async { 40 + 2 }), 42);
    }

    #[test]
    fn portable_current_thread_ambient_does_not_panic() {
        // The bash / MCP / VLM tool-call shape from a current-thread agent turn.
        let agent = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(
            agent.block_on(async { block_on_portable(async { 42 }) }),
            42
        );
    }
}
