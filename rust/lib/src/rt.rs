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
//!
//! The same asymmetry applies at the *end* of a runtime's life — dropping one is
//! legal from a sync caller and panics from an async one — so [`OwnedRuntime`] lives
//! here too, next to the rules it belongs with.

use tokio::runtime::{Builder, Handle, Runtime, RuntimeFlavor};

/// An owned `Runtime` that is safe to drop from **any** context, including while
/// unwinding out of an async fn.
///
/// The mirror image of the hazard above, and the one that is easy to miss: a plain
/// `Runtime` drop blocks until every spawned task exits, and tokio refuses to block
/// on a worker thread — the drop panics with "Cannot drop a runtime in a context
/// where blocking is not allowed". `shutdown_background()` is the escape hatch, but
/// it has to be reached on *every* path out, and the paths that forget are the error
/// paths: a `Drop` impl written by hand only ever sees a fully-constructed value,
/// while a `?` between "runtime built" and "value returned" drops the bare runtime
/// mid-unwind. The panic then replaces the error, so the operator reads a tokio
/// backtrace instead of "another process has this data dir open".
///
/// Owning the runtime in a value whose `Drop` decides makes those paths correct for
/// free, which is why a fallible constructor should hold this type from the moment it
/// builds a runtime rather than at the point it succeeds.
///
/// Deliberately not `Clone` and not constructible from a `Handle`: this is the type
/// for the one owner that must shut a runtime down. Everything else passes
/// `Handle`s, which are cheap to drop anywhere.
pub struct OwnedRuntime(Option<Runtime>);

impl OwnedRuntime {
    /// Take ownership of a runtime, so the drop rule applies from here on.
    pub fn new(runtime: Runtime) -> Self {
        Self(Some(runtime))
    }

    /// The runtime — `Some` for the whole lifetime, taken only by `Drop`.
    pub fn get(&self) -> &Runtime {
        self.0.as_ref().expect("runtime present until Drop")
    }

    /// Shorthand for `self.get().handle()`.
    pub fn handle(&self) -> &Handle {
        self.get().handle()
    }
}

impl std::ops::Deref for OwnedRuntime {
    type Target = Runtime;

    fn deref(&self) -> &Runtime {
        self.get()
    }
}

impl From<Runtime> for OwnedRuntime {
    fn from(runtime: Runtime) -> Self {
        Self::new(runtime)
    }
}

impl Drop for OwnedRuntime {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            // Inside another runtime the blocking shutdown is illegal, so cleanup is
            // scheduled off-thread; with no ambient runtime, the natural blocking
            // shutdown is what the caller wants (tasks finish before the process
            // moves on).
            if Handle::try_current().is_ok() {
                rt.shutdown_background();
            }
        }
    }
}

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

/// Bridge a sync façade onto an owned **multi-thread** inner runtime (`handle`) from
/// any context — the future runs on `handle`'s runtime. Use when the future's async
/// work depends on tasks driven by that specific runtime (raft consensus stores
/// whose `propose` awaits the transport loop; the kernel peer-RPC transport).
///
/// The inner runtime must be multi-thread, because this drives the FUTURE and trusts
/// that runtime's own workers to drive everything else — its IO and time drivers
/// included. Handed a current-thread runtime's handle, the future is polled while the
/// connect or timer it awaits is never polled by anyone, and the caller hangs rather
/// than failing: `Runtime::block_on` from a blocking-legal thread is the way to drive
/// one of those, since it drives the runtime and the future together.
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
    use super::{block_on_portable, block_on_via, OwnedRuntime};

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

    // OwnedRuntime — the drop rule, in the context where a bare drop panics.
    #[test]
    fn owned_runtime_drops_inside_an_async_context() {
        // The shape that panics with a bare `Runtime`: a fallible constructor that
        // builds one and then returns `Err`, with an ambient runtime around it. What
        // must survive is the error — the caller's reason, not a tokio backtrace.
        fn fails_after_building_one() -> Result<OwnedRuntime, &'static str> {
            let _rt = OwnedRuntime::new(inner());
            Err("the reason the operator needs to see")
        }
        let outer = inner();
        let reason = outer.block_on(async { fails_after_building_one().err() });
        assert_eq!(reason, Some("the reason the operator needs to see"));
    }

    #[test]
    fn owned_runtime_still_runs_work_and_drops_from_sync() {
        let rt = OwnedRuntime::new(inner());
        // Deref: an owner uses it exactly like the `Runtime` it wraps.
        assert_eq!(rt.block_on(async { 40 + 2 }), 42);
        assert_eq!(block_on_via(rt.handle(), async { 42 }), 42);
        drop(rt); // no ambient runtime: the blocking shutdown, as intended
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
