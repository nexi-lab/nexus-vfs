//! Sync façade → inner-runtime bridge, shared by every raft-backed
//! store that exposes a synchronous API over the async consensus core
//! (`ZoneManager`, `ZoneMetaStore`, `RaftAuthKeyStore`).
//!
//! One definition, one set of panic-safety rules — the helper used to
//! be copy-pasted per store, which meant the `block_in_place` reasoning
//! below had to be re-derived (and could drift) at each site.

/// Sync façade bridge to the inner runtime's async work.
///
/// The raft-backed stores expose a sync API to their callers
/// (`nexusd-cluster`, kernel) and own an inner tokio `Runtime` that
/// drives the raft `transport_loop`,
/// driver tasks, tonic gRPC server / clients, and `spawn_blocking`
/// redb I/O — all of which are `async fn` because tonic + tokio
/// `select!` make raft transport an async task by construction.
/// Bridging the sync façade to that async core requires `block_on`
/// on the inner runtime's handle. Two callsite shapes coexist:
///
/// * **Sync caller** (binary `fn main()` before it spawns its
///   runtime): no outer tokio context. `Handle::block_on`
///   parks the calling thread on the inner runtime — straight
///   forward, no panic.
/// * **Async caller** (anything reachable from `#[tokio::main]` or
///   inside `tokio::spawn` — `nexusd-cluster::run_daemon`'s topology
///   loop, `distributed_coordinator` async helpers): the calling
///   thread is registered as a worker of an
///   *outer* runtime. `Handle::block_on` panics on a worker thread
///   (tokio refuses to park a worker because it would deadlock when
///   the awaited future depends on a task that needs the same worker
///   pool). `tokio::task::block_in_place` releases the worker
///   temporarily — work-stealing covers in its absence — so we can
///   safely `block_on` the inner runtime within the closure.
///
/// `Handle::try_current()` resolves the two cases at runtime;
/// `block_in_place` requires a `multi_thread` outer runtime, which
/// every async caller of these stores already uses
/// (`#[tokio::main(flavor = "multi_thread")]`).
pub(crate) fn bridge_block_on<F>(handle: &tokio::runtime::Handle, fut: F) -> F::Output
where
    F: std::future::Future,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        handle.block_on(fut)
    }
}
