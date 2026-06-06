//! Regression: `ZoneManager` public sync API must work when called from
//! a `#[tokio::main]` async context (the production `nexusd-cluster`
//! daemon's call shape).
//!
//! Background: `ZoneManager::new` and several other sync methods bridge
//! to async raft IPC via the inner runtime's `block_on`. A nested
//! `Handle::block_on` call from a thread already registered as a tokio
//! worker panics — tokio refuses to park a worker because the awaited
//! future could deadlock against tasks needing the same worker pool.
//!
//! `nexusd-cluster::run_daemon` exposes exactly that shape:
//! `#[tokio::main(flavor = "multi_thread")]` makes the entry thread a
//! worker, then `open_zone_manager` calls `ZoneManager::new` (sync) on
//! that worker. Without the `bridge_block_on` wrapper inside
//! `ZoneManager`, this panics with "Cannot start a runtime from within
//! a runtime."
//!
//! The Federation E2E suite does NOT cover this path — it goes through
//! the cluster binary, where `fn main()` is a regular sync thread (no
//! outer tokio runtime) and `block_on` is straightforwardly safe.
//!
//! This test exercises every sync API that bridges to async work, all
//! from inside a `#[tokio::test(flavor = "multi_thread")]` context to
//! mirror the production daemon's tokio runtime shape.

#![cfg(all(feature = "grpc", has_protos))]

use nexus_raft::ZoneManager;
use std::time::Duration;
use tempfile::TempDir;

/// Pick a random unused TCP port for the raft gRPC server. The test
/// doesn't actually connect to it — we only need a unique bind address
/// so concurrent `cargo test` invocations don't collide.
fn ephemeral_bind_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("127.0.0.1:{}", port)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zone_manager_constructs_under_tokio_main() {
    // Phase 1 of the regression: ZoneManager::new internally calls
    // ZoneRaftRegistry::open_existing_zones_from_disk, which used to
    // be `async fn` and was driven via `inner.handle().block_on(...)`.
    // On a tokio worker (this test thread) that block_on panicked.
    // Fixed by making the registry layer fully sync (no campaign, no
    // .await needed in setup_zone) — block_on disappears from the
    // construction path entirely.
    let tmp = TempDir::new().unwrap();
    let bind = ephemeral_bind_addr();
    let zm = ZoneManager::new(
        "regression-host",
        tmp.path().to_str().unwrap(),
        vec![],
        &bind,
        None,
    )
    .expect("ZoneManager::new must not panic on tokio worker");
    zm.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zone_manager_create_and_apply_topology_under_tokio_main() {
    // Phase 2 of the regression: even after `new` works, the daemon
    // continues with `create_zone` and a `tokio::spawn`-driven
    // `apply_topology` loop. Both bridge to async raft IPC (channel
    // send + apply ack from the driver task) via `bridge_block_on` —
    // verifies that the helper takes the `block_in_place` branch when
    // the calling thread is a worker.
    let tmp = TempDir::new().unwrap();
    let bind = ephemeral_bind_addr();
    let zm = ZoneManager::new(
        "regression-host",
        tmp.path().to_str().unwrap(),
        vec![],
        &bind,
        None,
    )
    .expect("ZoneManager::new");

    // Single-voter zone — raft-rs election timer (default ~150-300ms)
    // will self-elect once `tick()` runs in the spawned transport_loop.
    zm.create_zone("root", vec![])
        .expect("create_zone must not panic on tokio worker");

    // Wait briefly for the election timer to fire so subsequent
    // raft-IPC ops (apply_topology drives propose) can land. raft-rs's
    // default election_tick is 10 ticks at 10ms = 100ms; give a small
    // margin for the driver to settle.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // apply_topology drives ensure_root_entry → propose root "/" entry
    // through the raft pipeline. With no pending mounts, returns true
    // once the root entry lands (or false if the leader hasn't elected
    // yet, in which case we just verify it didn't panic).
    let _ = zm
        .apply_topology("root")
        .expect("apply_topology must not panic on tokio worker");

    zm.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_voter_propose_converges_without_self_forward_loop() {
    // Regression: PR #25 (F1 + F2 — leader-detection race fix).
    //
    // F1: `is_leader()` derives from `leader_id()` rather than the
    //     parallel `cached_role` atomic, eliminating the inter-atomic
    //     race during the post-election update window.
    // F2: `forward_to_leader` detects "leader is self" and retries
    //     `submit_to_channel` locally instead of RPC-forwarding to
    //     self's advertised address (which would hairpin on
    //     Tailscale-on-Windows/macOS or round-trip back to the same
    //     process).
    //
    // Symptom before the fix: a 1-voter founder boot would log one
    // `Forward to leader failed (unreachable?): leader=<self_node_id>`
    // warning, then the `apply_topology` retry loop in the cluster
    // binary would paper over it by re-proposing every TOPOLOGY_TICK
    // until convergence — measured ~10 s on local hardware.  After the
    // fix the very first `apply_topology` propose lands cleanly within
    // a few election ticks.
    //
    // This test pins both invariants:
    //   1. `apply_topology` must return Ok on a 1-voter zone whose
    //      election has had time to fire.
    //   2. It must do so well under the apply_topology-retry-loop
    //      timescale — 2 s is comfortably above the ~100 ms election
    //      timer + propose pipeline budget and comfortably below the
    //      pre-fix ~10 s convergence floor.
    let tmp = TempDir::new().unwrap();
    let bind = ephemeral_bind_addr();
    let zm = ZoneManager::new(
        "regression-host",
        tmp.path().to_str().unwrap(),
        vec![],
        &bind,
        None,
    )
    .expect("ZoneManager::new");

    zm.create_zone("root", vec![]).expect("create_zone");

    // Election timer ~150 ms; give the driver a small margin to settle
    // cached_leader_id post-self-vote.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // `apply_topology` drives `ensure_root_entry` → `propose_set_metadata`
    // through `bridge_block_on(node.propose(...))`.  On a 1-voter zone
    // this is the exact path that hit the leader-detection race before
    // PR #25.  Bound the whole operation to 2 s — that's already ~20×
    // the pre-fix's pessimistic 10 s convergence budget under the
    // retry-loop workaround.
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking({
            let zm = zm.clone();
            move || zm.apply_topology("root")
        }),
    )
    .await
    .expect("apply_topology must not exceed 2 s — pre-#25 this took ~10 s")
    .expect("spawn_blocking join")
    .expect("apply_topology must return Ok on a 1-voter founder");
    let elapsed = started.elapsed();

    // `apply_topology` returns true on the "root entry written, nothing
    // pending" path and false on the "leader not yet stable" deferral.
    // Both are fine — what we're catching is the timeout / Err that the
    // pre-fix race produced.
    let _ = outcome;
    assert!(
        elapsed < Duration::from_secs(2),
        "1-voter founder propose must converge in <2 s (got {:?}); before #25 \
         this took ~10 s because forward_to_leader's self-RPC hairpin failure \
         was being papered over by an apply_topology retry loop",
        elapsed,
    );

    zm.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zone_manager_remove_zone_under_tokio_main() {
    // Phase 3: remove_zone bridges to the only inherently-async
    // registry op (awaits transport_handle JoinHandle for graceful
    // shutdown). On a tokio worker, naked block_on would panic;
    // bridge_block_on uses block_in_place to release the worker first.
    let tmp = TempDir::new().unwrap();
    let bind = ephemeral_bind_addr();
    let zm = ZoneManager::new(
        "regression-host",
        tmp.path().to_str().unwrap(),
        vec![],
        &bind,
        None,
    )
    .expect("ZoneManager::new");

    zm.create_zone("disposable", vec![]).expect("create_zone");

    zm.remove_zone("disposable", true)
        .expect("remove_zone must not panic on tokio worker");

    zm.shutdown();
}
