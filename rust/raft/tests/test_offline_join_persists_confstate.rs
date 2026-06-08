//! Regression: offline `nexusd-cluster join` MUST persist the
//! post-`JoinZone` ConfState before exiting.
//!
//! The CLI calls
//! `nexus_raft::distributed_coordinator::bootstrap_or_join_zone` (via
//! `spawn_blocking`) and then exits.  The function returns as soon as
//! the leader acks the `AddNode`/`AddLearnerNode` proposal, but the
//! joiner's local raft state only updates when raft-rs replays the
//! leader's AppendEntries through its `Ready` cycle.  Without an
//! explicit wait gate, the function returns while the joiner's
//! persisted state still reflects the pre-join `skip_bootstrap=true`
//! registration — `peers=0`, no leader, no log entries — and the next
//! daemon restart treats the zone as a "solo cluster of self".
//! Founder's heartbeats then flood
//! `raft: cannot step as peer not found`.
//!
//! The fix lives in `attempt_join_zone_round`: after a successful
//! `JoinZone` RPC, block until `leader_id().is_some()` AND
//! `commit_index() > 0` (the conf-change containing the joiner's
//! membership has been committed by raft-rs's apply loop, which
//! synchronously invokes `storage.set_conf_state(&cs)` for the
//! conf-change entry before `update_cached_status` refreshes
//! `cached_commit_index`).
//!
//! This test pins both contract points by:
//!
//!   1. Spinning up a single-voter founder ZoneManager with a sharedzone.
//!   2. Spinning up a separate joiner ZoneManager.
//!   3. Calling `bootstrap_or_join_zone` on the joiner with
//!      `as_learner=true` (the runbook §3b join shape).
//!   4. Asserting — IMMEDIATELY after the call returns, without any
//!      additional sleep — that the joiner's local raft state reflects
//!      the AddLearnerNode: `leader_id` is `Some(founder_id)` and
//!      `commit_index > 0`.
//!
//! Pre-fix the assertion would fail (both reads return defaults
//! because the leader's first AppendEntries hasn't landed yet).
//! Post-fix `bootstrap_or_join_zone` blocks until the conditions hold,
//! so the immediate assertion always passes.
//!
//! `applied_index` is NOT a usable signal here: `FullStateMachine`
//! only advances `last_applied` in the metadata-write path of
//! `sm.apply`, which conf-change entries bypass via `Command::Noop`.
//! A conf-only sequence would leave `applied_index` at 0 forever.
//! `commit_index` is the SSOT for "the apply_entries call (and its
//! set_conf_state write) has fired".

#![cfg(all(feature = "grpc", has_protos))]

use nexus_raft::distributed_coordinator::bootstrap_or_join_zone;
use nexus_raft::transport::NodeAddress;
use nexus_raft::ZoneManager;
use std::time::Duration;
use tempfile::TempDir;

const FOUNDER_HOSTNAME: &str = "joinpersist-founder";
const JOINER_HOSTNAME: &str = "joinpersist-joiner";
const ZONE_ID: &str = "sharedzone";

/// Pick a random unused TCP port on localhost so concurrent test
/// invocations don't collide on the raft gRPC bind.
fn ephemeral_bind_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("127.0.0.1:{port}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_join_persists_confstate_before_returning() {
    // -------------------------------------------------------------
    // 1. Founder — single-voter, owns the zone.
    // -------------------------------------------------------------
    let founder_dir = TempDir::new().expect("founder tmpdir");
    let founder_bind = ephemeral_bind_addr();
    let founder_self_addr = founder_bind.clone();
    let founder_zm = ZoneManager::new(
        FOUNDER_HOSTNAME,
        founder_dir.path().to_str().expect("utf-8 tmp path"),
        vec![],
        &founder_bind,
        None,
    )
    .expect("founder ZoneManager::new");

    founder_zm
        .create_zone(ZONE_ID, vec![])
        .expect("founder create_zone");

    // Give raft-rs's default election timer (~150 ms) plus a margin
    // to settle so the founder's `is_leader()` is stable before the
    // joiner starts pinging it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let founder_handle = founder_zm
        .get_zone(ZONE_ID)
        .expect("founder zone registered");
    assert!(
        founder_handle.wait_for_leader(Duration::from_secs(2)),
        "founder must self-elect on a 1-voter zone within 2 s"
    );
    let founder_node_id = founder_handle
        .leader_id()
        .expect("founder is leader of its own 1-voter zone");

    // -------------------------------------------------------------
    // 2. Joiner — fresh data dir, separate runtime/bind.
    // -------------------------------------------------------------
    let joiner_dir = TempDir::new().expect("joiner tmpdir");
    let joiner_bind = ephemeral_bind_addr();
    let joiner_self_addr = joiner_bind.clone();
    let joiner_zm = ZoneManager::new(
        JOINER_HOSTNAME,
        joiner_dir.path().to_str().expect("utf-8 tmp path"),
        vec![],
        &joiner_bind,
        None,
    )
    .expect("joiner ZoneManager::new");

    // -------------------------------------------------------------
    // 3. Invoke `bootstrap_or_join_zone` exactly as `run_join` does.
    //    The function is sync; the production CLI wraps it in
    //    spawn_blocking, so mirror that shape here so the test
    //    actually exercises the CLI-side contract.
    //
    //    Peer-string format mirrors runbook §3b's
    //    `<A_node_id>@<A_tailscale_ip>:2126` — `NodeAddress::parse`
    //    will derive the node id from `hostname_to_node_id(host)` if
    //    no `id@` prefix is given, which on localhost-IP test setups
    //    produces a node id that does NOT match the founder's actual
    //    id and breaks transport routing.  Carry the founder's real
    //    id explicitly.
    // -------------------------------------------------------------
    let founder_peer_str = format!("{founder_node_id}@{founder_self_addr}");
    let peer = NodeAddress::parse(&founder_peer_str, /* use_tls */ false)
        .expect("parse founder peer addr");
    let peer_addrs = vec![peer];
    let joiner_zm_for_task = joiner_zm.clone();
    let joiner_self_addr_for_task = joiner_self_addr.clone();
    let joiner_node_id = nexus_raft::transport::hostname_to_node_id(JOINER_HOSTNAME);

    tokio::task::spawn_blocking(move || {
        bootstrap_or_join_zone(
            joiner_zm_for_task.as_ref(),
            ZONE_ID,
            joiner_node_id,
            &joiner_self_addr_for_task,
            &peer_addrs,
            /* bootstrap_new */ false,
            /* max_attempts  */ Some(15),
            /* as_learner    */ true,
        )
    })
    .await
    .expect("join task panicked")
    .expect("bootstrap_or_join_zone");

    // -------------------------------------------------------------
    // 4. Contract check — must hold IMMEDIATELY after the call
    //    returns, with NO additional sleep.  Pre-fix both reads
    //    return defaults; the fix's wait gate makes them
    //    deterministic.
    // -------------------------------------------------------------
    let joiner_handle = joiner_zm
        .get_zone(ZONE_ID)
        .expect("joiner zone registered post-join");

    let observed_leader = joiner_handle.leader_id();
    let observed_commit = joiner_handle.commit_index();

    assert_eq!(
        observed_leader,
        Some(founder_node_id),
        "joiner must have observed the leader's AppendEntries before \
         the CLI exits — pre-fix this was None because \
         `attempt_join_zone_round` returned on the JoinZone ack \
         before the leader's first heartbeat arrived"
    );
    assert!(
        observed_commit > 0,
        "joiner's commit_index must be >0 before the CLI exits — \
         pre-fix it was 0 because the conf-change entry containing \
         the joiner's membership had not been processed by raft-rs's \
         apply loop, so `set_conf_state` had not been called and the \
         on-disk ConfState was still the skip_bootstrap stub"
    );

    // Cleanup — ordered so neither runtime drop races the other.
    drop(joiner_handle);
    drop(founder_handle);
    joiner_zm.shutdown();
    founder_zm.shutdown();
}
