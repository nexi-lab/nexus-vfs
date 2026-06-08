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
use nexus_raft::raft::RaftStorage;
use nexus_raft::transport::NodeAddress;
use nexus_raft::ZoneManager;
use raft::Storage;
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
    let founder_node_id_seed = nexus_raft::transport::hostname_to_node_id(FOUNDER_HOSTNAME);
    let founder_zm = ZoneManager::with_node_id(
        FOUNDER_HOSTNAME,
        founder_node_id_seed,
        founder_dir.path().to_str().expect("utf-8 tmp path"),
        vec![],
        &founder_bind,
        None,
        // Production nexusd-cluster always passes Some(self_address).
        // Pre-populating registry.self_address() is what the bootstrap
        // entry's `context` field reads from — without it the entry
        // ships with empty context, joiner replay learns ConfState but
        // not the founder's address, and the L1 cross-machine read
        // milestone wedges (see RaftConfig::bootstrap_self_address).
        Some(founder_self_addr.clone()),
        None,
    )
    .expect("founder ZoneManager::with_node_id");

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
    let joiner_node_id_seed = nexus_raft::transport::hostname_to_node_id(JOINER_HOSTNAME);
    let joiner_zm = ZoneManager::with_node_id(
        JOINER_HOSTNAME,
        joiner_node_id_seed,
        joiner_dir.path().to_str().expect("utf-8 tmp path"),
        vec![],
        &joiner_bind,
        None,
        Some(joiner_self_addr.clone()),
        None,
    )
    .expect("joiner ZoneManager::with_node_id");

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
    let joiner_node_id = joiner_node_id_seed;

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

    // Capture the joiner's zone path BEFORE shutdown so we can re-open
    // the RaftStorage in isolation.
    let joiner_zone_raft_path = joiner_dir.path().join(ZONE_ID).join("raft");

    // Cleanup — ordered so neither runtime drop races the other.
    drop(joiner_handle);
    drop(founder_handle);
    joiner_zm.shutdown();
    founder_zm.shutdown();

    // -------------------------------------------------------------
    // 5. Stricter contract check — read the joiner's PERSISTED
    //    ConfState directly off disk and assert it contains the
    //    founder as voter.
    //
    //    Why this is the right SSOT signal:
    //
    //    Pre-fix #31 the wait gate (commit_index > 0 + leader_id
    //    Some) could fire while the joiner's actual ConfState was
    //    still empty.  raft-rs's apply path silently skips a
    //    rejected ConfChange ("removed all voters" — see
    //    raft-0.7.0/src/confchange/changer.rs:181) but still
    //    advances commit_index.  So the gate said "applied" while
    //    the storage's ConfState voters list was still [], which
    //    meant the joiner thought it was a standalone cluster of
    //    nothing and downstream catchup never converged.
    //
    //    The fix seeds the joiner's local ConfState with the
    //    peer-list voter id BEFORE raft starts (see
    //    `ZoneRaftRegistry::join_zone` in
    //    `rust/raft/src/raft/zone_registry.rs`).  Replay of the
    //    leader's AppendEntries then applies AddLearnerNode-for-
    //    self on top of voters=[founder] → voters=[founder],
    //    learners=[joiner] — no rejection, ConfState is consistent
    //    with the leader's authoritative view.
    // -------------------------------------------------------------
    // `shutdown()` signals the transport loop + registry workers but the
    // underlying redb file lock is released only when the last
    // `Arc<RaftStorage>` drops on the worker threads.  A fixed-duration
    // sleep here would be flaky — instead, poll until the file is
    // openable or a generous deadline elapses.  If the deadline trips,
    // that's a real shutdown bug to surface, not a timing flake.
    let lock_release_deadline = std::time::Instant::now() + Duration::from_secs(5);
    let joiner_storage = loop {
        match RaftStorage::open(&joiner_zone_raft_path) {
            Ok(s) => break s,
            Err(e) if std::time::Instant::now() < lock_release_deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => panic!(
                "joiner raft storage still locked 5s after ZoneManager::shutdown() — \
                 likely a shutdown bug, not a test timing issue: {e}",
            ),
        }
    };
    let persisted = joiner_storage
        .initial_state()
        .expect("read joiner initial state");
    assert!(
        persisted.conf_state.voters.contains(&founder_node_id),
        "joiner's persisted ConfState must contain the founder as a voter \
         (post-replay of AddLearnerNode-for-self should not remove the only \
         voter).  Pre-fix this list was empty because (a) the joiner's local \
         ConfState was never seeded with the leader, and (b) raft-rs's \
         Changer::simple rejects any ConfChange that leaves voters empty, \
         silently dropping the AddLearnerNode-for-self entry.  \
         Observed voters: {:?}, learners: {:?}; expected founder id: {}",
        persisted.conf_state.voters,
        persisted.conf_state.learners,
        founder_node_id,
    );
    assert!(
        persisted.conf_state.learners.contains(&joiner_node_id),
        "joiner's persisted ConfState must list the joiner itself as a learner \
         (the AddLearnerNode entry that was committed by the leader for \
         joiner_node_id={joiner_node_id} during JoinZone).  Observed voters: {:?}, \
         learners: {:?}",
        persisted.conf_state.voters,
        persisted.conf_state.learners,
    );

    // -------------------------------------------------------------
    // 6. Stronger contract — the founder's bootstrap log entry at
    //    index 1 must carry the founder's advertise address in its
    //    `context` field.  On daemon restart the joiner re-runs the
    //    apply loop over all committed entries (raft-rs's default
    //    `applied = first_index - 1 = 0`) which calls
    //    `node_address_from_conf_context` per entry to repopulate
    //    `peer_map`.  Without the address in context the joiner
    //    finishes restart with ConfState=[founder, joiner-learner]
    //    but no way to dial the founder; the transport loop has no
    //    heartbeat target and `leader_id` never stabilises locally —
    //    exactly the symptom the L1 cross-machine read milestone
    //    was failing on before this commit.
    // -------------------------------------------------------------
    let log_entries = joiner_storage
        .entries(1, 2, None, raft::GetEntriesContext::empty(false))
        .expect("read joiner log entry 1");
    let bootstrap_entry = log_entries
        .first()
        .expect("joiner's log must contain entry 1 after AppendEntries replay");
    assert_eq!(
        bootstrap_entry.entry_type,
        raft::eraftpb::EntryType::EntryConfChange,
        "bootstrap entry must be EntryConfChange — observed: {:?}",
        bootstrap_entry.entry_type,
    );
    let cc: raft::eraftpb::ConfChange = protobuf::Message::parse_from_bytes(&bootstrap_entry.data)
        .expect("decode ConfChange from bootstrap entry");
    assert_eq!(
        cc.node_id, founder_node_id,
        "bootstrap entry must add the founder — observed node_id: {}",
        cc.node_id,
    );
    let cc_address = std::str::from_utf8(&cc.context).expect("context must be valid UTF-8");
    assert!(
        cc_address.contains(&founder_self_addr),
        "bootstrap entry's context must carry the founder's advertise address ({founder_self_addr:?}) \
         so a joiner's apply populates its peer_map with (founder_id -> founder_address) via \
         node_address_from_conf_context.  Observed context: {cc_address:?}",
    );
}
