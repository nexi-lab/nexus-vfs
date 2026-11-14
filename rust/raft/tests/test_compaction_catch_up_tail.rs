//! A learner a few entries behind when the leader compacts is caught up by
//! appends, not by a snapshot.
//!
//! A single-voter zone commits and compacts on the leader's own append, so at
//! each compaction a learner's last few entries are typically still in
//! flight. Compacting the whole log up to the applied index left those entries
//! below `first_index`, and every compaction then needed an InstallSnapshot of
//! the whole zone. Production showed one per compaction, about every 18
//! minutes, on a learner at lag 0 between them. The leader now keeps a
//! catch-up tail of half the compaction threshold.
//!
//! Topology: a founder (sole voter, leader) and a learner behind a
//! [`LossyLink`]. Every write happens while the link starves the learner, so
//! every compaction happens with the learner behind, by at most `LAG` entries.
//! The link then heals and the learner catches up before the next write window.
//! The link refuses any snapshot while starving and counts any it forwards, so
//! a snapshot attempt in either mode is visible.

#![cfg(all(feature = "grpc", has_protos))]

mod common;
#[path = "common/lossy_link.rs"]
mod lossy_link;

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use lossy_link::{LossyLink, PASS, STARVE};
use nexus_raft::prelude::{Command, FullStateMachine, RaftStorage, ZoneConsensus};
use nexus_raft::transport::call_join_zone_rpc;
use nexus_raft::ZoneManager;
use tempfile::TempDir;

const ZONE: &str = "sharedzone";
const SNAPSHOT_THRESHOLD: u64 = 16;
/// Entries written per starved window; below the tail of `SNAPSHOT_THRESHOLD / 2`.
const LAG: u64 = 3;
const BUDGET: Duration = Duration::from_secs(30);

fn node_dir() -> (TempDir, u64) {
    let dir = TempDir::new().expect("node dir");
    let id = loop {
        let id = rand::random::<u64>();
        if id != 0 {
            break id;
        }
    };
    std::fs::write(dir.path().join(".node_id"), id.to_be_bytes()).expect("write .node_id");
    (dir, id)
}

async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + BUDGET;
    while !done() {
        assert!(Instant::now() < deadline, "{what} within {BUDGET:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn write(node: &ZoneConsensus<FullStateMachine>, key: &str) {
    node.propose(Command::SetMetadata {
        key: key.to_string(),
        value: key.as_bytes().to_vec(),
    })
    .await
    .unwrap_or_else(|error| panic!("write {key}: {error}"));
}

/// The zone's raft log directory under a node's data directory.
fn raft_dir(root: &Path) -> PathBuf {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read node dir").flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if path.file_name().is_some_and(|name| name == "raft")
                && path
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|zone| zone == ZONE)
            {
                return path;
            }
            pending.push(path);
        }
    }
    panic!("no {ZONE}/raft under {}", root.display());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_learner_behind_by_a_few_entries_at_compaction_catches_up_by_appends() {
    // This binary's own process: no other test reads the variable.
    std::env::set_var(
        "NEXUS_SC_SNAPSHOT_THRESHOLD",
        SNAPSHOT_THRESHOLD.to_string(),
    );

    let (leader_dir, leader_id) = node_dir();
    let leader_bind = common::node_bind_addr();
    let leader_zm = ZoneManager::with_node_id(
        "leader",
        leader_id,
        leader_dir.path().to_str().unwrap(),
        vec![],
        &leader_bind,
        None,
        Some(leader_bind.clone()),
        None,
    )
    .expect("leader");
    let leader = leader_zm
        .create_zone(ZONE)
        .expect("create zone")
        .consensus_node();
    eventually("the founder elects itself", || leader.is_leader()).await;

    let (learner_dir, learner_id) = node_dir();
    let learner_bind = common::node_bind_addr();
    let link_addr = common::node_bind_socket_addr();
    let link = LossyLink::start(link_addr, &learner_bind).await;
    let learner_zm = ZoneManager::with_node_id(
        "learner",
        learner_id,
        learner_dir.path().to_str().unwrap(),
        vec![],
        &learner_bind,
        None,
        Some(link_addr.to_string()),
        None,
    )
    .expect("learner");
    let learner = learner_zm
        .join_zone(ZONE, true)
        .expect("learner join_zone")
        .consensus_node();
    let joined = call_join_zone_rpc(
        &format!("http://{leader_bind}"),
        ZONE,
        learner_id,
        &format!("http://{link_addr}"),
        true,
        None,
        30,
    )
    .await
    .expect("JoinZone RPC");
    assert!(joined.success, "JoinZone: {:?}", joined.error);
    write(&leader, "/joined").await;
    eventually("the learner replicates through the link", || {
        learner.applied_index() >= leader.applied_index()
    })
    .await;
    let forwarded_before = link.snapshots_forwarded.load(Ordering::SeqCst);

    // Enough windows for several compactions, each with the learner behind.
    let windows = 4 * SNAPSHOT_THRESHOLD / LAG + 1;
    for window in 0..windows {
        link.set(STARVE);
        for i in 0..LAG {
            write(&leader, &format!("/w{window}/{i}")).await;
        }
        link.set(PASS);
        eventually("the learner catches up after the window", || {
            learner.applied_index() >= leader.applied_index()
        })
        .await;
    }

    assert_eq!(
        link.snapshots_refused.load(Ordering::SeqCst),
        0,
        "no compaction left the starved learner needing a snapshot"
    );
    assert_eq!(
        link.snapshots_forwarded.load(Ordering::SeqCst),
        forwarded_before,
        "the learner was caught up by appends only"
    );

    let applied = leader.applied_index();
    learner_zm.shutdown();
    leader_zm.shutdown();
    // Release every handle on the leader's stores before reopening its log.
    drop((leader, learner, leader_zm, learner_zm));

    // The leader did compact, and kept the catch-up tail behind its snapshot.
    let storage = RaftStorage::open(raft_dir(leader_dir.path())).expect("reopen leader log");
    let first = storage.first_index_impl().expect("first index");
    assert!(
        first > 1,
        "the leader compacted its log (first index {first})"
    );
    assert!(
        applied + 1 - first >= SNAPSHOT_THRESHOLD / 2,
        "a catch-up tail of at least {} entries stays behind applied {applied} (first index {first})",
        SNAPSHOT_THRESHOLD / 2
    );
}
