//! Member addresses are replicated state: a restarted member reaches every
//! member its ConfState names from the zone's own records
//! (`docs/member-address.md`).
//!
//! The production failure this pins: a sole voter restarted after its log was
//! compacted past the learner's `AddLearnerNode` entry, with no `--peers`, and
//! dropped every message for the learner — the learner never initiates, so
//! nothing ever taught the leader its address, and the learner served stale
//! reads indefinitely.
//!
//! A dedicated binary: `NEXUS_SC_SNAPSHOT_THRESHOLD` is read in
//! `ZoneConsensus::new`, so it is set once per process before any zone opens.

#![cfg(all(feature = "grpc", has_protos))]

mod common;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nexus_raft::prelude::Command;
use nexus_raft::raft::{RaftStorage, StateMachine};
use nexus_raft::transport::{call_join_zone_rpc, ClientConfig, RaftApiClient};
use nexus_raft::ZoneManager;
use raft::eraftpb::ConfChangeType;
use raft::Storage;
use tempfile::TempDir;

const ZONE: &str = "sharedzone";
/// Small enough that a few dozen writes compact past the membership entries.
const SNAPSHOT_THRESHOLD: &str = "16";
const WRITES_PAST_THRESHOLD: usize = 48;
const BUDGET: Duration = Duration::from_secs(30);

fn configure_compaction() {
    std::env::set_var("NEXUS_SC_SNAPSHOT_THRESHOLD", SNAPSHOT_THRESHOLD);
}

/// One node's durable identity: its id, data directory and advertise/bind
/// address. A restart reuses all three unless the test moves it on purpose.
struct Node {
    id: u64,
    dir: TempDir,
    bind: String,
}

impl Node {
    fn new() -> Self {
        let dir = TempDir::new().expect("node dir");
        let id = loop {
            let id = rand::random::<u64>();
            if id != 0 {
                break id;
            }
        };
        std::fs::write(dir.path().join(".node_id"), id.to_be_bytes()).expect("write .node_id");
        Self {
            id,
            dir,
            bind: common::node_bind_addr(),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.bind)
    }

    fn raft_dir(&self) -> PathBuf {
        self.dir.path().join(ZONE).join("raft")
    }

    /// Start (or restart) this node. `seeds` are the operator `--peers`.
    async fn start(&self, seeds: Vec<String>) -> Arc<ZoneManager> {
        wait_until_bindable(&self.bind).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match ZoneManager::with_node_id(
                "member-address-ssot",
                self.id,
                self.dir.path().to_str().expect("utf-8 dir"),
                seeds.clone(),
                &self.bind,
                None,
                Some(self.bind.clone()),
                None,
            ) {
                Ok(manager) => return manager,
                Err(nexus_raft::raft::RaftError::DataDirLocked(_)) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("start node {}: {error}", self.id),
            }
        }
    }
}

/// A restarted node binds the same address; the previous listener must be
/// gone first (a failed bind ends the process).
async fn wait_until_bindable(bind: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpListener::bind(bind).is_err() {
        assert!(Instant::now() < deadline, "{bind} still bound");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn stop(manager: Arc<ZoneManager>) {
    tokio::task::spawn_blocking(move || manager.shutdown())
        .await
        .expect("shutdown");
}

async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + BUDGET;
    while !check().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn consensus(
    manager: &ZoneManager,
) -> nexus_raft::raft::ZoneConsensus<nexus_raft::raft::FullStateMachine> {
    manager
        .get_zone(ZONE)
        .expect("zone hosted here")
        .consensus_node()
}

async fn records(manager: &ZoneManager) -> Vec<(u64, String)> {
    let mut records = consensus(manager)
        .with_state_machine(|sm| sm.member_addresses().unwrap())
        .await;
    records.sort();
    records
}

async fn has_key(manager: &ZoneManager, key: &str) -> bool {
    consensus(manager)
        .with_state_machine(|sm| sm.get_metadata(key).unwrap().is_some())
        .await
}

async fn write(manager: &ZoneManager, key: &str) {
    consensus(manager)
        .propose(Command::SetMetadata {
            key: key.to_string(),
            value: key.as_bytes().to_vec(),
        })
        .await
        .unwrap_or_else(|e| panic!("write {key}: {e}"));
}

async fn found(node: &Node, seeds: Vec<String>) -> Arc<ZoneManager> {
    let manager = node.start(seeds).await;
    manager.create_zone(ZONE).expect("create zone");
    await_leader(&manager, node.id).await;
    manager
}

async fn await_leader(manager: &ZoneManager, id: u64) {
    eventually("the sole voter to lead", || async {
        consensus(manager).leader_id() == Some(id)
    })
    .await;
}

/// Join `learner` to the zone led by `leader`, advertising `advertised` in
/// the JoinZone request (the AddLearnerNode context).
async fn join_as_learner(manager: &ZoneManager, learner: &Node, leader: &Node, advertised: &str) {
    manager.join_zone(ZONE, true).expect("local join_zone");
    let joined = call_join_zone_rpc(
        &leader.endpoint(),
        ZONE,
        learner.id,
        advertised,
        true,
        None,
        30,
    )
    .await
    .expect("JoinZone RPC");
    assert!(joined.success, "JoinZone: {:?}", joined.error);
}

async fn wait_for_records(manager: &ZoneManager, expected: &[(u64, &str)], whose: &str) {
    let mut expected: Vec<(u64, String)> = expected
        .iter()
        .map(|(id, address)| (*id, address.to_string()))
        .collect();
    expected.sort();
    eventually(whose, || {
        let expected = expected.clone();
        async move { records(manager).await == expected }
    })
    .await;
}

/// The stopped node's first retained log index. Storage handles release
/// asynchronously after shutdown, so the reopen retries the lock only.
async fn first_retained_index(raft_dir: &Path) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match RaftStorage::open(raft_dir) {
            Ok(storage) => return storage.first_index().expect("first index"),
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "raft storage still locked: {error}"
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }
}

/// Restart `node` and make its zone resident, as a daemon does when it
/// serves the zone's mount.
async fn restart_member(node: &Node, seeds: Vec<String>) -> Arc<ZoneManager> {
    let manager = node.start(seeds).await;
    // The previous runtime releases the zone's store asynchronously; until
    // then materialization reports the zone absent.
    eventually("the restarted zone to become resident", || async {
        manager.get_zone(ZONE).is_some()
    })
    .await;
    manager
}

async fn cluster_info(endpoint: &str) -> nexus_raft::transport::ClusterInfoResult {
    RaftApiClient::connect(endpoint, ClientConfig::default())
        .await
        .expect("connect")
        .with_zone_id(ZONE.into())
        .get_cluster_info()
        .await
        .expect("GetClusterInfo")
}

/// The production failure, end to end: compaction drops the learner's
/// membership entry from the founder's log, the founder restarts alone
/// with no seeds, and its next write still reaches the learner — routed by
/// the replicated record, since a learner never sends first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_founder_reaches_its_learner_after_compaction() {
    configure_compaction();
    let founder = Node::new();
    let learner = Node::new();
    let founder_zm = found(&founder, Vec::new()).await;
    let learner_zm = learner.start(Vec::new()).await;
    join_as_learner(&learner_zm, &learner, &founder, &learner.bind).await;
    let membership_index = consensus(&founder_zm).applied_index();

    let both = [
        (founder.id, founder.bind.as_str()),
        (learner.id, learner.bind.as_str()),
    ];
    wait_for_records(&founder_zm, &both, "the founder's records").await;
    // The learner holding its own record means its self-registration has
    // finished: from here on it only answers its leader, never sends first.
    wait_for_records(&learner_zm, &both, "the learner's records").await;

    for i in 0..WRITES_PAST_THRESHOLD {
        write(&founder_zm, &format!("/before/{i}")).await;
    }
    let last = format!("/before/{}", WRITES_PAST_THRESHOLD - 1);
    eventually("the learner to replicate the first batch", || {
        has_key(&learner_zm, &last)
    })
    .await;

    stop(founder_zm).await;
    let first = first_retained_index(&founder.raft_dir()).await;
    assert!(
        first > membership_index,
        "the founder's log must be compacted past the membership entries \
         (first retained index {first}, membership applied at {membership_index})"
    );

    let founder_zm = restart_member(&founder, Vec::new()).await;
    await_leader(&founder_zm, founder.id).await;
    assert_eq!(
        founder_zm
            .registry()
            .get_peers(ZONE)
            .unwrap()
            .get(&learner.id)
            .map(|route| route.endpoint.clone()),
        Some(learner.endpoint()),
        "the restarted founder routes to its learner from the record"
    );
    write(&founder_zm, "/after-restart").await;
    eventually(
        "the learner to receive a write made after the restart",
        || has_key(&learner_zm, "/after-restart"),
    )
    .await;
    assert_eq!(
        founder_zm.cluster_status(ZONE).leader_contact_age_ms,
        Some(0),
        "the leader is its own leader"
    );
    let heard = learner_zm
        .cluster_status(ZONE)
        .leader_contact_age_ms
        .expect("the learner heard from its leader");
    assert!(
        heard < 5_000,
        "the learner heard from its leader {heard} ms ago"
    );

    let info = cluster_info(&founder.endpoint()).await;
    let config = info.config.expect("cluster config");
    let learners: Vec<(u64, String)> = config
        .learners
        .iter()
        .map(|node| (node.id, node.address.clone()))
        .collect();
    assert_eq!(learners, vec![(learner.id, learner.endpoint())]);
    let voters: Vec<(u64, String)> = config
        .voters
        .iter()
        .map(|node| (node.id, node.address.clone()))
        .collect();
    assert_eq!(voters, vec![(founder.id, founder.endpoint())]);

    stop(learner_zm).await;
    stop(founder_zm).await;
}

/// Today's production state: the learner is in the founder's ConfState but
/// no record names its address (it joined without one, and the founder's log
/// is compacted). Restarted with a seed, the learner registers itself through
/// that seed and replication resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_without_a_record_registers_through_a_seed_after_restart() {
    configure_compaction();
    let founder = Node::new();
    let learner = Node::new();
    let founder_zm = found(&founder, Vec::new()).await;
    let learner_zm = learner.start(Vec::new()).await;
    // An empty JoinZone address: the membership commits with no record.
    join_as_learner(&learner_zm, &learner, &founder, "").await;
    wait_for_records(
        &founder_zm,
        &[(founder.id, founder.bind.as_str())],
        "the founder's own record only",
    )
    .await;
    for i in 0..WRITES_PAST_THRESHOLD {
        write(&founder_zm, &format!("/before/{i}")).await;
    }
    assert!(
        !founder_zm
            .registry()
            .get_peers(ZONE)
            .unwrap()
            .contains_key(&learner.id),
        "the founder has no route to an unregistered learner that never sent"
    );
    assert!(!has_key(&learner_zm, "/before/0").await);
    stop(learner_zm).await;

    let learner_zm = restart_member(&learner, vec![founder.bind.clone()]).await;
    let both = [
        (founder.id, founder.bind.as_str()),
        (learner.id, learner.bind.as_str()),
    ];
    wait_for_records(
        &founder_zm,
        &both,
        "the learner's registration on the founder",
    )
    .await;
    write(&founder_zm, "/after-registration").await;
    eventually("the registered learner to catch up", || {
        has_key(&learner_zm, "/after-registration")
    })
    .await;
    wait_for_records(&learner_zm, &both, "the learner's own replicated records").await;

    stop(learner_zm).await;
    stop(founder_zm).await;
}

/// A member restarted on a new port updates its record; the leader routes to
/// the new address once the put commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_restarted_on_a_new_port_is_reachable_again() {
    configure_compaction();
    let founder = Node::new();
    let mut learner = Node::new();
    let founder_zm = found(&founder, Vec::new()).await;
    let learner_zm = learner.start(Vec::new()).await;
    join_as_learner(&learner_zm, &learner, &founder, &learner.bind).await;
    let old_bind = learner.bind.clone();
    wait_for_records(
        &learner_zm,
        &[
            (founder.id, founder.bind.as_str()),
            (learner.id, old_bind.as_str()),
        ],
        "the learner's records",
    )
    .await;
    stop(learner_zm).await;

    // No seeds: the learner reaches the founder through its replicated record.
    learner.bind = common::node_bind_addr();
    let learner_zm = restart_member(&learner, Vec::new()).await;
    let moved = [
        (founder.id, founder.bind.as_str()),
        (learner.id, learner.bind.as_str()),
    ];
    wait_for_records(
        &founder_zm,
        &moved,
        "the moved learner's record on the founder",
    )
    .await;
    write(&founder_zm, "/after-move").await;
    eventually("the moved learner to receive new writes", || {
        has_key(&learner_zm, "/after-move")
    })
    .await;
    let info = cluster_info(&founder.endpoint()).await;
    assert_eq!(
        info.config
            .expect("cluster config")
            .learners
            .iter()
            .map(|node| (node.id, node.address.clone()))
            .collect::<Vec<_>>(),
        vec![(learner.id, learner.endpoint())]
    );

    stop(learner_zm).await;
    stop(founder_zm).await;
}

/// RemoveNode deletes the member's record in the same apply as the change:
/// the record is gone the moment the committed removal returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_node_deletes_the_record_with_the_membership() {
    configure_compaction();
    let founder = Node::new();
    let learner = Node::new();
    let founder_zm = found(&founder, Vec::new()).await;
    let learner_zm = learner.start(Vec::new()).await;
    join_as_learner(&learner_zm, &learner, &founder, &learner.bind).await;
    wait_for_records(
        &founder_zm,
        &[
            (founder.id, founder.bind.as_str()),
            (learner.id, learner.bind.as_str()),
        ],
        "both records",
    )
    .await;

    let leader = consensus(&founder_zm);
    let membership = leader
        .propose_conf_change(ConfChangeType::RemoveNode, learner.id, Vec::new())
        .await
        .expect("RemoveNode commits");
    assert!(membership.learners.is_empty());
    assert_eq!(
        records(&founder_zm).await,
        vec![(founder.id, founder.bind.clone())],
        "the applied removal took the record with it"
    );
    eventually(
        "the removed member's route to leave the peer map",
        || async {
            !founder_zm
                .registry()
                .get_peers(ZONE)
                .unwrap()
                .contains_key(&learner.id)
        },
    )
    .await;

    stop(learner_zm).await;
    stop(founder_zm).await;
}
