//! A failed durable apply stops the actor, retains its suffix and replays it
//! after reopening. Actual Raft/redb are used with one injected apply failure.
#![cfg(all(feature = "grpc", has_protos))]

use nexus_raft::{
    raft::{
        Command, CommandResult, FullStateMachine, MembershipPolicy, RaftConfig, RaftError,
        RaftStorage, Result, StateMachine, ZoneConsensus, ZoneConsensusDriver,
    },
    storage::RedbStore,
    transport::{PeerMap, RaftClientPool, TransportLoop},
};
use raft::{eraftpb::Entry, Storage};
use std::{
    path::Path,
    sync::{atomic::AtomicU64, Arc, RwLock},
    time::Duration,
};

struct ApplyFault {
    inner: FullStateMachine,
    fail: bool,
}

impl StateMachine for ApplyFault {
    fn apply(&mut self, index: u64, command: &Command) -> Result<CommandResult> {
        if self.fail && matches!(command, Command::SetMetadata { key, .. } if key == "/failure") {
            return Err(RaftError::Storage("injected durable apply failure".into()));
        }
        self.inner.apply(index, command)
    }
    fn snapshot(&self) -> Result<Vec<u8>> {
        self.inner.snapshot()
    }
    fn restore_snapshot(&mut self, data: &[u8]) -> Result<()> {
        self.inner.restore_snapshot(data)
    }
    fn last_applied_index(&self) -> u64 {
        self.inner.last_applied_index()
    }
    fn last_applied_shared(&self) -> Option<Arc<AtomicU64>> {
        self.inner.last_applied_shared()
    }
}

fn open(path: &Path, fail: bool) -> (ZoneConsensus<ApplyFault>, ZoneConsensusDriver<ApplyFault>) {
    let storage = RaftStorage::open(path.join("raft")).unwrap();
    let store = RedbStore::open(path.join("state")).unwrap();
    ZoneConsensus::new(
        RaftConfig {
            id: 1,
            ..Default::default()
        },
        storage,
        ApplyFault {
            inner: FullStateMachine::new(&store).unwrap(),
            fail,
        },
        None,
    )
    .unwrap()
}

async fn ready(node: &ZoneConsensus<ApplyFault>, driver: &mut ZoneConsensusDriver<ApplyFault>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            driver.process_messages();
            driver.advance().await.unwrap();
            if node.is_leader() && node.applied_index() == node.last_index() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

fn write(path: &str) -> Command {
    Command::SetMetadata {
        key: path.into(),
        value: path.as_bytes().to_vec(),
    }
}

#[tokio::test]
async fn failed_apply_keeps_the_committed_suffix_for_cold_replay() {
    let directory = tempfile::tempdir().unwrap();
    let before;
    {
        let (node, mut driver) = open(directory.path(), true);
        ready(&node, &mut driver).await;
        before = node.applied_index();
        let caller = node.clone();
        let failed = tokio::spawn(async move { caller.propose(write("/failure")).await });
        assert!(driver.recv_and_handle().await);
        let caller = node.clone();
        let later = tokio::spawn(async move { caller.propose(write("/later")).await });
        assert!(driver.recv_and_handle().await);
        let error = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match driver.advance().await {
                    Err(error) => break error,
                    Ok(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .unwrap();
        assert!(error.to_string().contains("injected durable apply failure"));
        assert_eq!(node.applied_index(), before);
        assert!(!node.is_leader());
        for request in [failed, later] {
            assert!(tokio::time::timeout(Duration::from_secs(5), request)
                .await
                .unwrap()
                .unwrap()
                .is_err());
        }
        assert!(driver.advance().await.is_err());
        assert_eq!(node.applied_index(), before);
        assert!(tokio::time::timeout(
            Duration::from_secs(5),
            node.read_linearizable(StateMachine::last_applied_index)
        )
        .await
        .expect("failed driver retained a linearizable read")
        .is_err());
        assert!(node
            .with_state_machine(|s| s.inner.get_metadata("/later").unwrap())
            .await
            .is_none());
    }
    {
        let storage = RaftStorage::open(directory.path().join("raft")).unwrap();
        let commit = storage.initial_state_impl().unwrap().hard_state.commit;
        assert!(
            commit >= before + 2,
            "LightReady commit must precede application"
        );
        assert!(
            storage.first_index_impl().unwrap() <= before + 1,
            "failed suffix was compacted"
        );
        assert!(storage.last_index_impl().unwrap() >= commit);
    }
    let (node, mut driver) = open(directory.path(), false);
    ready(&node, &mut driver).await;
    for key in ["/failure", "/later"] {
        assert_eq!(
            node.with_state_machine(|s| s.inner.get_metadata(key).unwrap())
                .await,
            Some(key.as_bytes().to_vec())
        );
    }
    assert!(node.applied_index() >= before + 2);
}

#[tokio::test]
async fn transport_loop_terminates_and_releases_requests_after_apply_failure() {
    let directory = tempfile::tempdir().unwrap();
    let (node, mut driver) = open(directory.path(), true);
    ready(&node, &mut driver).await;
    let peers = Arc::new(RwLock::new(PeerMap::with_peers(1, Default::default())));
    let transport = TransportLoop::new(driver, peers, RaftClientPool::new());
    let (_shutdown, receiver) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(transport.run(receiver));
    assert!(
        tokio::time::timeout(Duration::from_secs(5), node.propose(write("/failure")))
            .await
            .unwrap()
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("failed driver kept running")
        .unwrap();
    assert!(!node.is_leader());
    assert!(
        tokio::time::timeout(Duration::from_secs(5), node.propose(write("/later")))
            .await
            .unwrap()
            .is_err()
    );
    assert!(node
        .with_state_machine(|s| s.inner.get_metadata("/later").unwrap())
        .await
        .is_none());
}

#[test]
fn both_membership_policies_refuse_malformed_normal_history_before_starting() {
    for policy in [MembershipPolicy::FixedLocal, MembershipPolicy::Managed] {
        for bytes in [vec![1], vec![0; 7], vec![0; 8], vec![255; 12]] {
            let directory = tempfile::tempdir().unwrap();
            let storage = RaftStorage::open(directory.path().join("raft")).unwrap();
            storage
                .set_conf_state(&raft::eraftpb::ConfState {
                    voters: vec![1],
                    ..Default::default()
                })
                .unwrap();
            let original = Entry {
                index: 1,
                term: 1,
                data: bytes.into(),
                ..Default::default()
            };
            storage.append(std::slice::from_ref(&original)).unwrap();
            let store = RedbStore::open(directory.path().join("state")).unwrap();
            let state = FullStateMachine::new(&store).unwrap();
            assert!(ZoneConsensus::new(
                RaftConfig {
                    id: 1,
                    membership_policy: policy,
                    ..Default::default()
                },
                storage,
                state,
                None
            )
            .is_err());
            let storage = RaftStorage::open(directory.path().join("raft")).unwrap();
            assert_eq!(
                storage
                    .entries(1, 2, None, raft::GetEntriesContext::empty(false))
                    .unwrap(),
                vec![original]
            );
        }
    }
}
