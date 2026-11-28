use super::{RaftConfig, RaftMsg, ZoneConsensus, ZoneConsensusDriver};
use crate::raft::state_machine::FullStateMachine;
use crate::raft::storage::RaftStorage;
use crate::storage::RedbStore;
use raft::eraftpb::{ConfState, Message};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tempfile::TempDir;

pub(super) type Driver = ZoneConsensusDriver<FullStateMachine>;

pub(super) fn poll<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
}

pub(super) fn node(id: u64, voters: &[u64]) -> (ZoneConsensus<FullStateMachine>, Driver, TempDir) {
    let dir = TempDir::new().unwrap();
    let (handle, driver) = open_node(id, voters, dir.path());
    (handle, driver, dir)
}

pub(super) fn open_node(
    id: u64,
    voters: &[u64],
    directory: &std::path::Path,
) -> (ZoneConsensus<FullStateMachine>, Driver) {
    let storage = RaftStorage::open(directory).unwrap();
    if !voters.is_empty() {
        storage
            .set_conf_state(&ConfState {
                voters: voters.to_vec(),
                ..Default::default()
            })
            .unwrap();
    }
    let store = RedbStore::open(directory.join("sm")).unwrap();
    let state_machine = FullStateMachine::new(&store).unwrap();
    let config = RaftConfig {
        id,
        skip_bootstrap: !voters.is_empty(),
        // Elections are explicitly driven through the public handle.
        tick_interval: Duration::from_secs(3600),
        ..Default::default()
    };
    ZoneConsensus::new(config, storage, state_machine, None).unwrap()
}

pub(super) fn campaign(handle: &ZoneConsensus<FullStateMachine>, driver: &mut Driver) {
    let mut request = Box::pin(handle.campaign());
    assert!(poll(&mut request).is_pending());
    driver.process_messages();
    assert!(matches!(poll(&mut request), Poll::Ready(Ok(()))));
}

pub(super) struct Cluster {
    pub(super) handles: Vec<ZoneConsensus<FullStateMachine>>,
    pub(super) drivers: Vec<Driver>,
    pub(super) _dirs: Vec<TempDir>,
}

impl Cluster {
    pub(super) fn new() -> Self {
        Self::with_members(|id| node(id, &[1, 2, 3]))
    }

    pub(super) fn with_members(
        mut build: impl FnMut(u64) -> (ZoneConsensus<FullStateMachine>, Driver, TempDir),
    ) -> Self {
        let mut cluster = Self {
            handles: Vec::new(),
            drivers: Vec::new(),
            _dirs: Vec::new(),
        };
        for id in 1..=3 {
            let (handle, driver, dir) = build(id);
            cluster.handles.push(handle);
            cluster.drivers.push(driver);
            cluster._dirs.push(dir);
        }
        cluster
    }

    pub(super) async fn round(&mut self, mut deliver: impl FnMut(&Message) -> bool) {
        let mut outgoing = Vec::new();
        for driver in &mut self.drivers {
            driver.process_messages();
            let messages = driver.advance().await.unwrap();
            let protocol = driver.raft_message_protocol();
            outgoing.extend(messages.into_iter().map(|message| (protocol, message)));
        }
        for (protocol, msg) in outgoing {
            if deliver(&msg) {
                let (tx, _) = tokio::sync::oneshot::channel();
                self.handles[msg.to as usize - 1]
                    .msg_tx
                    .try_send(RaftMsg::StepTransport { msg, protocol, tx })
                    .unwrap();
            }
        }
    }

    pub(super) async fn elect(&mut self, candidate: usize) {
        campaign(&self.handles[candidate], &mut self.drivers[candidate]);
        for _ in 0..12 {
            self.round(|_| true).await;
        }
        assert!(self.handles[candidate].is_leader());
        assert!(self
            .drivers
            .iter()
            .all(|driver| driver.raw_node.raft.commit_to_current_term()));
    }
}
