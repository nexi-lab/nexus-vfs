//! Admission of linearizable reads into the driver's Raft ReadIndex protocol.

use super::{Result, StateMachine, ZoneConsensusDriver};
use tokio::sync::oneshot;

pub(super) type ReadContext = [u8; 32];

/// Raft echoes an opaque context across nodes and retains it until quorum.
/// Keep each driver's request space separate across nodes and restarts.
pub(super) struct ReadRequestIds {
    prefix: [u8; 24],
    next: Option<u64>,
}

impl ReadRequestIds {
    pub(super) fn new(node_id: u64) -> Self {
        let mut prefix = [0; 24];
        prefix[..8].copy_from_slice(&node_id.to_be_bytes());
        prefix[8..].copy_from_slice(&rand::random::<[u8; 16]>());
        Self {
            prefix,
            next: Some(0),
        }
    }

    pub(super) fn allocate(&mut self) -> Option<ReadContext> {
        let next = self.next?;
        self.next = next.checked_add(1);
        let mut context = [0; 32];
        context[..24].copy_from_slice(&self.prefix);
        context[24..].copy_from_slice(&next.to_be_bytes());
        Some(context)
    }
}

pub(super) struct PendingRead {
    pub(super) tx: oneshot::Sender<Result<()>>,
    submitted_term: Option<u64>,
}

impl PendingRead {
    pub(super) fn new(tx: oneshot::Sender<Result<()>>) -> Self {
        Self {
            tx,
            submitted_term: None,
        }
    }
}

impl<S: StateMachine + 'static> ZoneConsensusDriver<S> {
    pub(super) fn submit_ready_reads(&mut self) {
        self.pending_reads_by_ctx
            .retain(|_, request| !request.tx.is_closed());
        if self.pending_reads_by_ctx.is_empty()
            || self.raw_node.raft.leader_id == 0
            || !self.raw_node.raft.commit_to_current_term()
        {
            return;
        }

        // raft-rs 0.7 drops reads before the leader commits a current-term
        // entry. A follower's current-term commit also proves that its leader
        // passed this gate. Raft remains responsible for the quorum check;
        // the caller still waits for ReadState and local apply in node.rs.
        let term = self.raw_node.raft.term;
        for (&id, request) in &mut self.pending_reads_by_ctx {
            if request.submitted_term != Some(term) {
                tracing::trace!(read_request_id = ?id, term, "raft.driver.read_index");
                self.raw_node.read_index(id.to_vec());
                request.submitted_term = Some(term);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::node::{RaftConfig, RaftMsg, ZoneConsensus};
    use crate::raft::state_machine::FullStateMachine;
    use crate::raft::storage::RaftStorage;
    use crate::storage::RedbStore;
    use raft::eraftpb::{ConfState, Message, MessageType};
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;
    use tempfile::TempDir;

    type Driver = ZoneConsensusDriver<FullStateMachine>;

    fn poll<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
        Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
    }

    fn node(id: u64, voters: &[u64]) -> (ZoneConsensus<FullStateMachine>, Driver, TempDir) {
        let dir = TempDir::new().unwrap();
        let (handle, driver) = open_node(id, voters, dir.path());
        (handle, driver, dir)
    }

    fn open_node(
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

    /// Whether `context` is a linearizable read `driver` still holds — as
    /// opposed to its commit probe, which shares the ReadIndex wire.
    fn is_pending_read(driver: &Driver, context: &[u8]) -> bool {
        driver
            .pending_reads_by_ctx
            .keys()
            .any(|pending| pending[..] == *context)
    }

    fn campaign(handle: &ZoneConsensus<FullStateMachine>, driver: &mut Driver) {
        let mut request = Box::pin(handle.campaign());
        assert!(poll(&mut request).is_pending());
        driver.process_messages();
        assert!(matches!(poll(&mut request), Poll::Ready(Ok(()))));
    }

    async fn early_singleton_read(before_campaign: bool) {
        let (handle, mut driver, _dir) = node(1, &[]);
        let mut read = Box::pin(handle.read_linearizable(StateMachine::last_applied_index));
        if before_campaign {
            assert!(poll(&mut read).is_pending());
            driver.process_messages();
            driver.advance().await.unwrap();
            assert!(poll(&mut read).is_pending());
        }
        campaign(&handle, &mut driver);
        assert!(handle.is_leader());
        assert!(!driver.raw_node.raft.commit_to_current_term());
        if !before_campaign {
            assert!(poll(&mut read).is_pending());
            driver.process_messages();
        }
        // Exercise the exact campaign -> read -> persist ordering without a
        // scheduler race, sleeps, retries or a longer timeout.
        driver.advance().await.unwrap();
        assert!(driver.raw_node.raft.commit_to_current_term());
        assert!(poll(&mut read).is_pending());
        assert!(driver.has_ready(), "the waiting read must prevent parking");
        driver.advance().await.unwrap();
        assert!(matches!(poll(&mut read), Poll::Ready(Ok(index)) if index >= 2));
        assert!(driver.pending_reads_by_ctx.is_empty());
        assert!(driver.applied_waiters.is_empty());
    }

    #[tokio::test]
    async fn read_queued_before_election_completes_after_commit_and_apply() {
        early_singleton_read(true).await;
    }

    #[tokio::test]
    async fn read_after_campaign_waits_for_current_term_persistence() {
        early_singleton_read(false).await;
    }

    #[tokio::test]
    async fn cancelled_read_is_removed_before_election() {
        let (handle, mut driver, _dir) = node(1, &[]);
        let mut read = Box::pin(handle.read_linearizable(|_| ()));
        assert!(poll(&mut read).is_pending());
        driver.process_messages();
        drop(read);
        driver.advance().await.unwrap();
        assert!(driver.pending_reads_by_ctx.is_empty());
        campaign(&handle, &mut driver);
        driver.advance().await.unwrap();
        assert!(!driver.has_ready());
    }

    struct Cluster {
        handles: Vec<ZoneConsensus<FullStateMachine>>,
        drivers: Vec<Driver>,
        _dirs: Vec<TempDir>,
    }

    impl Cluster {
        fn new() -> Self {
            let mut cluster = Self {
                handles: Vec::new(),
                drivers: Vec::new(),
                _dirs: Vec::new(),
            };
            for id in 1..=3 {
                let (handle, driver, dir) = node(id, &[1, 2, 3]);
                cluster.handles.push(handle);
                cluster.drivers.push(driver);
                cluster._dirs.push(dir);
            }
            cluster
        }

        async fn round(&mut self, mut deliver: impl FnMut(&Message) -> bool) {
            let mut outgoing = Vec::new();
            for driver in &mut self.drivers {
                driver.process_messages();
                outgoing.extend(driver.advance().await.unwrap());
            }
            for msg in outgoing {
                if deliver(&msg) {
                    self.handles[msg.to as usize - 1]
                        .msg_tx
                        .try_send(RaftMsg::Step { msg })
                        .unwrap();
                }
            }
        }

        async fn elect(&mut self, candidate: usize) {
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

    #[tokio::test]
    async fn follower_read_before_leader_exists_uses_read_index_after_election() {
        let mut cluster = Cluster::new();
        let follower = cluster.handles[2].clone();
        let mut read = Box::pin(follower.read_linearizable(StateMachine::last_applied_index));
        assert!(poll(&mut read).is_pending());
        cluster.round(|_| true).await;
        assert!(poll(&mut read).is_pending());
        cluster.elect(0).await;
        assert!(matches!(poll(&mut read), Poll::Ready(Ok(index)) if index >= 1));
    }

    #[tokio::test]
    async fn committed_term_does_not_replace_read_index_quorum() {
        let mut cluster = Cluster::new();
        cluster.elect(0).await;
        let leader = cluster.handles[0].clone();
        let mut read = Box::pin(leader.read_linearizable(|_| ()));
        assert!(poll(&mut read).is_pending());
        let mut held = Vec::new();
        for _ in 0..4 {
            cluster
                .round(|message| {
                    held.push(message.clone());
                    false
                })
                .await;
            assert!(poll(&mut read).is_pending());
        }
        assert!(held.iter().any(
            |message| message.get_msg_type() == MessageType::MsgHeartbeat
                && !message.context.is_empty()
        ));
        for msg in held {
            cluster.handles[msg.to as usize - 1]
                .msg_tx
                .try_send(RaftMsg::Step { msg })
                .unwrap();
        }
        for _ in 0..4 {
            cluster.round(|_| true).await;
        }
        assert!(matches!(poll(&mut read), Poll::Ready(Ok(()))));
    }

    #[tokio::test]
    async fn pending_follower_read_keeps_its_context_across_leader_change() {
        let mut cluster = Cluster::new();
        cluster.elect(0).await;
        let follower = cluster.handles[2].clone();
        let mut read = Box::pin(follower.read_linearizable(|_| ()));
        assert!(poll(&mut read).is_pending());
        let mut forwarded = Vec::new();
        cluster
            .round(|message| {
                if message.get_msg_type() == MessageType::MsgReadIndex {
                    forwarded.push(message.entries[0].data.clone());
                    false
                } else {
                    true
                }
            })
            .await;
        // Followers' commit probes are ReadIndex traffic too; the read is the
        // one its node still holds pending.
        let context = forwarded
            .into_iter()
            .find(|context| is_pending_read(&cluster.drivers[2], context))
            .expect("read was forwarded to the original leader");
        assert!(poll(&mut read).is_pending());
        let term = cluster.drivers[2].raw_node.raft.term;
        campaign(&cluster.handles[1], &mut cluster.drivers[1]);
        let mut resubmitted = false;
        for _ in 0..12 {
            cluster
                .round(|message| {
                    if message.get_msg_type() == MessageType::MsgReadIndex
                        && message.entries[0].data == context
                    {
                        assert_eq!(message.to, 2);
                        resubmitted = true;
                    }
                    true
                })
                .await;
        }
        assert!(cluster.handles[1].is_leader());
        assert!(cluster.drivers[2].raw_node.raft.term > term);
        assert!(resubmitted);
        assert!(matches!(poll(&mut read), Poll::Ready(Ok(()))));
    }

    #[tokio::test]
    async fn simultaneous_reads_from_all_replicas_have_distinct_contexts() {
        let mut cluster = Cluster::new();
        cluster.elect(0).await;
        let handles = cluster.handles.clone();
        let mut reads: Vec<_> = handles
            .iter()
            .map(|handle| Box::pin(handle.read_linearizable(StateMachine::last_applied_index)))
            .collect();
        for read in &mut reads {
            assert!(poll(read).is_pending());
        }
        for _ in 0..12 {
            cluster.round(|_| true).await;
        }
        for (node, read) in reads.iter_mut().enumerate() {
            assert!(
                matches!(poll(read), Poll::Ready(Ok(index)) if index >= 1),
                "node {node}'s read must retain its own quorum response"
            );
        }
        assert!(cluster
            .drivers
            .iter()
            .all(|driver| driver.pending_reads_by_ctx.is_empty()));
    }

    #[tokio::test]
    async fn delayed_response_from_before_restart_cannot_complete_a_new_read() {
        let mut cluster = Cluster::new();
        cluster.elect(0).await;
        let old_handle = cluster.handles[2].clone();
        let mut old_read = Box::pin(old_handle.read_linearizable(|_| ()));
        assert!(poll(&mut old_read).is_pending());
        let mut responses = Vec::new();
        for _ in 0..8 {
            cluster
                .round(|message| {
                    if message.to == 3 && message.get_msg_type() == MessageType::MsgReadIndexResp {
                        responses.push(message.clone());
                        false
                    } else {
                        true
                    }
                })
                .await;
        }
        let mut answers = responses
            .into_iter()
            .filter(|message| is_pending_read(&cluster.drivers[2], &message.entries[0].data));
        let response = answers.next().expect("leader confirmed the original read");
        assert!(answers.next().is_none(), "the read is confirmed once");
        let original_term = response.term;
        assert!(poll(&mut old_read).is_pending());
        drop(old_read);
        drop(old_handle);
        drop(cluster.handles.pop().unwrap());
        drop(cluster.drivers.pop().unwrap());

        let (handle, driver) = open_node(3, &[1, 2, 3], cluster._dirs[2].path());
        cluster.handles.push(handle);
        cluster.drivers.push(driver);
        let new_handle = cluster.handles[2].clone();
        let mut new_read = Box::pin(new_handle.read_linearizable(|_| ()));
        assert!(poll(&mut new_read).is_pending());
        cluster.handles[2]
            .msg_tx
            .try_send(RaftMsg::Step { msg: response })
            .unwrap();
        cluster.drivers[2].process_messages();
        cluster.drivers[2].advance().await.unwrap();
        assert_eq!(cluster.drivers[2].raw_node.raft.term, original_term);
        assert!(
            poll(&mut new_read).is_pending(),
            "the prior driver's response must not authorize the new read"
        );

        // Keep the same leader and term, so only the request incarnation
        // separates the old response from this reader's quorum exchange.
        cluster.drivers[0].raw_node.ping();
        for _ in 0..8 {
            cluster.round(|_| true).await;
        }
        assert_eq!(cluster.drivers[2].raw_node.raft.term, original_term);
        assert!(matches!(poll(&mut new_read), Poll::Ready(Ok(()))));
    }

    #[test]
    fn read_request_sequence_never_wraps_to_an_existing_context() {
        let mut ids = ReadRequestIds::new(7);
        let first = ids.allocate().unwrap();
        assert_eq!(&first[..8], &7_u64.to_be_bytes());
        assert_eq!(&first[24..], &0_u64.to_be_bytes());
        ids.next = Some(u64::MAX);
        let last = ids.allocate().unwrap();
        assert_eq!(&last[..24], &first[..24]);
        assert_eq!(&last[24..], &u64::MAX.to_be_bytes());
        assert_ne!(first, last);
        assert!(ids.allocate().is_none());
        assert!(ids.allocate().is_none());
    }
}
