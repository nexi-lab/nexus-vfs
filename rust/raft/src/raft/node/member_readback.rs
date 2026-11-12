//! Applied membership and address observations for an existing member's join.

use super::{
    channel_try_send_err, oneshot, read_membership, Membership, RaftError, RaftMsg, Result,
    StateMachine, ZoneConsensus, ZoneConsensusDriver,
};

/// One actor observation after the existing Raft read barrier.
pub struct MemberAddressView {
    pub(crate) membership: Membership,
    pub(crate) addresses: Vec<(u64, String)>,
}

impl<S: StateMachine + 'static> ZoneConsensus<S> {
    pub(crate) async fn read_member_addresses(&self) -> Result<MemberAddressView> {
        self.read_linearizable(|_| ()).await?;
        let (tx, rx) = oneshot::channel();
        self.msg_tx
            .try_send(RaftMsg::MemberAddressView { tx })
            .map_err(channel_try_send_err)?;
        rx.await.map_err(|_| RaftError::ChannelClosed)?
    }
}

impl<S: StateMachine + 'static> ZoneConsensusDriver<S> {
    pub(super) fn member_address_view(&self) -> Result<MemberAddressView> {
        if self.failed {
            return Err(RaftError::InvalidState("Raft driver has failed".into()));
        }
        // The actor processes this request between complete apply turns. A
        // concurrent external state write must finish before a new observation.
        let state = self
            .state_machine
            .try_read()
            .map_err(|_| RaftError::InvalidState("member address state is being updated".into()))?;
        Ok(MemberAddressView {
            membership: read_membership(&self.raw_node),
            addresses: state.member_addresses()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::{FullStateMachine, RaftConfig, RaftStorage};
    use crate::storage::RedbStore;
    use raft::eraftpb::ConfState;
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll, Waker},
        time::Duration,
    };
    use tempfile::TempDir;

    fn poll<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
        Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
    }

    fn node(
        voters: &[u64],
    ) -> (
        ZoneConsensus<FullStateMachine>,
        ZoneConsensusDriver<FullStateMachine>,
        TempDir,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let storage = RaftStorage::open(directory.path()).unwrap();
        if !voters.is_empty() {
            storage
                .set_conf_state(&ConfState {
                    voters: voters.to_vec(),
                    ..Default::default()
                })
                .unwrap();
        }
        let store = RedbStore::open(directory.path().join("state")).unwrap();
        let state = FullStateMachine::new(&store).unwrap();
        let (handle, driver) = ZoneConsensus::new(
            RaftConfig {
                id: 7,
                skip_bootstrap: !voters.is_empty(),
                tick_interval: Duration::from_secs(3600),
                ..Default::default()
            },
            storage,
            state,
            None,
        )
        .unwrap();
        (handle, driver, directory)
    }

    #[tokio::test]
    async fn member_readback_waits_for_raft_and_refuses_unavailable_quorum() {
        let (handle, mut driver, _directory) = node(&[7, 8, 9]);
        let mut read = Box::pin(handle.read_member_addresses());
        assert!(poll(&mut read).is_pending());
        for _ in 0..4 {
            driver.process_messages();
            driver.advance().await.unwrap();
            assert!(
                poll(&mut read).is_pending(),
                "membership read bypassed its Raft barrier"
            );
        }
        assert_eq!(driver.pending_reads_by_ctx.len(), 1);
        drop(read);
        driver.advance().await.unwrap();
        assert!(driver.pending_reads_by_ctx.is_empty());
    }

    #[tokio::test]
    async fn member_readback_completes_after_current_term_commit_and_apply() {
        let (handle, mut driver, _directory) = node(&[]);
        let mut campaign = Box::pin(handle.campaign());
        assert!(poll(&mut campaign).is_pending());
        driver.process_messages();
        assert!(matches!(poll(&mut campaign), Poll::Ready(Ok(()))));
        let mut read = Box::pin(handle.read_member_addresses());
        assert!(poll(&mut read).is_pending());
        for _ in 0..8 {
            driver.process_messages();
            driver.advance().await.unwrap();
            if let Poll::Ready(result) = poll(&mut read) {
                let view = result.unwrap();
                assert_eq!(view.membership.voters, vec![7]);
                assert!(view.membership.learners.is_empty());
                assert!(view.addresses.is_empty());
                assert!(driver.raw_node.raft.commit_to_current_term());
                return;
            }
        }
        panic!("committed singleton must answer the original membership read");
    }
}
