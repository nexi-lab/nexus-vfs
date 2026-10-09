//! A queued write must recheck leadership in the actor that owns Raft.
//! Real storage and Raft messages; the queue order makes the handoff deterministic.
#![cfg(feature = "consensus")]

use nexus_raft::raft::{
    Command, FullStateMachine, RaftConfig, RaftError, RaftStorage, ZoneConsensus,
    ZoneConsensusDriver,
};
use nexus_raft::storage::RedbStore;
use raft::eraftpb::{ConfChangeType, Message, MessageType};
use std::time::Duration;

async fn leader_with_two_voters() -> (
    tempfile::TempDir,
    ZoneConsensus<FullStateMachine>,
    ZoneConsensusDriver<FullStateMachine>,
) {
    let directory = tempfile::tempdir().unwrap();
    let storage = RaftStorage::open(directory.path().join("raft")).unwrap();
    let store = RedbStore::open(directory.path().join("state")).unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    let (handle, mut driver) =
        ZoneConsensus::new(RaftConfig::default(), storage, state, None).unwrap();

    let campaign = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.campaign().await })
    };
    assert!(driver.recv_and_handle().await);
    driver.advance().await.unwrap();
    campaign.await.unwrap().unwrap();
    assert!(handle.is_leader());

    // Admit node 2 while the founder still has a one-voter quorum. Its vote
    // request below is from a real member, rather than an unknown sender.
    let admission = {
        let handle = handle.clone();
        tokio::spawn(async move {
            handle
                .propose_conf_change(ConfChangeType::AddNode, 2, vec![])
                .await
        })
    };
    assert!(driver.recv_and_handle().await);
    driver.advance().await.unwrap();
    admission.await.unwrap().unwrap();
    assert_eq!(driver.voter_ids(), vec![1, 2]);
    (directory, handle, driver)
}

#[tokio::test]
async fn queued_write_reports_a_definite_refusal_after_leadership_changes() {
    let (_directory, handle, mut driver) = leader_with_two_voters().await;
    let last_index = handle.last_index();

    let mut vote = Message::default();
    vote.set_msg_type(MessageType::MsgRequestVote);
    vote.from = 2;
    vote.to = 1;
    vote.term = handle.term() + 1;
    vote.index = last_index;
    vote.log_term = handle.term();
    handle.step(vote).await.unwrap();
    let proposal = {
        let handle = handle.clone();
        tokio::spawn(async move {
            handle
                .propose(Command::SetMetadata {
                    key: "/handoff-refusal".into(),
                    value: b"must-not-append".to_vec(),
                })
                .await
        })
    };
    // The step is ahead of the proposal in the actor queue. It changes the
    // actual role before the next Ready refreshes the handle's cached view.
    assert!(driver.recv_and_handle().await);
    assert!(!driver.is_leader());
    assert!(driver.recv_and_handle().await);
    driver.advance().await.unwrap();

    let error = tokio::time::timeout(Duration::from_secs(2), proposal)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error, RaftError::NotLeader { .. }),
        "a write rejected before submission must retain its routing meaning: {error}"
    );
    assert!(!error.proposal_outcome_unknown());
    assert_eq!(
        handle.last_index(),
        last_index,
        "a refused write appended an entry"
    );
}

#[tokio::test]
async fn losing_the_reply_after_log_append_keeps_the_outcome_unknown() {
    let (_directory, handle, mut driver) = leader_with_two_voters().await;
    let last_index = handle.last_index();
    let proposal = {
        let handle = handle.clone();
        tokio::spawn(async move {
            handle
                .propose(Command::SetMetadata {
                    key: "/accepted-write".into(),
                    value: b"reply-will-be-lost".to_vec(),
                })
                .await
        })
    };
    assert!(driver.recv_and_handle().await);
    driver.advance().await.unwrap();
    assert_eq!(handle.last_index(), last_index + 1);
    assert!(
        !proposal.is_finished(),
        "a second voter has not acknowledged"
    );

    // The command reached the real log. Losing its response is different
    // from refusing it before submission, and must not trigger forwarding.
    drop(driver);
    let error = tokio::time::timeout(Duration::from_secs(2), proposal)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, RaftError::ProposalDropped), "{error}");
    assert!(error.proposal_outcome_unknown());
    assert_eq!(handle.last_index(), last_index + 1);
}
