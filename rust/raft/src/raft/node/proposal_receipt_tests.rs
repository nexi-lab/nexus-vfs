use super::{test_cluster::Cluster, Command, CommandResult, RaftError};

fn put(path: &str) -> Command {
    Command::SetMetadata {
        key: path.into(),
        value: path.as_bytes().to_vec(),
    }
}

#[tokio::test]
async fn committing_a_different_command_cannot_acknowledge_an_overwritten_write() {
    let mut cluster = Cluster::new();
    cluster.elect(0).await;
    let mut first = cluster.handles[0]
        .submit_to_channel(&put("/first"))
        .unwrap();
    cluster.round(|m| m.from != 1 && m.to != 1).await;
    assert!(matches!(
        first.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    cluster.elect(1).await;
    let second = cluster.handles[1]
        .submit_to_channel(&put("/second"))
        .unwrap();
    for _ in 0..12 {
        cluster.round(|_| true).await;
    }
    assert!(matches!(second.await, Ok(Ok(CommandResult::Success))));
    let error = first
        .try_recv()
        .expect("replacement must resolve the waiter")
        .unwrap_err();
    assert!(matches!(error, RaftError::ProposalSuperseded { .. }));
    assert!(!error.proposal_outcome_unknown());
    for member in &cluster.handles {
        member
            .with_state_machine(|sm| {
                assert!(sm.get_metadata("/first").unwrap().is_none());
                assert_eq!(
                    sm.get_metadata("/second").unwrap().as_deref(),
                    Some(b"/second".as_slice())
                );
            })
            .await;
    }
}

#[tokio::test]
async fn an_entry_retained_by_the_next_leader_can_still_complete() {
    let mut cluster = Cluster::new();
    cluster.elect(0).await;
    let mut first = cluster.handles[0]
        .submit_to_channel(&put("/first"))
        .unwrap();
    for _ in 0..3 {
        cluster.round(|m| m.to == 2).await;
    }
    assert!(matches!(
        first.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    cluster.elect(1).await;
    assert!(matches!(first.try_recv(), Ok(Ok(CommandResult::Success))));
    for member in &cluster.handles {
        assert_eq!(
            member
                .with_state_machine(|sm| sm.get_metadata("/first"))
                .await
                .unwrap()
                .as_deref(),
            Some(b"/first".as_slice())
        );
    }
}

#[tokio::test]
async fn installed_snapshot_releases_covered_receipts_with_unknown_outcome() {
    use super::{test_cluster::campaign, RaftMsg};
    use raft::{
        eraftpb::{Message, MessageType},
        Storage,
    };

    let mut cluster = Cluster::new();
    cluster.elect(0).await;
    let mut first = cluster.handles[0]
        .submit_to_channel(&put("/first"))
        .unwrap();
    let partition = |m: &Message| m.from != 1 && m.to != 1;
    cluster.round(partition).await;
    cluster.drivers[1].set_snapshot_threshold(1);
    campaign(&cluster.handles[1], &mut cluster.drivers[1]);
    for _ in 0..12 {
        cluster.round(partition).await;
    }
    assert!(cluster.handles[1].is_leader());
    let second = cluster.handles[1]
        .submit_to_channel(&put("/second"))
        .unwrap();
    for _ in 0..12 {
        cluster.round(partition).await;
    }
    assert!(matches!(second.await, Ok(Ok(CommandResult::Success))));
    assert!(matches!(
        first.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    let snapshot = cluster.drivers[1].raw_node.store().snapshot(0, 1).unwrap();
    assert!(snapshot.get_metadata().index >= cluster.handles[1].applied_index());
    let mut msg = Message {
        from: 2,
        to: 1,
        term: cluster.handles[1].term(),
        ..Default::default()
    };
    msg.set_msg_type(MessageType::MsgSnapshot);
    msg.set_snapshot(snapshot);
    cluster.handles[0]
        .msg_tx
        .try_send(RaftMsg::Step { msg })
        .unwrap();
    cluster.round(partition).await;
    let error = first
        .try_recv()
        .expect("installed snapshot must retire the waiter")
        .unwrap_err();
    assert!(error.proposal_outcome_unknown());
    assert_eq!(
        cluster.handles[0]
            .with_state_machine(|sm| sm.get_metadata("/second"))
            .await
            .unwrap()
            .as_deref(),
        Some(b"/second".as_slice())
    );
}

#[tokio::test]
async fn concurrent_membership_requests_for_the_same_member_get_their_own_outcomes() {
    use super::{test_cluster::poll, ConfChangeType};

    let mut cluster = Cluster::new();
    cluster.elect(0).await;
    let leader = cluster.handles[0].clone();
    let mut add =
        Box::pin(leader.propose_conf_change(ConfChangeType::AddLearnerNode, 4, Vec::new()));
    let mut remove =
        Box::pin(leader.propose_conf_change(ConfChangeType::RemoveNode, 4, Vec::new()));
    assert!(poll(&mut add).is_pending());
    assert!(poll(&mut remove).is_pending());
    for _ in 0..15 {
        cluster.round(|message| message.to <= 3).await;
    }
    assert!(add.await.unwrap().learners.contains(&4));
    let refused = remove.await.unwrap_err();
    assert!(!refused.proposal_outcome_unknown());
    for driver in &cluster.drivers {
        assert!(super::learner_ids_from_raw_node(&driver.raw_node).contains(&4));
    }
}
