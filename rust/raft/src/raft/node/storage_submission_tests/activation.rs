//! Configuration probes use the real driver and committed membership changes.

use super::*;
use raft::eraftpb::{ConfChangeSingle, ConfChangeTransition};

async fn apply_local<F: Future>(
    driver: &mut ZoneConsensusDriver<FullStateMachine>,
    future: F,
) -> F::Output {
    let mut future = Box::pin(future);
    assert!(poll(&mut future).is_pending());
    driver.process_messages();
    while driver.has_ready() {
        // The original sole voter commits learner membership. Sending a learner
        // its catch-up messages is outside this configuration-observation test.
        let _ = driver.advance().await.unwrap();
    }
    match poll(&mut future) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("single-voter configuration request remained pending"),
    }
}

#[tokio::test]
async fn activation_view_reads_actual_members_and_does_not_write_storage() {
    let (handle, mut driver, _dir) = node(MembershipPolicy::Managed);
    assert!(matches!(
        apply_local(&mut driver, handle.storage_activation_view()).await,
        Err(RaftError::NotLeader { .. })
    ));
    apply_local(&mut driver, handle.campaign()).await.unwrap();
    apply_local(
        &mut driver,
        handle.propose_conf_change(ConfChangeType::AddLearnerNode, 2, vec![]),
    )
    .await
    .unwrap();
    let before = handle.state_machine.read().await.snapshot().unwrap();
    let last = driver.raw_node.raft.raft_log.last_index();
    let observed = apply_local(&mut driver, handle.storage_activation_view())
        .await
        .unwrap();
    assert_eq!(observed.member_ids(), vec![1, 2]);
    driver.validate_storage_activation_view(&observed).unwrap();
    assert_eq!(driver.raw_node.raft.raft_log.last_index(), last);
    assert_eq!(
        handle.state_machine.read().await.snapshot().unwrap(),
        before
    );

    // A current configuration observation does not activate any storage domain.
    let (tx, rx) = oneshot::channel();
    handle
        .msg_tx
        .try_send(RaftMsg::ProposeStorage {
            submission: StorageSubmission {
                command: replica(),
                protocol: StorageProtocol::ReplicaControl,
                configuration: Some(observed.clone()),
            },
            tx,
        })
        .unwrap();
    driver.process_messages();
    let refused = rx.await.unwrap().unwrap_err();
    assert!(matches!(refused, RaftError::ProposalRejected(_)));
    assert!(!refused.proposal_outcome_unknown());
    assert!(refused
        .to_string()
        .contains("replica binding protocol is not activated"));
    assert_eq!(driver.raw_node.raft.raft_log.last_index(), last);
    assert_eq!(
        handle.state_machine.read().await.snapshot().unwrap(),
        before
    );

    apply_local(&mut driver, handle.propose(Command::Noop))
        .await
        .unwrap();
    assert!(driver.raw_node.raft.raft_log.last_index() > last);
    driver.validate_storage_activation_view(&observed).unwrap();
}

#[tokio::test]
async fn pending_and_completed_membership_roundtrip_refuse_original_view_at_submission() {
    let (handle, mut driver, _dir) = node(MembershipPolicy::Managed);
    apply_local(&mut driver, handle.campaign()).await.unwrap();
    let observed = apply_local(&mut driver, handle.storage_activation_view())
        .await
        .unwrap();
    let mut add = Box::pin(handle.propose_conf_change(ConfChangeType::AddLearnerNode, 2, vec![]));
    assert!(poll(&mut add).is_pending());
    driver.process_messages();
    assert!(driver
        .validate_storage_activation_view(&observed)
        .unwrap_err()
        .to_string()
        .contains("pending configuration"));
    while driver.has_ready() {
        let _ = driver.advance().await.unwrap();
    }
    assert!(matches!(poll(&mut add), Poll::Ready(Ok(_))));
    drop(add);
    apply_local(
        &mut driver,
        handle.propose_conf_change(ConfChangeType::RemoveNode, 2, vec![]),
    )
    .await
    .unwrap();
    let fresh = apply_local(&mut driver, handle.storage_activation_view())
        .await
        .unwrap();
    assert_eq!(fresh.member_ids(), observed.member_ids());
    driver.validate_storage_activation_view(&fresh).unwrap();

    let before = handle.state_machine.read().await.snapshot().unwrap();
    let last = driver.raw_node.raft.raft_log.last_index();
    let (tx, rx) = oneshot::channel();
    handle
        .msg_tx
        .try_send(RaftMsg::ProposeStorage {
            submission: StorageSubmission {
                command: replica(),
                protocol: StorageProtocol::ReplicaControl,
                configuration: Some(observed),
            },
            tx,
        })
        .unwrap();
    driver.process_messages();
    assert!(rx
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("configuration changed during qualification"));
    assert_eq!(driver.raw_node.raft.raft_log.last_index(), last);
    assert_eq!(
        handle.state_machine.read().await.snapshot().unwrap(),
        before
    );
}

#[tokio::test]
async fn reopened_driver_refuses_prior_incarnation_and_keeps_original_store() {
    let (handle, mut driver, dir) = node(MembershipPolicy::Managed);
    apply_local(&mut driver, handle.campaign()).await.unwrap();
    apply_local(
        &mut driver,
        handle.propose(Command::SetMetadata {
            key: "/ordinary".into(),
            value: b"retained".to_vec(),
        }),
    )
    .await
    .unwrap();
    let observed = apply_local(&mut driver, handle.storage_activation_view())
        .await
        .unwrap();
    let before = handle.state_machine.read().await.snapshot().unwrap();
    drop((driver, handle));

    let store = RedbStore::open(dir.path().join("state")).unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    assert_eq!(state.snapshot().unwrap(), before);
    let (handle, mut driver) = ZoneConsensus::new(
        RaftConfig {
            id: 1,
            ..Default::default()
        },
        RaftStorage::open(dir.path()).unwrap(),
        state,
        None,
    )
    .unwrap();
    assert!(driver
        .validate_storage_activation_view(&observed)
        .unwrap_err()
        .to_string()
        .contains("different driver incarnation"));
    // Rebuild the driver's committed configuration and advisory state before
    // requesting a new election, as the production Ready loop does on restart.
    while driver.has_ready() {
        let _ = driver.advance().await.unwrap();
    }
    assert_eq!(
        driver.raw_node.raft.raft_log.applied,
        driver.raw_node.raft.raft_log.committed
    );
    assert_eq!(
        handle.state_machine.read().await.snapshot().unwrap(),
        before
    );
    assert!(driver
        .validate_storage_activation_view(&observed)
        .unwrap_err()
        .to_string()
        .contains("different driver incarnation"));
    apply_local(&mut driver, handle.campaign()).await.unwrap();
    let fresh = apply_local(&mut driver, handle.storage_activation_view())
        .await
        .unwrap();
    driver.validate_storage_activation_view(&fresh).unwrap();
    assert_eq!(
        handle
            .state_machine
            .read()
            .await
            .get_metadata("/ordinary")
            .unwrap(),
        Some(b"retained".to_vec())
    );
}

#[tokio::test]
async fn joint_membership_and_leadership_changes_refuse_probe_reuse() {
    let (handle, mut driver, _dir) = node(MembershipPolicy::Managed);
    apply_local(&mut driver, handle.campaign()).await.unwrap();
    let observed = apply_local(&mut driver, handle.storage_activation_view())
        .await
        .unwrap();
    let next_term = driver.raw_node.raft.term + 1;
    driver.raw_node.raft.become_follower(next_term, 0);
    assert!(matches!(
        driver.validate_storage_activation_view(&observed),
        Err(RaftError::NotLeader { .. })
    ));
    driver.update_cached_status();
    apply_local(&mut driver, handle.campaign()).await.unwrap();
    assert!(driver
        .validate_storage_activation_view(&observed)
        .unwrap_err()
        .to_string()
        .contains("configuration changed"));

    let mut change = ConfChangeV2::default();
    change.set_transition(ConfChangeTransition::Explicit);
    let mut add = ConfChangeSingle::default();
    add.set_change_type(ConfChangeType::AddNode);
    add.node_id = 2;
    change.changes.push(add);
    driver.raw_node.propose_conf_change(vec![], change).unwrap();
    while driver.has_ready() {
        let _ = driver.advance().await.unwrap();
    }
    assert_eq!(
        driver
            .raw_node
            .raft
            .prs()
            .conf()
            .to_conf_state()
            .voters_outgoing,
        vec![1]
    );
    assert!(driver
        .storage_activation_view()
        .unwrap_err()
        .to_string()
        .contains("stable membership"));
}

#[tokio::test]
async fn empty_v2_joint_exit_keeps_original_view_invalid() {
    let (handle, mut driver, _dir) = node(MembershipPolicy::Managed);
    apply_local(&mut driver, handle.campaign()).await.unwrap();
    let original = apply_local(&mut driver, handle.storage_activation_view())
        .await
        .unwrap();
    let original_configuration = driver.raw_node.raft.prs().conf().to_conf_state();
    let original_epoch = driver.membership_epoch.unwrap();

    // A redundant voter addition enters joint consensus without changing the
    // final voter set. The empty V2 then leaves the joint configuration.
    let mut enter = ConfChangeV2::default();
    enter.set_transition(ConfChangeTransition::Explicit);
    let mut existing = ConfChangeSingle::default();
    existing.set_change_type(ConfChangeType::AddNode);
    existing.node_id = 1;
    enter.changes.push(existing);
    driver.raw_node.propose_conf_change(vec![], enter).unwrap();
    while driver.has_ready() {
        let _ = driver.advance().await.unwrap();
    }
    assert_eq!(driver.membership_epoch, Some(original_epoch + 1));
    assert_eq!(
        driver
            .raw_node
            .raft
            .prs()
            .conf()
            .to_conf_state()
            .voters_outgoing,
        vec![1]
    );
    assert!(driver.storage_activation_view().is_err());

    driver
        .raw_node
        .propose_conf_change(vec![], ConfChangeV2::default())
        .unwrap();
    while driver.has_ready() {
        let _ = driver.advance().await.unwrap();
    }
    assert_eq!(driver.membership_epoch, Some(original_epoch + 2));
    assert_eq!(
        driver.raw_node.raft.prs().conf().to_conf_state(),
        original_configuration
    );
    let fresh = apply_local(&mut driver, handle.storage_activation_view())
        .await
        .unwrap();
    driver.validate_storage_activation_view(&fresh).unwrap();
    let last = driver.raw_node.raft.raft_log.last_index();
    let before = handle.state_machine.read().await.snapshot().unwrap();
    assert!(driver
        .validate_storage_activation_view(&original)
        .unwrap_err()
        .to_string()
        .contains("configuration changed during qualification"));
    assert_eq!(driver.raw_node.raft.raft_log.last_index(), last);
    assert_eq!(
        handle.state_machine.read().await.snapshot().unwrap(),
        before
    );
}

#[tokio::test]
async fn actor_refuses_wrong_storage_authority_before_allocating_a_log_entry() {
    let (handle, mut driver, _dir) = node(MembershipPolicy::FixedLocal);
    apply_local(&mut driver, handle.campaign()).await.unwrap();
    assert!(apply_local(&mut driver, handle.storage_activation_view())
        .await
        .is_err());
    let before = handle.state_machine.read().await.snapshot().unwrap();
    let last = driver.raw_node.raft.raft_log.last_index();
    let (tx, rx) = oneshot::channel();
    handle
        .msg_tx
        .try_send(RaftMsg::ProposeStorage {
            submission: StorageSubmission {
                command: replica(),
                protocol: StorageProtocol::RecordLifetime,
                configuration: None,
            },
            tx,
        })
        .unwrap();
    driver.process_messages();
    let refused = rx.await.unwrap().unwrap_err();
    assert!(matches!(refused, RaftError::ProposalRejected(_)));
    assert!(!refused.proposal_outcome_unknown());
    assert!(refused.to_string().contains("different storage protocol"));
    assert_eq!(driver.raw_node.raft.raft_log.last_index(), last);
    assert_eq!(
        handle.state_machine.read().await.snapshot().unwrap(),
        before
    );
    apply_local(&mut driver, handle.commit_replica_control(replica()))
        .await
        .unwrap();
    assert_eq!(
        handle
            .state_machine
            .read()
            .await
            .node_identity(42)
            .unwrap()
            .unwrap()
            .node_id,
        42
    );
}

#[tokio::test]
async fn equal_term_and_membership_in_another_store_cannot_reuse_the_view() {
    let (a, mut a_driver, _a_dir) = node(MembershipPolicy::Managed);
    let (b, mut b_driver, _b_dir) = node(MembershipPolicy::Managed);
    apply_local(&mut a_driver, a.campaign()).await.unwrap();
    apply_local(&mut b_driver, b.campaign()).await.unwrap();
    let a_view = apply_local(&mut a_driver, a.storage_activation_view())
        .await
        .unwrap();
    let b_view = apply_local(&mut b_driver, b.storage_activation_view())
        .await
        .unwrap();
    assert_eq!(a_driver.raw_node.raft.term, b_driver.raw_node.raft.term);
    assert_eq!(a_view.member_ids(), b_view.member_ids());
    a_driver.validate_storage_activation_view(&a_view).unwrap();
    b_driver.validate_storage_activation_view(&b_view).unwrap();
    assert!(b_driver
        .validate_storage_activation_view(&a_view)
        .unwrap_err()
        .to_string()
        .contains("different driver incarnation"));
}

#[tokio::test]
async fn ordinary_storage_submission_cannot_publish_activation_fact() {
    let (handle, mut driver, _dir) = node(MembershipPolicy::FixedLocal);
    apply_local(&mut driver, handle.campaign()).await.unwrap();
    let before = handle.state_machine.read().await.snapshot().unwrap();
    let last = driver.raw_node.raft.raft_log.last_index();
    let (tx, rx) = oneshot::channel();
    handle
        .msg_tx
        .try_send(RaftMsg::ProposeStorage {
            submission: StorageSubmission {
                command: Command::ActivateReplicaControl {
                    operation_id: "ordinary-typed-submit".into(),
                },
                protocol: StorageProtocol::ReplicaControl,
                configuration: None,
            },
            tx,
        })
        .unwrap();
    driver.process_messages();
    let refused = rx.await.unwrap().unwrap_err();
    assert!(matches!(refused, RaftError::ProposalRejected(_)));
    assert!(!refused.proposal_outcome_unknown());
    assert!(refused
        .to_string()
        .contains("activation requires qualified member observation"));
    assert_eq!(driver.raw_node.raft.raft_log.last_index(), last);
    assert_eq!(
        handle.state_machine.read().await.snapshot().unwrap(),
        before
    );
    assert_eq!(
        handle
            .state_machine
            .read()
            .await
            .replica_control_activation()
            .unwrap(),
        None
    );
    apply_local(&mut driver, handle.commit_replica_control(replica()))
        .await
        .unwrap();
    assert!(handle
        .state_machine
        .read()
        .await
        .node_identity(42)
        .unwrap()
        .is_some());
}
