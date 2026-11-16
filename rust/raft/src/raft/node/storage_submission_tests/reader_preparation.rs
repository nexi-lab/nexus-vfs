//! Reader preparation is a local actor operation over the original Raft store.

use super::*;
use crate::raft::WitnessStateMachine;

async fn prepare<S: StateMachine + 'static>(
    handle: &ZoneConsensus<S>,
    driver: &mut ZoneConsensusDriver<S>,
) {
    let mut request = Box::pin(handle.prepare_replica_control_reader());
    assert!(poll(&mut request).is_pending());
    driver.process_messages();
    assert!(matches!(poll(&mut request), Poll::Ready(Ok(()))));
    assert!(driver
        .raw_node
        .store()
        .replica_control_reader_required()
        .unwrap());
}

#[tokio::test]
async fn follower_preparation_is_durable_without_a_log_or_activation_change() {
    let (handle, mut driver, directory) = node(MembershipPolicy::Managed);
    assert!(!handle.is_leader());
    assert!(!driver
        .raw_node
        .store()
        .replica_control_reader_required()
        .unwrap());
    let original = driver.raw_node.store().initial_state_impl().unwrap();
    let last = driver.raw_node.store().last_index_impl().unwrap();
    let state = handle.state_machine.read().await.snapshot().unwrap();
    prepare(&handle, &mut driver).await;
    prepare(&handle, &mut driver).await;
    let prepared = driver.raw_node.store().initial_state_impl().unwrap();
    assert_eq!(prepared.hard_state, original.hard_state);
    assert_eq!(prepared.conf_state, original.conf_state);
    assert_eq!(driver.raw_node.store().last_index_impl().unwrap(), last);
    assert_eq!(handle.state_machine.read().await.snapshot().unwrap(), state);
    assert!(!handle.is_leader());

    // An upgraded local reader does not grant the replicated storage protocol.
    finish(&mut driver, handle.campaign()).await.unwrap();
    assert!(handle.is_leader());
    let last = driver.raw_node.raft.raft_log.last_index();
    let refused = handle.commit_replica_control(replica()).await.unwrap_err();
    assert!(refused
        .to_string()
        .contains("replica binding protocol is not activated"));
    assert_eq!(driver.raw_node.raft.raft_log.last_index(), last);
    assert!(handle
        .state_machine
        .read()
        .await
        .node_identity(42)
        .unwrap()
        .is_none());
    drop(driver);
    drop(handle);
    let reopened = RaftStorage::open(directory.path()).unwrap();
    assert!(reopened.replica_control_reader_required().unwrap());
}

#[tokio::test]
async fn witness_and_learner_prepare_the_original_store_without_leadership() {
    for learner in [false, true] {
        let directory = TempDir::new().unwrap();
        let storage = RaftStorage::open(directory.path()).unwrap();
        let membership = if learner {
            ConfState {
                voters: vec![2],
                learners: vec![1],
                ..Default::default()
            }
        } else {
            ConfState {
                voters: vec![1, 2],
                ..Default::default()
            }
        };
        storage.set_conf_state(&membership).unwrap();
        let store = RedbStore::open(directory.path().join("state")).unwrap();
        let state = WitnessStateMachine::new(&store).unwrap();
        let config = RaftConfig {
            id: 1,
            is_witness: true,
            membership_policy: MembershipPolicy::Managed,
            skip_bootstrap: true,
            ..Default::default()
        };
        let (handle, mut driver) = ZoneConsensus::new(config, storage, state, None).unwrap();
        let original = driver.raw_node.store().initial_state_impl().unwrap();
        let last = driver.raw_node.store().last_index_impl().unwrap();
        prepare(&handle, &mut driver).await;
        assert!(!handle.is_leader());
        let prepared = driver.raw_node.store().initial_state_impl().unwrap();
        assert_eq!(prepared.hard_state, original.hard_state);
        assert_eq!(prepared.conf_state, membership);
        assert_eq!(driver.raw_node.store().last_index_impl().unwrap(), last);
        assert_eq!(handle.state_machine.read().await.last_applied_index(), 0);
        drop(driver);
        drop(handle);
        let reopened = RaftStorage::open(directory.path()).unwrap();
        assert!(reopened.replica_control_reader_required().unwrap());
        assert_eq!(
            reopened.initial_state_impl().unwrap().conf_state,
            membership
        );
    }
}

#[tokio::test]
async fn fixed_local_refuses_reader_preparation_at_handle_and_actor() {
    let (handle, mut driver, _directory) = node(MembershipPolicy::FixedLocal);
    let error = handle.prepare_replica_control_reader().await.unwrap_err();
    assert!(error.to_string().contains("fixed local membership"));
    assert!(driver.msg_rx.is_empty());
    let (tx, rx) = oneshot::channel();
    handle
        .msg_tx
        .try_send(RaftMsg::PrepareReplicaControlReader { tx })
        .unwrap();
    driver.process_messages();
    assert!(rx
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("fixed local membership"));
    assert!(!driver
        .raw_node
        .store()
        .replica_control_reader_required()
        .unwrap());
}

#[tokio::test]
async fn dropped_response_preserves_preparation_and_retry_uses_the_same_store() {
    let (handle, mut driver, directory) = node(MembershipPolicy::Managed);
    let mut request = Box::pin(handle.prepare_replica_control_reader());
    assert!(poll(&mut request).is_pending());
    drop(request);
    driver.process_messages();
    assert!(driver
        .raw_node
        .store()
        .replica_control_reader_required()
        .unwrap());
    prepare(&handle, &mut driver).await;
    drop(driver);
    drop(handle);
    let reopened = RaftStorage::open(directory.path()).unwrap();
    assert!(reopened.replica_control_reader_required().unwrap());
}
