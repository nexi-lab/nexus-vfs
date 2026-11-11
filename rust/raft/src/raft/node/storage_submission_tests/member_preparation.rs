//! Member preparation remains bound to the original driver observation.

use super::*;

async fn drive<F: Future>(
    driver: &mut ZoneConsensusDriver<FullStateMachine>,
    future: F,
) -> F::Output {
    let mut future = Box::pin(future);
    for _ in 0..16 {
        match poll(&mut future) {
            Poll::Ready(result) => return result,
            Poll::Pending => {
                driver.process_messages();
                while driver.has_ready() {
                    let _ = driver.advance().await.unwrap();
                }
            }
        }
    }
    panic!("local preparation did not finish through its original actor");
}

#[tokio::test]
async fn lone_member_prepares_original_store_without_creating_activation() {
    let (handle, mut driver, _directory) = node(MembershipPolicy::Managed);
    drive(&mut driver, handle.campaign()).await.unwrap();
    let before = handle.state_machine.read().await.snapshot().unwrap();
    let last = driver.raw_node.raft.raft_log.last_index();
    let prepared = drive(&mut driver, handle.prepare_replica_control_members())
        .await
        .unwrap();
    assert_eq!(prepared.member_ids(), vec![1]);
    assert!(driver
        .raw_node
        .store()
        .replica_control_reader_required()
        .unwrap());
    assert_eq!(driver.raw_node.raft.raft_log.last_index(), last);
    assert_eq!(
        handle.state_machine.read().await.snapshot().unwrap(),
        before
    );
    assert!(handle
        .state_machine
        .read()
        .await
        .replica_control_activation()
        .unwrap()
        .is_none());
    assert!(matches!(
        handle.commit_replica_control(replica()).await,
        Err(RaftError::UnsupportedOperation(_))
    ));
}

#[tokio::test]
async fn missing_member_transport_refuses_before_any_local_preparation() {
    let (handle, mut driver, _directory) = node(MembershipPolicy::Managed);
    drive(&mut driver, handle.campaign()).await.unwrap();
    drive(
        &mut driver,
        handle.propose_conf_change(ConfChangeType::AddLearnerNode, 2, vec![]),
    )
    .await
    .unwrap();
    let error = drive(&mut driver, handle.prepare_replica_control_members())
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("requires the owning zone transport"));
    assert!(!driver
        .raw_node
        .store()
        .replica_control_reader_required()
        .unwrap());
    assert!(handle
        .state_machine
        .read()
        .await
        .replica_control_activation()
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn completion_rechecks_epoch_and_original_incarnation_after_remote_awaits() {
    let (handle, mut driver, _directory) = node(MembershipPolicy::Managed);
    drive(&mut driver, handle.campaign()).await.unwrap();
    let observed = drive(&mut driver, handle.storage_activation_view())
        .await
        .unwrap();
    assert!(driver
        .complete_replica_control_preparation(observed.clone())
        .unwrap_err()
        .to_string()
        .contains("has not prepared"));
    drive(&mut driver, handle.prepare_replica_control_reader())
        .await
        .unwrap();
    driver
        .complete_replica_control_preparation(observed.clone())
        .unwrap();
    drive(
        &mut driver,
        handle.propose_conf_change(ConfChangeType::AddLearnerNode, 2, vec![]),
    )
    .await
    .unwrap();
    drive(
        &mut driver,
        handle.propose_conf_change(ConfChangeType::RemoveNode, 2, vec![]),
    )
    .await
    .unwrap();
    assert!(driver
        .complete_replica_control_preparation(observed.clone())
        .unwrap_err()
        .to_string()
        .contains("configuration changed"));
    let (other, mut other_driver, _other_directory) = node(MembershipPolicy::Managed);
    drive(&mut other_driver, other.campaign()).await.unwrap();
    drive(&mut other_driver, other.prepare_replica_control_reader())
        .await
        .unwrap();
    assert!(other_driver
        .complete_replica_control_preparation(observed)
        .unwrap_err()
        .to_string()
        .contains("different driver incarnation"));
    let fresh = drive(&mut driver, handle.prepare_replica_control_members())
        .await
        .unwrap();
    assert_eq!(fresh.member_ids(), vec![1]);
}
