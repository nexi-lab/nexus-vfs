//! Activation and replica storage use the original actor and persistent stores.

use super::member_preparation::drive;
use super::*;
use crate::raft::state_machine::assert_snapshots_equal;

async fn activate(
    handle: &ZoneConsensus<FullStateMachine>,
    driver: &mut ZoneConsensusDriver<FullStateMachine>,
    operation: &str,
) -> crate::raft::ReplicaControlActivation {
    let prepared = drive(driver, handle.prepare_replica_control_members())
        .await
        .unwrap();
    drive(
        driver,
        handle.activate_replica_control(prepared, operation.into()),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn activation_commits_replica_only_and_survives_original_store_reopen() {
    let (handle, mut driver, directory) = node(MembershipPolicy::Managed);
    drive(&mut driver, handle.campaign()).await.unwrap();
    let original = activate(&handle, &mut driver, "original").await;
    assert_eq!(original.operation_id, "original");
    drive(&mut driver, handle.commit_replica_control(replica()))
        .await
        .unwrap();
    let before = handle.state_machine.read().await.snapshot().unwrap();
    for (command, protocol) in [
        (conditional(), StorageProtocol::ConditionalMetadata),
        (record(), StorageProtocol::RecordLifetime),
    ] {
        assert!(matches!(
            handle.submit_storage_command(command, protocol).await,
            Err(RaftError::UnsupportedOperation(_))
        ));
    }
    assert!(handle.propose(replica()).await.is_err());
    assert!(handle.propose_ec(replica()).await.is_err());
    assert!(driver.msg_rx.is_empty());
    assert_snapshots_equal(
        &handle.state_machine.read().await.snapshot().unwrap(),
        &before,
    );
    driver.snapshot_threshold = 1;
    driver.maybe_snapshot_and_compact().await.unwrap();
    assert!(driver.raw_node.store().first_index_impl().unwrap() > 1);
    drop((handle, driver));

    let store = RedbStore::open(directory.path().join("state")).unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    assert_eq!(
        state.replica_control_activation().unwrap(),
        Some(original.clone())
    );
    let config = RaftConfig {
        id: 1,
        ..Default::default()
    };
    let (handle, mut driver) = ZoneConsensus::new(
        config,
        RaftStorage::open(directory.path()).unwrap(),
        state,
        None,
    )
    .unwrap();
    assert!(driver.replica_control_reader_prepared && driver.replica_control_active);
    drive(&mut driver, handle.campaign()).await.unwrap();
    assert_eq!(
        activate(&handle, &mut driver, "later-request").await,
        original
    );
    drive(&mut driver, handle.commit_replica_control(replica()))
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
async fn consumed_preparation_is_rechecked_at_submission_after_configuration_roundtrip() {
    let (handle, mut driver, _directory) = node(MembershipPolicy::Managed);
    drive(&mut driver, handle.campaign()).await.unwrap();
    let prepared = drive(&mut driver, handle.prepare_replica_control_members())
        .await
        .unwrap();
    for change in [ConfChangeType::AddLearnerNode, ConfChangeType::RemoveNode] {
        drive(&mut driver, handle.propose_conf_change(change, 2, vec![]))
            .await
            .unwrap();
    }
    let last = driver.raw_node.raft.raft_log.last_index();
    let before = handle.state_machine.read().await.snapshot().unwrap();
    let refused = drive(
        &mut driver,
        handle.activate_replica_control(prepared, "stale".into()),
    )
    .await
    .unwrap_err();
    assert!(matches!(refused, RaftError::ProposalRejected(_)));
    assert!(refused.to_string().contains("configuration changed"));
    assert_eq!(driver.raw_node.raft.raft_log.last_index(), last);
    assert_snapshots_equal(
        &handle.state_machine.read().await.snapshot().unwrap(),
        &before,
    );
    assert_eq!(
        activate(&handle, &mut driver, "current").await.operation_id,
        "current"
    );
}

#[tokio::test]
async fn prepared_observation_cannot_activate_another_driver_with_identical_members() {
    let (a, mut a_driver, _a_directory) = node(MembershipPolicy::Managed);
    let (b, mut b_driver, _b_directory) = node(MembershipPolicy::Managed);
    drive(&mut a_driver, a.campaign()).await.unwrap();
    drive(&mut b_driver, b.campaign()).await.unwrap();
    let prepared = drive(&mut a_driver, a.prepare_replica_control_members())
        .await
        .unwrap();
    drive(&mut b_driver, b.prepare_replica_control_reader())
        .await
        .unwrap();
    let last = b_driver.raw_node.raft.raft_log.last_index();
    let refused = drive(
        &mut b_driver,
        b.activate_replica_control(prepared, "wrong-driver".into()),
    )
    .await
    .unwrap_err();
    assert!(refused.to_string().contains("different driver incarnation"));
    assert_eq!(b_driver.raw_node.raft.raft_log.last_index(), last);
    assert!(b
        .state_machine
        .read()
        .await
        .replica_control_activation()
        .unwrap()
        .is_none());
    assert_eq!(
        activate(&b, &mut b_driver, "own-driver").await.operation_id,
        "own-driver"
    );
}

#[tokio::test]
async fn lost_activation_reply_reconciles_the_original_operation() {
    let (handle, mut driver, _directory) = node(MembershipPolicy::Managed);
    drive(&mut driver, handle.campaign()).await.unwrap();
    let prepared = drive(&mut driver, handle.prepare_replica_control_members())
        .await
        .unwrap();
    let mut request = Box::pin(handle.activate_replica_control(prepared, "lost-reply".into()));
    assert!(poll(&mut request).is_pending());
    driver.process_messages();
    while driver.has_ready() {
        driver.advance().await.unwrap();
    }
    // The client loses its original reply after real persistence and apply.
    drop(request);
    let original = drive(
        &mut driver,
        handle.read_linearizable(|sm| sm.replica_control_activation()),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(original.operation_id, "lost-reply");
    assert_eq!(
        activate(&handle, &mut driver, "replacement-request").await,
        original
    );
}

#[tokio::test]
async fn active_image_requires_local_reader_before_boot_and_snapshot_admission() {
    let (handle, mut driver, _directory) = node(MembershipPolicy::Managed);
    drive(&mut driver, handle.campaign()).await.unwrap();
    activate(&handle, &mut driver, "snapshot-original").await;
    driver.snapshot_threshold = 1;
    driver.maybe_snapshot_and_compact().await.unwrap();
    let raft_snapshot = driver.raw_node.store().snapshot(0, 1).unwrap();
    assert!(raft_snapshot.get_metadata().index > 0);
    let image = handle.state_machine.read().await.snapshot().unwrap();
    let target = TempDir::new().unwrap();
    let store = RedbStore::open(target.path().join("state")).unwrap();
    let mut state = FullStateMachine::new(&store).unwrap();
    assert!(state
        .validate_snapshot_reader(&image, MembershipPolicy::Managed, false)
        .is_err());
    state
        .validate_snapshot_reader(&image, MembershipPolicy::Managed, true)
        .unwrap();
    state.restore_snapshot(&image).unwrap();
    let config = RaftConfig {
        id: 1,
        ..Default::default()
    };
    let storage = RaftStorage::open(target.path()).unwrap();
    storage.apply_snapshot(&raft_snapshot).unwrap();
    assert!(ZoneConsensus::new(config.clone(), storage, state, None).is_err());
    let state = FullStateMachine::new(&store).unwrap();
    assert_snapshots_equal(&state.snapshot().unwrap(), &image);
    let storage = RaftStorage::open(target.path()).unwrap();
    storage.prepare_replica_control_reader().unwrap();
    let (restored, _driver) = ZoneConsensus::new(config, storage, state, None).unwrap();
    assert_eq!(
        restored
            .state_machine
            .read()
            .await
            .replica_control_activation()
            .unwrap()
            .unwrap()
            .operation_id,
        "snapshot-original"
    );
}

#[tokio::test]
async fn versioned_transport_keeps_raw_storage_proposals_refused() {
    let (handle, driver, _directory) = node(MembershipPolicy::Managed);
    for command in [
        replica(),
        Command::ActivateReplicaControl {
            operation_id: "raw".into(),
        },
    ] {
        let mut data = 0_u64.to_be_bytes().to_vec();
        data.extend(bincode::serialize(&command).unwrap());
        let mut message = Message::default();
        message.set_msg_type(raft::eraftpb::MessageType::MsgPropose);
        message.entries.push(Entry {
            data: data.into(),
            ..Default::default()
        });
        assert!(handle
            .step_transport(message, RaftMessageProtocol::ReplicaControlV1)
            .await
            .is_err());
        assert!(driver.msg_rx.is_empty());
    }
    assert!(!driver
        .raw_node
        .store()
        .replica_control_reader_required()
        .unwrap());
}
