//! Protocol admission is serialized with durable preparation by the same driver.

use super::*;

fn heartbeat(term: u64) -> Message {
    let mut message = Message::default();
    message.set_msg_type(raft::eraftpb::MessageType::MsgHeartbeat);
    message.from = 2;
    message.to = 1;
    message.term = term;
    message
}

async fn exchange(
    handle: &ZoneConsensus<FullStateMachine>,
    driver: &mut ZoneConsensusDriver<FullStateMachine>,
    term: u64,
    protocol: RaftMessageProtocol,
) -> Result<()> {
    let mut request = Box::pin(handle.step_transport(heartbeat(term), protocol));
    assert!(poll(&mut request).is_pending());
    driver.process_messages();
    match poll(&mut request) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("driver did not acknowledge protocol admission"),
    }
}

#[tokio::test]
async fn preparation_fences_an_already_queued_legacy_exchange_before_raft_step() {
    let (handle, mut driver, _directory) = node(MembershipPolicy::Managed);
    exchange(&handle, &mut driver, 4, RaftMessageProtocol::Legacy)
        .await
        .unwrap();
    assert_eq!(driver.raw_node.raft.term, 4);
    let mut preparation = Box::pin(handle.prepare_replica_control_reader());
    assert!(poll(&mut preparation).is_pending());
    let mut legacy = Box::pin(handle.step_transport(heartbeat(20), RaftMessageProtocol::Legacy));
    assert!(poll(&mut legacy).is_pending());
    driver.process_messages();
    assert!(matches!(poll(&mut preparation), Poll::Ready(Ok(()))));
    assert!(matches!(
        poll(&mut legacy),
        Poll::Ready(Err(RaftError::UnsupportedOperation(
            "prepared reader requires replica-control transport"
        )))
    ));
    assert_eq!(
        driver.raw_node.raft.term, 4,
        "legacy traffic reached RawNode"
    );
    // The native enqueue entry has the same driver gate, even without a reply.
    handle.step(heartbeat(30)).await.unwrap();
    driver.process_messages();
    assert_eq!(driver.raw_node.raft.term, 4);
    exchange(
        &handle,
        &mut driver,
        5,
        RaftMessageProtocol::ReplicaControlV1,
    )
    .await
    .unwrap();
    assert_eq!(driver.raw_node.raft.term, 5);
}

#[tokio::test]
async fn versioned_ingress_prepares_and_cold_boot_preserves_required_egress() {
    let (handle, mut driver, directory) = node(MembershipPolicy::Managed);
    assert_eq!(driver.raft_message_protocol(), RaftMessageProtocol::Legacy);
    exchange(
        &handle,
        &mut driver,
        4,
        RaftMessageProtocol::ReplicaControlV1,
    )
    .await
    .unwrap();
    assert_eq!(
        driver.raft_message_protocol(),
        RaftMessageProtocol::ReplicaControlV1
    );
    assert!(driver
        .raw_node
        .store()
        .replica_control_reader_required()
        .unwrap());
    driver.advance().await.unwrap();
    drop(driver);
    drop(handle);
    let storage = RaftStorage::open(directory.path()).unwrap();
    let store = RedbStore::open(directory.path().join("state")).unwrap();
    let (handle, mut driver) = ZoneConsensus::new(
        RaftConfig::default(),
        storage,
        FullStateMachine::new(&store).unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(
        driver.raft_message_protocol(),
        RaftMessageProtocol::ReplicaControlV1
    );
    let term = driver.raw_node.raft.term;
    assert!(
        exchange(&handle, &mut driver, term + 9, RaftMessageProtocol::Legacy)
            .await
            .is_err()
    );
    assert_eq!(driver.raw_node.raft.term, term);
    exchange(
        &handle,
        &mut driver,
        term + 1,
        RaftMessageProtocol::ReplicaControlV1,
    )
    .await
    .unwrap();
    assert_eq!(driver.raw_node.raft.term, term + 1);
    assert!(handle
        .state_machine
        .read()
        .await
        .replica_control_activation()
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn versioned_ingress_preserves_fixed_local_and_storage_domain_refusal() {
    let (local, mut driver, _directory) = node(MembershipPolicy::FixedLocal);
    let error = local
        .step_transport(heartbeat(8), RaftMessageProtocol::ReplicaControlV1)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("fixed local membership"));
    assert!(driver.msg_rx.is_empty());
    let (tx, rx) = oneshot::channel();
    local
        .msg_tx
        .try_send(RaftMsg::StepTransport {
            msg: heartbeat(8),
            protocol: RaftMessageProtocol::ReplicaControlV1,
            tx,
        })
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

    let (handle, driver, _directory) = node(MembershipPolicy::Managed);
    for command in [
        replica(),
        conditional(),
        record(),
        Command::ActivateReplicaControl {
            operation_id: "wire-is-not-activation".into(),
        },
    ] {
        let mut message = heartbeat(8);
        message.set_msg_type(raft::eraftpb::MessageType::MsgAppend);
        let mut data = 0_u64.to_be_bytes().to_vec();
        data.extend(bincode::serialize(&command).unwrap());
        message.entries.push(raft::eraftpb::Entry {
            data: data.into(),
            ..Default::default()
        });
        assert!(handle
            .step_transport(message, RaftMessageProtocol::ReplicaControlV1)
            .await
            .unwrap_err()
            .to_string()
            .contains("qualified fixed-local storage"));
        assert!(driver.msg_rx.is_empty());
    }
    assert!(!driver
        .raw_node
        .store()
        .replica_control_reader_required()
        .unwrap());
    drop(driver);
    assert!(matches!(
        handle
            .step_transport(heartbeat(9), RaftMessageProtocol::ReplicaControlV1)
            .await,
        Err(RaftError::ChannelClosed)
    ));
}
