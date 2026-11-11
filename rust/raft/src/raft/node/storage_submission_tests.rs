//! Typed authorities keep distinct proposal doors over the real Raft driver.

use super::*;
use crate::raft::{FullStateMachine, MembershipPolicy};
use crate::storage::RedbStore;
use contracts::node_identity::{NodeIdentity, NodeIdentityRequest};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use tempfile::TempDir;

fn node(
    policy: MembershipPolicy,
) -> (
    ZoneConsensus<FullStateMachine>,
    ZoneConsensusDriver<FullStateMachine>,
    TempDir,
) {
    let dir = TempDir::new().unwrap();
    let storage = RaftStorage::open(dir.path()).unwrap();
    let store = RedbStore::open(dir.path().join("state")).unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    let config = RaftConfig {
        id: 1,
        membership_policy: policy,
        ..Default::default()
    };
    let (handle, driver) = ZoneConsensus::new(config, storage, state, None).unwrap();
    (handle, driver, dir)
}

fn poll<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
}

async fn finish<F: Future>(
    driver: &mut ZoneConsensusDriver<FullStateMachine>,
    future: F,
) -> F::Output {
    let mut future = Box::pin(future);
    assert!(poll(&mut future).is_pending());
    driver.process_messages();
    while driver.has_ready() {
        assert!(driver.advance().await.unwrap().is_empty());
    }
    match poll(&mut future) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("local operation remained pending after persistence and apply"),
    }
}

fn replica() -> Command {
    Command::ReserveNodeIdentity(Box::new(NodeIdentityRequest {
        operation_id: "typed-protocol-node".into(),
        identity: NodeIdentity {
            node_id: 42,
            subject_public_key_sha256: [4; 32],
        },
    }))
}

fn record() -> Command {
    Command::AdmitRecordIoOwner {
        key: "/protocol/owner".into(),
        expected_version: vec![7; 24],
    }
}

fn conditional() -> Command {
    Command::AdoptProtectedMetadata {
        key: "/protocol/owner".into(),
        expected_image: None,
        incarnation: [1; 16],
    }
}

#[tokio::test]
async fn wrong_storage_door_refuses_before_enqueue_and_correct_door_commits() {
    let (handle, mut driver, _dir) = node(MembershipPolicy::FixedLocal);
    finish(&mut driver, handle.campaign()).await.unwrap();
    assert!(handle.is_leader());
    let before = handle.state_machine.read().await.snapshot().unwrap();
    for (command, owner) in [
        (conditional(), StorageProtocol::ConditionalMetadata),
        (record(), StorageProtocol::RecordLifetime),
        (replica(), StorageProtocol::ReplicaControl),
    ] {
        for wrong in [
            StorageProtocol::ConditionalMetadata,
            StorageProtocol::RecordLifetime,
            StorageProtocol::ReplicaControl,
        ] {
            if wrong != owner {
                assert!(matches!(
                    handle.submit_storage_command(command.clone(), wrong).await,
                    Err(RaftError::InvalidState(_))
                ));
            }
        }
        assert!(matches!(
            handle.propose(command.clone()).await,
            Err(RaftError::Config(_))
        ));
        assert!(matches!(
            handle.propose_ec(command).await,
            Err(RaftError::Config(_))
        ));
    }
    assert!(matches!(
        handle.commit_replica_control(Command::Noop).await,
        Err(RaftError::InvalidState(_))
    ));
    assert!(matches!(
        handle.commit_record_storage(Command::Noop).await,
        Err(RaftError::InvalidState(_))
    ));
    assert!(driver.msg_rx.is_empty());
    assert_eq!(
        handle.state_machine.read().await.snapshot().unwrap(),
        before
    );

    let adopted = finish(
        &mut driver,
        handle.adopt_protected_metadata("/protocol/owner".into(), None, [1; 16]),
    )
    .await
    .unwrap();
    assert!(matches!(
        adopted,
        CommandResult::ProtectedMetadata { protected: true }
    ));
    let written = finish(
        &mut driver,
        handle.replace_conditional_metadata(
            "/protocol/owner".into(),
            b"live owner".to_vec(),
            None,
            [2; 16],
        ),
    )
    .await
    .unwrap();
    let version = match written {
        CommandResult::ConditionalMetadata {
            committed: true,
            current,
        } => current.version.expect("committed owner revision"),
        other => panic!("owner write failed: {other:?}"),
    };
    assert!(matches!(
        finish(
            &mut driver,
            handle.commit_record_storage(Command::AdmitRecordIoOwner {
                key: "/protocol/owner".into(),
                expected_version: version.clone(),
            }),
        )
        .await
        .unwrap(),
        CommandResult::Success
    ));
    finish(&mut driver, handle.commit_replica_control(replica()))
        .await
        .unwrap();
    let state = handle.state_machine.read().await;
    assert_eq!(state.node_identity(42).unwrap().unwrap().node_id, 42);
    assert!(state
        .live_record_io_domain("/protocol/owner", &version)
        .is_ok());
    assert!(state.last_applied_index() > 0);
}

#[tokio::test]
async fn managed_membership_does_not_implicitly_enable_any_storage_protocol() {
    let (handle, mut driver, _dir) = node(MembershipPolicy::Managed);
    finish(&mut driver, handle.campaign()).await.unwrap();
    let before = handle.state_machine.read().await.snapshot().unwrap();
    for (command, protocol) in [
        (conditional(), StorageProtocol::ConditionalMetadata),
        (record(), StorageProtocol::RecordLifetime),
        (replica(), StorageProtocol::ReplicaControl),
    ] {
        assert!(matches!(
            handle.submit_storage_command(command, protocol).await,
            Err(RaftError::UnsupportedOperation(_))
        ));
    }
    assert!(driver.msg_rx.is_empty());
    assert_eq!(
        handle.state_machine.read().await.snapshot().unwrap(),
        before
    );
    assert!(matches!(
        finish(&mut driver, handle.propose(Command::Noop))
            .await
            .unwrap(),
        CommandResult::Success
    ));
}
