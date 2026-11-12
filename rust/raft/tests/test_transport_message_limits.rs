//! Real mTLS decoding, large-entry replication and full-state snapshot admission.
#![cfg(all(feature = "grpc", has_protos))]
mod common;
#[path = "transport_message_limits/fixture.rs"]
mod fixture;

use fixture::{node_tls, Role, Server, LARGE, ZONE};
use nexus_raft::{
    prelude::Command,
    raft::StateMachine,
    transport::{
        generate_zone_ca,
        proto::{
            zone_api_service_client::ZoneApiServiceClient,
            zone_transport_service_client::ZoneTransportServiceClient, GetClusterInfoRequest,
            ProposeRequest, StepMessageRequest,
        },
        ServerConfig,
    },
};
use protobuf::Message as _;
use raft::eraftpb::{ConfChangeType, Message, MessageType};
use std::time::Duration;

fn request(context_size: usize) -> StepMessageRequest {
    let mut message = Message::default();
    message.set_msg_type(MessageType::MsgHeartbeat);
    message.from = 1;
    message.to = 7;
    message.term = 1;
    message.context = vec![0x61; context_size].into();
    StepMessageRequest {
        zone_id: ZONE.into(),
        message: message.write_to_bytes().unwrap(),
        sender_address: String::new(),
    }
}

async fn accepts_large(role: Role) {
    let (ca, key) = generate_zone_ca(ZONE).unwrap();
    let server = Server::start(
        7,
        node_tls(&ca, &key, 7),
        role,
        ServerConfig::default().max_message_size,
    )
    .await;
    let mut client = ZoneTransportServiceClient::new(server.channel(node_tls(&ca, &key, 1)).await);
    let large = request(LARGE);
    assert!(prost::Message::encoded_len(&large) > 4 * 1024 * 1024);
    assert!(
        client
            .step_message(large.clone())
            .await
            .unwrap()
            .into_inner()
            .success
    );
    assert!(
        client
            .step_storage_v1(large.clone())
            .await
            .unwrap()
            .into_inner()
            .success
    );
    assert!(
        client
            .step_replica_control_v1(large)
            .await
            .unwrap()
            .into_inner()
            .success
    );
    // The enlarged decoder must still retain the real Node sender check.
    let mut forged = request(LARGE);
    let mut message = Message::parse_from_bytes(&forged.message).unwrap();
    message.from = 2;
    forged.message = message.write_to_bytes().unwrap();
    assert_eq!(
        client
            .step_replica_control_v1(forged)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    drop(client);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_node_applies_configured_limit_to_all_raft_methods() {
    accepts_large(Role::Learner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn witness_applies_configured_limit_to_all_raft_methods() {
    accepts_large(Role::Witness).await;
}

async fn refuses_above_limit(role: Role, api: bool) {
    let (ca, key) = generate_zone_ca(ZONE).unwrap();
    let server = Server::start(7, node_tls(&ca, &key, 7), role, 1024).await;
    let channel = server.channel(node_tls(&ca, &key, 1)).await;
    let mut client = ZoneTransportServiceClient::new(channel.clone());
    assert!(prost::Message::encoded_len(&request(512)) < 1024);
    assert!(
        client
            .step_message(request(512))
            .await
            .unwrap()
            .into_inner()
            .success
    );
    let large = request(2048);
    assert!(prost::Message::encoded_len(&large) > 1024);
    for result in [
        client.step_message(large.clone()).await,
        client.step_storage_v1(large.clone()).await,
        client.step_replica_control_v1(large).await,
    ] {
        let error = result.unwrap_err();
        assert_eq!(error.code(), tonic::Code::OutOfRange);
        assert!(error.message().contains("the limit is: 1024"), "{error}");
    }
    if api {
        let mut api = ZoneApiServiceClient::new(channel);
        api.get_cluster_info(GetClusterInfoRequest {
            zone_id: ZONE.into(),
        })
        .await
        .unwrap();
        let error = api
            .propose(ProposeRequest {
                zone_id: ZONE.into(),
                raw_command: vec![0; 2048],
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::OutOfRange);
        assert!(error.message().contains("the limit is: 1024"), "{error}");
    }
    drop(client);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_node_and_api_preserve_explicit_lower_limit() {
    refuses_above_limit(Role::Learner, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn witness_preserves_explicit_lower_limit() {
    refuses_above_limit(Role::Witness, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_transport_replicates_one_entry_larger_than_batch_limit() {
    let (ca, key) = generate_zone_ca(ZONE).unwrap();
    let limit = ServerConfig::default().max_message_size;
    let first = Server::start(1, node_tls(&ca, &key, 1), Role::Leader, limit).await;
    let second = Server::start(7, node_tls(&ca, &key, 7), Role::Learner, limit).await;
    let leader = first.full().get_node(ZONE).unwrap();
    leader
        .propose_conf_change(ConfChangeType::AddLearnerNode, 7, Vec::new())
        .await
        .unwrap();
    assert!(first.full().learn_peer_address(ZONE, 7, &second.address));
    let value = vec![0x71; LARGE];
    leader
        .propose(Command::SetMetadata {
            key: "/large-entry".into(),
            value: value.clone(),
        })
        .await
        .unwrap();
    let learner = second.full().get_node(ZONE).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if learner
                .with_state_machine(|state| state.get_metadata("/large-entry").unwrap())
                .await
                == Some(value.clone())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("production TransportLoop must deliver the actual large entry");
    assert_eq!(
        learner
            .read_linearizable(|state| state.get_metadata("/large-entry"))
            .await
            .unwrap()
            .unwrap(),
        Some(value)
    );
    drop(learner);
    drop(leader);
    second.shutdown().await;
    first.shutdown().await;
}

async fn snapshot_catchup(role: Role, full: bool) {
    let (ca, key) = generate_zone_ca(ZONE).unwrap();
    let limit = ServerConfig::default().max_message_size;
    let first = Server::start(1, node_tls(&ca, &key, 1), Role::Leader, limit).await;
    let second = Server::start(7, node_tls(&ca, &key, 7), role, limit).await;
    let leader = first.full().get_node(ZONE).unwrap();
    let value = vec![0x72; LARGE];
    leader
        .propose(Command::SetMetadata {
            key: "/snapshot-only".into(),
            value: value.clone(),
        })
        .await
        .unwrap();
    leader
        .propose_conf_change(ConfChangeType::AddLearnerNode, 7, Vec::new())
        .await
        .unwrap();
    // No leader route is installed: this catch-up receives only the actual
    // full-state snapshot, not the original metadata entry through Append.
    let (index, data) = leader
        .with_state_machine(|state| (state.last_applied_index(), state.snapshot().unwrap()))
        .await;
    assert!(data.len() > 4 * 1024 * 1024);
    let membership = leader.membership().await.unwrap();
    let mut message = Message::default();
    message.set_msg_type(MessageType::MsgSnapshot);
    message.from = 1;
    message.to = 7;
    message.term = leader.term();
    message.mut_snapshot().data = data.into();
    let metadata = message.mut_snapshot().mut_metadata();
    metadata.index = index;
    metadata.term = leader.term();
    metadata.mut_conf_state().voters = membership.voters;
    metadata.mut_conf_state().learners = membership.learners;
    let mut client = ZoneTransportServiceClient::new(second.channel(node_tls(&ca, &key, 1)).await);
    let response = client
        .step_message(StepMessageRequest {
            zone_id: ZONE.into(),
            message: message.write_to_bytes().unwrap(),
            sender_address: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(response.success, "{response:?}");
    tokio::time::timeout(Duration::from_secs(10), async {
        while second.applied_index() < index {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("snapshot must actually apply before acceptance");
    if full {
        assert_eq!(
            second
                .full()
                .get_node(ZONE)
                .unwrap()
                .with_state_machine(|state| state.get_metadata("/snapshot-only").unwrap())
                .await,
            Some(value)
        );
    }
    drop(client);
    drop(leader);
    second.shutdown().await;
    first.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_node_applies_large_state_snapshot() {
    snapshot_catchup(Role::Learner, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn witness_applies_large_state_snapshot() {
    snapshot_catchup(Role::Witness, false).await;
}
