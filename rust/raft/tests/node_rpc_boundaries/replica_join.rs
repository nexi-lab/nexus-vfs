//! Existing-member readback over actual Node and replica mTLS channels.

use super::{reader_preparation::node_tls, *};
use nexus_raft::raft::{FullStateMachine, StateMachine, ZoneConsensus};
use nexus_raft::transport::proto::{JoinZoneRequest, RemoveVoterRequest};

const ZONE: &str = "replica-readback";
fn request(address: &str) -> JoinZoneRequest {
    JoinZoneRequest {
        zone_id: ZONE.into(),
        node_id: 4,
        node_address: address.into(),
        as_learner: true,
    }
}

async fn unchanged_state(node: &ZoneConsensus<FullStateMachine>) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
    let membership = node.membership().await.unwrap();
    let snapshot = node
        .read_linearizable(StateMachine::snapshot)
        .await
        .unwrap()
        .unwrap();
    (membership.voters, membership.learners, snapshot)
}

struct Fixture {
    server: PeerServer,
    node: ZoneConsensus<FullStateMachine>,
    control: ZoneApiServiceClient<Channel>,
    replica: ZoneApiServiceClient<Channel>,
    join: JoinZoneRequest,
}

async fn fixture() -> Fixture {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let server = PeerServer::start(node_tls(&ca, &key, 7)).await;
    let node = server
        .registry
        .create_zone(ZONE, &tokio::runtime::Handle::current())
        .unwrap();
    node.campaign().await.unwrap();
    let endpoint = server.endpoint.strip_prefix("http://").unwrap();
    let (cert, private) = generate_node_cert(2, "root", &ca, &key, &[], None).unwrap();
    let mut control = ZoneApiServiceClient::new(connect(endpoint, &ca, cert, private).await);
    let join = request(&common::node_bind_addr());
    let (cert, private) =
        generate_user_replica_cert("runtime", "alice", 4, 300, &ca, &key).unwrap();
    let mut replica = ZoneApiServiceClient::new(connect(endpoint, &ca, cert, private).await);
    let before = unchanged_state(&node).await;
    assert_eq!(
        replica.join_zone(join.clone()).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(unchanged_state(&node).await, before);
    let admitted = control.join_zone(join.clone()).await.unwrap().into_inner();
    assert!(admitted.success);
    let learner = &admitted.config.unwrap().learners[0];
    assert_eq!(learner.id, 4);
    assert_eq!(learner.address, format!("https://{}", join.node_address));
    Fixture {
        server,
        node,
        control,
        replica,
        join,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replica_join_reads_its_committed_role_and_address_without_writing() {
    let Fixture {
        server,
        node,
        control,
        mut replica,
        join,
    } = fixture().await;
    let before = unchanged_state(&node).await;
    for address in [
        join.node_address.clone(),
        format!("https://{}", join.node_address),
    ] {
        let reply = replica
            .join_zone(JoinZoneRequest {
                node_address: address,
                ..join.clone()
            })
            .await
            .unwrap()
            .into_inner();
        assert!(reply.success && !reply.catching_up);
        assert!(reply.error.is_none());
        let config = reply.config.unwrap();
        assert_eq!(config.voters.len(), 1);
        assert_eq!(config.voters[0].id, 7);
        assert_eq!(config.learners.len(), 1);
        assert_eq!(config.learners[0].id, 4);
        assert_eq!(
            config.learners[0].address,
            format!("https://{}", join.node_address)
        );
        assert_eq!(unchanged_state(&node).await, before);
    }
    drop(replica);
    drop(control);
    drop(node);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replica_join_refuses_changes_and_removed_members_on_the_original_channel() {
    let Fixture {
        server,
        node,
        mut control,
        mut replica,
        join,
    } = fixture().await;
    let before = unchanged_state(&node).await;
    for invalid in [
        JoinZoneRequest {
            node_id: 5,
            ..join.clone()
        },
        JoinZoneRequest {
            node_address: common::node_bind_addr(),
            ..join.clone()
        },
        JoinZoneRequest {
            as_learner: false,
            ..join.clone()
        },
        JoinZoneRequest {
            zone_id: "root".into(),
            ..join.clone()
        },
        JoinZoneRequest {
            zone_id: "unopened-replica-zone".into(),
            ..join.clone()
        },
    ] {
        let error = replica.join_zone(invalid).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied, "{error}");
        assert_eq!(unchanged_state(&node).await, before);
    }
    assert!(server.registry.get_node("unopened-replica-zone").is_none());
    assert!(
        replica
            .join_zone(join.clone())
            .await
            .unwrap()
            .into_inner()
            .success
    );
    let removed = control
        .remove_voter(RemoveVoterRequest {
            zone_id: ZONE.into(),
            target_node_id: 4,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(removed.success);
    let after = unchanged_state(&node).await;
    assert!(after.1.is_empty());
    assert_eq!(
        replica.join_zone(join).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(unchanged_state(&node).await, after);
    drop(replica);
    drop(control);
    drop(node);
    server.shutdown().await;
}
