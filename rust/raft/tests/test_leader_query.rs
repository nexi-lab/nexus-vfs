//! Compare local and quorum-backed queries before, during and after quorum loss.
#![cfg(all(feature = "grpc", has_protos))]

mod common;
#[path = "common/zone_cluster.rs"]
mod zone_cluster;

use nexus_raft::transport::proto::nexus::core::FileMetadata;
use nexus_raft::transport::proto::nexus::raft::{
    raft_query, raft_query_response, zone_api_service_client::ZoneApiServiceClient, GetMetadata,
    QueryRequest, QueryResponse, RaftQuery,
};
use nexus_raft::transport::{call_join_zone_rpc, ClientConfig, RaftApiClient};
use zone_cluster::{
    cluster_info, eventually, found, join_as_learner, restart_member, stop, Node, ZONE,
};

const KEY: &str = "/marker";
fn request(leader: bool) -> QueryRequest {
    QueryRequest {
        query: Some(RaftQuery {
            query: Some(raft_query::Query::GetMetadata(GetMetadata {
                path: KEY.into(),
                zone_id: ZONE.into(),
            })),
        }),
        zone_id: ZONE.into(),
        read_from_leader: leader,
    }
}

fn assert_marker(response: QueryResponse) {
    assert!(response.success, "{:?}", response.error);
    let Some(raft_query_response::Result::GetMetadataResult(row)) =
        response.result.and_then(|r| r.result)
    else {
        panic!("expected a metadata row");
    };
    assert_eq!(row.metadata.unwrap().content_id, "committed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leader_query_requires_quorum_and_releases_after_recovery() {
    let a = Node::new();
    let b = Node::new();
    let founder = found(&a, vec![]).await;
    let peer = b.start(vec![a.bind.clone()]).await;
    join_as_learner(&peer, &b, &a, &b.endpoint()).await;
    eventually("promote the caught-up voter", || async {
        call_join_zone_rpc(&a.endpoint(), ZONE, b.id, &b.endpoint(), false, None, 5)
            .await
            .is_ok_and(|result| result.success)
    })
    .await;
    let mut writer = RaftApiClient::connect(&a.endpoint(), ClientConfig::default())
        .await
        .unwrap()
        .with_zone_id(ZONE.into());
    assert!(
        writer
            .put_metadata(FileMetadata {
                path: KEY.into(),
                zone_id: ZONE.into(),
                content_id: "committed".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .success
    );
    let mut leader = ZoneApiServiceClient::connect(a.endpoint()).await.unwrap();
    let mut follower = ZoneApiServiceClient::connect(b.endpoint()).await.unwrap();
    assert_marker(leader.query(request(true)).await.unwrap().into_inner());
    let redirect = follower.query(request(true)).await.unwrap().into_inner();
    assert!(!redirect.success && redirect.result.is_none());
    assert!(redirect.leader_address.is_some());

    stop(peer).await;
    assert_marker(leader.query(request(false)).await.unwrap().into_inner());
    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        leader.query(request(true)),
    )
    .await
    .expect("bounded server refusal")
    .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Unavailable);

    let peer = restart_member(&b, vec![a.bind.clone()]).await;
    eventually("the two voters elect a leader", || async {
        cluster_info(&a.endpoint()).await.is_leader || cluster_info(&b.endpoint()).await.is_leader
    })
    .await;
    let current = if cluster_info(&a.endpoint()).await.is_leader {
        a.endpoint()
    } else {
        b.endpoint()
    };
    let mut current = ZoneApiServiceClient::connect(current).await.unwrap();
    assert_marker(current.query(request(true)).await.unwrap().into_inner());
    stop(peer).await;
    stop(founder).await;
}
