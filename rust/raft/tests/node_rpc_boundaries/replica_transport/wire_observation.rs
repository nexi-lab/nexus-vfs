//! Observe the production sender's decoded wire request independently of catch-up.

use super::*;
use nexus_raft::transport::proto::{StepMessageRequest, StepMessageResponse};
use std::task::{Context, Poll};
use tonic::{
    body::Body,
    codegen::{http, BoxFuture, Service},
    server::NamedService,
    Status,
};

#[derive(Debug)]
struct WireRequest {
    method: String,
    zone: String,
    from: u64,
    to: u64,
}

/// This wire observer decodes the actual RPC over mTLS. The adjacent two-node
/// test separately requires original Raft replication, ReadIndex and restart.
#[derive(Clone)]
struct ObserveWire(tokio::sync::mpsc::Sender<WireRequest>);

impl NamedService for ObserveWire {
    const NAME: &'static str = "nexus.raft.ZoneTransportService";
}

impl Service<http::Request<Body>> for ObserveWire {
    type Response = http::Response<Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let method = request.uri().path().to_owned();
        if !matches!(
            method.as_str(),
            "/nexus.raft.ZoneTransportService/StepMessage"
                | "/nexus.raft.ZoneTransportService/StepStorageV1"
                | "/nexus.raft.ZoneTransportService/StepReplicaControlV1"
        ) {
            return Box::pin(async {
                Ok(Status::unimplemented("wire observer accepts Raft exchanges").into_http())
            });
        }
        struct Step {
            method: String,
            observer: ObserveWire,
        }
        impl tonic::server::UnaryService<StepMessageRequest> for Step {
            type Response = StepMessageResponse;
            type Future = BoxFuture<tonic::Response<Self::Response>, Status>;

            fn call(&mut self, request: tonic::Request<StepMessageRequest>) -> Self::Future {
                let method = self.method.clone();
                let observer = self.observer.clone();
                Box::pin(async move {
                    let body = request.into_inner();
                    let message = raft::eraftpb::Message::parse_from_bytes(&body.message)
                        .map_err(|error| Status::invalid_argument(error.to_string()))?;
                    let _ = observer.0.try_send(WireRequest {
                        method,
                        zone: body.zone_id,
                        from: message.from,
                        to: message.to,
                    });
                    Ok(tonic::Response::new(StepMessageResponse {
                        success: true,
                        error: None,
                    }))
                })
            }
        }
        let service = Step {
            method,
            observer: self.clone(),
        };
        Box::pin(async move {
            Ok(tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                .unary(service, request)
                .await)
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_production_sender_selects_required_rpc_before_replication_wait() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let first = RunningNode::start(1, node_tls(&ca, &key, 1)).await;
    let address = common::node_bind_addr();
    let incoming = lib::transport_primitives::federated_mtls_incoming(
        address.parse().unwrap(),
        common::cluster_server_identity(&node_tls(&ca, &key, 2)),
    )
    .await
    .unwrap();
    let (observed, mut observation) = tokio::sync::mpsc::channel(1);
    let service = ObserveWire(observed);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    listener_ready(&address).await;
    let zone = "observed-required-wire";
    let leader = first
        .registry
        .create_zone(zone, &tokio::runtime::Handle::current())
        .unwrap();
    leader.campaign().await.unwrap();
    leader.prepare_replica_control_reader().await.unwrap();
    leader
        .propose_conf_change(raft::eraftpb::ConfChangeType::AddLearnerNode, 2, Vec::new())
        .await
        .unwrap();
    assert!(first.registry.learn_peer_address(zone, 2, &address));
    let received = tokio::time::timeout(Duration::from_secs(10), observation.recv())
        .await
        .expect("the actual transport must send a decoded Raft exchange")
        .unwrap();
    assert_eq!((received.from, received.to), (1, 2));
    assert_eq!(received.zone, zone);
    assert_eq!(
        received.method, "/nexus.raft.ZoneTransportService/StepReplicaControlV1",
        "the production send loop must select the prepared transport"
    );
    drop(leader);
    first.stop().await;
    stop.send(()).unwrap();
    task.await.unwrap();
}
