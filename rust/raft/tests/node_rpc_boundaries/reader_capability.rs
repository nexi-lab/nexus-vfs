//! An earlier empty preparation reply cannot qualify the required transport.

use super::reader_preparation::{node_tls, pool, reopened};
use super::*;
use nexus_raft::{
    raft::{FullStateMachine, ZoneConsensus},
    transport::{
        proto::{PrepareReplicaControlReaderRequest, PrepareReplicaControlReaderResponse},
        NodeAddress, TransportError,
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tonic::{
    body::Body,
    codegen::{http, BoxFuture, Service},
    server::NamedService,
    Status,
};

/// The previous preparation method persists through the real driver and emits
/// its original empty protobuf reply. No newer capability is advertised.
#[derive(Clone)]
struct ReaderOnly {
    node: ZoneConsensus<FullStateMachine>,
    calls: Arc<AtomicUsize>,
}

impl NamedService for ReaderOnly {
    const NAME: &'static str = "nexus.raft.ZoneTransportService";
}

impl Service<http::Request<Body>> for ReaderOnly {
    type Response = http::Response<Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        if request.uri().path() != "/nexus.raft.ZoneTransportService/PrepareReplicaControlReaderV1"
        {
            return Box::pin(async {
                Ok(Status::unimplemented("reader-only method table").into_http())
            });
        }
        struct Prepare(ReaderOnly);
        impl tonic::server::UnaryService<PrepareReplicaControlReaderRequest> for Prepare {
            type Response = PrepareReplicaControlReaderResponse;
            type Future = BoxFuture<tonic::Response<Self::Response>, Status>;

            fn call(
                &mut self,
                request: tonic::Request<PrepareReplicaControlReaderRequest>,
            ) -> Self::Future {
                let service = self.0.clone();
                Box::pin(async move {
                    if request.get_ref().zone_id != "root" {
                        return Err(Status::not_found("reader-only fixture hosts root"));
                    }
                    service
                        .node
                        .prepare_replica_control_reader()
                        .await
                        .map_err(|error| Status::internal(error.to_string()))?;
                    service.calls.fetch_add(1, Ordering::SeqCst);
                    let response = PrepareReplicaControlReaderResponse {
                        replica_control_transport_v1: false,
                    };
                    assert_eq!(prost::Message::encoded_len(&response), 0);
                    Ok(tonic::Response::new(response))
                })
            }
        }
        let service = Prepare(self.clone());
        Box::pin(async move {
            let codec = tonic_prost::ProstCodec::default();
            Ok(tonic::server::Grpc::new(codec)
                .unary(service, request)
                .await)
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_durable_reader_reply_cannot_qualify_transport_on_the_same_node_channel() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let registry = Arc::new(ZoneRaftRegistry::new(directory.path().to_path_buf(), 7));
    let node = registry
        .create_zone("root", &tokio::runtime::Handle::current())
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let service = ReaderOnly {
        node: node.clone(),
        calls: calls.clone(),
    };
    let address = common::node_bind_addr();
    let incoming = lib::transport_primitives::federated_mtls_incoming(
        address.parse().unwrap(),
        &node_tls(&ca, &key, 7),
        None,
    )
    .await
    .unwrap();
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
    let clients = pool(node_tls(&ca, &key, 2));
    let peer = NodeAddress::new(7, format!("http://{address}"));
    for attempt in 1..=2 {
        let mut client = clients.get_node(&peer).await.unwrap();
        client.prepare_replica_control_reader("root").await.unwrap();
        let error = client
            .prepare_replica_control_transport("root")
            .await
            .unwrap_err();
        assert!(matches!(error, TransportError::Rpc(ref reason)
            if reason == "peer did not acknowledge replica-control transport v1"));
        assert_eq!(calls.load(Ordering::SeqCst), attempt * 2);
        assert_eq!(clients.connection_count().await, 1);
    }
    assert!(node
        .with_state_machine(
            |state| nexus_raft::raft::StateMachine::replica_control_activation(state).unwrap()
        )
        .await
        .is_none());
    drop(clients);
    stop.send(()).unwrap();
    task.await.unwrap();
    registry.shutdown().released().await;
    drop(node);
    drop(registry);
    assert!(reopened(directory.path())
        .replica_control_reader_required()
        .unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_member_preparation_refuses_an_old_member_even_when_the_quorum_is_current() {
    use super::replica_transport::RunningNode;
    use nexus_raft::{raft::ReplicaPreparationError, transport::PeerMap};

    let (ca, key) = generate_zone_ca("root").unwrap();
    let first = RunningNode::start(1, node_tls(&ca, &key, 1)).await;
    let directory = tempfile::tempdir().unwrap();
    let registry = Arc::new(ZoneRaftRegistry::new(directory.path().to_path_buf(), 7));
    let old_node = registry
        .create_zone("root", &tokio::runtime::Handle::current())
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let service = ReaderOnly {
        node: old_node.clone(),
        calls: calls.clone(),
    };
    let address = common::node_bind_addr();
    let incoming = lib::transport_primitives::federated_mtls_incoming(
        address.parse().unwrap(),
        &node_tls(&ca, &key, 7),
        None,
    )
    .await
    .unwrap();
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
    let mut leader = first.registry.get_node("root").unwrap();
    leader
        .propose_conf_change(raft::eraftpb::ConfChangeType::AddLearnerNode, 7, Vec::new())
        .await
        .unwrap();
    let mut routes = PeerMap::new(1);
    routes.observe(7, NodeAddress::new(7, format!("http://{address}")));
    let clients = pool(node_tls(&ca, &key, 1));
    leader.set_forward_ctx(
        clients.clone(),
        Arc::new(std::sync::RwLock::new(routes)),
        "root".into(),
    );
    let last = leader.last_index();
    // The sole voter already provides a current majority. The old learner must
    // still prevent a complete member observation from being returned.
    let error = leader.prepare_replica_control_members().await.unwrap_err();
    assert!(
        matches!(error, ReplicaPreparationError::Member { member: 7, error }
        if matches!(*error, TransportError::Rpc(ref reason)
            if reason == "peer did not acknowledge replica-control transport v1"))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(leader.last_index(), last);
    assert!(leader
        .with_state_machine(
            |state| nexus_raft::raft::StateMachine::replica_control_activation(state).unwrap()
        )
        .await
        .is_none());
    drop((leader, clients));
    first.stop().await;
    stop.send(()).unwrap();
    task.await.unwrap();
    registry.shutdown().released().await;
    drop((old_node, registry));
    assert!(reopened(directory.path())
        .replica_control_reader_required()
        .unwrap());
}
