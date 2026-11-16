//! A lossy link in front of a node's raft transport: the node advertises the
//! link's address, so every message other members send it crosses the link,
//! while its own messages go out directly. Bounded like every current-build
//! endpoint, so the link itself never limits a message.
//!
//! Included with `#[path]` by the binaries that use it.

#![allow(dead_code)] // each test binary uses a different subset

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;

use nexus_raft::raft::message_bound::MAX_RAFT_MESSAGE_BYTES;
use nexus_raft::transport::proto::nexus::raft::{
    zone_transport_service_client::ZoneTransportServiceClient,
    zone_transport_service_server::{ZoneTransportService, ZoneTransportServiceServer},
    PrepareReplicaControlReaderRequest, PrepareReplicaControlReaderResponse,
    ReplicateEntriesRequest, ReplicateEntriesResponse, SnapshotEcStateRequest,
    SnapshotEcStateResponse, StepMessageRequest, StepMessageResponse,
};
use protobuf::Message as _;
use raft::eraftpb::MessageType;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};

/// Forward everything.
pub const PASS: u8 = 0;
/// Refuse appends and snapshots (`Unavailable`); pass heartbeats and the rest.
pub const STARVE: u8 = 1;
/// Answer the next snapshot "delivered" without forwarding it, then pass.
pub const SWALLOW_NEXT_SNAPSHOT: u8 = 2;

/// The node's side of the network, as the other members see it.
pub struct LossyLink {
    mode: AtomicU8,
    target: ZoneTransportServiceClient<Channel>,
    pub snapshots_forwarded: AtomicUsize,
    pub snapshots_swallowed: AtomicUsize,
    pub snapshots_refused: AtomicUsize,
    /// The largest raft message forwarded, in encoded bytes.
    pub largest_forwarded: AtomicUsize,
}

impl LossyLink {
    pub async fn start(listen: SocketAddr, learner: &str) -> Arc<Self> {
        let target = ZoneTransportServiceClient::new(
            Channel::from_shared(format!("http://{learner}"))
                .expect("learner uri")
                .connect_lazy(),
        )
        .max_decoding_message_size(MAX_RAFT_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_RAFT_MESSAGE_BYTES);
        let link = Arc::new(Self {
            mode: AtomicU8::new(PASS),
            target,
            snapshots_forwarded: AtomicUsize::new(0),
            snapshots_swallowed: AtomicUsize::new(0),
            snapshots_refused: AtomicUsize::new(0),
            largest_forwarded: AtomicUsize::new(0),
        });
        let service = ZoneTransportServiceServer::from_arc(Arc::clone(&link))
            .max_decoding_message_size(MAX_RAFT_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_RAFT_MESSAGE_BYTES);
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve(listen),
        );
        link
    }

    pub fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    async fn step(
        &self,
        request: Request<StepMessageRequest>,
    ) -> Result<Response<StepMessageResponse>, Status> {
        let message_type = raft::eraftpb::Message::parse_from_bytes(&request.get_ref().message)
            .map(|message| message.get_msg_type())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let snapshot = message_type == MessageType::MsgSnapshot;
        match self.mode.load(Ordering::SeqCst) {
            STARVE if snapshot || message_type == MessageType::MsgAppend => {
                if snapshot {
                    self.snapshots_refused.fetch_add(1, Ordering::SeqCst);
                }
                return Err(Status::unavailable("lossy link: starving the learner"));
            }
            SWALLOW_NEXT_SNAPSHOT if snapshot => {
                // Delivered, as far as the sender can tell; never installed.
                self.set(PASS);
                self.snapshots_swallowed.fetch_add(1, Ordering::SeqCst);
                return Ok(Response::new(StepMessageResponse {
                    success: true,
                    error: None,
                }));
            }
            _ => {}
        }
        if snapshot {
            self.snapshots_forwarded.fetch_add(1, Ordering::SeqCst);
        }
        self.largest_forwarded
            .fetch_max(request.get_ref().message.len(), Ordering::SeqCst);
        self.target.clone().step_message(request.into_inner()).await
    }
}

#[tonic::async_trait]
impl ZoneTransportService for LossyLink {
    async fn step_message(
        &self,
        request: Request<StepMessageRequest>,
    ) -> Result<Response<StepMessageResponse>, Status> {
        self.step(request).await
    }

    async fn step_storage_v1(
        &self,
        request: Request<StepMessageRequest>,
    ) -> Result<Response<StepMessageResponse>, Status> {
        self.target
            .clone()
            .step_storage_v1(request.into_inner())
            .await
    }

    async fn step_replica_control_v1(
        &self,
        request: Request<StepMessageRequest>,
    ) -> Result<Response<StepMessageResponse>, Status> {
        self.target
            .clone()
            .step_replica_control_v1(request.into_inner())
            .await
    }

    async fn prepare_replica_control_reader_v1(
        &self,
        request: Request<PrepareReplicaControlReaderRequest>,
    ) -> Result<Response<PrepareReplicaControlReaderResponse>, Status> {
        self.target
            .clone()
            .prepare_replica_control_reader_v1(request.into_inner())
            .await
    }

    async fn replicate_entries(
        &self,
        request: Request<ReplicateEntriesRequest>,
    ) -> Result<Response<ReplicateEntriesResponse>, Status> {
        self.target
            .clone()
            .replicate_entries(request.into_inner())
            .await
    }

    async fn snapshot_ec_state(
        &self,
        request: Request<SnapshotEcStateRequest>,
    ) -> Result<Response<SnapshotEcStateResponse>, Status> {
        self.target
            .clone()
            .snapshot_ec_state(request.into_inner())
            .await
    }
}
