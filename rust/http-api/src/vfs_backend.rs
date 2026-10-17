//! Typed file RPC client using the configured node's existing TLS channels.

use crate::upstream::GrpcEndpoint;
use crate::BackendError;
use contracts::constants::MAX_GRPC_MESSAGE_BYTES;
use kernel::kernel::vfs_proto::nexus_vfs_service_client::NexusVfsServiceClient;
use nexus_search_common::transport::PeerChannelCache;
use std::sync::Arc;
use tonic::transport::Channel;

#[derive(Clone)]
pub struct VfsBackend {
    endpoint: GrpcEndpoint,
}

impl VfsBackend {
    pub fn new(target: impl Into<Arc<str>>) -> Self {
        Self::from_endpoint(GrpcEndpoint::new(target))
    }

    pub fn with_channels(target: impl Into<Arc<str>>, channels: Arc<PeerChannelCache>) -> Self {
        Self::from_endpoint(GrpcEndpoint::with_channels(target, channels))
    }

    pub(crate) fn from_endpoint(endpoint: GrpcEndpoint) -> Self {
        Self { endpoint }
    }

    pub async fn client(&self) -> Result<NexusVfsServiceClient<Channel>, BackendError> {
        Ok(NexusVfsServiceClient::new(self.endpoint.channel().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES))
    }
}
