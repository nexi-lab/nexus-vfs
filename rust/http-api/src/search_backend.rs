//! Cached SearchService transport, shared by local and remote HTTP query legs.
use crate::search_proto::search_service_client::SearchServiceClient;
use crate::upstream::GrpcEndpoint;
use nexus_search_common::transport::PeerChannelCache;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Channel;

pub use nexus_search_common::transport::DialError as BackendError;

/// Applies the interactive RPC deadline at the request boundary.
pub(crate) async fn bounded_rpc<T>(
    response: impl std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<tonic::Response<T>, tonic::Status> {
    tokio::time::timeout(Duration::from_secs(8), response)
        .await
        .unwrap_or_else(|_| Err(tonic::Status::deadline_exceeded("Search RPC timed out")))
}

#[derive(Clone)]
pub struct SearchBackend {
    endpoint: GrpcEndpoint,
}

impl SearchBackend {
    pub fn new(target: impl Into<Arc<str>>) -> Self {
        Self {
            endpoint: GrpcEndpoint::new(target),
        }
    }

    /// Use the composition root's TLS identity and shared connection cache.
    pub fn with_channels(target: impl Into<Arc<str>>, channels: Arc<PeerChannelCache>) -> Self {
        Self {
            endpoint: GrpcEndpoint::with_channels(target, channels),
        }
    }

    pub async fn client(&self) -> Result<SearchServiceClient<Channel>, BackendError> {
        let channel = self.endpoint.channel().await?;
        Ok(SearchServiceClient::new(channel).max_decoding_message_size(64 * 1024 * 1024))
    }

    pub(crate) fn endpoint(&self) -> &GrpcEndpoint {
        &self.endpoint
    }
}
