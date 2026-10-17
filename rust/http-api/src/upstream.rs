//! Node address and TLS channels shared by the HTTP protocol clients.

use nexus_search_common::transport::{DialError, PeerChannelCache, PeerChannelConfig};
use std::sync::Arc;
use tonic::transport::Channel;

#[derive(Clone)]
pub(crate) struct GrpcEndpoint {
    target: Arc<str>,
    pub(crate) channels: Arc<PeerChannelCache>,
}

impl GrpcEndpoint {
    pub(crate) fn new(target: impl Into<Arc<str>>) -> Self {
        Self::with_channels(
            target,
            Arc::new(PeerChannelCache::new(PeerChannelConfig::default())),
        )
    }

    pub(crate) fn with_channels(
        target: impl Into<Arc<str>>,
        channels: Arc<PeerChannelCache>,
    ) -> Self {
        Self {
            target: target.into(),
            channels,
        }
    }

    pub(crate) async fn channel(&self) -> Result<Channel, DialError> {
        self.channels.get_or_dial(&self.target).await
    }
}
