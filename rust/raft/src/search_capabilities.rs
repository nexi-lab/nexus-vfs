//! Runtime capability provider for the peer-facing zone API.

use std::sync::Arc;

use crate::transport::proto::SearchCapabilities;

#[tonic::async_trait]
pub trait SearchCapabilitiesProvider: Send + Sync {
    async fn capabilities(&self, zone: &str) -> Result<SearchCapabilities, tonic::Status>;
}

pub type SearchCapabilitiesSlot =
    Arc<parking_lot::RwLock<Option<Arc<dyn SearchCapabilitiesProvider>>>>;

pub fn new_search_capabilities_slot() -> SearchCapabilitiesSlot {
    Arc::new(parking_lot::RwLock::new(None))
}
