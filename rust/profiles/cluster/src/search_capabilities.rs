//! Connect peer capability discovery to the daemon's current Search plugin.

use std::sync::{Arc, Weak};

use contracts::operation_context::OperationContext;
use contracts::rust_service::RustCallError;
use kernel::kernel::Kernel;
use nexus_raft::search_capabilities::SearchCapabilitiesProvider;
use nexus_raft::transport::proto::SearchCapabilities;
use nexus_raft::ZoneManager;
use tonic::Status;

struct HostCapabilities(Weak<Kernel>);

#[tonic::async_trait]
impl SearchCapabilitiesProvider for HostCapabilities {
    async fn capabilities(&self, zone: &str) -> Result<SearchCapabilities, Status> {
        let kernel = self
            .0
            .upgrade()
            .ok_or_else(|| Status::unavailable("search host is stopped"))?;
        let zone = zone.to_owned();
        tokio::task::spawn_blocking(move || {
            let ctx = OperationContext::new("nexusd-cluster", &zone, false, None, false);
            let result = kernel
                .dispatch_rust_call("search", "capabilities", b"{}", &ctx)
                .ok_or_else(|| Status::unimplemented("Search service is not loaded"))?;
            let bytes = result.map_err(|error| match error {
                RustCallError::NotFound => {
                    Status::unimplemented("Search service does not report capabilities")
                }
                _ => Status::internal("Search capability query failed"),
            })?;
            let caps: nexus_search_common::capabilities::SearchCapabilities =
                serde_json::from_slice(&bytes)
                    .map_err(|_| Status::internal("invalid Search capabilities"))?;
            Ok(SearchCapabilities {
                zone_id: zone,
                device_tier: caps.device_tier,
                search_modes: caps.search_modes,
                embedding_model: caps.embedding_model,
                embedding_dimensions: i32::try_from(caps.embedding_dimensions).map_err(|_| {
                    Status::failed_precondition(
                        "embedding dimension exceeds the capability protocol",
                    )
                })?,
                has_graph: caps.has_graph,
            })
        })
        .await
        .map_err(|_| Status::internal("Search capability task failed"))?
    }
}

pub fn install(zones: &ZoneManager, kernel: &Arc<Kernel>) {
    *zones.search_capabilities_slot().write() =
        Some(Arc::new(HostCapabilities(Arc::downgrade(kernel))));
}
