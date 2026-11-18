//! A zone's online Agents: a read-only fan-out over the existing authenticated
//! peer pool. Every member of the zone may read it, as it may list the zone's
//! Agents, and it carries names only.

use super::FederationClient;
use contracts::runtime_status::{
    online_agent_names, resolve_runtime_zone, ListRuntimesRequest, OnlineAgents, PresenceRequest,
    RuntimeInventory,
};
use contracts::{AgentContextError, OperationContext, RustCallError, RustService};
use futures::{stream, StreamExt};
use kernel::kernel::vfs_proto::{nexus_vfs_service_client::NexusVfsServiceClient, CallRequest};
use kernel::kernel::Kernel;
use std::sync::{Arc, Weak};
use std::time::Duration;

const NAME: &str = "runtime_directory";

/// Reuses the coordinator's client; no new connection manager or runtime.
pub fn install(
    kernel: &Arc<Kernel>,
    client: Arc<FederationClient>,
    namespace: &str,
) -> Result<(), String> {
    let service = Arc::new(DirectoryService {
        kernel: Arc::downgrade(kernel),
        client,
        namespace: namespace.to_owned(),
    });
    kernel.register_rust_service(NAME, service.clone(), service.exports())
}

struct DirectoryService {
    kernel: Weak<Kernel>,
    client: Arc<FederationClient>,
    namespace: String,
}

impl DirectoryService {
    fn peer_endpoints(&self, kernel: &Kernel, zone: &str) -> Result<Vec<String>, RustCallError> {
        // Metadata authorization and host namespace routing are separate.
        // A pure agent uses node-local root; its mailbox can live in a shared
        // zone. The mount table and coordinator remain the routing SSOT.
        let peer_zone = kernel
            .vfs_router_arc()
            .route(&self.namespace, zone)
            .ok_or_else(|| RustCallError::Internal("runtime namespace is unroutable".into()))?
            .zone_id;
        let mut peers = kernel
            .distributed_coordinator()
            .zone_peers(kernel, &peer_zone);
        peers.sort();
        peers.dedup();
        Ok(peers)
    }
}

impl FederationClient {
    /// One peer's inventory of `zone` for every owner, or nothing when the peer
    /// cannot answer it.
    async fn runtime_inventory(&self, endpoint: &str, zone: &str) -> Option<RuntimeInventory> {
        // A trusted node already has peer-plane authority; never forward a
        // client token or delegation.
        if !self.channels.uses_tls() {
            return None;
        }
        let channel = self.channels.channel_for(endpoint).await.ok()?;
        let payload = serde_json::to_vec(&ListRuntimesRequest {
            owner_id: None,
            zone_id: Some(zone.into()),
        })
        .ok()?;
        let response = NexusVfsServiceClient::new(channel)
            .call(tonic::Request::new(CallRequest {
                method: "agent_runtime_list_v1".into(),
                payload,
                auth_token: String::new(),
            }))
            .await
            .ok()?
            .into_inner();
        if response.is_error {
            return None;
        }
        let envelope: serde_json::Value = serde_json::from_slice(&response.payload).ok()?;
        let inventory: RuntimeInventory =
            serde_json::from_value(envelope["result"].clone()).ok()?;
        (inventory.version == 1
            && inventory.scope.complete
            && inventory.scope.owner_id.is_none()
            && inventory.scope.zone_id == zone
            && inventory
                .instances
                .iter()
                .all(|item| item.instance.registry_id == inventory.scope.registry_id))
        .then_some(inventory)
    }
}

impl RustService for DirectoryService {
    fn name(&self) -> &str {
        NAME
    }
    fn exports(&self) -> Vec<String> {
        vec!["presence_v1".into()]
    }

    fn dispatch(
        &self,
        method: &str,
        payload: &[u8],
        ctx: &OperationContext,
    ) -> Result<Vec<u8>, RustCallError> {
        if method != "presence_v1" {
            return Err(RustCallError::NotFound);
        }
        let request: PresenceRequest = serde_json::from_slice(payload)
            .map_err(|error| RustCallError::InvalidArgument(error.to_string()))?;
        let zone =
            resolve_runtime_zone(ctx, request.zone_id.as_deref()).map_err(|error| match error {
                AgentContextError::InvalidArgument(message) => {
                    RustCallError::InvalidArgument(message)
                }
                AgentContextError::PermissionDenied(message) => {
                    RustCallError::PermissionDenied(message)
                }
            })?;
        let kernel = self
            .kernel
            .upgrade()
            .ok_or_else(|| RustCallError::Internal("runtime host retired".into()))?;
        let mut inventories = vec![kernel.agent_registry().runtime_inventory(None, &zone)];
        let peers = self.peer_endpoints(&kernel, &zone)?;
        // Peers answer the node plane for every owner; only names leave this call.
        // A peer that does not answer contributes no names: not seen online.
        inventories.extend(self.client.block_on_safely(async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            stream::iter(peers)
                .map(|endpoint| {
                    let zone = &zone;
                    async move {
                        tokio::time::timeout_at(
                            deadline,
                            self.client.runtime_inventory(&endpoint, zone),
                        )
                        .await
                        .ok()
                        .flatten()
                    }
                })
                .buffer_unordered(4)
                .filter_map(std::future::ready)
                .collect::<Vec<_>>()
                .await
        }));
        let online = OnlineAgents {
            version: 1,
            online: online_agent_names(&inventories),
            zone_id: zone,
        };
        serde_json::to_vec(&online).map_err(|error| RustCallError::Internal(error.to_string()))
    }
}
