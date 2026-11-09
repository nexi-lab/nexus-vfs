//! Owner-scoped, read-only fan-out over the existing authenticated peer pool.

use super::FederationClient;
use contracts::runtime_status::{
    resolve_runtime_scope, ListRuntimesRequest, RuntimeDirectory, RuntimeInventory,
    RuntimeUnavailableScope,
};
use contracts::{AgentContextError, OperationContext, RustCallError, RustService};
use futures::{stream, StreamExt};
use kernel::kernel::vfs_proto::{nexus_vfs_service_client::NexusVfsServiceClient, CallRequest};
use kernel::kernel::Kernel;
use std::sync::{Arc, Weak};
use std::time::Duration;

const NAME: &str = "runtime_directory";

/// Reuses the coordinator's client; no new connection manager or runtime.
pub fn install(kernel: &Arc<Kernel>, client: Arc<FederationClient>) -> Result<(), String> {
    let service = Arc::new(DirectoryService {
        kernel: Arc::downgrade(kernel),
        client,
    });
    kernel.register_rust_service(NAME, service.clone(), service.exports())
}

struct DirectoryService {
    kernel: Weak<Kernel>,
    client: Arc<FederationClient>,
}

impl FederationClient {
    async fn runtime_inventory(
        &self,
        endpoint: &str,
        owner: Option<&str>,
        zone: &str,
    ) -> Result<RuntimeInventory, &'static str> {
        // A trusted node already has peer-plane authority. Keep the original
        // caller's resolved filter; never forward a client token or delegation.
        if self.tls.read().is_none() {
            return Err("peer_identity_unavailable");
        }
        let channel = self
            .channel_for(endpoint)
            .await
            .map_err(|_| "unavailable")?;
        let payload = serde_json::to_vec(&ListRuntimesRequest {
            owner_id: owner.map(str::to_owned),
            zone_id: Some(zone.into()),
        })
        .map_err(|_| "invalid_request")?;
        let response = NexusVfsServiceClient::new(channel)
            .call(tonic::Request::new(CallRequest {
                method: "agent_runtime_list_v1".into(),
                payload,
                auth_token: String::new(),
            }))
            .await
            .map_err(|_| "unavailable")?
            .into_inner();
        if response.is_error {
            return Err("unsupported_or_denied");
        }
        let envelope: serde_json::Value =
            serde_json::from_slice(&response.payload).map_err(|_| "invalid_response")?;
        let mut inventory: RuntimeInventory =
            serde_json::from_value(envelope["result"].clone()).map_err(|_| "invalid_response")?;
        if inventory.version != 1
            || !inventory.scope.complete
            || inventory.scope.owner_id.as_deref() != owner
            || inventory.scope.zone_id != zone
            || inventory
                .instances
                .iter()
                .any(|item| item.instance.registry_id != inventory.scope.registry_id)
        {
            return Err("invalid_scope");
        }
        // Fan out only to the local coordinator's peers, never peer-supplied endpoints.
        inventory.peers.clear();
        Ok(inventory)
    }
}

impl RustService for DirectoryService {
    fn name(&self) -> &str {
        NAME
    }
    fn exports(&self) -> Vec<String> {
        vec!["list_v1".into()]
    }

    fn dispatch(
        &self,
        method: &str,
        payload: &[u8],
        ctx: &OperationContext,
    ) -> Result<Vec<u8>, RustCallError> {
        if method != "list_v1" {
            return Err(RustCallError::NotFound);
        }
        let request: ListRuntimesRequest = serde_json::from_slice(payload)
            .map_err(|error| RustCallError::InvalidArgument(error.to_string()))?;
        let (owner, zone) = resolve_runtime_scope(ctx, &request).map_err(|error| match error {
            AgentContextError::InvalidArgument(message) => RustCallError::InvalidArgument(message),
            AgentContextError::PermissionDenied(message) => {
                RustCallError::PermissionDenied(message)
            }
        })?;
        let kernel = self
            .kernel
            .upgrade()
            .ok_or_else(|| RustCallError::Internal("runtime host retired".into()))?;
        let local = kernel
            .agent_registry()
            .runtime_inventory(owner.as_deref(), &zone);
        let mut peers = kernel.distributed_coordinator().zone_peers(&kernel, &zone);
        peers.sort();
        peers.dedup();
        let results = self.client.block_on_safely(async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            stream::iter(peers)
                .map(|endpoint| {
                    let owner = owner.as_deref();
                    let zone = &zone;
                    async move {
                        let result = tokio::time::timeout_at(
                            deadline,
                            self.client.runtime_inventory(&endpoint, owner, zone),
                        )
                        .await
                        .unwrap_or(Err("unavailable"));
                        (endpoint, result)
                    }
                })
                .buffer_unordered(4)
                .collect::<Vec<_>>()
                .await
        });
        let mut directory = RuntimeDirectory {
            version: 1,
            inventories: vec![local],
            unavailable: Vec::new(),
        };
        for (endpoint, result) in results {
            match result {
                Ok(inventory) => directory.inventories.push(inventory),
                Err(reason) => directory.unavailable.push(RuntimeUnavailableScope {
                    endpoint,
                    reason: reason.into(),
                }),
            }
        }
        directory
            .inventories
            .sort_by(|left, right| left.scope.registry_id.cmp(&right.scope.registry_id));
        directory
            .inventories
            .dedup_by(|left, right| left.scope.registry_id == right.scope.registry_id);
        directory
            .unavailable
            .sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
        serde_json::to_vec(&directory).map_err(|error| RustCallError::Internal(error.to_string()))
    }
}
