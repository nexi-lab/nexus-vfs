//! Small runtime observations shared by engine and host adapters.
//!
//! These values describe work, not durable Agent identity, liveness inferred
//! from output, or permission to control a runtime. Hosts own instance routing
//! and observation freshness separately from the engine's foreground state.

use crate::{resolve_agent_owner, resolve_agent_zone, AgentContextError, OperationContext};
use serde::{Deserialize, Serialize};

/// The outstanding human request that owns foreground input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputReason {
    Permission,
    Question,
}

/// Foreground work is independent of background tasks and other tool workers.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", content = "waiting_for", rename_all = "snake_case")]
pub enum ForegroundState {
    Idle,
    Running,
    AwaitingInput(InputReason),
}

/// Counts from the engine's existing task registry, without task output.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackgroundTaskSummary {
    pub terminals: usize,
    pub agents: usize,
    pub execution_unconfirmed: usize,
    pub tool_operations: usize,
}

/// One engine snapshot. Availability and freshness belong to its runtime host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStatus {
    pub foreground: ForegroundState,
    pub background: BackgroundTaskSummary,
}

/// A host-scoped registration, distinct from a reusable PID or durable SID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInstanceId {
    pub registry_id: String,
    pub pid: String,
    pub incarnation: String,
}

/// Engine-owned metadata. A SID can belong to several running instances.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIdentity {
    pub session_id: Option<String>,
    /// Diagnostic OS PID, never a process-control grant or instance identity.
    pub os_pid: Option<u32>,
}

/// Engine facts have no publication clock. The owning host supplies ordering.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFacts {
    pub identity: RuntimeIdentity,
    pub status: RuntimeStatus,
}

/// A host's monotonic observation revision; never compare across instances.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStatusUpdate {
    pub revision: u64,
    pub identity: RuntimeIdentity,
    pub status: RuntimeStatus,
}

impl RuntimeStatusUpdate {
    #[must_use]
    pub fn from_facts(revision: u64, facts: RuntimeFacts) -> Self {
        let RuntimeFacts { identity, status } = facts;
        Self {
            revision,
            identity,
            status,
        }
    }

    #[must_use]
    pub fn into_facts(self) -> RuntimeFacts {
        let Self {
            revision: _,
            identity,
            status,
        } = self;
        RuntimeFacts { identity, status }
    }
}

/// A host may know an instance without having a current engine observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAvailability {
    Fresh,
    Stale,
    Unsupported,
    Unavailable,
}

/// Attendance and engine facts expire independently. Silence never proves exit.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePresence {
    Online,
    Unknown,
}

/// A host's observation of one instance; unavailable state is never called idle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeObservation {
    pub instance: RuntimeInstanceId,
    pub agent_id: String,
    pub presence: RuntimePresence,
    pub last_seen_age_ms: Option<u64>,
    pub availability: RuntimeAvailability,
    pub age_ms: Option<u64>,
    pub update: Option<RuntimeStatusUpdate>,
}

/// Exact authorized scope of a node-local enumeration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInventoryScope {
    pub registry_id: String,
    pub owner_id: Option<String>,
    pub zone_id: String,
    pub complete: bool,
}

/// A node-local inventory contains facts and its exact authorized scope.
/// Cross-node routing belongs to the owning host directory adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInventory {
    pub version: u32,
    pub scope: RuntimeInventoryScope,
    pub instances: Vec<RuntimeObservation>,
}

/// External attendance creates no filesystem, tenancy or process-control grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRuntimeRequest {
    pub name: String,
    pub connection_id: String,
    /// Idempotent admission intent, distinct from the reusable logical PID.
    pub registration_id: String,
    pub owner_id: Option<String>,
    pub zone_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInstanceRequest {
    pub instance: RuntimeInstanceId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishRuntimeRequest {
    pub instance: RuntimeInstanceId,
    pub update: RuntimeStatusUpdate,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListRuntimesRequest {
    pub owner_id: Option<String>,
    pub zone_id: Option<String>,
}

/// The caller's authorized attendance scope, shared by local and federated reads.
pub fn resolve_runtime_scope(
    ctx: &OperationContext,
    request: &ListRuntimesRequest,
) -> Result<(Option<String>, String), AgentContextError> {
    if ctx.trust_domain.is_some() && !ctx.is_admin && !ctx.is_system {
        return Err(AgentContextError::PermissionDenied(
            "foreign runtime scope is not authorized".into(),
        ));
    }
    let owner = if ctx.is_admin || ctx.is_system {
        request.owner_id.clone()
    } else {
        Some(resolve_agent_owner(ctx, request.owner_id.as_deref())?)
    };
    // Attendance is owner-private metadata, not a filesystem or tenancy grant.
    let zone = match request.zone_id.as_deref() {
        Some(zone) if zone != ctx.zone_id => resolve_agent_zone(ctx, Some(zone))?,
        _ => ctx.zone_id.clone(),
    };
    Ok((owner, zone))
}

/// A missing peer is a coverage gap, never evidence that its agents are offline.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeUnavailableScope {
    pub endpoint: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDirectory {
    pub version: u32,
    pub inventories: Vec<RuntimeInventory>,
    pub unavailable: Vec<RuntimeUnavailableScope>,
}

/// One non-owning engine reader. Neither transcript storage nor task output is retained.
pub type RuntimeStatusSource = std::sync::Arc<dyn Fn() -> Option<RuntimeFacts> + Send + Sync>;

/// Host policy supplies routing and exact-instance ownership; engines supply facts.
/// Binding must not wait for a network connection or create another model runtime.
pub trait RuntimeObservationHost: Send + Sync + std::fmt::Debug {
    fn bind(&self, source: RuntimeStatusSource) -> Option<Box<dyn Send>>;
    fn instance(&self) -> Option<RuntimeInstanceId>;
    fn discover(&self) -> Result<RuntimeDirectory, String>;
}
