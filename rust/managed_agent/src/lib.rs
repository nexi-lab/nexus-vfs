//! `ManagedAgentService` — Rust-flavoured service that owns the
//! managed-agent surface: the stamping + workspace hooks plus the
//! session lifecycle behind the `proto/nexus/grpc/managed_agent` gRPC
//! contract.
//!
//! Registered to the kernel `ServiceRegistry` as a Rust service via the
//! `Kernel::register_rust_service` surface (parallel of `add_mount` for
//! drivers). Pre-existing services (AcpService for unmanaged agents,
//! AgentRegistry, ReBAC, …) keep their Python implementations; this is
//! the first Rust-flavoured service to land alongside them, owning
//! `AgentKind::MANAGED` agents end-to-end.
//!
//! Today's responsibilities, all generic to `AgentKind::MANAGED` (not
//! sudo-code-specific):
//!
//!   * On `install`, register `WorkspaceBoundaryHook` into the kernel's
//!     `KernelDispatch` so every cross-owner `/proc/{pid}/workspace/`
//!     write is rejected. The mailbox `from`-stamp hook now lives in the
//!     `a2a` messaging substrate (nexus-vfs), armed once at cluster boot
//!     — every message-log write is stamped there, for all writers.
//!   * On `enlist_rust`, take the place in the registry that
//!     `nx.service("managed_agent")` resolves to (Python lookup
//!     returns None — this service is reachable from Rust callers via
//!     `service_registry.lookup_rust("managed_agent")`).
//!   * `start_session` / `cancel` / `get_session` — Rust-native
//!     session lifecycle that talks directly to `AgentRegistry` (the
//!     Rust SSOT for agent state). Zero PyO3 boundary; managed agents
//!     don't go through Python `AgentRegistry` because their PCB
//!     metadata (cwd / external_info / subprocess handle) doesn't
//!     apply — those are unmanaged-agent fields.
//!
//! The actual managed-agent runtime (the sudo-code Rust crate that
//! drives the LLM loop after `start_session` allocates a pid) is a
//! separate Cargo dep that lands later. Today's `start_session` plants
//! the AgentRegistry record and returns the session identity tuple;
//! the runtime spawn is tracked separately so the gRPC contract works
//! ahead of the runtime crate.

// Until the tonic gRPC handler + runtime crate dep land, the
// session-lifecycle surface (request / response shapes,
// start_session / cancel / get_session) is reachable only from tests.
// The dead-code allowances below stop the unused-symbol warnings; each
// gets used as soon as its consumer commits.
#![allow(dead_code)]

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use kernel::core::agents::registry::{
    AgentDescriptor, AgentKind, AgentRegistry, AgentState, RepoMount,
};
use kernel::kernel::syscall::KernelSyscall;
use kernel::service_registry::{RustCallError, RustService};

// The subprocess adapter owns stdio and exchanges ACP envelopes through the
// same SessionMailbox as an in-process host. Slim builds reject spawn_spec.
#[cfg(feature = "subprocess-host")]
pub(crate) mod raw_spawn;

pub(crate) mod proc_entry;
pub(crate) mod session;
pub(crate) mod workspace_boundary_hook;

use proc_entry::{register_proc_entry, unregister_proc_entry};

/// Install ManagedAgentService on `kernel` with an injected
/// [`SpawnTask`] provider. This is the entry the binary edge
/// (`profiles/cluster` binary,
/// `profiles/cluster` for the cluster binary) calls with a
/// concrete adapter that wraps a runtime crate (e.g.
/// `engine_acp::managed_agent::SudoCodeSpawnAdapter`).
///
/// Pure-Rust slim builds without a runtime body call
/// [`install_managed_agent`] (no spawn provider) instead.
pub fn install_managed_agent_with_spawn(
    kernel: &Arc<kernel::kernel::Kernel>,
    spawn_provider: Arc<dyn SpawnTask<kernel::kernel::Kernel>>,
) -> Result<(), String> {
    ManagedAgentService::<kernel::kernel::Kernel>::install_with_spawn(kernel, spawn_provider)
}

/// Install ManagedAgentService on `kernel` without a runtime body
/// (procfs + AgentRegistry only) — for callers that do not ship a
/// runtime spawn provider.
pub fn install_managed_agent(kernel: &Arc<kernel::kernel::Kernel>) -> Result<(), String> {
    ManagedAgentService::<kernel::kernel::Kernel>::install(kernel)
}

/// This service's canonical name, as it appears in a `ServiceDecl` and in the
/// boot log.
///
/// Exported because an assembly that REPLACES this service — a co-host swapping
/// the bodiless decl for one carrying a spawn provider — has to find it in the
/// default list by name, and a name matched as a literal in another repository is
/// a rename waiting to go unnoticed.
pub const SERVICE_NAME: &str = "managed_agent";

/// The managed-agent service as a boot declaration for
/// [`kernel::kernel::Kernel::bring_up_services`] — the uniform path by
/// which the assembly hands services to the kernel. Wraps
/// [`install_managed_agent`], which wires the session lifecycle, the
/// workspace/procfs hooks, and the subprocess session adapter via `install_returning`.
///
/// No runtime body: `spawn` registers the agent and stamps its procfs subtree,
/// and nothing turns that into a running loop. For a build that hosts one
/// in-process, see [`service_decl_with_spawn`].
pub fn service_decl() -> kernel::kernel::ServiceDecl {
    kernel::kernel::ServiceDecl {
        name: SERVICE_NAME.to_string(),
        install: Box::new(install_managed_agent),
    }
}

/// The same service, installed WITH an in-process runtime body.
///
/// The sibling of [`service_decl`], here rather than at the call site because the
/// pairing of this service's name with this service's install is the service's own
/// knowledge: an assembly that hand-rolled the `ServiceDecl` would be spelling
/// both, and a rename here would leave that copy compiling and wrong.
///
/// `spawn_provider` is what turns a `start_session` into a running agent —
/// typically a thin adapter over a runtime crate (`sudocode`'s
/// `SudoCodeSpawnAdapter`). It cannot live in this repo: the runtime crate depends
/// on the kernel, so linking it here would be a cycle.
pub fn service_decl_with_spawn(
    spawn_provider: Arc<dyn SpawnTask<kernel::kernel::Kernel>>,
) -> kernel::kernel::ServiceDecl {
    kernel::kernel::ServiceDecl {
        name: SERVICE_NAME.to_string(),
        install: Box::new(move |kernel| install_managed_agent_with_spawn(kernel, spawn_provider)),
    }
}

/// Label key used to stash the LLM model id on the descriptor so
/// `get_session` can echo it back without a sidecar table.  Read by
/// `GetSessionResponse.model`; the runtime crate may also read it
/// when wiring the loop.
const MODEL_LABEL: &str = "model";

use session::{alloc_pid, now_ms};

// ── Public request / response shapes ────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct WorkspaceRepo {
    pub host_path: String,
    pub alias: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct StartSessionRequest {
    /// Static agent profile id (e.g. `scode-standard`) — names the
    /// directory under `/agents/{agent_id}/`.  Same `agent_id`
    /// terminology the ACP service uses.
    pub agent_id: String,
    #[serde(default)]
    pub repos: Vec<WorkspaceRepo>,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub owner_id: String,
    #[serde(default)]
    pub zone_id: String,
    /// Embedder-computed launch specification. The adapter translates internal
    /// ACP stdio into the same authenticated session mailbox as in-process hosts.
    /// Launch policy (command, model and credentials) belongs to the embedder.
    #[serde(default)]
    pub spawn_spec: Option<SpawnSpec>,
    /// Durable transcript to restore in an in-process runtime. This is NOT
    /// the pid-valued `session_id` accepted by get/cancel.
    #[serde(default)]
    pub resume_session_id: Option<String>,
}

/// Subprocess specification supplied by the embedder. The kernel owns process
/// supervision and ACP framing into the public session mailbox.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct SpawnSpec {
    pub cmd: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub cwd: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StartSessionResponse {
    /// AgentRegistry pid for the spawned managed agent.  cancel /
    /// get_session take this back.
    pub session_id: String,
    /// The only public transport for driving this hosted session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_endpoint: Option<a2a::session::SessionEndpoint>,
    /// Runtime-owned transcript ID, when the spawn provider supports persistence.
    /// Absent for raw subprocesses and providers without durable sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_session_id: Option<String>,
    pub workspace_path: String,
    /// Real OS pid of the spawned subprocess — set ONLY on the raw ACP
    /// control-plane path (`spawn_spec` supplied); `None` for the
    /// runtime-body / procfs-only paths. Surfaced SEPARATELY from
    /// `session_id` (which stays the synthetic AgentRegistry pid) per
    /// the frozen contract ④: the embedder (sudowork) keys its
    /// pid-bound auth-proxy on the OS pid; the process handle for
    /// cancel / get_session remains `session_id`.
    #[serde(default)]
    pub os_pid: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GetSessionResponse {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_endpoint: Option<a2a::session::SessionEndpoint>,
    /// Static agent profile id (mirrors `StartSessionRequest.agent_id`).
    pub agent_id: String,
    /// Whose session this is, as recorded on the descriptor.
    ///
    /// Reported because the caller can no longer infer it. `start_session_v1`
    /// takes the owner from a delegated credential in preference to the
    /// request body (see `authenticated_owner`), so a front door that sends no
    /// `owner_id` has no other way to learn what the daemon attributed the
    /// session to — and attribution nobody can read back is attribution
    /// nobody can check.
    pub owner_id: String,
    /// Runtime-owned transcript ID, when the spawn provider supports persistence.
    /// Absent for raw subprocesses and providers without durable sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_session_id: Option<String>,
    pub workspace_path: String,
    pub model: String,
    pub state: String,
    /// Agent-reported reason the session is in `awaiting_input` (opaque,
    /// e.g. "permission"); `None` in every other state.
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CancelMode {
    Turn,
    Session,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CancelRequest {
    pub session_id: String,
    pub mode: CancelMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GetSessionRequest {
    pub session_id: String,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub(crate) struct CancelResponse {
    pub cancelled: bool,
}

#[derive(Debug)]
pub(crate) enum ManagedAgentError {
    InvalidArgument(String),
    UnknownSession(String),
    Internal(String),
}

impl std::fmt::Display for ManagedAgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Self::UnknownSession(s) => write!(f, "unknown session_id {s:?}"),
            Self::Internal(m) => write!(f, "internal: {m}"),
        }
    }
}

impl std::error::Error for ManagedAgentError {}

// ── Spawn-task DI surface ──────────────────────────────────────────────
//
// Services rlib does NOT depend on the sudocode crate (cross-repo
// git-deps would couple services' build to a specific sudocode rev,
// which is the wrong layer for cross-repo coupling — same reason
// `KernelSyscall` lives at the trait boundary). Instead, services
// declares a small DI trait that nexus's binary edge
// (`profiles/cluster` for all builds — the sole binary edge
// Python wheel) implements by wrapping `engine_acp::managed_agent::SudoCodeSpawnAdapter`.
// The trait method is `dyn`-dispatched but only fires once per
// `start_session` call (out of the hot path); the spawn body itself
// is fully monomorphised over `K: KernelSyscall` inside the concrete
// impl, so there's no per-`sys_read` vtable cost.

/// Per-pid spawn handle returned by [`SpawnTask::spawn`]. Concrete
/// impls (e.g. the sudocode-runtime adapter) hold whatever
/// in-process state the spawn body needs (worker thread join handle,
/// abort signal, future tokio task handle). The services-tier sees
/// only the abort capability — that's what the on_terminate observer
/// needs to tear the loop down on session termination.
pub trait SpawnHandle: Send + Sync {
    /// Signal the spawn body to stop. Implementations MUST be
    /// idempotent — the on_terminate observer can fire concurrently
    /// with an in-progress `cancel(Session)`.
    fn abort(&self);

    fn session_endpoint(&self) -> Option<&a2a::session::SessionEndpoint> {
        None
    }

    /// Durable transcript identity, independent of the registry pid.
    fn durable_session_id(&self) -> Option<&str> {
        None
    }
}

/// Optional runtime session selection. Existing providers retain their spawn
/// implementation and explicitly reject recovery until they implement it.
#[derive(Clone, Debug, Default)]
pub struct SpawnOptions {
    pub resume_session_id: Option<String>,
    pub session_endpoint: Option<a2a::session::SessionEndpoint>,
}

/// Spawn-task provider. `start_session` calls
/// [`Self::spawn`] after `register_proc_entry` succeeds to kick off
/// the per-pid runtime body. The concrete impl wraps whatever
/// runtime crate the deployment chose (today: sudocode); generic K
/// keeps the spawn body monomorphised against the same kernel
/// concrete that the service holds.
pub trait SpawnTask<K: KernelSyscall>: Send + Sync + 'static {
    /// Spawn the per-pid runtime body. Returns an opaque handle the
    /// service stores in its `spawn_handles` sidecar; the
    /// on_terminate observer aborts via the handle on session
    /// termination.
    ///
    /// `state_observer` is the SSOT writer for the session's
    /// [`AgentState`]. The closure is constructed by
    /// `ManagedAgentService::start_session` — it captures the
    /// service's `Arc<AgentRegistry>` and the session's pid and
    /// forwards each reported [`AgentState`] through
    /// `AgentRegistry::update_state`. The spawn body reports the
    /// running-state subset ([`AgentState::WarmingUp`] /
    /// [`AgentState::Ready`] / [`AgentState::Busy`] /
    /// [`AgentState::AwaitingInput`] — the runtime is first-hand aware
    /// it has blocked on a requested reply); the lifecycle bookends
    /// ([`AgentState::Registered`] at plant, [`AgentState::Terminated`]
    /// at teardown) are service-set. The spawn body's only role w.r.t.
    /// state is to invoke the observer on each transition; it MUST
    /// NOT write to AgentRegistry through any other path.
    /// # Errors
    ///
    /// When this host cannot run an agent at all — no model configuration, an
    /// unusable host directory. `start_session` turns that into a refusal, which is
    /// the only place a caller can act on it: a spawn body that cannot report
    /// failure has to panic on the daemon's own thread, and the operator then reads
    /// a backtrace about a missing config file instead of an RPC error naming it.
    ///
    /// Reserved for "this cannot start", not "this run ended" — a session that
    /// starts and later fails reports that through `state_observer`.
    fn spawn(
        &self,
        kernel: Arc<K>,
        desc: AgentDescriptor,
        state_observer: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>,
    ) -> Result<Box<dyn SpawnHandle>, String>;

    /// Spawn with durable session selection. Never silently start fresh when
    /// the caller requested recovery from a provider that cannot restore.
    fn spawn_with_options(
        &self,
        kernel: Arc<K>,
        desc: AgentDescriptor,
        options: SpawnOptions,
        state_observer: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>,
    ) -> Result<Box<dyn SpawnHandle>, String> {
        if options.resume_session_id.is_some() {
            return Err("this runtime does not support resume_session_id".into());
        }
        if options.session_endpoint.is_some() {
            return Err("this runtime does not support acp-mailbox/1".into());
        }
        self.spawn(kernel, desc, state_observer)
    }
}

/// Raw ACP-subprocess control-plane spawner — the DI seam for the
/// `spawn_spec` path (frozen contract 2026-08-01). Distinct from
/// [`SpawnTask`] (the in-process LLM runtime body): this launches an
/// external subprocess and exposes its stdio as a byte tunnel that the
/// CLIENT drives, whereas `SpawnTask` runs the agent loop in-process.
///
/// The concrete impl ([`raw_spawn::KernelRawSpawn`]) drives Kernel-inherent
/// stream ops that aren't on the `KernelSyscall` trait, so it's Kernel-
/// concrete and injected at install (Kernel-specific); this trait erases
/// `K` so the generic `start_session` can call it. `None` in slim builds ⇒ `spawn_spec` is rejected with InvalidArgument.
pub(crate) trait RawSpawn: Send + Sync {
    /// Launch `spec`, connect its private stdio to the session mailbox, and store
    /// an abort handle in the shared `spawn_handles` (keyed by `pid`, so
    /// the `on_terminate` observer tears it down). Returns the real OS pid
    /// (contract ④). `Err` on bad spec / launch failure — the impl rolls
    /// back the half-planted session.
    fn spawn(
        &self,
        desc: &AgentDescriptor,
        spec: SpawnSpec,
        endpoint: a2a::session::SessionEndpoint,
    ) -> Result<Option<u32>, String>;
}

// ── Service ─────────────────────────────────────────────────────────────

pub(crate) struct ManagedAgentService<K: KernelSyscall> {
    /// Shared kernel handle for `start_session` to stamp the per-pid
    /// procfs subtree (`/proc/{pid}/`, `/proc/{pid}/workspace/`,
    /// workspace shortcut DT_LINK, per-repo alias DT_LINKs) and for
    /// the on_terminate observer to tear it down.
    kernel: Arc<K>,
    agent_registry: Arc<AgentRegistry>,
    /// Optional per-pid spawn provider. `None` for slim deployments
    /// that ship managed-agent without a runtime body (procfs +
    /// AgentRegistry only); `Some` when `install_with_spawn` injects
    /// a concrete provider (production: the binary edge wraps
    /// `engine_acp::managed_agent::SudoCodeSpawnAdapter`). `start_session` calls
    /// `provider.spawn(...)` after `register_proc_entry` and stores
    /// the returned handle in [`Self::spawn_handles`].
    spawn_provider: Option<Arc<dyn SpawnTask<K>>>,
    /// Per-pid spawn handles populated by `start_session` (both the
    /// `SpawnTask` runtime path and the `RawSpawn` tunnel path). The
    /// on_terminate observer (registered in `install_returning`) removes
    /// and aborts the handle on session termination so the worker /
    /// supervisor leaves cleanly.
    spawn_handles: Arc<dashmap::DashMap<String, Box<dyn SpawnHandle>>>,
    /// Optional raw-subprocess control-plane spawner for the `spawn_spec`
    /// path. `Some` only when `install_returning` wired the Kernel-concrete
    /// [`raw_spawn::KernelRawSpawn`] (`subprocess-host`); `None`
    /// elsewhere, in which case a `spawn_spec` request is rejected.
    raw_spawn: Option<Arc<dyn RawSpawn>>,
}

impl<K: KernelSyscall> ManagedAgentService<K> {
    pub(crate) const NAME: &'static str = "managed_agent";

    /// Service constructor.  Production callers reach this through
    /// [`ManagedAgentService::<Kernel>::install`] against the boot-time
    /// `Arc<Kernel>`; tests instantiate directly with a `Kernel::new()`
    /// (cheap in-memory construction) so the per-pid procfs entries
    /// land in the same metastore the assertion helpers read back.
    pub(crate) fn new(kernel: Arc<K>, agent_registry: Arc<AgentRegistry>) -> Self {
        Self {
            kernel,
            agent_registry,
            spawn_provider: None,
            spawn_handles: Arc::new(dashmap::DashMap::new()),
            raw_spawn: None,
        }
    }

    /// Constructor variant that injects a [`SpawnTask`] provider.
    /// The binary edge (`profiles/cluster`) calls
    /// this with a concrete adapter (e.g. sudocode-runtime
    /// `spawn_task` wrapper) so `start_session` actually kicks off a
    /// runtime body. Pure-Rust slim builds without a runtime body
    /// use [`Self::new`] which leaves the provider unset.
    pub(crate) fn with_spawn(
        kernel: Arc<K>,
        agent_registry: Arc<AgentRegistry>,
        spawn_provider: Arc<dyn SpawnTask<K>>,
    ) -> Self {
        Self {
            kernel,
            agent_registry,
            spawn_provider: Some(spawn_provider),
            spawn_handles: Arc::new(dashmap::DashMap::new()),
            raw_spawn: None,
        }
    }

    // ── Session lifecycle ─────────────────────────────────────────────

    /// Allocate a managed-agent session. Plants a fresh AgentRegistry
    /// record (`AgentRegistry::register` directly — no Python boundary)
    /// and returns the session identity tuple sudowork uses for
    /// follow-up cancel / get_session calls.
    ///
    /// `session_id` and `agent_id` are the same value: the AgentRegistry
    /// pid.  No second identifier is allocated — the descriptor is the
    /// SSOT for everything cancel / get_session needs.  On `register`
    /// collision (effectively impossible given uuid-allocated pids) we
    /// surface `Internal` so the caller sees a hard error.
    #[cfg(test)]
    pub(crate) fn start_session(
        &self,
        req: StartSessionRequest,
    ) -> Result<StartSessionResponse, ManagedAgentError> {
        self.start_session_for(req, Some("test-controller"))
    }

    fn start_session_for(
        &self,
        mut req: StartSessionRequest,
        controller: Option<&str>,
    ) -> Result<StartSessionResponse, ManagedAgentError> {
        if req.agent_id.is_empty() {
            return Err(ManagedAgentError::InvalidArgument(
                "'agent_id' is required".into(),
            ));
        }
        if let Some(id) = req.resume_session_id.as_deref() {
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            {
                return Err(ManagedAgentError::InvalidArgument(
                    "resume_session_id must be a durable ID, not a path".into(),
                ));
            }
            if req.spawn_spec.is_some() || self.spawn_provider.is_none() {
                return Err(ManagedAgentError::InvalidArgument(
                    "resume_session_id requires an in-process runtime provider".into(),
                ));
            }
        }
        // Take the raw spawn spec out early — it selects the spawn
        // strategy below (raw ACP subprocess vs. runtime body) and the
        // rest of the descriptor build doesn't touch it.
        let spawn_spec = req.spawn_spec.take();
        let session_endpoint = if spawn_spec.is_some() || self.spawn_provider.is_some() {
            let controller = controller.filter(|id| !id.is_empty()).ok_or_else(|| {
                ManagedAgentError::InvalidArgument(
                    "hosted sessions require an authenticated controller agent".into(),
                )
            })?;
            let endpoint = a2a::session::SessionEndpoint::new(
                req.agent_id.clone(),
                controller.to_string(),
                uuid::Uuid::new_v4().to_string(),
            );
            endpoint
                .validate()
                .map_err(ManagedAgentError::InvalidArgument)?;
            Some(endpoint)
        } else {
            None
        };
        let owner_id = if req.owner_id.is_empty() {
            "system".to_string()
        } else {
            req.owner_id.clone()
        };
        let zone_id = if req.zone_id.is_empty() {
            "root".to_string()
        } else {
            req.zone_id.clone()
        };

        let pid = alloc_pid();
        let workspace_path = format!("/proc/{pid}/workspace/");

        let repos: Vec<RepoMount> = req
            .repos
            .iter()
            .filter(|r| !r.alias.is_empty() && !r.host_path.is_empty())
            .map(|r| RepoMount {
                alias: r.alias.clone(),
                mount_path: r.host_path.clone(),
            })
            .collect();

        let mut labels = std::collections::HashMap::new();
        if !req.model.is_empty() {
            labels.insert(MODEL_LABEL.to_string(), req.model.clone());
        }

        let now = now_ms();
        let desc = AgentDescriptor {
            pid: pid.clone(),
            name: req.agent_id.clone(),
            kind: AgentKind::Managed,
            state: AgentState::Registered,
            owner_id,
            zone_id,
            created_at_ms: now,
            updated_at_ms: now,
            labels,
            repos,
            ..Default::default()
        };

        if !self.agent_registry.register(desc) {
            return Err(ManagedAgentError::Internal(format!(
                "AgentRegistry.register collided on freshly-allocated pid {pid}"
            )));
        }
        // Move into WARMING_UP — the runtime crate is responsible for
        // the WARMING_UP → READY transition once it finishes
        // initialising the agent loop. The transition is best-effort:
        // a failure here would drop us back to REGISTERED, which the
        // runtime crate will still see as "spawn me" so it's
        // recoverable.
        let _ = self
            .agent_registry
            .update_state(&pid, AgentState::WarmingUp);

        // Stamp the per-pid procfs subtree: dirents for /proc/,
        // /proc/{pid}/, /proc/{pid}/workspace/, plus the workspace
        // shortcut DT_LINK and one DT_LINK per repo alias. VFSRouter
        // follows the DT_LINK rows transparently on read/write.  A
        // failed stamp is logged but doesn't abort the session — the
        // AgentRegistry record is already planted and a future
        // re-stamp closes the gap.
        // Hosting differs; the session endpoint and protocol do not. The raw
        // adapter translates internal stdio. An injected provider hosts its
        // engine in-process. Slim builds without either only register procfs.
        let mut os_pid: Option<u32> = None;
        let mut durable_session_id = None;
        if let Some(desc) = self.agent_registry.get(&pid) {
            if let Err(e) = register_proc_entry(self.kernel.as_ref(), &desc) {
                tracing::warn!(pid=%pid, error=%e, "register_proc_entry failed");
            }
            // The agent's replicated attention-state stream, under its
            // `/agents/{name}` presence. Creating it is also what brings that
            // presence directory into being, which the conversation chat list
            // (`/agents/{name}/conversations/{peer}`) hangs off. The observer below publishes
            // `AwaitingInput` enter/exit here so any node can answer the
            // cross-machine "which agents are waiting on me?" with a plain read. Best-effort: a std / non-stream
            // deployment simply has no reader and the agent runs unaffected.
            if let Err(e) = a2a::ensure_agent_state_stream(self.kernel.as_ref(), &desc.name) {
                tracing::warn!(pid=%pid, error=%e, "ensure_agent_state_stream failed");
            }
            if let Some(spec) = spawn_spec {
                match self.raw_spawn.as_ref() {
                    Some(rs) => {
                        os_pid = rs
                            .spawn(
                                &desc,
                                spec,
                                session_endpoint.clone().expect("hosted endpoint"),
                            )
                            .map_err(ManagedAgentError::Internal)?;
                    }
                    None => {
                        // No raw spawner wired (slim / non-unix). Roll back
                        // the half-planted session so the caller sees a
                        // clean failure rather than a zombie record.
                        let _ = self.agent_registry.kill(&pid, 127);
                        return Err(ManagedAgentError::InvalidArgument(
                            "spawn_spec (raw subprocess host) requires a unix build with the \
                             subprocess-host feature"
                                .into(),
                        ));
                    }
                }
            } else if let Some(provider) = self.spawn_provider.as_ref() {
                // Construct the SSOT state observer. AgentRegistry is
                // the single writer of AgentState in the runtime path
                // (see kernel::core::agents::registry::update_state +
                // can_transition_to FSM); the spawn body reports an
                // AgentState on each transition (the running-state
                // subset WarmingUp/Ready/Busy — Registered/Suspended/
                // Terminated are service-set at plant/teardown) and this
                // closure forwards it through update_state.
                // InvalidTransition is logged rather than panicked so
                // an FSM bug in the runtime body surfaces as a warning
                // instead of taking down the worker thread.
                let registry = Arc::clone(&self.agent_registry);
                let pid_for_observer = pid.clone();
                let kernel_for_observer = Arc::clone(&self.kernel);
                let agent_name = desc.name.clone();
                let observer: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync> =
                    Arc::new(move |state: AgentState, reason: Option<String>| {
                        // Note the pre-update AwaitingInput status so we publish
                        // only the attention enter/exit edges (bounded), not
                        // every Ready↔Busy flip.
                        let was_awaiting = registry
                            .get(&pid_for_observer)
                            .map(|d| d.state == AgentState::AwaitingInput)
                            .unwrap_or(false);
                        if let Err(e) = registry.update_state_with_reason(
                            &pid_for_observer,
                            state,
                            reason.clone(),
                        ) {
                            tracing::warn!(
                                pid = %pid_for_observer,
                                state = ?state,
                                error = %e,
                                "AgentRegistry.update_state rejected runtime-side transition",
                            );
                        }
                        // Publish the AwaitingInput enter/exit edge to the
                        // agent's replicated state stream — best-effort, so a
                        // non-stream / std deployment (no reader) never disturbs
                        // the agent.
                        let is_awaiting = state == AgentState::AwaitingInput;
                        if was_awaiting != is_awaiting {
                            let event = serde_json::json!({
                                "state": state.as_str(),
                                "reason": reason,
                            })
                            .to_string();
                            let ctx = kernel::kernel::OperationContext::new(
                                "managed_agent",
                                "root",
                                true,
                                None,
                                true,
                            );
                            if let Err(e) = kernel_for_observer.sys_write(
                                &a2a::agent_state_path(&agent_name),
                                &ctx,
                                event.as_bytes(),
                                0,
                            ) {
                                tracing::warn!(
                                    agent = %agent_name,
                                    error = ?e,
                                    "publish agent attention state failed (best-effort)",
                                );
                            }
                        }
                    });
                // A refusal here is the session NOT starting: unwind the registration
                // rather than leaving a pid whose runtime never existed, so a caller
                // that retries after fixing the cause is not told the agent is
                // already running.
                let handle = provider
                    .spawn_with_options(
                        Arc::clone(&self.kernel),
                        desc,
                        SpawnOptions {
                            resume_session_id: req.resume_session_id.clone(),
                            session_endpoint: session_endpoint.clone(),
                        },
                        observer,
                    )
                    .map_err(|e| {
                        let _ = self.agent_registry.kill(&pid, 1);
                        // `Internal`, not `InvalidArgument`: the request was fine and
                        // the caller cannot fix this by sending a different one — the
                        // HOST is missing something (model configuration, a usable
                        // directory). The dispatch vocabulary has no
                        // failed-precondition code, and widening it for one service is
                        // not this change's call, so the distinction lives in the
                        // message the refusal carries.
                        ManagedAgentError::Internal(format!("spawn agent runtime: {e}"))
                    })?;
                if req
                    .resume_session_id
                    .as_deref()
                    .is_some_and(|requested| handle.durable_session_id() != Some(requested))
                {
                    handle.abort();
                    let _ = self.agent_registry.kill(&pid, 1);
                    return Err(ManagedAgentError::Internal(
                        "runtime did not restore the requested durable session".into(),
                    ));
                }
                durable_session_id = handle.durable_session_id().map(str::to_owned);
                if handle.session_endpoint() != session_endpoint.as_ref() {
                    handle.abort();
                    let _ = self.agent_registry.kill(&pid, 1);
                    return Err(ManagedAgentError::Internal(
                        "runtime did not attach the session mailbox".into(),
                    ));
                }
                self.spawn_handles.insert(pid.clone(), handle);
            }
        }

        Ok(StartSessionResponse {
            session_id: pid,
            session_endpoint,
            durable_session_id,
            workspace_path,
            os_pid,
        })
    }

    /// Cancel an in-flight turn or terminate the entire session.
    ///
    /// `Turn` — abort the current generation; AgentRegistry record stays.
    /// The runtime crate observes the cancellation through whatever
    /// mechanism it picks (channel, atomic flag, …) — kernel doesn't
    /// know about turn boundaries.
    ///
    /// `Session` — terminate: transition AgentRegistry to `Terminated`.
    /// The on_terminate observer registered at install time tears down
    /// the per-pid procfs dirent.  The runtime crate observes the state
    /// transition and shuts down the agent task.
    pub(crate) fn cancel(
        &self,
        session_id: &str,
        mode: CancelMode,
    ) -> Result<CancelResponse, ManagedAgentError> {
        // session_id IS the pid in AgentRegistry (no second identifier).
        if self.agent_registry.get(session_id).is_none() {
            return Err(ManagedAgentError::UnknownSession(session_id.to_string()));
        }

        match mode {
            CancelMode::Turn => Err(ManagedAgentError::InvalidArgument(
                "turn cancellation uses session/cancel on the session mailbox".into(),
            )),
            CancelMode::Session => {
                // `kill` transitions to Terminated (firing the
                // on_terminate observer that drops the procfs dirent)
                // and auto-reaps the descriptor when the agent is an
                // orphan — which managed agents always are today
                // (start_session passes parent_pid=None).  Reaping is
                // what surfaces `UnknownSession` on a follow-up
                // cancel / get_session.
                let cancelled = self
                    .agent_registry
                    .kill(session_id, 0)
                    .map(|_| true)
                    .unwrap_or(false);
                Ok(CancelResponse { cancelled })
            }
        }
    }

    /// Read-through liveness snapshot. Cheap by design; the live
    /// message flow uses `sys_watch` over `/proc/{pid}/transcript`,
    /// not this RPC.
    pub(crate) fn get_session(
        &self,
        session_id: &str,
    ) -> Result<GetSessionResponse, ManagedAgentError> {
        // session_id IS the pid; the descriptor is the SSOT.
        let desc = self
            .agent_registry
            .get(session_id)
            .ok_or_else(|| ManagedAgentError::UnknownSession(session_id.to_string()))?;
        let workspace_path = format!("/proc/{}/workspace/", desc.pid);
        let model = desc.labels.get(MODEL_LABEL).cloned().unwrap_or_default();
        Ok(GetSessionResponse {
            session_id: desc.pid.clone(),
            session_endpoint: self
                .spawn_handles
                .get(session_id)
                .and_then(|handle| handle.session_endpoint().cloned()),
            durable_session_id: self
                .spawn_handles
                .get(session_id)
                .and_then(|handle| handle.durable_session_id().map(str::to_owned)),
            agent_id: desc.name.clone(),
            owner_id: desc.owner_id.clone(),
            workspace_path,
            model,
            state: desc.state.as_str().to_lowercase(),
            reason: desc.reason.clone(),
        })
    }
}

// Production install path stays specific to the concrete `Kernel`
// because `register_on_terminate` is an inherent accessor on
// `AgentRegistry` reached through `kernel.agent_registry()` — that
// accessor is deliberately *not* on the `KernelSyscall` trait (the v2
// audit pulled kernel-internal struct accessors out of the
// service-facing surface). Lifecycle methods stay generic above so
// non-Kernel `K: KernelSyscall` test fixtures and future runtime targets
// (sudo-code in-process spawn) compile without `Kernel`.
impl ManagedAgentService<kernel::kernel::Kernel> {
    /// Install the service into a freshly-constructed kernel:
    ///
    ///   1. Register the workspace-boundary hook into
    ///      the kernel's `KernelDispatch`.
    ///   2. Enlist the service into `ServiceRegistry` so future tonic
    ///      gRPC handlers + Python factory wiring can resolve it via
    ///      `service_registry.lookup_rust(NAME)`.
    ///
    /// Called from `Kernel::new()`. The service holds an
    /// `Arc<AgentRegistry>` — the same `Arc` `Kernel` keeps for
    /// `AgentStatusResolver` reads — so `start_session` mutates the
    /// same SSOT every other agent surface reads from.
    pub(crate) fn install(kernel: &Arc<kernel::kernel::Kernel>) -> Result<(), String> {
        Self::install_returning(kernel, None).map(|_| ())
    }

    /// Install variant that injects a [`SpawnTask`] provider. Used
    /// by the binary edge (`profiles/cluster`) to
    /// wire the sudocode-runtime adapter — the actual managed-agent
    /// runtime body. Slim builds without a runtime body call
    /// [`Self::install`] which leaves `spawn_provider = None` and
    /// ships procfs + AgentRegistry only.
    pub(crate) fn install_with_spawn(
        kernel: &Arc<kernel::kernel::Kernel>,
        spawn_provider: Arc<dyn SpawnTask<kernel::kernel::Kernel>>,
    ) -> Result<(), String> {
        Self::install_returning(kernel, Some(spawn_provider)).map(|_| ())
    }

    /// Install variant that returns the wired service handle so tests
    /// can assert the on_terminate observer behaves correctly without
    /// having to fish the service back out of the kernel registry.
    pub(crate) fn install_returning(
        kernel: &Arc<kernel::kernel::Kernel>,
        spawn_provider: Option<Arc<dyn SpawnTask<kernel::kernel::Kernel>>>,
    ) -> Result<Arc<Self>, String> {
        // State at boot what this build can and cannot do with a session,
        // because the two capabilities look identical from a caller until the
        // agent fails to come up.
        //
        // `start_session_v1` succeeds either way: a provider-less build
        // registers identity, ownership and the /proc subtree on purpose, and
        // those are real. What it cannot do is RUN the agent loop — and the
        // caller learns that only as `session_endpoint: None`, `os_pid: null`,
        // and a session that never leaves WARMING_UP. Nothing in that set says
        // "wrong binary".
        //
        // That is not hypothetical. A cross-machine bring-up was told to use
        // `nexusd-cluster`, which CANNOT embed the sudocode runtime — the
        // dependency edge is one-way, sudocode → nexus-vfs — so there was
        // nothing to dispatch to, and the session sat in WARMING_UP with an
        // empty log while the operator looked for the bug in their own call.
        // One line at boot answers the question they were actually asking:
        // is this the binary that can host an agent?
        //
        // Deliberately at install rather than per call: the answer is a
        // property of the build, fixed before any request arrives, and an
        // operator choosing a binary reads the boot log, not a per-call warning
        // they have to provoke first.
        if spawn_provider.is_some() {
            tracing::info!(
                "managed-agent: in-process runtime provider WIRED — start_session_v1 \
                 can host agent loops"
            );
        } else {
            tracing::warn!(
                "managed-agent: NO in-process runtime provider — start_session_v1 \
                 will register sessions (identity, ownership, /proc) but cannot run \
                 an agent loop, so a session stays WARMING_UP with no os_pid and no \
                 session mailbox. Use a build that wires one (install_with_spawn), \
                 or drive a subprocess agent by passing spawn_spec."
            );
        }

        // Mount the /proc namespace this service stamps into. VFSRouter
        // routes by mount-point lookup, so `sys_unlink` on
        // `/proc/{pid}/...` paths needs the mount entry to exist
        // (`route()` returns NotMounted otherwise and unlink no-ops).
        // No backing store / per-mount metastore — `metastore=None`
        // means dirent reads/writes fall through to the global
        // metastore (matches the procfs-virtualised semantics this
        // mount represents). Idempotent re-call: VFSRouter::add_mount
        // ignores duplicates.
        kernel
            .vfs_router_arc()
            .add_mount("/proc", "root", None, false);

        // Holding `Arc<Kernel>` inside the service does create a
        // Kernel ↔ Service Arc cycle, but services live for process
        // lifetime — same convention AcpService follows. The procfs
        // dirent stamp in `start_session` and the on_terminate
        // teardown both need the owned Arc.
        //
        // Built as a struct literal (not `new`/`with_spawn`) so the raw
        // control-plane spawner can share the SAME `agent_registry` +
        // `spawn_handles` the service and its on_terminate observer use.
        let agent_registry = Arc::clone(kernel.agent_registry());
        let spawn_handles: Arc<dashmap::DashMap<String, Box<dyn SpawnHandle>>> =
            Arc::new(dashmap::DashMap::new());

        // Raw ACP subprocess control-plane spawner (memory-DT_STREAM byte
        // tunnel). Kernel-concrete — built here because it drives
        // Kernel-inherent stream ops off the service surface. Cross-platform;
        // `subprocess-host` only. `None` in a slim build ⇒ `spawn_spec`
        // rejected.
        #[cfg(feature = "subprocess-host")]
        let raw_spawn: Option<Arc<dyn RawSpawn>> = Some(Arc::new(raw_spawn::KernelRawSpawn::new(
            Arc::clone(kernel),
            Arc::clone(&agent_registry),
            Arc::clone(&spawn_handles),
        )));
        #[cfg(not(feature = "subprocess-host"))]
        let raw_spawn: Option<Arc<dyn RawSpawn>> = None;

        let svc = Arc::new(ManagedAgentService {
            kernel: Arc::clone(kernel),
            agent_registry,
            spawn_provider,
            spawn_handles,
            raw_spawn,
        });

        // Tear down the per-pid procfs subtree on out-of-band
        // termination — SIGKILL, orphan auto-reap, any path that flips
        // an agent to Terminated without going through
        // `cancel_session(Session)`. `fire_on_terminate` runs before
        // `AgentRegistry::reap` on the orphan path, so the descriptor
        // is still reachable here and we can use its `repos` to drop
        // the per-alias DT_LINK rows alongside the dirents. The
        // descriptor itself is reaped by AgentRegistry after the
        // observer returns, so subsequent `get_session` returns
        // `UnknownSession`.
        //
        // The spawn-handles sidecar lives on the service itself, so
        // the observer captures `Arc::clone(&svc.spawn_handles)`.
        // Removing the handle and aborting it is best-effort — the
        // worker thread also exits naturally when its sys_read on
        // the now-missing procfs path returns FileNotFound,
        // but the explicit abort gives a clean exit without an
        // error-path walk.
        let kernel_for_cb = Arc::clone(kernel);
        let registry_for_cb = Arc::clone(kernel.agent_registry());
        let spawn_handles_for_cb = Arc::clone(&svc.spawn_handles);
        kernel.agent_registry().register_on_terminate(
            Self::NAME,
            Arc::new(move |pid: &str| {
                if let Some((_, handle)) = spawn_handles_for_cb.remove(pid) {
                    handle.abort();
                }
                if let Some(desc) = registry_for_cb.get(pid) {
                    unregister_proc_entry(kernel_for_cb.as_ref(), &desc);
                }
            }),
        );

        let svc_for_return = Arc::clone(&svc);
        kernel.register_rust_service(Self::NAME, svc as Arc<dyn RustService>, Vec::new())?;

        // Register the hook the service owns via the enforced ownership
        // surface — the handle binds it to this service's
        // `ServiceRegistry` entry so
        // `Kernel::unregister_service("managed_agent")` / `swap_managed_service`
        // batch-remove it alongside the service instance.  Hooks are
        // stateless so ordering (enlist-then-hook) has no correctness
        // dependency; the two-step flow matches the pattern
        // `services::audit::install_root` established: enlist the
        // owning entity first, then plug hooks in through the handle.
        //
        // The mailbox `from`-stamp hook is NOT registered here anymore:
        // it belongs to the `a2a` messaging substrate (nexus-vfs) and is
        // armed once at cluster boot, so the guarantee holds for every
        // writer — not only agents spawned through this service.
        let handle = kernel
            .service_handle(Self::NAME)
            .expect("just enlisted managed_agent above; handle must exist");
        kernel.register_service_hook(
            &handle,
            Box::new(workspace_boundary_hook::WorkspaceBoundaryHook::new(
                Arc::clone(kernel.agent_registry()),
            )),
        );

        Ok(svc_for_return)
    }
}

impl From<ManagedAgentError> for RustCallError {
    fn from(e: ManagedAgentError) -> Self {
        match e {
            ManagedAgentError::InvalidArgument(m) => Self::InvalidArgument(m),
            ManagedAgentError::UnknownSession(s) => {
                Self::InvalidArgument(format!("unknown session_id {s:?}"))
            }
            ManagedAgentError::Internal(m) => Self::Internal(m),
        }
    }
}

/// Whose session this is, deciding between what the caller *said* and what its
/// credential *proves*.
///
/// The credential wins. `start_session_v1` used to take `owner_id` from the
/// request body and had no way to check it, so an agent could open a session
/// attributed to anyone; that is the hole this closes. Per `OperationContext`,
/// `user_id` is the principal and `agent_id` the actor, and they differ
/// exactly when the caller holds a delegated credential — a session cert
/// carrying a `nexus://owner/` SAN, which the auth layer has already resolved
/// into `user_id`. This never parses a certificate; it reads the context the
/// auth layer built.
///
/// Three cases, and the middle one is the decision worth stating:
///
/// * **No delegated credential** — the caller presented an ordinary agent
///   cert, an `sk-` key, or nothing. Behaviour is unchanged: the body's
///   `owner_id` stands, empty defaulting to `system` downstream. This is what
///   makes the enforcement arrive *with the credential* instead of on a flag
///   day: a caller that starts presenting a session cert starts being held to
///   it, and everything else keeps working.
///
/// * **Delegated, and the body disagrees** — refused, not overwritten.
///   Overwriting is quieter and that is exactly what is wrong with it: the
///   caller believes it opened a session for one person while the system
///   recorded another, with nothing said. A mismatch is a bug in the caller or
///   a credential being used for someone it was not issued for, and both want
///   to be loud. For the caller this FR is about, the two agree, so this never
///   fires in the correct case.
///
/// * **Delegated, body empty or already matching** — the credential's owner
///   is used. An empty body is not a disagreement, so an existing caller that
///   sends no `owner_id` needs no change.
fn authenticated_owner(
    requested: &str,
    ctx: &contracts::OperationContext,
) -> Result<String, String> {
    let delegated = ctx
        .agent_id
        .as_deref()
        .is_some_and(|actor| actor != ctx.user_id);
    if !delegated {
        return Ok(requested.to_string());
    }
    let proven = ctx.user_id.as_str();
    if !requested.is_empty() && requested != proven {
        return Err(format!(
            "owner_id {requested:?} does not match the caller's credential, which is \
             issued for {proven:?}; omit owner_id to use the credential's owner"
        ));
    }
    Ok(proven.to_string())
}

impl<K: KernelSyscall> RustService for ManagedAgentService<K> {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn start(&self) -> Result<(), String> {
        // Hooks were registered at `install` time so they're live from
        // kernel boot. No async state to spin up today; tonic gRPC
        // handler wiring goes here once that lands.
        Ok(())
    }

    fn stop(&self) -> Result<(), String> {
        Ok(())
    }

    /// Route the three session-lifecycle methods exposed over
    /// `NexusVFSService.Call`. Method names are versioned so the wire
    /// contract can evolve without breaking older sudowork clients.
    fn dispatch(
        &self,
        method: &str,
        payload: &[u8],
        ctx: &contracts::OperationContext,
    ) -> Result<Vec<u8>, RustCallError> {
        match method {
            "start_session_v1" => {
                let mut req: StartSessionRequest = serde_json::from_slice(payload)
                    .map_err(|e| RustCallError::InvalidArgument(e.to_string()))?;
                req.owner_id = authenticated_owner(&req.owner_id, ctx)
                    .map_err(RustCallError::InvalidArgument)?;
                let resp = self.start_session_for(
                    req,
                    Some(ctx.agent_id.as_deref().unwrap_or(&ctx.user_id)),
                )?;
                serde_json::to_vec(&resp).map_err(|e| RustCallError::Internal(e.to_string()))
            }
            "cancel_v1" => {
                let req: CancelRequest = serde_json::from_slice(payload)
                    .map_err(|e| RustCallError::InvalidArgument(e.to_string()))?;
                let resp = self.cancel(&req.session_id, req.mode)?;
                serde_json::to_vec(&resp).map_err(|e| RustCallError::Internal(e.to_string()))
            }
            "get_session_v1" => {
                let req: GetSessionRequest = serde_json::from_slice(payload)
                    .map_err(|e| RustCallError::InvalidArgument(e.to_string()))?;
                let resp = self.get_session(&req.session_id)?;
                serde_json::to_vec(&resp).map_err(|e| RustCallError::Internal(e.to_string()))
            }
            _ => Err(RustCallError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kernel::kernel::Kernel;

    /// Build a `ManagedAgentService` with a real `Kernel::new()`.  The
    /// returned tuple shares the AgentRegistry between caller and
    /// service so tests can read the descriptor table without going
    /// through the service's read accessors.
    fn fresh_service() -> (Arc<Kernel>, Arc<AgentRegistry>, ManagedAgentService<Kernel>) {
        let kernel = Arc::new(Kernel::new());
        let registry = Arc::clone(kernel.agent_registry());
        let svc = ManagedAgentService::<Kernel>::new(Arc::clone(&kernel), Arc::clone(&registry));
        (kernel, registry, svc)
    }

    fn req(agent_id: &str) -> StartSessionRequest {
        StartSessionRequest {
            agent_id: agent_id.to_string(),
            repos: Vec::new(),
            model: "claude-sonnet-4-6".to_string(),
            owner_id: "ethan".to_string(),
            zone_id: "root".to_string(),
            spawn_spec: None,
            resume_session_id: None,
        }
    }

    /// Mock [`SpawnTask`] that invokes the injected `state_observer`
    /// with a scripted WARMING_UP → READY → BUSY transition sequence,
    /// then returns a no-op handle. Used by the
    /// `state_observer_drives_agent_registry_through_loop_states`
    /// test to verify the service-constructed observer closure is the
    /// SSOT writer of AgentState.
    struct ScriptedSpawn;
    struct NoopHandle(Option<a2a::session::SessionEndpoint>);
    impl SpawnHandle for NoopHandle {
        fn abort(&self) {}
        fn session_endpoint(&self) -> Option<&a2a::session::SessionEndpoint> {
            self.0.as_ref()
        }
    }
    impl SpawnTask<Kernel> for ScriptedSpawn {
        fn spawn_with_options(
            &self,
            kernel: Arc<Kernel>,
            desc: AgentDescriptor,
            options: SpawnOptions,
            observer: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>,
        ) -> Result<Box<dyn SpawnHandle>, String> {
            self.spawn(kernel, desc, observer)?;
            Ok(Box::new(NoopHandle(options.session_endpoint)))
        }

        fn spawn(
            &self,
            _kernel: Arc<Kernel>,
            _desc: AgentDescriptor,
            state_observer: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>,
        ) -> Result<Box<dyn SpawnHandle>, String> {
            state_observer(AgentState::WarmingUp, None);
            state_observer(AgentState::Ready, None);
            state_observer(AgentState::Busy, None);
            // Blocked on a reply it requested — carries an opaque reason.
            state_observer(AgentState::AwaitingInput, Some("permission".to_string()));
            Ok(Box::new(NoopHandle(None)))
        }
    }

    /// A host that cannot run an agent at all — no model configuration, an unusable
    /// host directory — refuses the session instead of dying on the daemon's thread.
    struct RefusingSpawn;
    impl SpawnTask<Kernel> for RefusingSpawn {
        fn spawn_with_options(
            &self,
            kernel: Arc<Kernel>,
            desc: AgentDescriptor,
            options: SpawnOptions,
            observer: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>,
        ) -> Result<Box<dyn SpawnHandle>, String> {
            self.spawn(kernel, desc, observer)?;
            Ok(Box::new(NoopHandle(options.session_endpoint)))
        }

        fn spawn(
            &self,
            _kernel: Arc<Kernel>,
            _desc: AgentDescriptor,
            _state_observer: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>,
        ) -> Result<Box<dyn SpawnHandle>, String> {
            Err("no sudocode configuration at /nowhere".to_string())
        }
    }

    /// `start_session` answers with the refusal, and the pid it had already planted
    /// does not linger as a session whose runtime never existed.
    ///
    /// Before the seam could refuse, a co-host with no model configuration panicked
    /// inside the spawn — so an RPC that should have answered "this daemon has no
    /// agent configuration" instead took down a daemon thread and left the operator
    /// reading a backtrace about a missing file.
    #[test]
    fn a_host_that_cannot_start_an_agent_refuses_the_session() {
        let kernel = Arc::new(Kernel::new());
        let registry = Arc::clone(kernel.agent_registry());
        let svc = ManagedAgentService::<Kernel>::with_spawn(
            Arc::clone(&kernel),
            Arc::clone(&registry),
            Arc::new(RefusingSpawn),
        );

        let err = svc
            .start_session(req("scode-standard"))
            .expect_err("a host that cannot spawn must refuse");
        let text = err.to_string();
        assert!(
            text.contains("no sudocode configuration"),
            "the refusal must carry the host's reason, not a generic failure: {text}"
        );

        // Whatever pid was planted is Terminated WITH that reason — a caller listing
        // sessions sees why, and a retry after fixing the cause is not told the agent
        // is already running.
        let live: Vec<_> = registry
            .list(None, None, None, None)
            .into_iter()
            .filter(|d| d.state != AgentState::Terminated)
            .map(|d| (d.pid, d.state))
            .collect();
        assert!(
            live.is_empty(),
            "a refused spawn must leave no live session: {live:?}"
        );
    }

    #[test]
    fn service_has_canonical_name() {
        let (_kernel, _table, svc) = fresh_service();
        assert_eq!(svc.name(), "managed_agent");
        assert_eq!(ManagedAgentService::<Kernel>::NAME, "managed_agent");
    }

    #[test]
    fn state_observer_drives_agent_registry_through_loop_states() {
        let kernel = Arc::new(Kernel::new());
        let registry = Arc::clone(kernel.agent_registry());
        let svc = ManagedAgentService::<Kernel>::with_spawn(
            Arc::clone(&kernel),
            Arc::clone(&registry),
            Arc::new(ScriptedSpawn),
        );

        let resp = svc.start_session(req("scode-standard")).unwrap();
        let desc = registry
            .get(&resp.session_id)
            .expect("AgentRegistry record present");
        // The scripted observer fired WARMING_UP → READY → BUSY →
        // AwaitingInput("permission"); the SSOT reflects the last transition
        // AND the agent-reported reason. (start_session already moves
        // REGISTERED → WARMING_UP before spawn, so a re-fired WARMING_UP from
        // the observer is a no-op via the from==new shortcut.)
        assert_eq!(desc.state, AgentState::AwaitingInput);
        assert_eq!(desc.reason.as_deref(), Some("permission"));
    }

    #[test]
    fn awaiting_input_publishes_to_agent_state_stream() {
        let kernel = Arc::new(Kernel::new());
        // Route `/agents/*` so the state stream provisions + the publish lands
        // (a fresh Kernel mounts nothing; a real host has the `/agents` mount).
        kernel
            .vfs_router_arc()
            .add_mount("/agents", "root", None, false);
        let registry = Arc::clone(kernel.agent_registry());
        let svc = ManagedAgentService::<Kernel>::with_spawn(
            Arc::clone(&kernel),
            Arc::clone(&registry),
            Arc::new(ScriptedSpawn),
        );
        let resp = svc.start_session(req("state-probe")).unwrap();
        let name = registry.get(&resp.session_id).unwrap().name;
        // The scripted spawn entered AwaitingInput("permission"); the host
        // published that enter-edge to the agent's replicated state stream.
        let (data, _next) = kernel
            .stream_read_at_blocking(&format!("/agents/{name}/state"), 0, 1_000)
            .expect("agent state stream readable");
        let text = String::from_utf8_lossy(&data);
        assert!(
            text.contains("AWAITING_INPUT") && text.contains("permission"),
            "AwaitingInput enter-edge published with its reason: {text}"
        );
    }

    #[test]
    fn lifecycle_methods_succeed_on_empty_service() {
        let (_kernel, _table, svc) = fresh_service();
        svc.start().unwrap();
        svc.stop().unwrap();
    }

    /// Nexus-half of the in-process sudocode co-host: prove the seam.
    ///
    /// Each spawn body receives the SHARED `Arc<Kernel>` and does a REAL
    /// in-process `KernelSyscall` against it. Three concurrent sessions ⇒
    /// three agent loops, ONE kernel, direct Rust syscalls (no gRPC). This is
    /// exactly what a co-hosted `sudocode_runtime` gets through the
    /// `SpawnTask<Kernel>` adapter at the `nexusd-cluster` binary edge.
    struct ProbingSpawn {
        /// Test sink: (kernel Arc ptr, pid, whether the loop's in-process
        /// stat of its own stamped `/proc/{pid}/workspace` hit).
        seen: Arc<std::sync::Mutex<Vec<(usize, String, bool)>>>,
    }
    impl SpawnTask<Kernel> for ProbingSpawn {
        fn spawn_with_options(
            &self,
            kernel: Arc<Kernel>,
            desc: AgentDescriptor,
            options: SpawnOptions,
            observer: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>,
        ) -> Result<Box<dyn SpawnHandle>, String> {
            self.spawn(kernel, desc, observer)?;
            Ok(Box::new(NoopHandle(options.session_endpoint)))
        }

        fn spawn(
            &self,
            kernel: Arc<Kernel>,
            desc: AgentDescriptor,
            state_observer: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>,
        ) -> Result<Box<dyn SpawnHandle>, String> {
            state_observer(AgentState::WarmingUp, None);
            let ptr = Arc::as_ptr(&kernel) as usize;
            // Real in-process KernelSyscall on the SHARED kernel: stat the
            // procfs workspace `start_session` stamped for THIS pid (procfs
            // is virtual — no backend needed). A hit proves the loop reached
            // the very kernel the service planted into: not a copy, not gRPC.
            let ws = format!("/proc/{}/workspace", desc.pid);
            let hit = kernel.sys_stat(&ws, &desc.zone_id).is_some();
            self.seen.lock().unwrap().push((ptr, desc.pid.clone(), hit));
            state_observer(AgentState::Ready, None);
            Ok(Box::new(NoopHandle(None)))
        }
    }

    #[test]
    fn multiple_loops_share_one_kernel_via_in_process_syscall() {
        let kernel = Arc::new(Kernel::new());
        let kernel_ptr = Arc::as_ptr(&kernel) as usize;
        let registry = Arc::clone(kernel.agent_registry());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let svc = ManagedAgentService::<Kernel>::with_spawn(
            Arc::clone(&kernel),
            registry,
            Arc::new(ProbingSpawn {
                seen: Arc::clone(&seen),
            }),
        );

        for id in ["agent-a", "agent-b", "agent-c"] {
            svc.start_session(req(id)).expect("start_session");
        }

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3, "all three loops ran: {seen:?}");
        // (1) ONE shared kernel: every loop received the SAME `Arc<Kernel>` the
        //     service holds (pointer identity) — co-hosted, not per-agent copies.
        assert!(
            seen.iter().all(|(ptr, _, _)| *ptr == kernel_ptr),
            "every loop shares the ONE service kernel: {seen:?}"
        );
        // (2) In-process syscall: each loop's stat hit its own stamped procfs
        //     subtree, proving the loop reached the shared kernel directly.
        assert!(
            seen.iter().all(|(_, _, hit)| *hit),
            "each loop's in-process sys_stat saw its /proc/pid/workspace: {seen:?}"
        );
        // (3) Three distinct pids — three real sessions, not one reused.
        let pids: std::collections::BTreeSet<&String> =
            seen.iter().map(|(_, pid, _)| pid).collect();
        assert_eq!(pids.len(), 3, "three distinct pids: {seen:?}");
    }

    #[test]
    fn start_session_returns_identity_tuple_and_plants_agent_registry_record() {
        let (_kernel, table, svc) = fresh_service();
        let resp = svc.start_session(req("scode-standard")).unwrap();

        // session_id IS the pid — no second identifier.
        assert!(resp.session_id.starts_with("pid-"));
        assert_eq!(
            resp.workspace_path,
            format!("/proc/{}/workspace/", resp.session_id)
        );

        let desc = table
            .get(&resp.session_id)
            .expect("AgentRegistry record present");
        assert_eq!(desc.name, "scode-standard");
        assert_eq!(desc.kind, AgentKind::Managed);
        assert_eq!(desc.state, AgentState::WarmingUp);
        assert_eq!(desc.owner_id, "ethan");
        assert_eq!(desc.zone_id, "root");
        // Model lands on the descriptor as a label so get_session can
        // echo it back without a sidecar table.
        assert_eq!(
            desc.labels.get("model").map(String::as_str),
            Some("claude-sonnet-4-6")
        );
    }

    #[test]
    fn start_session_rejects_empty_agent_name() {
        let (_kernel, _table, svc) = fresh_service();
        let err = svc.start_session(req("")).unwrap_err();
        assert!(matches!(err, ManagedAgentError::InvalidArgument(_)));
    }

    #[test]
    fn start_session_defaults_owner_and_zone() {
        let (_kernel, _table, svc) = fresh_service();
        let r = StartSessionRequest {
            agent_id: "scode-standard".to_string(),
            ..Default::default()
        };
        let resp = svc.start_session(r).unwrap();
        let desc = svc.agent_registry.get(&resp.session_id).unwrap();
        assert_eq!(desc.owner_id, "system");
        assert_eq!(desc.zone_id, "root");
    }

    #[test]
    fn cancel_session_terminates_pid_and_reaps_descriptor() {
        let (_kernel, table, svc) = fresh_service();
        let resp = svc.start_session(req("scode-standard")).unwrap();
        let pid = resp.session_id.clone();

        let r = svc.cancel(&pid, CancelMode::Session).unwrap();
        assert!(r.cancelled);

        // Managed agents are orphans (start_session passes parent_pid=
        // None), so AgentRegistry::kill auto-reaps the descriptor on
        // the Terminated transition.
        assert!(table.get(&pid).is_none());

        // Second cancel surfaces UnknownSession (descriptor reaped).
        let err = svc.cancel(&pid, CancelMode::Session).unwrap_err();
        assert!(matches!(err, ManagedAgentError::UnknownSession(_)));
    }

    #[test]
    fn cancel_turn_keeps_pid_alive() {
        let (_kernel, table, svc) = fresh_service();
        let resp = svc.start_session(req("scode-standard")).unwrap();
        let pid = resp.session_id.clone();

        assert!(matches!(
            svc.cancel(&pid, CancelMode::Turn),
            Err(ManagedAgentError::InvalidArgument(_))
        ));
        // pid still WARMING_UP — turn cancel doesn't terminate.
        let desc = table.get(&pid).unwrap();
        assert_eq!(desc.state, AgentState::WarmingUp);
        // Descriptor still present — get_session still works.
        let _ = svc.get_session(&pid).unwrap();
    }

    #[test]
    fn cancel_unknown_session_errors() {
        let (_kernel, _table, svc) = fresh_service();
        let err = svc.cancel("pid-bogus", CancelMode::Session).unwrap_err();
        assert!(matches!(err, ManagedAgentError::UnknownSession(_)));
    }

    #[test]
    fn get_session_returns_state_from_agent_registry() {
        let (_kernel, _table, svc) = fresh_service();
        let resp = svc.start_session(req("scode-standard")).unwrap();
        let snap = svc.get_session(&resp.session_id).unwrap();
        assert_eq!(snap.session_id, resp.session_id);
        // agent_id in the response is the static profile name.
        assert_eq!(snap.agent_id, "scode-standard");
        assert_eq!(snap.workspace_path, resp.workspace_path);
        assert_eq!(snap.model, "claude-sonnet-4-6");
        assert_eq!(snap.state, "warming_up");
    }

    #[test]
    fn get_session_surfaces_unknown_for_reaped_pid() {
        // Pre-collapse, the service kept its own session row so a
        // get_session against a reaped pid returned the snapshot with
        // state="terminated".  Post-collapse the descriptor IS the
        // SSOT: once it's reaped, get_session must surface
        // UnknownSession.
        let (_kernel, table, svc) = fresh_service();
        let resp = svc.start_session(req("scode-standard")).unwrap();
        table.unregister(&resp.session_id);
        let err = svc.get_session(&resp.session_id).unwrap_err();
        assert!(matches!(err, ManagedAgentError::UnknownSession(_)));
    }

    #[test]
    fn get_session_unknown_session_errors() {
        let (_kernel, _table, svc) = fresh_service();
        let err = svc.get_session("pid-bogus").unwrap_err();
        assert!(matches!(err, ManagedAgentError::UnknownSession(_)));
    }

    // ── dispatch round-trip ─────────────────────────────────────────

    mod dispatch {
        use super::*;
        use serde_json::json;

        /// A caller holding an ordinary credential: an agent cert with no
        /// owner SAN, or an `sk-` key. The auth layer sets `agent_id` to the
        /// same subject as `user_id` for an agent acting for itself (and
        /// `None` for a person), so this is what every caller that predates
        /// session certs looks like.
        fn plain_caller() -> contracts::OperationContext {
            contracts::OperationContext::new("moss", "root", false, Some("moss"), false)
        }

        /// A caller holding a session cert: the actor is the session identity,
        /// the principal is the owner its `nexus://owner/` SAN names. This is
        /// the shape `ApiKeyAuthProvider::agent_context` produces when a cert
        /// carries an owner, and the only shape that reads as delegated.
        fn session_caller(owner: &str) -> contracts::OperationContext {
            contracts::OperationContext::new(owner, "root", false, Some("session-7f3a1c20"), false)
        }

        /// Decision 2 for the requester: a caller with no delegated credential
        /// is unaffected. The body's `owner_id` stands, so every caller that
        /// exists today keeps working and the enforcement arrives *with* the
        /// credential rather than on a flag day.
        #[test]
        fn an_ordinary_caller_still_names_its_own_owner() {
            let ctx = plain_caller();
            assert_eq!(authenticated_owner("ethan", &ctx).unwrap(), "ethan");
            assert_eq!(authenticated_owner("", &ctx).unwrap(), "");
        }

        /// The point of the whole change: a session cert's owner is used, and
        /// the caller need not repeat it.
        #[test]
        fn a_session_cert_supplies_the_owner() {
            let ctx = session_caller("alice");
            assert_eq!(authenticated_owner("", &ctx).unwrap(), "alice");
            assert_eq!(authenticated_owner("alice", &ctx).unwrap(), "alice");
        }

        /// Decision 1: a body that disagrees with the credential is refused,
        /// not quietly overwritten. Overwriting would leave the caller
        /// believing it opened a session for one person while the system
        /// recorded another — and a mismatch is either a caller bug or a
        /// credential being used for someone it was not issued for.
        #[test]
        fn a_session_cert_refuses_an_owner_it_does_not_prove() {
            let ctx = session_caller("alice");
            let err = authenticated_owner("bob", &ctx).unwrap_err();
            assert!(err.contains("bob"), "err names what was asked: {err}");
            assert!(err.contains("alice"), "err names what was proven: {err}");
        }

        /// End to end through `dispatch`: the recorded owner comes from the
        /// credential, not the body. Asserted on the session the table holds,
        /// because that — not the response — is what an audit trail reads.
        #[test]
        fn start_session_v1_records_the_credentials_owner() {
            let (_kernel, table, svc) = fresh_service();
            let payload = json!({"agent_id": "scode-standard"}).to_string();
            let bytes = svc
                .dispatch(
                    "start_session_v1",
                    payload.as_bytes(),
                    &session_caller("alice"),
                )
                .unwrap();
            let resp: StartSessionResponse = serde_json::from_slice(&bytes).unwrap();
            let desc = table.get(&resp.session_id).expect("session registered");
            assert_eq!(
                desc.owner_id, "alice",
                "the owner is the credential's, not the body's default"
            );
        }

        /// `get_session_v1` reports the owner, so a caller that sent none can
        /// read back what the daemon attributed the session to. Without this
        /// the attribution exists only on the descriptor, where the caller
        /// cannot see it.
        #[test]
        fn get_session_v1_reports_the_owner_that_was_recorded() {
            let (_kernel, _table, svc) = fresh_service();
            let started = svc
                .dispatch(
                    "start_session_v1",
                    json!({"agent_id": "scode-standard"}).to_string().as_bytes(),
                    &session_caller("alice"),
                )
                .unwrap();
            let started: StartSessionResponse = serde_json::from_slice(&started).unwrap();

            let payload = json!({"session_id": started.session_id}).to_string();
            let bytes = svc
                .dispatch(
                    "get_session_v1",
                    payload.as_bytes(),
                    &session_caller("alice"),
                )
                .unwrap();
            let snap: GetSessionResponse = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                snap.owner_id, "alice",
                "the caller sent no owner_id; the credential's owner is what it reads back"
            );
        }

        /// The refusal reaches the wire as `InvalidArgument`, not a panic and
        /// not a session started under the wrong name.
        #[test]
        fn start_session_v1_rejects_a_body_the_credential_does_not_prove() {
            let (_kernel, table, svc) = fresh_service();
            let payload = json!({"agent_id": "scode-standard", "owner_id": "bob"}).to_string();
            let err = svc
                .dispatch(
                    "start_session_v1",
                    payload.as_bytes(),
                    &session_caller("alice"),
                )
                .unwrap_err();
            assert!(matches!(err, RustCallError::InvalidArgument(_)));
            assert!(
                table.list(None, None, None, None).is_empty(),
                "a refused call must not leave a session behind"
            );
        }

        #[test]
        fn start_session_v1_round_trip() {
            let (_kernel, _table, svc) = fresh_service();
            let payload = json!({
                "agent_id": "scode-standard",
                "model": "claude-sonnet-4-6",
                "owner_id": "ethan",
                "zone_id": "root",
                "repos": [{"host_path": "/x/repo", "alias": "repo"}],
            })
            .to_string();
            let bytes = svc
                .dispatch("start_session_v1", payload.as_bytes(), &plain_caller())
                .unwrap();
            let resp: StartSessionResponse = serde_json::from_slice(&bytes).unwrap();
            assert!(resp.session_id.starts_with("pid-"));
            assert_eq!(
                resp.workspace_path,
                format!("/proc/{}/workspace/", resp.session_id)
            );
        }

        #[test]
        fn start_session_v1_defaults_optional_fields() {
            let (_kernel, _table, svc) = fresh_service();
            let payload = json!({"agent_id": "scode-standard"}).to_string();
            let bytes = svc
                .dispatch("start_session_v1", payload.as_bytes(), &plain_caller())
                .unwrap();
            let resp: StartSessionResponse = serde_json::from_slice(&bytes).unwrap();
            assert!(resp.session_id.starts_with("pid-"));
        }

        #[test]
        fn cancel_v1_session_round_trip() {
            let (_kernel, _table, svc) = fresh_service();
            let resp = svc.start_session(req("scode-standard")).unwrap();
            let payload = json!({"session_id": resp.session_id, "mode": "session"}).to_string();
            let bytes = svc
                .dispatch("cancel_v1", payload.as_bytes(), &plain_caller())
                .unwrap();
            let cancel: CancelResponse = serde_json::from_slice(&bytes).unwrap();
            assert!(cancel.cancelled);
        }

        #[test]
        fn cancel_v1_turn_requires_the_session_mailbox() {
            let (_kernel, _table, svc) = fresh_service();
            let resp = svc.start_session(req("scode-standard")).unwrap();
            let payload = json!({"session_id": resp.session_id, "mode": "turn"}).to_string();
            let error = svc
                .dispatch("cancel_v1", payload.as_bytes(), &plain_caller())
                .unwrap_err();
            assert!(
                matches!(error, RustCallError::InvalidArgument(message) if message.contains("session/cancel"))
            );
        }

        #[test]
        fn cancel_v1_unknown_session_surfaces_invalid_argument() {
            let (_kernel, _table, svc) = fresh_service();
            let payload = json!({"session_id": "pid-bogus", "mode": "session"}).to_string();
            let err = svc
                .dispatch("cancel_v1", payload.as_bytes(), &plain_caller())
                .unwrap_err();
            assert!(matches!(err, RustCallError::InvalidArgument(_)));
        }

        #[test]
        fn get_session_v1_round_trip() {
            let (_kernel, _table, svc) = fresh_service();
            let resp = svc.start_session(req("scode-standard")).unwrap();
            let payload = json!({"session_id": resp.session_id}).to_string();
            let bytes = svc
                .dispatch("get_session_v1", payload.as_bytes(), &plain_caller())
                .unwrap();
            let snap: GetSessionResponse = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(snap.session_id, resp.session_id);
            assert_eq!(snap.state, "warming_up");
        }

        #[test]
        fn unknown_method_returns_not_found() {
            let (_kernel, _table, svc) = fresh_service();
            let err = svc
                .dispatch("does_not_exist", b"{}", &plain_caller())
                .unwrap_err();
            assert!(matches!(err, RustCallError::NotFound));
        }

        #[test]
        fn malformed_payload_surfaces_invalid_argument() {
            let (_kernel, _table, svc) = fresh_service();
            let err = svc
                .dispatch("start_session_v1", b"this is not json", &plain_caller())
                .unwrap_err();
            assert!(matches!(err, RustCallError::InvalidArgument(_)));
        }
    }

    /// Procfs lifecycle tests — exercise start_session through a real
    /// `Kernel` and assert the metastore carries the dirents + DT_LINK
    /// rows the integration doc §2.2 promises.
    mod procfs {
        use super::*;
        use kernel::core::agents::registry::AgentSignal;
        use kernel::kernel::Kernel;
        use kernel::ROOT_ZONE_ID;

        const DT_DIR: u8 = 1;
        const DT_STREAM: u8 = 4;
        const DT_LINK: u8 = 6;

        /// True when `path` is present in the metastore as DT_DIR.
        fn dir_exists(kernel: &Kernel, path: &str) -> bool {
            let path = path.trim_end_matches('/');
            kernel
                .sys_stat(path, ROOT_ZONE_ID)
                .is_some_and(|e| e.entry_type == DT_DIR)
        }

        /// True when `path` has any metastore entry.
        fn entry_exists(kernel: &Kernel, path: &str) -> bool {
            let path = path.trim_end_matches('/');
            kernel.access(path, ROOT_ZONE_ID)
        }

        /// DT_LINK target string at `path` — None if the entry is
        /// missing or not a DT_LINK.
        fn link_target_at(kernel: &Kernel, path: &str) -> Option<String> {
            kernel
                .sys_stat(path, ROOT_ZONE_ID)
                .filter(|e| e.entry_type == DT_LINK)
                .and_then(|e| e.link_target)
        }

        /// Build a `ManagedAgentService` with a real Kernel inside —
        /// the only setup needed is `Kernel::new`.
        fn svc_with_kernel() -> (Arc<Kernel>, ManagedAgentService<Kernel>) {
            let k = Arc::new(Kernel::new());
            let svc = ManagedAgentService::new(Arc::clone(&k), Arc::clone(k.agent_registry()));
            (k, svc)
        }

        fn install_managed_agent(kernel: &Arc<Kernel>) -> Arc<ManagedAgentService<Kernel>> {
            ManagedAgentService::install_returning(kernel, None)
                .expect("install ManagedAgentService")
        }

        #[test]
        fn start_session_stamps_the_workspace_dirent() {
            let (kernel, svc) = svc_with_kernel();
            let resp = svc.start_session(req("scode-standard")).unwrap();

            assert!(dir_exists(&kernel, &resp.workspace_path));
        }

        #[test]
        fn start_session_stamps_one_dt_link_per_repo() {
            let (kernel, svc) = svc_with_kernel();
            let mut r = req("scode-standard");
            r.repos = vec![
                WorkspaceRepo {
                    host_path: "/host/repos/myrepo".into(),
                    alias: "myrepo".into(),
                },
                WorkspaceRepo {
                    host_path: "/host/repos/another".into(),
                    alias: "another".into(),
                },
            ];
            let resp = svc.start_session(r).unwrap();
            let desc = kernel
                .agent_registry()
                .get(&resp.session_id)
                .expect("descriptor must carry repos");
            assert_eq!(desc.repos.len(), 2);

            for (alias, expected) in [
                ("myrepo", "/host/repos/myrepo"),
                ("another", "/host/repos/another"),
            ] {
                let alias_path = format!("{}{alias}", resp.workspace_path);
                assert_eq!(
                    link_target_at(&kernel, &alias_path).as_deref(),
                    Some(expected),
                    "alias {alias} DT_LINK target",
                );
            }
        }

        #[test]
        fn cancel_session_reaps_descriptor_on_kernelless_path() {
            // svc_with_kernel() does NOT call install_returning, so the
            // on_terminate observer is not registered.  cancel(Session)
            // still runs `kill` which auto-reaps the orphan descriptor;
            // the procfs subtree however stays put because no observer
            // fires to remove it.  The companion test
            // `cancel_session_with_observer_reaps_descriptor_and_subtree`
            // covers the install-path semantics.
            let (kernel, svc) = svc_with_kernel();
            let mut r = req("scode-standard");
            r.repos = vec![WorkspaceRepo {
                host_path: "/host/repos/myrepo".into(),
                alias: "myrepo".into(),
            }];
            let resp = svc.start_session(r).unwrap();
            assert!(dir_exists(&kernel, &resp.workspace_path));
            svc.cancel(&resp.session_id, CancelMode::Session).unwrap();
            // Descriptor reaped → both get_session and a follow-up
            // cancel surface UnknownSession.
            let err = svc.get_session(&resp.session_id).unwrap_err();
            assert!(matches!(err, ManagedAgentError::UnknownSession(_)));
            assert!(kernel.agent_registry().get(&resp.session_id).is_none());
            // Dirent still in metastore — no observer ran.
            assert!(dir_exists(&kernel, &resp.workspace_path));
        }

        #[test]
        fn cancel_turn_keeps_subtree_and_descriptor_alive() {
            let (kernel, svc) = svc_with_kernel();
            let resp = svc.start_session(req("scode-standard")).unwrap();
            assert!(svc.cancel(&resp.session_id, CancelMode::Turn).is_err());
            assert!(
                dir_exists(&kernel, &resp.workspace_path),
                "the workspace subtree should survive turn cancel",
            );
        }

        #[test]
        fn sigkill_drops_subtree_through_on_terminate_observer() {
            let kernel = Arc::new(Kernel::new());
            let svc = install_managed_agent(&kernel);
            let mut r = req("scode-standard");
            r.repos = vec![WorkspaceRepo {
                host_path: "/host/core".into(),
                alias: "core".into(),
            }];
            let resp = svc.start_session(r).unwrap();
            assert!(dir_exists(&kernel, &resp.workspace_path));
            let alias_path = format!("{}core", resp.workspace_path);
            assert!(entry_exists(&kernel, &alias_path));

            kernel
                .agent_registry()
                .signal(&resp.session_id, AgentSignal::Sigkill, None)
                .expect("SIGKILL");

            assert!(
                !dir_exists(&kernel, &resp.workspace_path),
                "workspace dirent should be dropped after SIGKILL",
            );
            assert!(
                !entry_exists(&kernel, &alias_path),
                "per-repo DT_LINK should be dropped after SIGKILL",
            );
            let err = svc.get_session(&resp.session_id).unwrap_err();
            assert!(matches!(err, ManagedAgentError::UnknownSession(_)));
        }

        #[test]
        fn orphan_sigterm_drops_subtree_through_on_terminate_observer() {
            let kernel = Arc::new(Kernel::new());
            let svc = install_managed_agent(&kernel);
            let resp = svc.start_session(req("scode-standard")).unwrap();
            kernel
                .agent_registry()
                .signal(&resp.session_id, AgentSignal::Sigterm, None)
                .expect("SIGTERM");
            assert!(!dir_exists(&kernel, &resp.workspace_path));
        }

        #[test]
        fn cancel_session_with_observer_reaps_descriptor_and_subtree() {
            // With an installed observer, cancel(Session) ends with
            // both the descriptor reaped (orphan auto-reap inside
            // AgentRegistry::kill) and the procfs subtree dropped
            // (on_terminate observer).
            let kernel = Arc::new(Kernel::new());
            let svc = install_managed_agent(&kernel);
            let mut r = req("scode-standard");
            r.repos = vec![WorkspaceRepo {
                host_path: "/host/core".into(),
                alias: "core".into(),
            }];
            let resp = svc.start_session(r).unwrap();
            svc.cancel(&resp.session_id, CancelMode::Session).unwrap();
            assert!(!dir_exists(&kernel, &resp.workspace_path));
            let alias_path = format!("{}core", resp.workspace_path);
            assert!(!entry_exists(&kernel, &alias_path));
            assert!(kernel.agent_registry().get(&resp.session_id).is_none());
            let err = svc.get_session(&resp.session_id).unwrap_err();
            assert!(matches!(err, ManagedAgentError::UnknownSession(_)));
        }
    }
}
