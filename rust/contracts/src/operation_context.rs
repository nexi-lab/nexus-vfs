//! Syscall credential carried through every kernel operation.
//!
//! Lifted out of `rust/kernel/src/kernel.rs` so out-of-kernel
//! services (`rust/services/src/{acp,managed_agent,…}/`) can build
//! `OperationContext` values for system-tier calls without pulling
//! kernel as a dep just for this struct. Kernel re-exports under
//! the historical `kernel::kernel::OperationContext` path so every
//! existing call site keeps compiling.
//!
//! Analogous to Linux `struct cred` — immutable after construction.
//! Constructed by thin wrappers (Python, gRPC, in-process service
//! calls) with identity fields. The kernel uses `zone_id` for
//! routing; hooks use the full context.

#[derive(Clone, Debug)]
pub struct OperationContext {
    /// Subject identity (human user or service account).
    pub user_id: String,
    /// Routing zone — NexusFS instance zone for mount lookup
    /// (always set).
    pub zone_id: String,
    /// Admin privilege flag.
    pub is_admin: bool,
    /// Agent identity (optional, for agent-initiated operations).
    pub agent_id: Option<String>,
    /// System operation flag (bypasses all checks).
    pub is_system: bool,
    /// Group memberships for ReBAC.
    pub groups: Vec<String>,
    /// Granted admin capabilities (e.g. "MANAGE_ZONES",
    /// "READ_ALL").
    pub admin_capabilities: Vec<String>,
    /// Subject type for ReBAC (default: "user").
    pub subject_type: String,
    /// Subject ID for ReBAC (defaults to user_id).
    pub subject_id: Option<String>,
    /// Audit trail correlation ID.
    pub request_id: String,
    /// Caller's zone_id (None = no zone restriction). Distinct
    /// from routing zone_id.
    pub context_zone_id: Option<String>,
    /// Federation zone permission grants — list of (zone_id,
    /// perm_chars) pairs.  Non-federation tokens carry an empty Vec.
    /// Threaded through the Rust boundary so the permission gate can
    /// enforce zone allow-lists without the Python ContextVar hack
    /// (`request_zone_perms_scope`).
    pub zone_perms: Vec<(String, String)>,
    /// Whether this operation's consumer demands cross-node visibility
    /// of any content observed or produced during the call.
    ///
    /// Two values, two roles:
    ///
    /// * **`true`**: the consumer is **federation-visible** — either a
    ///   `sys_write` caller (explicit Nexus tracking opt-in) or a
    ///   peer-served call (remote node is asking via `ReadBlob` /
    ///   federation transport).  Triggers lazy `observe_backend_content`
    ///   to propose metadata so the path becomes routable across nodes.
    ///   Disables fan-out (we are already serving a peer — fanning out
    ///   again would loop).
    ///
    /// * **`false`**: the consumer is **local-only** — a local user's
    ///   `sys_read` against their own backend.  No metadata propose
    ///   (cheap — zero raft traffic for cold-storage host-fs content).
    ///   Enables fan-out: on local backend miss in a federated zone,
    ///   sys_read may fan out to peers to discover the byte host.
    ///
    /// **Duality contract** (see `propagates_cross_node()` /
    /// `fan_out_allowed()` accessors):
    /// `fan_out_allowed() == !propagates_cross_node()`.
    /// This is intentional — exactly one of "propose metadata" and
    /// "fan out to peers" makes sense per operation, and the two
    /// derived predicates lockstep through this single flag.
    pub propagates_cross_node: bool,
}

impl OperationContext {
    pub fn new(
        user_id: &str,
        zone_id: &str,
        is_admin: bool,
        agent_id: Option<&str>,
        is_system: bool,
    ) -> Self {
        Self {
            user_id: user_id.to_string(),
            zone_id: zone_id.to_string(),
            is_admin,
            agent_id: agent_id.map(|s| s.to_string()),
            is_system,
            groups: Vec::new(),
            admin_capabilities: Vec::new(),
            subject_type: "user".to_string(),
            subject_id: None,
            request_id: String::new(),
            context_zone_id: None,
            zone_perms: Vec::new(),
            // Default: local-only consumer.  sys_write callers and
            // peer-served `BlobFetcher::read` flip this to `true` at
            // their explicit construction sites.
            propagates_cross_node: false,
        }
    }

    /// True when this operation's consumer is federation-visible —
    /// triggers `observe_backend_content` to propose metadata.
    ///
    /// See the field doc on `propagates_cross_node` for the duality
    /// with `fan_out_allowed()`.
    #[inline]
    pub fn propagates_cross_node(&self) -> bool {
        self.propagates_cross_node
    }

    /// True when this operation can fan out to peers on local
    /// backend miss in a federated zone.  Strictly the negation of
    /// `propagates_cross_node()` — already-peer-served calls (which
    /// have `propagates_cross_node = true`) MUST NOT fan out again,
    /// or a misrouted read loops forever.
    #[inline]
    pub fn fan_out_allowed(&self) -> bool {
        !self.propagates_cross_node
    }
}
