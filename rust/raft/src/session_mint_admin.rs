//! SessionMintAdmin — trait abstracting the session-mint allow-list's
//! administration (allow / deny / list) so the Raft gRPC server can serve those
//! RPCs without depending on the `transport` crate for the node-cert gate.
//!
//! These let an operator change which agents may mint session credentials
//! against a live daemon: the write forwards to the control-zone leader and
//! replicates, so the policy is one value cluster-wide rather than a copy per
//! broker that nothing reconciles. Mirrors
//! [`crate::foreign_ca_registrar::ForeignCaRegistrar`], which administers the
//! other cross-org trust decision the same way and for the same reasons.
//!
//! Separate from [`crate::agent_minter::AgentMinter`] on purpose: issuing a
//! credential and deciding who may issue one are different authorities with
//! different gates. Minting a session is reachable by an allow-listed AGENT;
//! changing the allow-list is node-only, because an agent that could edit it
//! could grant itself anything.

#![cfg(all(feature = "grpc", has_protos))]

use std::sync::Arc;

/// Administers the session-mint allow-list on a live daemon for a remote CLI
/// caller.
///
/// `caller_cert_der` is the requester's verified mTLS client leaf cert (DER),
/// forwarded opaquely so the impl can gate to a trusted NODE peer. The raft
/// transport applies no auth logic itself — gate and store live in the impl.
#[tonic::async_trait]
pub trait SessionMintAdmin: Send + Sync {
    /// Permit `agent_id` to mint session credentials.
    ///
    /// `agent_id` is the id the agent is known by — bare for a local agent,
    /// org-qualified `{trust_domain}/agent/{name}` for a foreign one — which is
    /// what stops allow-listing a local `moss` from admitting another org's.
    async fn allow(&self, caller_cert_der: Option<Vec<u8>>, agent_id: &str) -> Result<(), String>;

    /// Withdraw permission. Returns whether an entry was present.
    async fn deny(&self, caller_cert_der: Option<Vec<u8>>, agent_id: &str) -> Result<bool, String>;

    /// Enumerate permitted ids from the local control-zone replica.
    async fn list(&self, caller_cert_der: Option<Vec<u8>>) -> Result<Vec<String>, String>;
}

/// Late-bindable slot. Installed on every auth-on node's daemon (any node
/// serves — the write forwards to the control-zone leader); left empty under
/// `--no-tls`, where the RPCs return success=false.
pub type SessionMintAdminSlot = Arc<parking_lot::RwLock<Option<Arc<dyn SessionMintAdmin>>>>;

/// Construct an unbound slot (mirrors
/// [`crate::foreign_ca_registrar::new_foreign_ca_registrar_slot`]).
pub fn new_session_mint_admin_slot() -> SessionMintAdminSlot {
    Arc::new(parking_lot::RwLock::new(None))
}
