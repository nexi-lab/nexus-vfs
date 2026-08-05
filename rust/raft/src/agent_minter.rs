//! AgentMinter — trait abstracting agent identity-cert signing so the Raft
//! gRPC server can serve `MintAgent` without depending on the `auth` crate,
//! the kernel, or `transport::peer_identity`.
//!
//! `MintAgent` lets an agent on ANY cluster node obtain a CA-signed identity
//! cert from the CA holder (founder), so a joiner's `auth mint --subject-type
//! agent` just-works without hand-carrying a private key. The raft crate only
//! sees this trait; the cluster profile provides the impl — it holds the CA key
//! and the auth store, and gates the caller to a trusted NODE peer. Mirrors
//! [`crate::blob_fetcher`]: a late-bound slot the founder installs at boot.

#![cfg(all(feature = "grpc", has_protos))]

use std::sync::Arc;

/// A signed agent identity bundle — the same three artifacts the local
/// `auth mint --subject-type agent` writes.
pub struct AgentBundle {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}

/// Signs an agent identity cert on the CA holder for a remote caller.
///
/// `caller_cert_der` is the requester's verified mTLS client leaf cert (DER),
/// forwarded opaquely so the impl can gate to a trusted NODE peer (an agent
/// must not mint agents). The raft transport applies no auth logic itself —
/// the gate + the CA + the store all live in the impl (cluster profile).
#[tonic::async_trait]
pub trait AgentMinter: Send + Sync {
    async fn mint(
        &self,
        caller_cert_der: Option<Vec<u8>>,
        subject_id: &str,
        display_name: &str,
        allow_existing: bool,
    ) -> Result<AgentBundle, String>;
}

/// Late-bindable slot. Installed ONLY on the CA holder (founder); left empty on
/// a joiner, so `MintAgent` there returns success=false ("not the CA holder").
pub type AgentMinterSlot = Arc<parking_lot::RwLock<Option<Arc<dyn AgentMinter>>>>;

/// Construct an unbound slot — spelt once here so callers don't import
/// parking_lot (mirrors [`crate::blob_fetcher::new_blob_fetcher_slot`]).
pub fn new_agent_minter_slot() -> AgentMinterSlot {
    Arc::new(parking_lot::RwLock::new(None))
}
