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
    /// The identity this bundle carries. Stated rather than left to be
    /// re-parsed out of `cert_pem`: for a session credential the minter CHOOSES
    /// the subject, so the signer is the one party that knows it without
    /// inspecting its own output.
    pub subject_id: String,
}

/// The CA holder's credential operations for remote callers: issue, and
/// withdraw.
///
/// Revocation lives here rather than in a second trait behind a second slot
/// because it needs exactly what minting needs — the CA, the data dir, and the
/// same "only the CA holder is armed" install gate. A parallel slot would
/// duplicate that whole install path to express the same precondition.
///
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

    /// Sign a SESSION credential: an agent identity bound to `owner_id`, valid
    /// for `validity_secs`, with a subject minted fresh per call and never
    /// reused.
    ///
    /// Gated differently from [`Self::mint`], and that difference is the point.
    /// `mint` is node-only — an agent may not mint agents. This one is reachable
    /// by an AGENT, so that a front door holding only an agent cert can obtain a
    /// per-session identity for a person without ever holding a node cert.
    /// What keeps that from being "any agent may forge any identity" is that the
    /// caller must be on the replicated allow-list, matched on its resolved
    /// display id; the impl fails closed when that list cannot be read.
    ///
    /// The owner's truthfulness is the caller's responsibility: it is the
    /// authenticated front door for people, and this seam exists so an agent
    /// cannot forge its OWN identity and so its actions can be attributed —
    /// not so the cluster can independently verify who a person is.
    async fn mint_session(
        &self,
        caller_cert_der: Option<Vec<u8>>,
        owner_id: &str,
        validity_secs: u64,
    ) -> Result<AgentBundle, String>;

    /// Record `agent_cert_pem`'s serial in the CA-plane CRL, with its expiry.
    ///
    /// Takes the certificate, not a name: a session credential is never written
    /// to disk, so there is no bundle to read a serial from, and its holder is
    /// the one party that has it.
    ///
    /// The impl MUST verify the certificate chains to this cluster's CA before
    /// recording anything. Without that this is an unauthenticated way to fill
    /// the CRL with arbitrary serials — and a CRL that can be flooded is a
    /// denial-of-service against every legitimate credential that has to be
    /// checked against it.
    async fn revoke_cert(
        &self,
        caller_cert_der: Option<Vec<u8>>,
        agent_cert_pem: &[u8],
    ) -> Result<(), String>;
}

/// Late-bindable slot. Installed ONLY on the CA holder (founder); left empty on
/// a joiner, so `MintAgent` there returns success=false ("not the CA holder").
pub type AgentMinterSlot = Arc<parking_lot::RwLock<Option<Arc<dyn AgentMinter>>>>;

/// Construct an unbound slot — spelt once here so callers don't import
/// parking_lot (mirrors [`crate::blob_fetcher::new_blob_fetcher_slot`]).
pub fn new_agent_minter_slot() -> AgentMinterSlot {
    Arc::new(parking_lot::RwLock::new(None))
}
