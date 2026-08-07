//! ForeignCaRegistrar — trait abstracting cross-org CA-anchor register / unregister
//! / list so the Raft gRPC server can serve `RegisterForeignCa` (and siblings)
//! without depending on the `transport` crate (for the node-cert gate) or naming
//! the anchor schema.
//!
//! These let an operator register a foreign org's CA against the live daemon, so
//! that org's agents are trusted at the mTLS handshake (the apply observer
//! hot-swaps the client-cert verifier) — WITHOUT a restart, and without hand-
//! carrying the anchor into every node (the write forwards to the control-zone
//! leader and replicates). Mirrors [`crate::key_minter`]: a late-bound slot the
//! daemon installs at boot, and the impl (cluster profile) owns the node-only
//! gate + the [`crate::foreign_ca_store::RaftForeignCaStore`] + the out-of-band
//! fingerprint check.

#![cfg(all(feature = "grpc", has_protos))]

use std::sync::Arc;

/// Registers / unregisters / lists cross-org CA anchors on a live daemon for a
/// remote CLI caller.
///
/// `caller_cert_der` is the requester's verified mTLS client leaf cert (DER),
/// forwarded opaquely so the impl can gate to a trusted NODE peer (a cross-org
/// trust decision is an admin op, never an agent's). The raft transport applies
/// no auth logic itself — gate + store + fingerprint-verify live in the impl.
#[tonic::async_trait]
pub trait ForeignCaRegistrar: Send + Sync {
    /// Register `ca_cert_pem` (PEM) under `trust_domain_id`, verifying its
    /// computed fingerprint equals `expected_fingerprint` (out-of-band anti-swap)
    /// before trusting it. Returns the computed `sha256:<hex>` fingerprint.
    async fn register(
        &self,
        caller_cert_der: Option<Vec<u8>>,
        trust_domain_id: &str,
        ca_cert_pem: &[u8],
        expected_fingerprint: &str,
    ) -> Result<String, String>;

    /// Drop the anchor with `fingerprint` (coarse per-org revocation). Returns
    /// whether an anchor was present + removed.
    async fn unregister(
        &self,
        caller_cert_der: Option<Vec<u8>>,
        fingerprint: &str,
    ) -> Result<bool, String>;

    /// Enumerate registered anchors as `(trust_domain_id, fingerprint)` from the
    /// local control-zone replica.
    async fn list(&self, caller_cert_der: Option<Vec<u8>>)
        -> Result<Vec<(String, String)>, String>;
}

/// Late-bindable slot. Installed on every auth-on node's daemon (any node serves
/// — the write forwards to the control-zone leader); left empty under `--no-tls`
/// (no cross-org trust plane), where the RPCs return success=false.
pub type ForeignCaRegistrarSlot = Arc<parking_lot::RwLock<Option<Arc<dyn ForeignCaRegistrar>>>>;

/// Construct an unbound slot (mirrors [`crate::key_minter::new_key_minter_slot`]).
pub fn new_foreign_ca_registrar_slot() -> ForeignCaRegistrarSlot {
    Arc::new(parking_lot::RwLock::new(None))
}
