//! KeyMinter — trait abstracting `sk-` credential mint/revoke so the Raft gRPC
//! server can serve `MintKey`/`RevokeKey` without depending on the `auth` crate,
//! the api-key secret, or `transport::peer_identity`.
//!
//! These let `auth mint --subject-type user|service` and `auth revoke` run
//! against a LIVE daemon (which holds the redb store lock), instead of forcing
//! the operator to stop the daemon for an offline store-open. The daemon HMACs
//! the key with its cluster secret and writes through consensus (the write
//! forwards to the control-zone leader), so any node can serve it. Mirrors
//! [`crate::agent_minter`]: a late-bound slot the daemon installs at boot, and
//! the impl (cluster profile) owns the secret + store + the node-only gate.

#![cfg(all(feature = "grpc", has_protos))]

use std::sync::Arc;

/// Parameters for an `sk-` key mint — the `MintKey` request, minus transport.
pub struct MintKeyParams {
    /// `"user"` or `"service"` (agents use [`crate::agent_minter`] instead).
    pub subject_type: String,
    pub subject_id: String,
    /// Zone grants as `zone:perms`; may be empty when `admin`.
    pub zones: Vec<String>,
    pub admin: bool,
    /// Expiry in ms since epoch; `0` = never.
    pub expires_at_ms: u64,
    pub name: String,
    /// Rotation escape: mint even if the subject already holds an active key.
    pub allow_existing: bool,
}

/// Mints / revokes `sk-` credentials on a live daemon for a remote CLI caller.
///
/// `caller_cert_der` is the requester's verified mTLS client leaf cert (DER),
/// forwarded opaquely so the impl can gate to a trusted NODE peer (minting a
/// credential is an admin op, never an agent's to do). The raft transport
/// applies no auth logic itself — the gate + secret + store live in the impl.
#[tonic::async_trait]
pub trait KeyMinter: Send + Sync {
    /// Mint an `sk-` key; returns the one-time plaintext key.
    async fn mint_key(
        &self,
        caller_cert_der: Option<Vec<u8>>,
        params: MintKeyParams,
    ) -> Result<String, String>;

    /// Revoke by key OR key-hash (exactly one `Some`); returns whether a record
    /// was removed.
    async fn revoke_key(
        &self,
        caller_cert_der: Option<Vec<u8>>,
        key: Option<String>,
        key_hash: Option<String>,
    ) -> Result<bool, String>;

    /// Enumerate credential records `(key_hash, opaque_record)` from this
    /// daemon's LOCAL replica — a read, no leader round-trip, so it works on a
    /// learner. Backs `auth list` against a running daemon (offline list is
    /// refused on an enrolled joiner). Hashes are not secrets; the caller
    /// decodes + renders the records.
    async fn list_keys(
        &self,
        caller_cert_der: Option<Vec<u8>>,
    ) -> Result<Vec<(String, Vec<u8>)>, String>;
}

/// Late-bindable slot. Installed on every auth-on node's daemon (any node can
/// serve — the write forwards to the control-zone leader); left empty on an
/// auth-off node, where `MintKey`/`RevokeKey` return success=false.
pub type KeyMinterSlot = Arc<parking_lot::RwLock<Option<Arc<dyn KeyMinter>>>>;

/// Construct an unbound slot (mirrors [`crate::agent_minter::new_agent_minter_slot`]).
pub fn new_key_minter_slot() -> KeyMinterSlot {
    Arc::new(parking_lot::RwLock::new(None))
}
