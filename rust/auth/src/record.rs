//! The API-key record — what a `key_hash` resolves to.
//!
//! This crate owns the schema. The store ([`kernel::hal::auth_key_store`])
//! treats a record as opaque bytes and never parses one, which is what
//! keeps the store a generic kernel primitive rather than this policy's
//! private table: a second credential policy (JWT, OIDC) would put its own
//! record shape in the same tree.
//!
//! A record is **not a secret**. It holds the HMAC of a key plus that
//! key's grants, so possessing every record does not let you mint one —
//! minting needs the HMAC signing key, which never leaves the composition
//! root. That is what makes it safe to replicate a record through the raft
//! log and to list its hash in `/__sys__/auth/keys/`.
//!
//! Encoded as JSON. The record is read on a cache miss, not per syscall, so
//! the encoding is chosen for being self-describing across versions rather
//! than for bytes on the wire: an operator dumping a record should be able
//! to read it, and an older node should be able to decode a record written
//! by a newer one (unknown fields are ignored, missing ones default).

use serde::{Deserialize, Serialize};

/// What kind of principal the key authenticates.
///
/// The distinction is load-bearing for A2A: **an `Agent` key's
/// `subject_id` becomes the context's `agent_id`**, which is the identity
/// the mailbox hook stamps into an envelope's `from`. A `User` key carries
/// no `agent_id` and therefore cannot author agent mail at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    User,
    Agent,
    Service,
}

impl SubjectType {
    /// The ReBAC subject-type string. The engine keys on
    /// `(subject_type, subject_id)`, and these are the values the Python
    /// tier already writes, so a record minted by either side resolves the
    /// same relations.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Agent => "agent",
            Self::Service => "service",
        }
    }
}

/// One credential's grants, keyed in the store by the HMAC of the key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthKeyRecord {
    /// Stable id for logs and revocation tooling. Never derived from the
    /// key material — logging a `key_id` is safe, logging a hash prefix is
    /// merely unhelpful.
    pub key_id: String,
    /// Human label ("mac-ai laptop", "ci runner").
    #[serde(default)]
    pub name: String,
    pub subject_type: SubjectType,
    /// The principal. For an `Agent` key this is the agent name that ends
    /// up in `OperationContext::agent_id`.
    pub subject_id: String,
    /// Global admin. The only kind of principal allowed to hold a key with
    /// no zone grants at all — see the zoneless gate in the provider.
    #[serde(default)]
    pub is_admin: bool,
    /// Tombstone. A revoked record is normally deleted outright
    /// (`DeleteAuthKey`), but the flag lets a revocation be recorded
    /// without losing the audit row.
    #[serde(default)]
    pub revoked: bool,
    /// Expiry, epoch milliseconds. `None` = never expires.
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    /// Per-zone grants as `(zone_id, permission_chars)` — the same shape
    /// `OperationContext::zone_perms` carries into the permission gate.
    /// Empty means "no zone access", which only a global admin may hold.
    #[serde(default)]
    pub zone_perms: Vec<(String, String)>,
}

impl AuthKeyRecord {
    /// Encode for the store. Infallible in practice — the struct is plain
    /// data — but surfaced as a `Result` rather than an `unwrap` so a
    /// future non-serialisable field cannot panic a minting call.
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Has this key passed its expiry as of `now_ms`?
    pub fn is_expired(&self, now_ms: u64) -> bool {
        matches!(self.expires_at_ms, Some(exp) if now_ms > exp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> AuthKeyRecord {
        AuthKeyRecord {
            key_id: "key-1".into(),
            name: "mac-ai".into(),
            subject_type: SubjectType::Agent,
            subject_id: "mac-ai".into(),
            is_admin: false,
            revoked: false,
            expires_at_ms: Some(2_000),
            zone_perms: vec![("sharedzone".into(), "rw".into())],
        }
    }

    #[test]
    fn roundtrips_through_the_store_encoding() {
        let restored = AuthKeyRecord::decode(&record().encode().unwrap()).unwrap();
        assert_eq!(restored, record());
    }

    #[test]
    fn expiry_is_exclusive_of_the_expiry_instant() {
        let r = record();
        assert!(!r.is_expired(1_999), "not yet expired");
        assert!(
            !r.is_expired(2_000),
            "the expiry instant itself still resolves"
        );
        assert!(r.is_expired(2_001), "past expiry");
    }

    #[test]
    fn a_key_without_an_expiry_never_expires() {
        let mut r = record();
        r.expires_at_ms = None;
        assert!(!r.is_expired(u64::MAX));
    }

    /// A node running an older build must not choke on a record a newer
    /// node minted — the store replicates records verbatim, so a decode
    /// failure would take the whole credential offline cluster-wide.
    #[test]
    fn unknown_fields_are_ignored_and_missing_ones_default() {
        let json = br#"{
            "key_id": "key-2",
            "subject_type": "user",
            "subject_id": "alice",
            "future_field": {"nested": true}
        }"#;
        let r = AuthKeyRecord::decode(json).expect("forward-compatible decode");
        assert_eq!(r.subject_id, "alice");
        assert_eq!(r.subject_type, SubjectType::User);
        // Defaults are the safe ones: no admin, not revoked, no zones.
        assert!(!r.is_admin);
        assert!(!r.revoked);
        assert!(r.zone_perms.is_empty());
        assert_eq!(r.expires_at_ms, None);
    }
}
