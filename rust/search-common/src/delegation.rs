//! [`SearchDelegation`] — read-only, short-lived, search-scoped
//! credential a source zone hands to a remote zone so the remote can
//! run a search on behalf of the original caller without full VFS
//! access.
//!
//! # Security model
//!
//! * **Method allowlist** — only the two dispatch methods in
//!   [`SEARCH_DELEGATION_METHODS`] are permitted.  Enforced in the
//!   servicer BEFORE dispatch, so a leaked delegation cannot be used
//!   to read files, mint keys, or invoke any non-search RPC.
//! * **Zone allowlist** — the delegation names the target zones
//!   explicitly; the servicer refuses any zone not in the set.
//! * **Short TTL** — [`DEFAULT_TTL_SECONDS`] (30 s), matching the
//!   Python contract.  Long enough for a wide-fanout dispatcher
//!   round-trip; short enough that a leaked credential is unusable
//!   in a follow-up attack.
//! * **No signature** — the peer identity is proven at the transport
//!   layer (mTLS peer certificate).  The delegation is a trust-
//!   carrier the RPC servicer inspects only after transport auth has
//!   passed.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Dispatch methods a caller holding a [`SearchDelegation`] may
/// invoke.  Every other method is refused BEFORE it reaches the
/// dispatch table — a leaked delegation cannot be widened.
pub const SEARCH_DELEGATION_METHODS: &[&str] = &["search", "semantic_search"];

/// gRPC metadata key both the source-side stamper
/// (`nexus-http-api::backends::tonic_remote`) and the destination-
/// side extractor (`nexus-search-plugin::delegation_gate`) key on.
/// `-bin` suffix per the gRPC metadata spec — tonic transparently
/// base64-encodes / decodes so both sides see raw JSON bytes.
///
/// Kept next to [`SearchDelegation`] itself so a rename lands in
/// ONE place; a caller reading the wire needs both symbols and
/// pairing them here removes the "which crate holds the key
/// string" question.
pub const DELEGATION_METADATA_KEY: &str = "x-nexus-search-delegation-bin";

/// TTL a delegation carries when the caller does not override it.
/// Matches the Python contract so a Python-to-Rust cluster does not
/// see a policy skew mid-migration.
pub const DEFAULT_TTL_SECONDS: u64 = 30;

/// A delegation issued by a trusted cluster node. Its timestamp is Unix
/// milliseconds, comparable across processes. Receivers validate the original
/// timestamp; receipt or replay never renews the credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchDelegation {
    pub delegation_id: String,
    pub source_zone_id: String,
    pub target_zones: Vec<String>,
    pub subject: (String, String),
    pub created_at_unix_ms: u64,
    /// Time-to-live in seconds.
    pub ttl_seconds: u64,
}

impl SearchDelegation {
    /// Mint a fresh delegation with the current Unix clock and
    /// the default TTL.  This is the constructor the dispatcher
    /// uses on the source-zone side.
    pub fn new_from_now(
        delegation_id: impl Into<String>,
        source_zone_id: impl Into<String>,
        target_zones: impl IntoIterator<Item = String>,
        subject: (String, String),
    ) -> Self {
        Self::new_with_ttl(
            delegation_id,
            source_zone_id,
            target_zones,
            subject,
            DEFAULT_TTL_SECONDS,
        )
    }

    /// Mint a fresh delegation with an explicit TTL. Validation permits
    /// at most [`DEFAULT_TTL_SECONDS`].
    pub fn new_with_ttl(
        delegation_id: impl Into<String>,
        source_zone_id: impl Into<String>,
        target_zones: impl IntoIterator<Item = String>,
        subject: (String, String),
        ttl_seconds: u64,
    ) -> Self {
        let created_at_unix_ms = unix_time_ms();
        Self {
            delegation_id: delegation_id.into(),
            source_zone_id: source_zone_id.into(),
            target_zones: target_zones.into_iter().collect(),
            subject,
            created_at_unix_ms,
            ttl_seconds,
        }
    }

    /// Expiry is derived from the issuer timestamp. Overflow fails closed.
    pub fn expires_at_unix_ms(&self) -> Option<u64> {
        self.created_at_unix_ms
            .checked_add(self.ttl_seconds.checked_mul(1_000)?)
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at_unix_ms()
            .is_none_or(|expiry| unix_time_ms() >= expiry)
    }

    /// True when `zone_id` is in the delegation's target set.
    pub fn is_zone_permitted(&self, zone_id: &str) -> bool {
        self.target_zones.iter().any(|z| z == zone_id)
    }

    /// True when `method` is a search dispatch the delegation
    /// authorises.  See [`SEARCH_DELEGATION_METHODS`].
    pub fn is_method_permitted(method: &str) -> bool {
        SEARCH_DELEGATION_METHODS.contains(&method)
    }

    /// Validate the delegation against a specific `(method,
    /// target_zone)` pair.  Returns [`DelegationError`] on any
    /// refusal so the servicer maps it 1:1 to a gRPC status.
    pub fn validate(&self, method: &str, target_zone: &str) -> Result<(), DelegationError> {
        self.validate_at(method, target_zone, unix_time_ms())
    }

    /// Validate against the receiver's Unix clock. A small future skew is
    /// tolerated, but expiration is never extended. Both nodes need synced clocks.
    pub fn validate_at(
        &self,
        method: &str,
        target_zone: &str,
        now_ms: u64,
    ) -> Result<(), DelegationError> {
        if !Self::is_method_permitted(method) {
            return Err(DelegationError::MethodNotPermitted {
                method: method.to_string(),
            });
        }
        if !self.is_zone_permitted(target_zone) {
            return Err(DelegationError::ZoneNotPermitted {
                zone_id: target_zone.to_string(),
                permitted: self.target_zones.clone(),
            });
        }
        if self.ttl_seconds > DEFAULT_TTL_SECONDS {
            return Err(DelegationError::InvalidLifetime);
        }
        if self.created_at_unix_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
            return Err(DelegationError::IssuedInFuture);
        }
        if self
            .expires_at_unix_ms()
            .is_none_or(|expiry| now_ms >= expiry)
        {
            return Err(DelegationError::Expired {
                delegation_id: self.delegation_id.clone(),
                ttl_seconds: self.ttl_seconds,
            });
        }
        Ok(())
    }
}

/// Errors a delegation validation may surface.  Kept small so a
/// servicer's status mapper is a one-arm-per-variant match.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum DelegationError {
    #[error("SearchDelegation lifetime exceeds the {DEFAULT_TTL_SECONDS}s maximum")]
    InvalidLifetime,
    #[error("SearchDelegation issue time is ahead of the receiver clock")]
    IssuedInFuture,

    #[error("SearchDelegation permits only {SEARCH_DELEGATION_METHODS:?}, got '{method}'")]
    MethodNotPermitted { method: String },
    #[error("Zone '{zone_id}' not in delegation scope {permitted:?}")]
    ZoneNotPermitted {
        zone_id: String,
        permitted: Vec<String>,
    },
    #[error("SearchDelegation '{delegation_id}' expired (TTL={ttl_seconds}s)")]
    Expired {
        delegation_id: String,
        ttl_seconds: u64,
    },
}

/// Tolerate five seconds of clock skew when validating the issue time.
/// The absolute expiration check still uses the unmodified issuer timestamp.
pub const MAX_CLOCK_SKEW_MS: u64 = 5_000;

fn unix_time_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(id: &str) -> (String, String) {
        ("user".into(), id.into())
    }

    #[test]
    fn is_method_permitted_only_allowlists_search_and_semantic_search() {
        assert!(SearchDelegation::is_method_permitted("search"));
        assert!(SearchDelegation::is_method_permitted("semantic_search"));
        for bad in ["read", "write", "list", "mint_key", "grant"] {
            assert!(!SearchDelegation::is_method_permitted(bad));
        }
    }

    #[test]
    fn is_zone_permitted_checks_target_zones_membership() {
        let d = SearchDelegation::new_from_now(
            "sd_x",
            "eng",
            ["eng".to_string(), "legal".to_string()],
            subject("alice"),
        );
        assert!(d.is_zone_permitted("eng"));
        assert!(d.is_zone_permitted("legal"));
        assert!(!d.is_zone_permitted("finance"));
    }

    #[test]
    fn is_expired_is_false_immediately_after_mint() {
        let d =
            SearchDelegation::new_from_now("sd_x", "eng", ["eng".to_string()], subject("alice"));
        assert!(!d.is_expired());
    }

    #[test]
    fn is_expired_becomes_true_after_ttl() {
        let d = SearchDelegation::new_with_ttl(
            "sd_x",
            "eng",
            ["eng".to_string()],
            subject("alice"),
            0, // 0 s TTL: expires immediately
        );
        assert!(d.is_expired());
    }

    #[test]
    fn validate_ok_on_method_zone_and_ttl() {
        let d = SearchDelegation::new_from_now(
            "sd_x",
            "eng",
            ["eng".to_string(), "legal".to_string()],
            subject("alice"),
        );
        d.validate("search", "eng").unwrap();
        d.validate("semantic_search", "legal").unwrap();
    }

    #[test]
    fn validate_refuses_disallowed_method() {
        let d =
            SearchDelegation::new_from_now("sd_x", "eng", ["eng".to_string()], subject("alice"));
        let err = d.validate("write", "eng").unwrap_err();
        assert!(matches!(err, DelegationError::MethodNotPermitted { .. }));
    }

    #[test]
    fn validate_refuses_zone_not_in_scope() {
        let d =
            SearchDelegation::new_from_now("sd_x", "eng", ["eng".to_string()], subject("alice"));
        let err = d.validate("search", "finance").unwrap_err();
        match err {
            DelegationError::ZoneNotPermitted { zone_id, permitted } => {
                assert_eq!(zone_id, "finance");
                assert_eq!(permitted, vec!["eng".to_string()]);
            }
            other => panic!("expected ZoneNotPermitted, got {other:?}"),
        }
    }

    #[test]
    fn validate_refuses_expired_delegation() {
        let d =
            SearchDelegation::new_with_ttl("sd_x", "eng", ["eng".to_string()], subject("alice"), 0);
        let err = d.validate("search", "eng").unwrap_err();
        assert!(matches!(err, DelegationError::Expired { .. }));
    }

    #[test]
    fn expires_at_is_created_plus_ttl_derived_never_stored() {
        // Regression pin: `expires_at_unix_ms` is a method, not a field,
        // so a caller mutating `ttl_seconds` after mint stays
        // consistent (the field can never drift out of sync with the
        // derived value).
        let mut d = SearchDelegation::new_with_ttl(
            "sd_x",
            "eng",
            ["eng".to_string()],
            subject("alice"),
            10,
        );
        let base = d.created_at_unix_ms;
        assert_eq!(d.expires_at_unix_ms(), Some(base + 10 * 1_000));
        d.ttl_seconds = 60;
        assert_eq!(d.expires_at_unix_ms(), Some(base + 60 * 1_000));
    }

    #[test]
    fn receiver_enforces_original_expiry_and_clock_skew_boundaries() {
        let mut d = SearchDelegation::new_from_now("sd_x", "eng", ["eng".into()], subject("alice"));
        d.created_at_unix_ms = 100_000;
        assert!(d.validate_at("search", "eng", 129_999).is_ok());
        for now in [130_000, 140_000] {
            assert!(matches!(
                d.validate_at("search", "eng", now),
                Err(DelegationError::Expired { .. })
            ));
        }
        assert!(d.validate_at("search", "eng", 95_000).is_ok());
        assert_eq!(
            d.validate_at("search", "eng", 94_999),
            Err(DelegationError::IssuedInFuture)
        );
        d.ttl_seconds = DEFAULT_TTL_SECONDS + 1;
        assert_eq!(
            d.validate_at("search", "eng", 100_000),
            Err(DelegationError::InvalidLifetime)
        );
    }

    #[test]
    fn invalid_wire_lifetimes_fail_closed() {
        let mut d = SearchDelegation::new_from_now("sd_x", "eng", ["eng".into()], subject("alice"));
        d.created_at_unix_ms = u64::MAX;
        assert!(d.expires_at_unix_ms().is_none());
        assert!(d.validate_at("search", "eng", u64::MAX).is_err());
        d.ttl_seconds = u64::MAX;
        assert!(d.expires_at_unix_ms().is_none());
        assert!(d.validate_at("search", "eng", u64::MAX).is_err());
        let mut wire = serde_json::to_value(&d).unwrap();
        wire.as_object_mut().unwrap().remove("created_at_unix_ms");
        wire["created_at_ns"] = serde_json::json!(123);
        assert!(serde_json::from_value::<SearchDelegation>(wire).is_err());
    }
}
