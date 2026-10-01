//! [`extract_and_validate`] — servicer-side extract + validation of
//! the [`SearchDelegation`] a peer daemon stamped on tonic metadata
//! (`nexus-http-api::backends::tonic_remote` mints it, the SSOT
//! metadata key lives on [`nexus_search_common::DELEGATION_METADATA_KEY`]).
//!
//! # Contract
//!
//! Callers wrap their gRPC handler entry with this function.  The
//! result tells them what to do:
//!
//! * `Ok(GateOutcome::NoDelegation)` — no delegation on this
//!   request.  Fall through to whatever auth path was in place
//!   before (auth_token, mTLS peer identity, …).  The vast majority
//!   of local queries take this path.
//! * `Ok(GateOutcome::Accepted { subject })` — a valid delegation
//!   is present.  The handler should run the search AS `subject`
//!   (for logging / audit).  Zone + method already validated
//!   here; the handler proceeds unchanged otherwise.
//! * `Err(Status)` — a delegation IS present but INVALID (expired,
//!   wrong method, wrong zone, malformed).  The handler MUST return
//!   this Status verbatim — the source daemon's
//!   `TonicRemoteSearchBackend` maps it back into `BackendError::Backend`
//!   so the leg lands in `zones_failed` with a specific message.
//!
//! # Rejection semantics
//!
//! Every rejection returns [`tonic::Code::Unauthenticated`] with a
//! message that names the specific violation.  Auth-shaped codes
//! are what the client-side error mapper (`tonic_remote.rs`) reads
//! to distinguish "peer refused the credential" from "transport
//! failed".  A malformed delegation (bad JSON) also uses
//! `Unauthenticated` rather than `InvalidArgument` — the caller
//! MINTED the delegation, so a broken shape is functionally an
//! auth failure (their auth material is unusable).
//!
//! Delegations are admitted only with host-verified cluster-node provenance.
//! The original Unix timestamp survives transport unchanged, including on replay.

use nexus_plugin_abi::grpc::GrpcPeer;
use nexus_search_common::{SearchDelegation, DELEGATION_METADATA_KEY};
use tonic::{Request, Status};

/// What the gate found on an incoming request.  See the module
/// docstring for the caller contract.
#[derive(Debug, Clone)]
pub enum GateOutcome {
    /// No delegation metadata on the request — the handler falls
    /// through to its default auth path.  Not an error.
    NoDelegation,
    /// A valid delegation is present.  `subject` is the original
    /// caller the source daemon minted the delegation FOR (a
    /// `(type, id)` pair, e.g. `("user", "alice")`); the handler
    /// runs the search AS this subject for audit purposes.
    Accepted {
        /// The delegation the source stamped — kept whole so a
        /// caller with per-hit ReBAC filtering can pull additional
        /// context off it without re-parsing.
        delegation: SearchDelegation,
    },
}

/// Extract + validate the delegation the source daemon may have
/// stamped on the request.  See the module docstring for the
/// caller contract.
///
/// `method` — the RPC method name to check against
/// [`nexus_search_common::SEARCH_DELEGATION_METHODS`].  For
/// `SearchServiceImpl::query`, pass `"search"`; for a future
/// semantic-search dispatch, `"semantic_search"`.
///
/// `zone_id` — the zone the request is asking about, checked
/// against `delegation.target_zones`.  A delegation scoped to
/// `["eng"]` cannot be replayed against zone `"legal"`.
pub fn extract_and_validate<T>(
    request: &Request<T>,
    method: &str,
    zone_id: &str,
) -> Result<GateOutcome, Status> {
    // 1. Look for the delegation on tonic metadata.  Absent → the
    // caller is not using delegation, fall through to the default
    // auth path.
    let raw = match request.metadata().get_bin(DELEGATION_METADATA_KEY) {
        None => return Ok(GateOutcome::NoDelegation),
        Some(v) => v,
    };
    if !request
        .extensions()
        .get::<GrpcPeer>()
        .is_some_and(|peer| peer.is_cluster_node)
    {
        return Err(Status::unauthenticated(
            "SearchDelegation requires a verified cluster node",
        ));
    }
    let bytes = raw.to_bytes().map_err(|e| {
        Status::unauthenticated(format!(
            "SearchDelegation metadata not valid base64 (per gRPC -bin rule): {e}"
        ))
    })?;

    // 2. Deserialise.  A malformed blob is functionally an auth
    // failure (see module docstring's rationale) — return
    // Unauthenticated so the client-side mapper reads it as
    // "backend refused" rather than "transport bad payload".
    let delegation: SearchDelegation = serde_json::from_slice(&bytes)
        .map_err(|e| Status::unauthenticated(format!("SearchDelegation malformed JSON: {e}")))?;

    delegation
        .validate(method, zone_id)
        .map_err(|error| Status::unauthenticated(error.to_string()))?;

    Ok(GateOutcome::Accepted { delegation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::MetadataValue;

    fn stamp<T>(req: &mut Request<T>, d: &SearchDelegation) {
        req.extensions_mut().insert(GrpcPeer {
            is_cluster_node: true,
        });
        let bytes = serde_json::to_vec(d).unwrap();
        let key: tonic::metadata::MetadataKey<tonic::metadata::Binary> =
            DELEGATION_METADATA_KEY.parse().unwrap();
        req.metadata_mut()
            .insert_bin(key, MetadataValue::from_bytes(&bytes));
    }

    fn delegation(zone: &str) -> SearchDelegation {
        SearchDelegation::new_from_now(
            "sd_abc123",
            "peer",
            [zone.to_string()],
            ("user".into(), "alice".into()),
        )
    }

    #[test]
    fn no_delegation_metadata_returns_no_delegation() {
        // Regression pin: absent metadata → local auth path
        // engages, NOT a spurious refusal.  Every non-federated
        // query relies on this behaviour.
        let req = Request::new(());
        match extract_and_validate(&req, "search", "root").unwrap() {
            GateOutcome::NoDelegation => {}
            other => panic!("expected NoDelegation, got {other:?}"),
        }
    }

    #[test]
    fn valid_delegation_accepted_with_subject_carried_through() {
        let d = delegation("eng");
        let mut req = Request::new(());
        stamp(&mut req, &d);
        match extract_and_validate(&req, "search", "eng").unwrap() {
            GateOutcome::Accepted { delegation } => {
                assert_eq!(delegation.subject, ("user".into(), "alice".into()));
                assert_eq!(delegation.source_zone_id, "peer");
                assert_eq!(delegation.target_zones, vec!["eng".to_string()]);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn wrong_zone_returns_unauthenticated() {
        // Regression pin: a delegation scoped to `eng` MUST NOT be
        // replayable against `legal`.  Refusal comes back with
        // Unauthenticated so the client-side mapper reads it as
        // Backend (auth-shaped), not Transport.
        let d = delegation("eng");
        let mut req = Request::new(());
        stamp(&mut req, &d);
        let err = extract_and_validate(&req, "search", "legal").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("legal"), "{}", err.message());
    }

    #[test]
    fn wrong_method_returns_unauthenticated() {
        // A delegation authorises only the `search` / `semantic_search`
        // methods (per SEARCH_DELEGATION_METHODS).  A leaked
        // delegation cannot be widened to `write` or `list`.
        let d = delegation("eng");
        let mut req = Request::new(());
        stamp(&mut req, &d);
        let err = extract_and_validate(&req, "write", "eng").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("write"), "{}", err.message());
    }

    #[test]
    fn expired_delegation_returns_unauthenticated() {
        // A delegation past its TTL is refused — replay defence.
        // A zero TTL is expired at issuance, with no scheduler-dependent sleep.
        let d = SearchDelegation::new_with_ttl(
            "sd_expiredx1",
            "peer",
            ["eng".to_string()],
            ("user".into(), "alice".into()),
            0,
        );
        let mut req = Request::new(());
        stamp(&mut req, &d);
        let err = extract_and_validate(&req, "search", "eng").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn malformed_json_returns_unauthenticated_not_bad_request() {
        // A delegation whose blob is unparseable is FUNCTIONALLY
        // an auth failure — the caller's auth material is unusable.
        // Returning Unauthenticated keeps the client-side mapper's
        // "backend refused vs transport failed" split honest.
        let mut req = Request::new(());
        req.extensions_mut().insert(GrpcPeer {
            is_cluster_node: true,
        });
        let key: tonic::metadata::MetadataKey<tonic::metadata::Binary> =
            DELEGATION_METADATA_KEY.parse().unwrap();
        req.metadata_mut()
            .insert_bin(key, MetadataValue::from_bytes(b"not valid json"));
        let err = extract_and_validate(&req, "search", "eng").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(
            err.message().to_lowercase().contains("malformed")
                || err.message().to_lowercase().contains("json"),
            "{}",
            err.message()
        );
    }

    #[test]
    fn semantic_search_method_is_permitted() {
        // Both allowed methods pass the gate.  Regression pin
        // against a future rename dropping semantic_search from the
        // allowlist without updating the gate.
        let d = delegation("eng");
        let mut req = Request::new(());
        stamp(&mut req, &d);
        match extract_and_validate(&req, "semantic_search", "eng").unwrap() {
            GateOutcome::Accepted { .. } => {}
            other => panic!("expected Accepted for semantic_search, got {other:?}"),
        }
    }

    #[test]
    fn replay_preserves_the_original_expiration() {
        let mut d = delegation("eng");
        // A positive TTL already elapsed before this request reached the node.
        d.created_at_unix_ms -= 60_000;
        let mut req = Request::new(());
        stamp(&mut req, &d);
        let err = extract_and_validate(&req, "search", "eng").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("expired"), "{err}");
    }

    #[test]
    fn unverified_caller_cannot_supply_a_delegation() {
        let mut req = Request::new(());
        stamp(&mut req, &delegation("eng"));
        req.extensions_mut().remove::<GrpcPeer>();
        let err = extract_and_validate(&req, "search", "eng").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("verified cluster node"));
    }
}
