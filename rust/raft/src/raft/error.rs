//! Error types for Raft consensus module.

use thiserror::Error;

/// Raft-specific errors.
#[derive(Debug, Error)]
pub enum RaftError {
    /// Storage operation failed.
    #[error("storage error: {0}")]
    Storage(String),

    /// Raft protocol error.
    #[error("raft error: {0}")]
    Raft(String),

    /// Node is not the leader.
    ///
    /// `leader_hint` carries the operator-form address (`host:port`) of
    /// the known leader when the local peer_map has an entry.  It is
    /// intentionally NOT the raw u64 node_id: operators and peer AIs
    /// reading the resulting Display line commonly mistake a bare
    /// node_id (locally derived from `hostname_to_node_id(hostname)`)
    /// for an authoritative transport-resolved identifier — the two
    /// concepts share zero state.  Callers that already have the
    /// address in hand should pass `Some(addr.to_operator_str())`;
    /// callers where the leader is unknown (no election yet, or
    /// leader address not learned) MUST pass `None`.
    #[error("not leader, leader hint: {leader_hint:?}")]
    NotLeader {
        /// Operator-form (`host:port`) address of the known leader, or
        /// `None` if unknown.  See variant docstring for rationale.
        leader_hint: Option<String>,
    },

    /// Proposal was dropped (e.g., leader changed).
    #[error("proposal dropped")]
    ProposalDropped,

    /// Proposal timed out waiting for consensus.
    #[error("proposal timed out after {0} seconds")]
    Timeout(u64),

    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Node not initialized.
    #[error("node not initialized")]
    NotInitialized,

    /// Invalid state transition.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// The actor channel was closed (driver dropped).
    #[error("raft actor channel closed")]
    ChannelClosed,

    /// The actor channel is full — backpressure.
    #[error("raft actor channel full (capacity {0}), driver overloaded")]
    ChannelFull(usize),

    /// Transport error (gRPC forwarding failed).
    #[error("transport error: {0}")]
    Transport(String),

    /// `create_zone` was called for a zone that already exists with a
    /// different peer-address-book.  Idempotency holds when the
    /// requested address book matches the existing one (same set of
    /// `(hostname, port)` tuples); a different set is operator error
    /// — surface it loudly rather than silently mutating ConfState.
    #[error(
        "zone already exists with different membership: actual={actual:?} requested={requested:?}"
    )]
    ZoneAlreadyExistsWithDifferentMembership {
        actual: Vec<String>,
        requested: Vec<String>,
    },
}

impl From<crate::storage::StorageError> for RaftError {
    fn from(e: crate::storage::StorageError) -> Self {
        RaftError::Storage(e.to_string())
    }
}

impl From<bincode::Error> for RaftError {
    fn from(e: bincode::Error) -> Self {
        RaftError::Serialization(e.to_string())
    }
}

/// Result type for Raft operations.
pub type Result<T> = std::result::Result<T, RaftError>;

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    /// Regression pin: RaftError::NotLeader Display must NEVER embed a
    /// bare u64 node_id (the pre-refactor shape was `Some(<u64>)`;
    /// operator/AI diagnostic confusion documented in the peer-identity-
    /// surface audit).  A ~19-digit unbroken integer inside the Display
    /// output is the failure mode; explicit `host:port` addresses (which
    /// contain `:` and non-digit characters) pass.
    #[test]
    fn not_leader_display_never_leaks_bare_node_id() {
        // Case 1 — no hint.  Display should stringify as
        // `"not leader, leader hint: None"`.  No digits at all.
        let none = RaftError::NotLeader { leader_hint: None };
        let s = none.to_string();
        assert!(s.contains("leader hint"));
        assert!(
            !Regex::new(r"\b\d{10,}\b").unwrap().is_match(&s),
            "NotLeader-None Display leaks a long-integer node_id: {s:?}",
        );

        // Case 2 — host:port hint.  Display contains the address but no
        // raw u64.  The port itself is short (<10 digits); reject only
        // 10+-digit bare integers to catch node_id shapes without
        // false-firing on ports or short IPv4 octets.
        let with_addr = RaftError::NotLeader {
            leader_hint: Some("100.64.0.27:2126".to_string()),
        };
        let s = with_addr.to_string();
        assert!(s.contains("100.64.0.27:2126"), "hint addr missing: {s:?}");
        assert!(
            !Regex::new(r"\b\d{10,}\b").unwrap().is_match(&s),
            "NotLeader-Some Display leaks a long-integer node_id: {s:?}",
        );

        // Case 3 — belt & braces: even if a caller ATTEMPTS to jam an
        // integer-looking string in (contract violation), Display still
        // renders it inside quotes — regex above catches it and the
        // test fails, forcing the caller to route through
        // NodeAddress::to_operator_str.
        let violated = RaftError::NotLeader {
            leader_hint: Some("17903436530205787304".to_string()),
        };
        let s = violated.to_string();
        assert!(
            Regex::new(r"\b\d{10,}\b").unwrap().is_match(&s),
            "regex sanity check failed to detect embedded long integer: {s:?}",
        );
    }
}
