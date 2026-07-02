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
