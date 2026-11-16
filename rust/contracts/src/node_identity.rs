//! Durable Node identity reservation in the native control authority.
//!
//! Enrollment verifies the key and controller before constructing a request.
//! Reservation records identity custody; certificate publication and current
//! membership each retain their own authority.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: u64,
    /// SHA-256 of the verified SubjectPublicKeyInfo DER.
    pub subject_public_key_sha256: [u8; 32],
}

impl NodeIdentity {
    pub fn validate(&self) -> Result<(), String> {
        if self.node_id == 0 {
            return Err("Node identity requires a nonzero ID".into());
        }
        Ok(())
    }
}

/// Retain this exact request before submission. An unknown result is reconciled
/// with this operation and key, including after a controller restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentityRequest {
    pub operation_id: String,
    pub identity: NodeIdentity,
}

impl NodeIdentityRequest {
    pub fn validate(&self) -> Result<(), String> {
        crate::validate_operation_id(&self.operation_id).map_err(|e| e.to_string())?;
        self.identity.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeIdentityOutcome {
    Reserved(NodeIdentity),
    IdReserved,
    OperationMismatch,
}
