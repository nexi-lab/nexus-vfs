//! Durable allocation identity consumed by the native replica issuer.
//!
//! Trusted controllers supply observed storage authority/UID and canonical
//! owner/allocation values. Pod UID, process identity and network addresses are
//! runtime observations. Credential signing and zone membership are separate
//! operations that consume an active, current binding.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaAllocation {
    pub owner_id: String,
    pub allocation_id: String,
}

impl ReplicaAllocation {
    pub fn validate(&self) -> Result<(), String> {
        identity(&self.owner_id)?;
        let bytes = self.allocation_id.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 64
            || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
            || !bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return Err("invalid runtime allocation ID".into());
        }
        Ok(())
    }
}

/// An observed PVC UID in its enrolled storage authority. A local persistent
/// volume uses the same opaque incarnation contract at its trusted controller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaStorage {
    pub authority: String,
    pub uid: String,
}

impl ReplicaStorage {
    pub fn validate(&self) -> Result<(), String> {
        identity(&self.authority)?;
        identity(&self.uid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicaBindingState {
    Active,
    Retired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaBinding {
    pub allocation: ReplicaAllocation,
    pub storage: ReplicaStorage,
    pub replica_id: u64,
    /// Advances for every accepted binding transition.
    pub revision: u64,
    /// Advances when an explicitly retired binding is replaced.
    pub generation: u64,
    pub state: ReplicaBindingState,
}

impl ReplicaBinding {
    pub fn validate(&self) -> Result<(), String> {
        self.allocation.validate()?;
        self.storage.validate()?;
        if self.replica_id == 0 || self.generation == 0 || self.revision < self.generation {
            return Err("invalid replica binding identity or revision".into());
        }
        Ok(())
    }
}

/// Every ID here is assigned by the native control-plane allocator. This is a
/// trusted store contract; an Agent-facing request cannot select an ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicaBindingChange {
    Register {
        storage: ReplicaStorage,
        replica_id: u64,
    },
    Retire {
        expected_revision: u64,
    },
    Replace {
        expected_revision: u64,
        storage: ReplicaStorage,
        replica_id: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaBindingRequest {
    pub operation_id: String,
    pub allocation: ReplicaAllocation,
    pub change: ReplicaBindingChange,
}

impl ReplicaBindingRequest {
    pub fn validate(&self) -> Result<(), String> {
        crate::validate_operation_id(&self.operation_id).map_err(|e| e.to_string())?;
        self.allocation.validate()?;
        match &self.change {
            ReplicaBindingChange::Register {
                storage,
                replica_id,
            }
            | ReplicaBindingChange::Replace {
                storage,
                replica_id,
                ..
            } => {
                storage.validate()?;
                if *replica_id == 0 {
                    return Err("replica identity requires a nonzero node ID".into());
                }
            }
            ReplicaBindingChange::Retire { .. } => {}
        }
        match self.change {
            ReplicaBindingChange::Retire { expected_revision }
            | ReplicaBindingChange::Replace {
                expected_revision, ..
            } if expected_revision == 0 => {
                Err("replica mutation requires an observed revision".into())
            }
            _ => Ok(()),
        }
    }
}

/// A receipt describes the original committed operation. After a later
/// retirement/replacement, callers read `current` again before signing or
/// reporting readiness; replaying a receipt does not restore its authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicaBindingOutcome {
    Applied(ReplicaBinding),
    Conflict(Option<ReplicaBinding>),
    ReplicaIdReserved,
    OperationMismatch,
}

fn identity(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err("identity must contain 1 to 512 bytes without control characters".into())
    } else {
        Ok(())
    }
}
