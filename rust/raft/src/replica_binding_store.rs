//! Trusted control-plane access to durable replica allocation bindings.
//!
//! The composition root authenticates the controller and its observed owner,
//! allocation and PVC UID before constructing a request. Signing, current
//! issuer validation and zone admission consume this store independently.

use crate::{
    control_state_store::ControlStateStore,
    prelude::{CommandResult, FullStateMachine, ZoneConsensus},
};
use contracts::{
    constants::CONTROL_NS_REPLICA,
    replica_binding::{
        ReplicaAllocation, ReplicaBinding, ReplicaBindingOutcome, ReplicaBindingRequest,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum ReplicaBindingError {
    #[error("replica binding protocol is not activated for this control zone")]
    Unsupported,
    #[error("invalid replica binding request: {0}")]
    Invalid(String),
    #[error("replica binding mutation outcome is unknown: {0}")]
    Unknown(String),
    #[error("replica binding observation unavailable: {0}")]
    Unavailable(String),
}

pub struct RaftReplicaBindingStore {
    inner: ControlStateStore,
}

impl RaftReplicaBindingStore {
    pub fn new(node: ZoneConsensus<FullStateMachine>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            inner: ControlStateStore::new(node, runtime, CONTROL_NS_REPLICA),
        }
    }

    /// One proposal, with revision check and receipt at apply. The caller
    /// retains this exact request before submission and reconciles it on
    /// Unknown; it does not allocate another identity after a lost reply.
    pub fn apply(
        &self,
        request: &ReplicaBindingRequest,
    ) -> Result<ReplicaBindingOutcome, ReplicaBindingError> {
        request.validate().map_err(ReplicaBindingError::Invalid)?;
        if !self.inner.supports_replica_binding() {
            return Err(ReplicaBindingError::Unsupported);
        }
        let result = self
            .inner
            .commit_replica_binding(request.clone())
            .map_err(ReplicaBindingError::Unknown)?;
        let CommandResult::Value(bytes) = result else {
            return Err(ReplicaBindingError::Unknown(
                "unexpected binding proposal result".into(),
            ));
        };
        let outcome = bincode::deserialize(&bytes)
            .map_err(|e| ReplicaBindingError::Unknown(format!("invalid binding receipt: {e}")))?;
        self.inner
            .read_barrier()
            .map_err(ReplicaBindingError::Unknown)?;
        Ok(outcome)
    }

    /// Observe the authoritative current generation at one ReadIndex.
    pub fn current(
        &self,
        allocation: &ReplicaAllocation,
    ) -> Result<Option<ReplicaBinding>, ReplicaBindingError> {
        allocation
            .validate()
            .map_err(ReplicaBindingError::Invalid)?;
        let allocation = allocation.clone();
        self.inner
            .read_linearizable(move |sm| sm.replica_binding(&allocation))
            .map_err(ReplicaBindingError::Unavailable)?
            .map_err(|e| ReplicaBindingError::Unavailable(e.to_string()))
    }

    /// Resolve a signed replica ID through its retained reservation at the
    /// same read point as the allocation. Replaced IDs resolve no authority;
    /// the caller still checks Active state and the signed owner.
    pub fn current_for_replica(
        &self,
        id: u64,
    ) -> Result<Option<ReplicaBinding>, ReplicaBindingError> {
        if id == 0 {
            return Err(ReplicaBindingError::Invalid("replica ID is zero".into()));
        }
        self.inner
            .read_linearizable(move |sm| sm.replica_binding_by_id(id))
            .map_err(ReplicaBindingError::Unavailable)?
            .map_err(|e| ReplicaBindingError::Unavailable(e.to_string()))
    }

    /// Read the original operation receipt. None means unresolved: an earlier
    /// in-flight proposal can still commit after this read. Even Applied is a
    /// historical result; signing/readiness also requires a fresh current read.
    pub fn reconcile(
        &self,
        request: &ReplicaBindingRequest,
    ) -> Result<Option<ReplicaBindingOutcome>, ReplicaBindingError> {
        request.validate().map_err(ReplicaBindingError::Invalid)?;
        let request = request.clone();
        self.inner
            .read_linearizable(move |sm| sm.replica_binding_receipt(&request))
            .map_err(ReplicaBindingError::Unavailable)?
            .map_err(|e| ReplicaBindingError::Unavailable(e.to_string()))
    }
}
