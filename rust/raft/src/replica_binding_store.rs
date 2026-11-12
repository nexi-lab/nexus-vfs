//! Trusted control-plane access to durable replica allocation bindings.
//!
//! The composition root authenticates the controller and its observed owner,
//! allocation and PVC UID before constructing a request. Signing, current
//! issuer validation and zone admission consume this store independently.

use crate::{
    control_state_store::ControlStateStore,
    prelude::{Command, CommandResult, FullStateMachine, ZoneConsensus},
};
use contracts::{
    constants::CONTROL_NS_REPLICA,
    node_identity::{NodeIdentity, NodeIdentityOutcome, NodeIdentityRequest},
    replica_binding::{
        ReplicaAllocation, ReplicaBinding, ReplicaBindingOutcome, ReplicaBindingRequest,
    },
    replica_credential::{
        ReplicaCredential, ReplicaIssuanceOutcome, ReplicaIssuanceRequest, ReplicaIssuerAuthority,
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

    /// Publish issuance facts using the same authority as allocation changes.
    /// The trusted caller validates controller/CSR possession and retains the
    /// original request; Unknown is reconciled with that exact operation.
    pub fn issue(
        &self,
        request: &ReplicaIssuanceRequest,
    ) -> Result<ReplicaIssuanceOutcome, ReplicaBindingError> {
        request.validate().map_err(ReplicaBindingError::Invalid)?;
        self.commit(Command::ApplyReplicaIssuance(Box::new(request.clone())))
    }

    pub fn issuer_authority(&self) -> Result<Option<ReplicaIssuerAuthority>, ReplicaBindingError> {
        self.inner
            .read_linearizable(|sm| sm.replica_issuer_authority())
            .map_err(ReplicaBindingError::Unavailable)?
            .map_err(|error| ReplicaBindingError::Unavailable(error.to_string()))
    }

    pub fn credential(&self, id: &str) -> Result<Option<ReplicaCredential>, ReplicaBindingError> {
        contracts::validate_operation_id(id)
            .map_err(|error| ReplicaBindingError::Invalid(error.to_string()))?;
        let id = id.to_owned();
        self.inner
            .read_linearizable(move |sm| sm.replica_credential(&id))
            .map_err(ReplicaBindingError::Unavailable)?
            .map_err(|error| ReplicaBindingError::Unavailable(error.to_string()))
    }

    pub fn reconcile_issuance(
        &self,
        request: &ReplicaIssuanceRequest,
    ) -> Result<Option<ReplicaIssuanceOutcome>, ReplicaBindingError> {
        request.validate().map_err(ReplicaBindingError::Invalid)?;
        let request = request.clone();
        self.inner
            .read_linearizable(move |sm| sm.replica_issuance_receipt(&request))
            .map_err(ReplicaBindingError::Unavailable)?
            .map_err(|error| ReplicaBindingError::Unavailable(error.to_string()))
    }

    /// One proposal, with revision check and receipt at apply. The caller
    /// retains this exact request before submission and reconciles it on
    /// Unknown; it does not allocate another identity after a lost reply.
    pub fn apply(
        &self,
        request: &ReplicaBindingRequest,
    ) -> Result<ReplicaBindingOutcome, ReplicaBindingError> {
        request.validate().map_err(ReplicaBindingError::Invalid)?;
        self.commit(Command::ApplyReplicaBinding(Box::new(request.clone())))
    }

    /// Reserve a founder/enrolled Node identity in the same ID index as replica
    /// allocation. A new operation cannot reclaim an existing ID, even with
    /// the same public key. Enrollment retains its original operation to retry.
    pub fn reserve_node(
        &self,
        request: &NodeIdentityRequest,
    ) -> Result<NodeIdentityOutcome, ReplicaBindingError> {
        request.validate().map_err(ReplicaBindingError::Invalid)?;
        self.commit(Command::ReserveNodeIdentity(Box::new(request.clone())))
    }

    fn commit<T: serde::de::DeserializeOwned>(
        &self,
        command: Command,
    ) -> Result<T, ReplicaBindingError> {
        if !self
            .inner
            .supports_replica_binding()
            .map_err(ReplicaBindingError::Unavailable)?
        {
            return Err(ReplicaBindingError::Unsupported);
        }
        let result = self
            .inner
            .commit_replica_control(command)
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

    /// Read the retained Node key binding at one control-zone ReadIndex.
    pub fn node_identity(&self, id: u64) -> Result<Option<NodeIdentity>, ReplicaBindingError> {
        if id == 0 {
            return Err(ReplicaBindingError::Invalid("Node ID is zero".into()));
        }
        self.inner
            .read_linearizable(move |sm| sm.node_identity(id))
            .map_err(ReplicaBindingError::Unavailable)?
            .map_err(|e| ReplicaBindingError::Unavailable(e.to_string()))
    }

    /// Recover the exact original Node reservation. An absent receipt remains
    /// unresolved while a previously submitted proposal can still commit.
    pub fn reconcile_node(
        &self,
        request: &NodeIdentityRequest,
    ) -> Result<Option<NodeIdentityOutcome>, ReplicaBindingError> {
        request.validate().map_err(ReplicaBindingError::Invalid)?;
        let request = request.clone();
        self.inner
            .read_linearizable(move |sm| sm.node_identity_receipt(&request))
            .map_err(ReplicaBindingError::Unavailable)?
            .map_err(|e| ReplicaBindingError::Unavailable(e.to_string()))
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
