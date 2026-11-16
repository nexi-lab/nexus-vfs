//! Authenticated control-plane access to the existing replica lifecycle.

use contracts::{
    replica_binding::{
        ReplicaAllocation, ReplicaBinding, ReplicaBindingOutcome, ReplicaBindingRequest,
    },
    replica_credential::{
        ReplicaIssuanceChange, ReplicaIssuanceOutcome, ReplicaIssuanceRequest,
        ReplicaIssuerAuthority,
    },
};
use nexus_raft::{
    replica_binding_store::{RaftReplicaBindingStore, ReplicaBindingError},
    transport::{current_local_node_certificate, with_unrevoked_serials},
};
use std::path::Path;

#[derive(Debug)]
pub enum ReplicaControlError {
    /// Authentication, possession or an explicit committed rejection.
    Refused(String),
    /// Preserves Unsupported, Unavailable and Unknown from the original store.
    Store(ReplicaBindingError),
}

impl std::fmt::Display for ReplicaControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => write!(formatter, "replica control refused: {reason}"),
            Self::Store(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for ReplicaControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Refused(_) => None,
        }
    }
}

impl From<ReplicaBindingError> for ReplicaControlError {
    fn from(error: ReplicaBindingError) -> Self {
        Self::Store(error)
    }
}

pub(crate) type Result<T> = std::result::Result<T, ReplicaControlError>;

/// A request-local view of the original authenticated connection identity.
/// Wall-clock validity is checked around blocking work; the CRL guard is held
/// by the enclosing issuer operation.
pub(crate) struct CurrentController<'a> {
    pub(crate) der: &'a [u8],
    pub(crate) ca: &'a [u8],
}

impl CurrentController<'_> {
    pub(crate) fn check(&self) -> Result<()> {
        current_local_node_certificate(self.der, self.ca)
            .map(|_| ())
            .map_err(refused)
    }

    pub(crate) fn observe<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.check()?;
        let result = operation();
        self.check()?;
        result
    }

    pub(crate) fn commit<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.check()?;
        let result = operation();
        // Expiry cannot undo an in-flight proposal. Withhold the result and
        // retain the original operation for authenticated readback.
        self.check().map_err(after_submission)?;
        result
    }
}

pub(crate) fn with_current_controller<T>(
    caller_der: &[u8],
    local_ca_der: &[u8],
    revocations: &Path,
    other_serials: &[&[u8]],
    operation: impl FnOnce(&CurrentController<'_>) -> Result<T>,
) -> Result<T> {
    let identity = current_local_node_certificate(caller_der, local_ca_der).map_err(refused)?;
    let caller_serial = identity.serial.as_slice();
    let mut serials = Vec::with_capacity(other_serials.len() + 1);
    serials.push(caller_serial);
    serials.extend_from_slice(other_serials);
    // Both issuance and readback recheck the Node after any lock wait.
    // The nested result preserves Raft Unknown through this CRL boundary.
    with_unrevoked_serials(revocations, &serials, || {
        let controller = CurrentController {
            der: caller_der,
            ca: local_ca_der,
        };
        Ok(controller.check().and_then(|()| operation(&controller)))
    })
    .map_err(refused)?
}

pub(crate) fn refused(error: impl std::fmt::Display) -> ReplicaControlError {
    ReplicaControlError::Refused(error.to_string())
}

pub(crate) fn unknown(error: impl std::fmt::Display) -> ReplicaControlError {
    ReplicaBindingError::Unknown(error.to_string()).into()
}

pub(crate) fn after_submission(error: ReplicaControlError) -> ReplicaControlError {
    match error {
        ReplicaControlError::Store(ReplicaBindingError::Unknown(_)) => error,
        other => unknown(format!(
            "original replica operation requires readback: {other:?}"
        )),
    }
}

/// The trusted observer supplies canonical owner/allocation and storage facts.
/// The original request is retained before its first possible submission.
pub struct ReplicaController<'a> {
    store: &'a RaftReplicaBindingStore,
    local_ca_der: &'a [u8],
    revocations: &'a Path,
}

impl<'a> ReplicaController<'a> {
    pub fn new(
        store: &'a RaftReplicaBindingStore,
        local_ca_der: &'a [u8],
        revocations: &'a Path,
    ) -> Self {
        Self {
            store,
            local_ca_der,
            revocations,
        }
    }

    fn authorized<T>(
        &self,
        caller_der: &[u8],
        operation: impl FnOnce(&CurrentController<'_>) -> Result<T>,
    ) -> Result<T> {
        with_current_controller(
            caller_der,
            self.local_ca_der,
            self.revocations,
            &[],
            operation,
        )
    }

    /// Submit Register, Retire or Replace through the original atomic transition.
    pub fn apply_binding(
        &self,
        caller_der: &[u8],
        original: &ReplicaBindingRequest,
    ) -> Result<ReplicaBindingOutcome> {
        self.authorized(caller_der, |caller| {
            caller.commit(|| Ok(self.store.apply(original)?))
        })
    }

    /// Observe current authority independently from an earlier operation receipt.
    pub fn current_binding(
        &self,
        caller_der: &[u8],
        allocation: &ReplicaAllocation,
    ) -> Result<Option<ReplicaBinding>> {
        self.authorized(caller_der, |caller| {
            caller.observe(|| Ok(self.store.current(allocation)?))
        })
    }

    /// None remains unresolved while an earlier submission can still commit.
    pub fn reconcile_binding(
        &self,
        caller_der: &[u8],
        original: &ReplicaBindingRequest,
    ) -> Result<Option<ReplicaBindingOutcome>> {
        self.authorized(caller_der, |caller| {
            caller.observe(|| Ok(self.store.reconcile(original)?))
        })
    }

    fn validate_issuer_control(original: &ReplicaIssuanceRequest) -> Result<()> {
        original.validate().map_err(refused)?;
        match &original.change {
            ReplicaIssuanceChange::Authority { .. } | ReplicaIssuanceChange::Revoke { .. } => {
                Ok(())
            }
            _ => Err(refused("issuer control accepts only Authority or Revoke")),
        }
    }

    /// Commit issuer authority or credential revocation in the control zone.
    /// The receipt describes that durable fact; data-zone removal and CRL
    /// propagation retain their own completion boundaries.
    pub fn apply_issuer_control(
        &self,
        caller_der: &[u8],
        original: &ReplicaIssuanceRequest,
    ) -> Result<ReplicaIssuanceOutcome> {
        self.authorized(caller_der, |caller| {
            Self::validate_issuer_control(original)?;
            if let ReplicaIssuanceChange::Authority { issuer_sha256, .. } = &original.change {
                if issuer_sha256.is_some_and(|value| {
                    value != lib::transport_primitives::cert_fingerprint(self.local_ca_der)
                }) {
                    return Err(refused(
                        "issuer authority differs from the configured local CA",
                    ));
                }
            }
            caller.commit(|| Ok(self.store.issue(original)?))
        })
    }

    pub fn current_issuer(&self, caller_der: &[u8]) -> Result<Option<ReplicaIssuerAuthority>> {
        self.authorized(caller_der, |caller| {
            caller.observe(|| Ok(self.store.issuer_authority()?))
        })
    }

    pub fn reconcile_issuer_control(
        &self,
        caller_der: &[u8],
        original: &ReplicaIssuanceRequest,
    ) -> Result<Option<ReplicaIssuanceOutcome>> {
        self.authorized(caller_der, |caller| {
            // An original receipt remains queryable across CA rotation. Its
            // historical value grants no authority to a new mutation.
            Self::validate_issuer_control(original)?;
            caller.observe(|| Ok(self.store.reconcile_issuance(original)?))
        })
    }
}
