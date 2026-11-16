//! Typed mutations and original-operation recovery over the same control store.

use super::{CrlStateError, RaftCollaborationCrlStore};
use crate::prelude::{Command, CommandResult};
use contracts::crl_control::{CrlControlOutcome, CrlControlRequest, LocalCrlIssuer};

impl RaftCollaborationCrlStore {
    /// Submit one authenticated composition-root request without changing its
    /// operation ID, issuer selection or observed time. The caller retains the
    /// exact request before this call. A returned receipt is historical evidence,
    /// not a current admission decision.
    pub fn apply_control(
        &self,
        request: &CrlControlRequest,
    ) -> Result<CrlControlOutcome, CrlStateError> {
        request.validate().map_err(CrlStateError::Refused)?;
        if !self.inner.supports_signed_crl() {
            return Err(CrlStateError::Refused(
                "signed CRL control is not activated for this zone".into(),
            ));
        }
        let result = self
            .inner
            .commit_crl_control(Command::ApplyCrlControl(Box::new(request.clone())))
            .map_err(CrlStateError::Unknown)?;
        let CommandResult::Value(bytes) = result else {
            return Err(CrlStateError::Unknown(
                "unexpected signed CRL proposal result".into(),
            ));
        };
        let outcome = bincode::deserialize(&bytes)
            .map_err(|error| CrlStateError::Unknown(format!("invalid CRL receipt: {error}")))?;
        self.inner.read_barrier().map_err(CrlStateError::Unknown)?;
        Ok(outcome)
    }

    /// Read the original outcome at one ReadIndex without submitting anything.
    /// None does not prove that an outstanding proposal cannot still apply;
    /// callers must retain the original operation instead of minting a new one.
    pub fn reconcile_control(
        &self,
        request: &CrlControlRequest,
    ) -> Result<Option<CrlControlOutcome>, CrlStateError> {
        request.validate().map_err(CrlStateError::Refused)?;
        let request = request.clone();
        self.inner
            .read_linearizable(move |state| state.crl_control_receipt(&request))
            .map_err(CrlStateError::Unavailable)?
            .map_err(|error| CrlStateError::Unavailable(error.to_string()))
    }

    /// Observe the current local issuer, including explicit withdrawal. This
    /// separate observation is useful for control preparation, not for composing
    /// an admission with another read of grants or revocations.
    pub fn current_local_issuer(&self) -> Result<Option<LocalCrlIssuer>, CrlStateError> {
        self.inner
            .read_linearizable(|state| state.local_crl_issuer())
            .map_err(CrlStateError::Unavailable)?
            .map_err(|error| CrlStateError::Unavailable(error.to_string()))
    }
}

#[cfg(test)]
mod tests;
