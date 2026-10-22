//! Immutable first-agent issuance receipts in the existing `agent:<name>` row.
//!
//! The minter authenticates the caller, verifies its CSR and signs a candidate
//! BEFORE calling this module. This is not a network authorization boundary or
//! a signer. Only the winning public certificate leaves the coordinator API.
//! A CAS loser is not returned or application-logged, but its proposed value
//! may exist in consensus/WAL logs. See docs/credential-lifecycle-receipts.md
//! for this trust boundary before enabling an issuance RPC.

use std::{fmt, sync::Arc};

use kernel::hal::auth_key_store::{AuthKeyStore, AuthKeyStoreError};
use serde::{Deserialize, Serialize};

use crate::{agent_store_key, AuthKeyRecord, SubjectType};

/// Reserved top-level marker; any version (even malformed) blocks legacy writes.
const MARKER: &str = "credential_lifecycle";

/// Constructed from verified issuer/caller policy, not raw request identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceBinding {
    pub issuer_sha256: String,
    pub caller_id: String,
    pub owner_id: String,
    pub agent_name: String,
    pub operation_id: String,
    /// Canonical full request digest, including CSR and policy/validity inputs.
    pub request_sha256: [u8; 32],
}

/// Public committed result. Contains no private key, CSR secret or token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIssuanceReceipt {
    pub schema_version: u8,
    pub binding: IssuanceBinding,
    pub certificate_der: Vec<u8>,
    pub serial: Vec<u8>,
}

impl fmt::Debug for AgentIssuanceReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentIssuanceReceipt")
            .field("schema_version", &self.schema_version)
            .field("binding", &self.binding)
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
}

/// The old record stays at the JSON top level, so all legacy readers decode it.
/// The name claim and receipt are ONE value in ONE apply-time put-if-absent.
#[derive(Serialize, Deserialize)]
struct ManagedAgentRecord {
    #[serde(flatten)]
    authorization: AuthKeyRecord,
    credential_lifecycle: AgentIssuanceReceipt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssuanceConflict {
    LegacyNameOccupied,
    DifferentOperation,
    DifferentRequest,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IssuanceError {
    Invalid(String),
    NotAuthorized,
    Conflict(IssuanceConflict),
    /// The operation may have committed. Recover using the SAME binding/op/key.
    Unknown(String),
}

impl fmt::Display for IssuanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid issuance: {reason}"),
            Self::NotAuthorized => f.write_str("not authorized to replay this agent issuance"),
            Self::Conflict(kind) => write!(f, "agent issuance conflict: {kind:?}"),
            Self::Unknown(reason) => write!(f, "agent issuance outcome unknown: {reason}"),
        }
    }
}

impl std::error::Error for IssuanceError {}

#[derive(Debug, PartialEq, Eq)]
pub struct CommittedAgentIssuance {
    pub receipt: AgentIssuanceReceipt,
    pub replayed: bool,
}

impl IssuanceBinding {
    fn validate(&self) -> Result<(), IssuanceError> {
        contracts::validate_operation_id(&self.operation_id)
            .map_err(|e| IssuanceError::Invalid(e.to_string()))?;
        if self.issuer_sha256.len() != 64
            || !self
                .issuer_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(IssuanceError::Invalid(
                "issuer fingerprint must be lowercase SHA256".into(),
            ));
        }
        for value in [&self.caller_id, &self.owner_id, &self.agent_name] {
            if value.is_empty()
                || value.len() > 256
                || value
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || c == '/' || c == '\\')
            {
                return Err(IssuanceError::Invalid(
                    "invalid caller, owner or agent identity".into(),
                ));
            }
        }
        Ok(())
    }
}

impl AgentIssuanceReceipt {
    fn validate(&self) -> Result<(), IssuanceError> {
        self.binding.validate()?;
        if self.schema_version != 1
            || self.certificate_der.is_empty()
            || self.certificate_der.len() > 16 * 1024
            || self.serial.is_empty()
            || self.serial.len() > 20
        {
            return Err(IssuanceError::Invalid(
                "invalid public receipt shape/version".into(),
            ));
        }
        Ok(())
    }
}

/// Commit the pre-signed candidate atomically with the existing agent-name claim.
/// No separate receipt key, pending state, overwrite, takeover or local fallback.
pub fn commit_agent_issuance(
    store: &Arc<dyn AuthKeyStore>,
    authorization: AuthKeyRecord,
    candidate: AgentIssuanceReceipt,
) -> Result<CommittedAgentIssuance, IssuanceError> {
    candidate.validate()?;
    if authorization.subject_type != SubjectType::Agent
        || authorization.subject_id != candidate.binding.agent_name
        || authorization.is_admin
        || authorization.revoked
        || !authorization.zone_perms.is_empty()
        || authorization.expires_at_ms.is_some()
    {
        return Err(IssuanceError::Invalid(
            "issuance requires a pure agent identity record".into(),
        ));
    }
    let key = agent_store_key(&candidate.binding.agent_name);
    let record = ManagedAgentRecord {
        authorization,
        credential_lifecycle: candidate,
    };
    let bytes = serde_json::to_vec(&record).map_err(|e| IssuanceError::Invalid(e.to_string()))?;
    if store.put_if_absent_atomic(&key, &bytes).map_err(unknown)? {
        return Ok(CommittedAgentIssuance {
            receipt: record.credential_lifecycle,
            replayed: false,
        });
    }
    // Never return the losing candidate. Read only the committed winner;
    // its proposed bytes may still exist in consensus logs (module docs).
    let receipt =
        query_agent_issuance(store, &record.credential_lifecycle.binding)?.ok_or_else(|| {
            IssuanceError::Unknown("CAS conflict without an observed winning row".into())
        })?;
    Ok(CommittedAgentIssuance {
        receipt,
        replayed: true,
    })
}

/// Recover by authenticated caller/issuer/owner/name and exact operation/digest.
/// `None` means not observed at this read barrier, NOT proof that an in-flight
/// proposal cannot commit later. It never authorizes a new op, key or name.
pub fn query_agent_issuance(
    store: &Arc<dyn AuthKeyStore>,
    expected: &IssuanceBinding,
) -> Result<Option<AgentIssuanceReceipt>, IssuanceError> {
    expected.validate()?;
    let Some(bytes) = store
        .get_linearizable(&agent_store_key(&expected.agent_name))
        .map_err(unknown)?
    else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| IssuanceError::Unknown("unreadable agent name row".into()))?;
    if value.get(MARKER).is_none() {
        return Err(IssuanceError::Conflict(
            IssuanceConflict::LegacyNameOccupied,
        ));
    }
    let record: ManagedAgentRecord = serde_json::from_value(value)
        .map_err(|_| IssuanceError::Unknown("unreadable managed agent receipt".into()))?;
    let receipt = record.credential_lifecycle;
    receipt
        .validate()
        .map_err(|_| IssuanceError::Unknown("unsupported managed agent receipt".into()))?;
    let actual = &receipt.binding;
    if actual.issuer_sha256 != expected.issuer_sha256
        || actual.caller_id != expected.caller_id
        || actual.owner_id != expected.owner_id
        || actual.agent_name != expected.agent_name
    {
        return Err(IssuanceError::NotAuthorized);
    }
    if actual.operation_id != expected.operation_id {
        return Err(IssuanceError::Conflict(
            IssuanceConflict::DifferentOperation,
        ));
    }
    if actual.request_sha256 != expected.request_sha256 {
        return Err(IssuanceError::Conflict(IssuanceConflict::DifferentRequest));
    }
    if record.authorization.subject_type != SubjectType::Agent
        || record.authorization.subject_id != actual.agent_name
    {
        return Err(IssuanceError::Unknown(
            "managed agent claim/receipt mismatch".into(),
        ));
    }
    Ok(Some(receipt))
}

fn unknown(error: AuthKeyStoreError) -> IssuanceError {
    IssuanceError::Unknown(error.to_string())
}

/// The proof behind the legacy rotation guard: agent rows cannot be removed
/// through supported token revocation, and a managed row can only be inserted
/// when absent. Therefore an existing legacy row cannot change class between
/// this check and its legacy update. The absent branch MUST use CAS instead.
pub(crate) fn require_legacy_agent_record(
    bytes: &[u8],
    name: &str,
) -> Result<(), AuthKeyStoreError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
        AuthKeyStoreError::Backend("refusing to overwrite an unreadable agent claim".into())
    })?;
    if value.get(MARKER).is_some() {
        return Err(AuthKeyStoreError::Backend(
            "managed agent claims cannot be rotated through allow_existing".into(),
        ));
    }
    let record: AuthKeyRecord = serde_json::from_value(value).map_err(|_| {
        AuthKeyStoreError::Backend("refusing to overwrite an unknown agent claim".into())
    })?;
    if record.subject_type != SubjectType::Agent || record.subject_id != name {
        return Err(AuthKeyStoreError::Backend(
            "agent claim identity mismatch".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
