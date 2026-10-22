//! Two immutable records in the existing auth store: unsigned winning identity,
//! then a selected final certificate. No RPC, private key, mutable takeover or
//! second database. The minter authenticates/authorizes every call and verifies
//! CSR possession before preparing an intent through the trusted crypto adapter.

use crate::{agent_store_key, AuthKeyRecord, SubjectType};
use contracts::{AgentCertificateIntent, SignedAgentCertificate};
use kernel::hal::auth_key_store::{AuthKeyStore, AuthKeyStoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};

const MARKER: &str = "credential_lifecycle";
/// All present and future lifecycle keys use this non-token namespace.
pub const CREDENTIAL_LIFECYCLE_KEY_PREFIX: &str = "credential-";
pub const FINAL_CERTIFICATE_KEY_PREFIX: &str = "credential-final:";

pub fn is_reserved_lifecycle_key(key: &str) -> bool {
    key.starts_with("agent:") || key.starts_with(CREDENTIAL_LIFECYCLE_KEY_PREFIX)
}

/// Per-request policy from the composition root. Implementations must derive
/// identity from verified caller context and recheck current validity/CRL and
/// owner authority. A receipt, operation ID or expired sentinel is not auth.
pub trait IssuanceAuthorizer {
    fn authorize(&self, binding: &IssuanceBinding) -> Result<(), String>;
}

fn authorize(
    authorizer: &dyn IssuanceAuthorizer,
    binding: &IssuanceBinding,
) -> Result<(), IssuanceError> {
    binding.validate()?;
    authorizer
        .authorize(binding)
        .map_err(|_| IssuanceError::NotAuthorized)
}

/// Constructed from verified caller/issuer policy, never raw request identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceBinding {
    pub issuer_sha256: String,
    pub caller_id: String,
    pub owner_id: String,
    pub agent_name: String,
    pub operation_id: String,
    pub request_sha256: [u8; 32],
}

/// Version 2 supersedes the unshipped signed-candidate prototype. Contains no
/// certificate signature: even a losing Raft proposal is only an unsigned TBS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIssuanceIntent {
    pub schema_version: u8,
    pub binding: IssuanceBinding,
    pub certificate: AgentCertificateIntent,
}

#[derive(Serialize, Deserialize)]
struct ManagedAgentRecord {
    #[serde(flatten)]
    authorization: AuthKeyRecord,
    credential_lifecycle: AgentIssuanceIntent,
}

/// Exact final DER is elected once. Other ECDSA encodings may exist in proposal
/// logs, but every encoding must describe the SAME committed serial and TBS.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalAgentCertificate {
    pub schema_version: u8,
    pub intent_sha256: [u8; 32],
    pub tbs_sha256: [u8; 32],
    pub serial: Vec<u8>,
    pub certificate_der: Vec<u8>,
}

impl fmt::Debug for FinalAgentCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalAgentCertificate")
            .field("intent_sha256", &self.intent_sha256)
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
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
    /// Preserve the same key/CSR/op. Missing or uncertain finalization never
    /// authorizes electing a different identity or silently minting again.
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
pub struct CommittedAgentIntent {
    pub intent: AgentIssuanceIntent,
    pub replayed: bool,
}

/// Derived from immutable records, never a mutable PENDING/COMPLETED journal.
#[derive(Debug, PartialEq, Eq)]
pub enum AgentIssuanceState {
    /// Not observed at this barrier; an in-flight proposal may still commit.
    NotObserved,
    IntentCommitted(AgentIssuanceIntent),
    Finalized {
        intent: AgentIssuanceIntent,
        certificate: FinalAgentCertificate,
    },
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

impl AgentIssuanceIntent {
    fn validate(&self) -> Result<(), IssuanceError> {
        self.binding.validate()?;
        self.certificate
            .validate_shape()
            .map_err(IssuanceError::Invalid)?;
        let issuer: String = self
            .certificate
            .issuer_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if self.schema_version != 2
            || self.binding.agent_name != self.certificate.agent_name
            || self.binding.issuer_sha256 != issuer
        {
            return Err(IssuanceError::Invalid(
                "certificate intent identity/issuer mismatch".into(),
            ));
        }
        Ok(())
    }
}

/// Domain-separated canonical typed intent digest, not a client-supplied key.
pub fn agent_intent_digest(intent: &AgentIssuanceIntent) -> Result<[u8; 32], IssuanceError> {
    intent.validate()?;
    let mut hash = Sha256::new();
    hash.update(b"nexus-agent-intent-v2\0");
    hash.update(serde_json::to_vec(intent).map_err(|e| IssuanceError::Invalid(e.to_string()))?);
    Ok(hash.finalize().into())
}

fn final_key(intent: &AgentIssuanceIntent) -> Result<String, IssuanceError> {
    let digest = agent_intent_digest(intent)?;
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{FINAL_CERTIFICATE_KEY_PREFIX}{hex}"))
}

/// Atomically bind the name and complete unsigned identity before any signing.
pub fn commit_agent_intent(
    store: &Arc<dyn AuthKeyStore>,
    authorizer: &dyn IssuanceAuthorizer,
    mut authorization: AuthKeyRecord,
    candidate: AgentIssuanceIntent,
) -> Result<CommittedAgentIntent, IssuanceError> {
    candidate.validate()?;
    authorize(authorizer, &candidate.binding)?;
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
    // Legacy auth readers see an expired, non-authenticating record even while
    // finalization is incomplete. Keep revoked=false so legacy name dedup still
    // treats it as a permanent binding. Managed completion is read from F.
    authorization.expires_at_ms = Some(0);
    let key = agent_store_key(&candidate.binding.agent_name);
    let row = ManagedAgentRecord {
        authorization,
        credential_lifecycle: candidate,
    };
    let bytes = serde_json::to_vec(&row).map_err(|e| IssuanceError::Invalid(e.to_string()))?;
    if store.put_if_absent_atomic(&key, &bytes).map_err(unknown)? {
        authorize(authorizer, &row.credential_lifecycle.binding)?;
        return Ok(CommittedAgentIntent {
            intent: row.credential_lifecycle,
            replayed: false,
        });
    }
    let intent = read_intent(store, &row.credential_lifecycle.binding)?
        .ok_or_else(|| IssuanceError::Unknown("CAS conflict without an observed intent".into()))?;
    authorize(authorizer, &intent.binding)?;
    Ok(CommittedAgentIntent {
        intent,
        replayed: true,
    })
}

fn read_intent(
    store: &Arc<dyn AuthKeyStore>,
    expected: &IssuanceBinding,
) -> Result<Option<AgentIssuanceIntent>, IssuanceError> {
    expected.validate()?;
    let Some(bytes) = store
        .get_linearizable(&agent_store_key(&expected.agent_name))
        .map_err(unknown)?
    else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| IssuanceError::Unknown("unreadable agent claim".into()))?;
    if value.get(MARKER).is_none() {
        return Err(IssuanceError::Conflict(
            IssuanceConflict::LegacyNameOccupied,
        ));
    }
    let row: ManagedAgentRecord = serde_json::from_value(value)
        .map_err(|_| IssuanceError::Unknown("unsupported managed agent claim".into()))?;
    let intent = row.credential_lifecycle;
    intent
        .validate()
        .map_err(|_| IssuanceError::Unknown("invalid committed intent".into()))?;
    let actual = &intent.binding;
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
    if row.authorization.subject_type != SubjectType::Agent
        || row.authorization.subject_id != actual.agent_name
        || row.authorization.expires_at_ms != Some(0)
        || row.authorization.revoked
        || row.authorization.is_admin
        || !row.authorization.zone_perms.is_empty()
    {
        return Err(IssuanceError::Unknown(
            "managed claim prefix is not fail-closed".into(),
        ));
    }
    Ok(Some(intent))
}

fn read_final(
    store: &Arc<dyn AuthKeyStore>,
    intent: &AgentIssuanceIntent,
) -> Result<Option<FinalAgentCertificate>, IssuanceError> {
    let Some(bytes) = store
        .get_linearizable(&final_key(intent)?)
        .map_err(unknown)?
    else {
        return Ok(None);
    };
    let final_cert: FinalAgentCertificate = serde_json::from_slice(&bytes)
        .map_err(|_| IssuanceError::Unknown("unreadable final certificate".into()))?;
    let tbs_hash: [u8; 32] = Sha256::digest(&intent.certificate.tbs_certificate_der).into();
    if final_cert.schema_version != 1
        || final_cert.intent_sha256 != agent_intent_digest(intent)?
        || final_cert.tbs_sha256 != tbs_hash
        || final_cert.serial != intent.certificate.serial
        || final_cert.certificate_der.is_empty()
        || final_cert.certificate_der.len() > 16 * 1024
    {
        return Err(IssuanceError::Unknown(
            "final certificate does not match committed intent".into(),
        ));
    }
    Ok(Some(final_cert))
}

/// Authenticated exact-operation recovery. No result permits a new op/key/name.
pub fn query_agent_issuance(
    store: &Arc<dyn AuthKeyStore>,
    authorizer: &dyn IssuanceAuthorizer,
    expected: &IssuanceBinding,
) -> Result<AgentIssuanceState, IssuanceError> {
    authorize(authorizer, expected)?;
    let Some(intent) = read_intent(store, expected)? else {
        return Ok(AgentIssuanceState::NotObserved);
    };
    let final_record = read_final(store, &intent)?;
    authorize(authorizer, expected)?;
    match final_record {
        Some(certificate) => Ok(AgentIssuanceState::Finalized {
            intent,
            certificate,
        }),
        None => Ok(AgentIssuanceState::IntentCommitted(intent)),
    }
}

/// The callback is the trusted crypto adapter, never a raw remote signer.
/// It is invoked ONLY with the committed winning intent and after replay auth.
/// Only the final record read back from storage can be returned to the caller.
pub fn finalize_agent_issuance<F>(
    store: &Arc<dyn AuthKeyStore>,
    authorizer: &dyn IssuanceAuthorizer,
    expected: &IssuanceBinding,
    sign: F,
) -> Result<FinalAgentCertificate, IssuanceError>
where
    F: FnOnce(&AgentCertificateIntent) -> Result<SignedAgentCertificate, String>,
{
    authorize(authorizer, expected)?;
    let intent = read_intent(store, expected)?.ok_or_else(|| {
        IssuanceError::Unknown("no committed intent observed; signing refused".into())
    })?;
    if let Some(final_cert) = read_final(store, &intent)? {
        authorize(authorizer, expected)?;
        return Ok(final_cert);
    }
    authorize(authorizer, expected)?;
    let candidate = sign(&intent.certificate).map_err(IssuanceError::Unknown)?;
    if candidate.tbs_certificate_der != intent.certificate.tbs_certificate_der
        || candidate.serial != intent.certificate.serial
        || candidate.certificate_der.is_empty()
        || candidate.certificate_der.len() > 16 * 1024
    {
        return Err(IssuanceError::Invalid(
            "signer output differs from committed identity".into(),
        ));
    }
    let final_cert = FinalAgentCertificate {
        schema_version: 1,
        intent_sha256: agent_intent_digest(&intent)?,
        tbs_sha256: Sha256::digest(&candidate.tbs_certificate_der).into(),
        serial: candidate.serial,
        certificate_der: candidate.certificate_der,
    };
    let bytes =
        serde_json::to_vec(&final_cert).map_err(|e| IssuanceError::Invalid(e.to_string()))?;
    // A losing proposal can contain an ECDSA encoding of the same committed
    // identity, never a signed alternative identity. Both outcomes read F.
    authorize(authorizer, expected)?;
    store
        .put_if_absent_atomic(&final_key(&intent)?, &bytes)
        .map_err(unknown)?;
    let selected = read_final(store, &intent)?.ok_or_else(|| {
        IssuanceError::Unknown("final CAS without an observed final record".into())
    })?;
    authorize(authorizer, expected)?;
    Ok(selected)
}

fn unknown(error: AuthKeyStoreError) -> IssuanceError {
    IssuanceError::Unknown(error.to_string())
}

/// Existing legacy rows cannot become managed: managed insertion requires
/// absence and supported token revocation never deletes reserved claim keys.
/// The absent legacy-rotation branch must use CAS, not a preflight upsert.
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
