//! Durable replica issuance facts consumed by the native control plane.

use crate::SignedAgentCertificate;
use crate::{
    credential_intent::CertificateIntent,
    replica_binding::{ReplicaBinding, ReplicaBindingState},
};
use serde::{Deserialize, Serialize};

/// Admitted CA identity for replica publication. TLS CA material must match
/// this current authority before preparing or signing a credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaIssuerAuthority {
    pub revision: u64,
    /// None records an explicitly disabled issuer at this revision.
    pub issuer_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaCertificateIntent {
    pub version: u32,
    pub binding: ReplicaBinding,
    pub issuer_revision: u64,
    pub subject_name: String,
    pub certificate: CertificateIntent,
}

impl ReplicaCertificateIntent {
    pub fn validate_shape(&self) -> Result<(), String> {
        self.binding.validate()?;
        if self.version != 1
            || self.binding.state != ReplicaBindingState::Active
            || self.issuer_revision == 0
            || self.subject_name.is_empty()
            || self.subject_name.len() > 256
        {
            return Err("invalid replica certificate intent".into());
        }
        self.certificate
            .as_ref()
            .validate_shape(crate::USER_RUNTIME_MAX_VALIDITY_SECS as i64)
    }
}

/// Controller-only mutations. Authentication, observed storage ownership and
/// CSR/renewal possession are verified before submitting this typed request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicaIssuanceChange {
    Authority {
        expected_revision: Option<u64>,
        issuer_sha256: Option<[u8; 32]>,
    },
    Prepare {
        intent: Box<ReplicaCertificateIntent>,
        /// Original preparation operation of the certificate being renewed.
        renews: Option<String>,
    },
    Publish {
        credential_id: String,
        certificate: SignedAgentCertificate,
    },
    Revoke {
        credential_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaIssuanceRequest {
    pub operation_id: String,
    pub change: ReplicaIssuanceChange,
}

impl ReplicaIssuanceRequest {
    pub fn validate(&self) -> Result<(), String> {
        crate::validate_operation_id(&self.operation_id).map_err(|e| e.to_string())?;
        match &self.change {
            ReplicaIssuanceChange::Authority {
                expected_revision,
                issuer_sha256,
            } => {
                if *expected_revision == Some(0)
                    || expected_revision.is_none() && issuer_sha256.is_none()
                {
                    return Err(
                        "issuer transition requires a current revision or initial CA".into(),
                    );
                }
            }
            ReplicaIssuanceChange::Prepare { intent, renews } => {
                intent.validate_shape()?;
                if let Some(id) = renews {
                    crate::validate_operation_id(id).map_err(|e| e.to_string())?;
                }
            }
            ReplicaIssuanceChange::Publish {
                credential_id,
                certificate,
            } => {
                crate::validate_operation_id(credential_id).map_err(|e| e.to_string())?;
                if certificate.certificate_der.is_empty()
                    || certificate.certificate_der.len() > 20 * 1024
                    || certificate.tbs_certificate_der.is_empty()
                    || certificate.tbs_certificate_der.len() > 16 * 1024
                    || certificate.serial.is_empty()
                    || certificate.serial.len() > 20
                {
                    return Err("invalid signed replica certificate shape".into());
                }
            }
            ReplicaIssuanceChange::Revoke { credential_id } => {
                crate::validate_operation_id(credential_id).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicaIssuanceRejection {
    AuthorityChanged,
    BindingChanged,
    MissingCredential,
    CredentialRevoked,
    AlreadyPublished,
    CertificateMismatch,
    RenewalMismatch,
}

/// Immutable original result. A later query supplies current authorization;
/// replaying Published after retirement does not restore credential authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicaIssuanceOutcome {
    AuthorityChanged(ReplicaIssuerAuthority),
    Prepared {
        intent: Box<ReplicaCertificateIntent>,
        renews: Option<String>,
    },
    Published {
        credential_id: String,
        certificate_der: Vec<u8>,
    },
    Revoked {
        credential_id: String,
    },
    Rejected(ReplicaIssuanceRejection),
    OperationMismatch,
}

/// View assembled at one ReadIndex from the original receipts, revocation and
/// current binding/issuer authority. The caller verifies X.509 lifetime before
/// serving the credential; a prepared intent has no published certificate yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaCredential {
    pub intent: ReplicaCertificateIntent,
    pub renews: Option<String>,
    pub certificate_der: Option<Vec<u8>>,
    pub revoked: bool,
    pub authority_denial: Option<ReplicaIssuanceRejection>,
}
