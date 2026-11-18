//! Native signed-CRL installation in the existing replicated control store.
//!
//! These values do not authenticate a controller or register a foreign CA.
//! The composition root supplies an authorized operation; apply checks its
//! original issuer selection against the current durable authority.

use serde::{Deserialize, Serialize};

pub const MAX_CRL_BYTES: usize = 1024 * 1024;
pub const CRL_MAXIMUM_AGE_SECS: u32 = 300;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalCrlIssuer {
    pub revision: u64,
    /// None is an explicit withdrawal, not an absent initial configuration.
    pub ca_pem: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrlIssuerSelection {
    Local {
        revision: u64,
    },
    /// Exact bytes from the existing foreign-CA registry, including purpose.
    /// Reusing a fingerprint with different registration bytes is refused.
    Foreign {
        registration: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrlControlChange {
    LocalIssuer {
        expected_revision: Option<u64>,
        ca_pem: Option<Vec<u8>>,
    },
    Install {
        issuer: CrlIssuerSelection,
        crl_pem: Vec<u8>,
        /// Native proposal time. Apply is deterministic; admission checks its
        /// own current clock again rather than reusing this observation.
        observed_unix_s: i64,
        maximum_age_secs: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrlControlRequest {
    pub operation_id: String,
    pub change: CrlControlChange,
}

impl CrlControlRequest {
    pub fn validate(&self) -> Result<(), String> {
        crate::validate_operation_id(&self.operation_id).map_err(|e| e.to_string())?;
        match &self.change {
            CrlControlChange::LocalIssuer {
                expected_revision,
                ca_pem,
            } => {
                if *expected_revision == Some(0)
                    || expected_revision.is_none() && ca_pem.is_none()
                    || ca_pem
                        .as_ref()
                        .is_some_and(|pem| pem.is_empty() || pem.len() > 64 * 1024)
                {
                    return Err("invalid local CRL issuer transition".into());
                }
            }
            CrlControlChange::Install {
                issuer,
                crl_pem,
                observed_unix_s,
                maximum_age_secs,
            } => {
                if crl_pem.is_empty()
                    || crl_pem.len() > MAX_CRL_BYTES
                    || *observed_unix_s < 0
                    || *maximum_age_secs == 0
                    || *maximum_age_secs > CRL_MAXIMUM_AGE_SECS
                {
                    return Err("invalid signed CRL installation shape".into());
                }
                match issuer {
                    CrlIssuerSelection::Local { revision: 0 } => {
                        return Err("local CRL issuer revision must be nonzero".into())
                    }
                    CrlIssuerSelection::Foreign { registration }
                        if registration.is_empty() || registration.len() > 128 * 1024 =>
                    {
                        return Err("invalid foreign CRL issuer registration".into())
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

/// An immutable result for the original request. It is not a current grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrlControlOutcome {
    LocalIssuerChanged(LocalCrlIssuer),
    Installed {
        authority: [u8; 32],
        signed_der_sha256: [u8; 32],
        number: Vec<u8>,
    },
    Refused(String),
    OperationMismatch,
}
