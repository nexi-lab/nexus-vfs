//! Public unsigned certificate data shared by policy and the CA adapter.
//! No keys, signing implementation or storage dependencies belong here.

use serde::{Deserialize, Serialize};

/// Complete ordinary-agent v1 certificate commitment. The crypto adapter
/// prepares this after verifying CSR possession; callers never supply policy.
/// Exact TBS bytes bind every encoded field across retries and upgrades.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCertificateIntent {
    pub version: u32,
    pub agent_name: String,
    pub issuer_sha256: [u8; 32],
    pub subject_public_key_info_der: Vec<u8>,
    pub serial: Vec<u8>,
    pub not_before_unix_s: i64,
    pub not_after_unix_s: i64,
    pub tbs_certificate_der: Vec<u8>,
}

impl AgentCertificateIntent {
    /// Structural bounds only; the CA adapter validates the actual X.509 policy.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.version != 1
            || self.agent_name.is_empty()
            || self.agent_name.len() > 256
            || self.subject_public_key_info_der.is_empty()
            || self.subject_public_key_info_der.len() > 1024
            || self.serial.is_empty()
            || self.serial.len() > 20
            || self.serial[0] == 0
            || self.serial[0] & 0x80 != 0
            || self.tbs_certificate_der.is_empty()
            || self.tbs_certificate_der.len() > 16 * 1024
            || self.not_after_unix_s <= self.not_before_unix_s
            || self
                .not_after_unix_s
                .checked_sub(self.not_before_unix_s)
                .is_none_or(|seconds| seconds > 90 * 86400)
        {
            return Err("invalid ordinary-agent certificate intent".into());
        }
        Ok(())
    }
}

/// Output of the trusted crypto adapter, not a request-body claim about a cert.
/// The coordinator compares the parsed TBS/serial with the committed intent.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedAgentCertificate {
    pub certificate_der: Vec<u8>,
    pub tbs_certificate_der: Vec<u8>,
    pub serial: Vec<u8>,
}

impl std::fmt::Debug for SignedAgentCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedAgentCertificate")
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
}
