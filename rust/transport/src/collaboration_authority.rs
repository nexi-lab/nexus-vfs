//! Native current-issuer/CRL composition for actual TLS Agent admissions.
//!
//! This does not install a profile, fetch a CRL, trust an endpoint or grant a
//! space. A native refresh must publish authentic fresh evidence first. Missing,
//! stale or unavailable consensus evidence refuses admission, including on a
//! previously established channel. No alternate issuer or cached allow path.

use std::sync::Arc;

use nexus_raft::collaboration_crl::RaftCollaborationCrlStore;

use crate::collaboration_identity::{CertificateAgent, CurrentAgentAuthority};

pub struct RaftCurrentAgentAuthority {
    local_ca_pem: Vec<u8>,
    store: Arc<RaftCollaborationCrlStore>,
}

impl RaftCurrentAgentAuthority {
    /// The composition root supplies its actual cluster CA and control store.
    /// No caller body or serialized descriptor constructs this policy.
    pub fn new(
        local_ca_pem: Vec<u8>,
        store: Arc<RaftCollaborationCrlStore>,
    ) -> Result<Self, String> {
        lib::transport_primitives::ca_spki_sha256(&local_ca_pem)?;
        Ok(Self {
            local_ca_pem,
            store,
        })
    }
}

impl CurrentAgentAuthority for RaftCurrentAgentAuthority {
    fn check_current(&self, agent: &CertificateAgent) -> Result<(), String> {
        self.store
            .check_registered_serial(
                &self.local_ca_pem,
                agent.address().authority(),
                agent.issuer_sha256(),
                agent.trust_domain(),
                agent.serial(),
            )
            .map_err(|error| format!("current collaboration authority refused: {error:?}"))
    }
}
