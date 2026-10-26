//! Experimental revocation evidence in the EXISTING replicated control store.
//!
//! Signed snapshots have bounded freshness. Every observed revoked serial is
//! additionally retained as an irreversible, authority-scoped tombstone, so
//! replaying an older signed list cannot un-revoke it, including after restart.
//! No second CA, identity registry, daemon or mutable transcript is introduced.
//!
//! This is a trusted composition-root primitive, NOT an Agent RPC or a trust
//! grant. The caller must select the CA through its CURRENT native issuer
//! registry on every admission and bind it to the actual TLS principal. No
//! profile installs that composition yet. A newly revoked foreign certificate
//! cannot be known before an authentic refresh: the freshness budget bounds
//! that uncertainty; it does not promise instantaneous cross-domain revocation.

use crate::{
    control_state_store::ControlStateStore,
    prelude::{FullStateMachine, ZoneConsensus},
};
use lib::transport_primitives::{
    canonical_certificate_serial, verify_signed_crl, ForeignCaAnchor, ForeignCaScope, VerifiedCrl,
    CRL_MAXIMUM_AGE_SECS,
};
use sha2::{Digest, Sha256};

const REVOKED: &[u8] = b"collaboration-certificate-revoked-v1";

#[derive(Debug, PartialEq, Eq)]
pub enum CrlStateError {
    /// Validation failed before this operation attempted any control write.
    Refused(String),
    /// A control mutation may already have applied. Never auto-resubmit.
    Unknown(String),
    Unavailable(String),
    Revoked,
}

#[derive(Debug)]
pub struct CrlSnapshotReceipt {
    pub authority: [u8; 32],
    pub snapshot_sha256: [u8; 32],
    pub this_update: i64,
    pub next_update: i64,
}

pub struct RaftCollaborationCrlStore {
    inner: ControlStateStore,
    maximum_age_secs: u32,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs()
        .try_into()
        .map_err(|_| "clock overflow".into())
}

fn snapshot_key(authority: &[u8; 32]) -> String {
    format!("crl-v1:{}", hex(authority))
}

fn revoked_key(authority: &[u8; 32], serial: &[u8]) -> Result<String, String> {
    Ok(format!(
        "certificate-revoked-v1:{}:{}",
        hex(authority),
        hex(canonical_certificate_serial(serial)?)
    ))
}

impl RaftCollaborationCrlStore {
    pub fn new(
        node: ZoneConsensus<FullStateMachine>,
        runtime: tokio::runtime::Handle,
        maximum_age_secs: u32,
    ) -> Result<Self, String> {
        if maximum_age_secs == 0 || maximum_age_secs > CRL_MAXIMUM_AGE_SECS {
            return Err("CRL maximum age must be between 1 and 300 seconds".into());
        }
        Ok(Self {
            inner: ControlStateStore::new(
                node,
                runtime,
                contracts::constants::CONTROL_NS_COLLABORATION,
            ),
            maximum_age_secs,
        })
    }

    /// Persist revocations BEFORE publishing the signed freshness snapshot.
    /// An interruption can deny more access, never erase an observed revoke.
    /// Refreshing a snapshot does not register/trust its CA or grant a space.
    pub fn publish(
        &self,
        ca_pem: &[u8],
        crl_pem: &[u8],
    ) -> Result<CrlSnapshotReceipt, CrlStateError> {
        let at = now().map_err(CrlStateError::Refused)?;
        let verified = verify_signed_crl(crl_pem, ca_pem).map_err(CrlStateError::Refused)?;
        verified
            .check_freshness(at, self.maximum_age_secs)
            .map_err(CrlStateError::Refused)?;
        let authority = verified.authority();
        // Validate every key before the first possible mutation.
        let keys: Vec<_> = verified
            .revoked_serials()
            .iter()
            .map(|serial| revoked_key(authority, serial))
            .collect::<Result<_, _>>()
            .map_err(CrlStateError::Refused)?;
        for key in keys {
            // A local miss only costs another CAS, never weakens the write.
            // Existing records cannot be deleted by this typed store.
            match self.inner.get(&key).map_err(CrlStateError::Unknown)? {
                Some(value) if value == REVOKED => {}
                Some(_) => return Err(CrlStateError::Unknown("invalid revocation marker".into())),
                None => {
                    self.inner
                        .put_if_absent(&key, REVOKED)
                        .map_err(CrlStateError::Unknown)?;
                }
            }
        }
        let key = snapshot_key(authority);
        // A large refresh may take time to persist its markers. Those writes
        // may already have committed, so late freshness failure is Unknown.
        verified
            .check_freshness(
                now().map_err(CrlStateError::Unknown)?,
                self.maximum_age_secs,
            )
            .map_err(CrlStateError::Unknown)?;
        self.inner
            .put(&key, crl_pem)
            .map_err(CrlStateError::Unknown)?;
        let observed = self
            .inner
            .get_many_linearizable(&[key])
            .map_err(CrlStateError::Unknown)?;
        if observed != [Some(crl_pem.to_vec())] {
            return Err(CrlStateError::Unknown(
                "snapshot changed before receipt; query current state".into(),
            ));
        }
        Ok(CrlSnapshotReceipt {
            authority: *authority,
            snapshot_sha256: Sha256::digest(crl_pem).into(),
            this_update: verified.this_update(),
            next_update: verified.next_update(),
        })
    }

    /// One linearizable snapshot of freshness bytes and the actor's irreversible
    /// revoke marker. This orders this admission, not a subsequent data append.
    pub fn check_serial(&self, ca_pem: &[u8], serial: &[u8]) -> Result<(), CrlStateError> {
        self.check_at(ca_pem, serial, now().map_err(CrlStateError::Unavailable)?)
    }

    /// Compose CURRENT issuer registration and revocation in ONE consensus
    /// snapshot. Inputs must come from the actual admitted TLS leaf/anchor;
    /// this trusted composition method does not authenticate public values.
    /// Foreign callers require the versioned collaboration-only purpose.
    pub fn check_registered_serial(
        &self,
        local_ca_pem: &[u8],
        authority: &[u8; 32],
        selected_issuer_sha256: &[u8; 32],
        trust_domain: Option<&str>,
        serial: &[u8],
    ) -> Result<(), CrlStateError> {
        let snapshot = snapshot_key(authority);
        let revoked = revoked_key(authority, serial).map_err(CrlStateError::Unavailable)?;
        let (anchors, values) = self
            .inner
            .read_linearizable(move |sm| {
                let anchors = sm
                    .list_control_state(contracts::CONTROL_NS_FOREIGN_CA)
                    .map_err(|e| e.to_string())?;
                let values = [snapshot, revoked]
                    .iter()
                    .map(|key| {
                        sm.get_control_state(contracts::constants::CONTROL_NS_COLLABORATION, key)
                            .map_err(|e| e.to_string())
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                Ok::<_, String>((anchors, values))
            })
            .map_err(CrlStateError::Unavailable)?
            .map_err(CrlStateError::Unavailable)?;
        let local_authority = lib::transport_primitives::ca_spki_sha256(local_ca_pem)
            .map_err(CrlStateError::Unavailable)?;
        let local_der = pem::parse(local_ca_pem)
            .map_err(|e| CrlStateError::Unavailable(e.to_string()))?
            .into_contents();
        if trust_domain.is_some() && *authority == local_authority {
            return Err(CrlStateError::Unavailable(
                "local authority cannot be foreign".into(),
            ));
        }
        let mut selected = None;
        for (key, bytes) in anchors {
            let anchor = ForeignCaAnchor::decode(&bytes)
                .map_err(|error| CrlStateError::Unavailable(error.to_string()))?;
            if key != anchor.fingerprint_hex() {
                return Err(CrlStateError::Unavailable(
                    "foreign registry key mismatch".into(),
                ));
            }
            let pem = pem::encode(&pem::Pem::new("CERTIFICATE", anchor.ca_cert_der.as_slice()));
            let candidate = lib::transport_primitives::ca_spki_sha256(pem.as_bytes())
                .map_err(CrlStateError::Unavailable)?;
            if candidate != *authority {
                continue;
            }
            if trust_domain != Some(anchor.trust_domain_id.as_str())
                || anchor.scope != ForeignCaScope::CollaborationOnlyV1
            {
                return Err(CrlStateError::Unavailable(
                    "ambiguous authority or trust purpose".into(),
                ));
            }
            if anchor.fingerprint() == *selected_issuer_sha256 {
                selected = Some(pem.into_bytes());
            }
        }
        let ca_pem = match trust_domain {
            None if *authority == local_authority
                && <[u8; 32]>::from(Sha256::digest(&local_der)) == *selected_issuer_sha256 =>
            {
                local_ca_pem
            }
            Some(_) => selected.as_deref().ok_or_else(|| {
                CrlStateError::Unavailable("TLS issuer is no longer registered".into())
            })?,
            _ => {
                return Err(CrlStateError::Unavailable(
                    "local issuer binding mismatch".into(),
                ))
            }
        };
        self.check_values(
            &values,
            ca_pem,
            serial,
            now().map_err(CrlStateError::Unavailable)?,
        )
    }

    fn check_at(&self, ca_pem: &[u8], serial: &[u8], at: i64) -> Result<(), CrlStateError> {
        let authority = lib::transport_primitives::ca_spki_sha256(ca_pem)
            .map_err(CrlStateError::Unavailable)?;
        let revoked = revoked_key(&authority, serial).map_err(CrlStateError::Unavailable)?;
        let values = self
            .inner
            .get_many_linearizable(&[snapshot_key(&authority), revoked])
            .map_err(CrlStateError::Unavailable)?;
        self.check_values(&values, ca_pem, serial, at)
    }

    fn check_values(
        &self,
        values: &[Option<Vec<u8>>],
        ca_pem: &[u8],
        serial: &[u8],
        at: i64,
    ) -> Result<(), CrlStateError> {
        match values {
            [_, Some(value)] if value == REVOKED => Err(CrlStateError::Revoked),
            [_, Some(_)] => Err(CrlStateError::Unavailable(
                "invalid revocation marker".into(),
            )),
            [Some(bytes), None] => self.verify_current(bytes, ca_pem, serial, at),
            _ => Err(CrlStateError::Unavailable(
                "no complete current CRL snapshot".into(),
            )),
        }
    }

    fn verify_current(
        &self,
        bytes: &[u8],
        ca_pem: &[u8],
        serial: &[u8],
        at: i64,
    ) -> Result<(), CrlStateError> {
        let verified: VerifiedCrl =
            verify_signed_crl(bytes, ca_pem).map_err(CrlStateError::Unavailable)?;
        verified
            .check_freshness(at, self.maximum_age_secs)
            .map_err(CrlStateError::Unavailable)?;
        if verified.is_revoked(serial) {
            Err(CrlStateError::Revoked)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
