//! CA-plane proof verification for renewing a live execution controller.

use crate::agent_minter::SessionRenewal;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Canonical request bytes shared with the Node SDK. No caller-selected identity.
pub fn session_renewal_message(
    session_cert_der: &[u8],
    caller_cert_der: &[u8],
    validity_secs: u64,
    issued_at_unix_ms: u64,
) -> Vec<u8> {
    let mut message = b"nexus/session-renewal/v1\0".to_vec();
    message.extend_from_slice(&Sha256::digest(session_cert_der));
    message.extend_from_slice(&Sha256::digest(caller_cert_der));
    message.extend_from_slice(&validity_secs.to_be_bytes());
    message.extend_from_slice(&issued_at_unix_ms.to_be_bytes());
    message
}

/// Facts derived from a verified certificate, never from request identity fields.
pub struct VerifiedSessionRenewal {
    pub subject_id: String,
    pub owner_id: String,
    pub serial: Vec<u8>,
    pub runtime_server_name: Option<String>,
}

/// Verify the existing key, issuer, credential lifetime and requester binding.
/// Revocation and the replicated minter allow-list are the issuer's policy.
pub fn verify_session_renewal(
    renewal: &SessionRenewal<'_>,
    caller_cert_der: &[u8],
    ca_pem: &[u8],
    now_unix_ms: u64,
) -> Result<VerifiedSessionRenewal, String> {
    if renewal.cert_pem.len() > 16 * 1024 || renewal.proof.len() > 128 {
        return Err("session renewal proof exceeds its size bound".into());
    }
    if renewal.issued_at_unix_ms > now_unix_ms.saturating_add(1_000)
        || now_unix_ms.saturating_sub(renewal.issued_at_unix_ms) > 30_000
    {
        return Err("session renewal proof is outside its validity window".into());
    }
    let pem = ::pem::parse(renewal.cert_pem).map_err(|_| "invalid session certificate PEM")?;
    let (_, cert) =
        X509Certificate::from_der(pem.contents()).map_err(|_| "invalid session certificate DER")?;
    let (_, caller) =
        X509Certificate::from_der(caller_cert_der).map_err(|_| "invalid minter certificate DER")?;
    let now = ASN1Time::from_timestamp((now_unix_ms / 1_000) as i64)
        .map_err(|_| "invalid renewal time")?;
    if !cert.validity().is_valid_at(now) || !caller.validity().is_valid_at(now) {
        return Err("session renewal requires current certificates".into());
    }
    let previous_validity =
        cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
    if renewal.validity_secs == 0
        || renewal.validity_secs > u64::try_from(previous_validity).unwrap_or(0)
    {
        return Err("session renewal cannot increase credential lifetime".into());
    }
    let message = session_renewal_message(
        pem.contents(),
        caller_cert_der,
        renewal.validity_secs,
        renewal.issued_at_unix_ms,
    );
    let subject_id = lib::transport_primitives::authorship::verify(
        &message,
        renewal.proof,
        renewal.cert_pem,
        ca_pem,
    )?;
    if !subject_id.starts_with("session-") {
        return Err("only session credentials can be renewed".into());
    }
    let owner_id = lib::transport_primitives::authorship::owner_from_x509(&cert)
        .filter(|owner| !owner.is_empty())
        .ok_or("session renewal requires a signed owner")?;
    let runtime_server_name = lib::transport_primitives::user_runtime_name_from_x509(&cert)?;
    Ok(VerifiedSessionRenewal {
        subject_id,
        owner_id,
        serial: cert.raw_serial().to_vec(),
        runtime_server_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{generate_agent_cert, generate_session_agent_cert, generate_zone_ca};

    struct Fixture {
        ca: Vec<u8>,
        cert: Vec<u8>,
        key: Vec<u8>,
        caller: Vec<u8>,
        now: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let (ca, ca_key) = generate_zone_ca("root").unwrap();
            let (cert, key) =
                generate_session_agent_cert("session-fixture", "alice", 300, &ca, &ca_key).unwrap();
            let (caller, _) = generate_agent_cert("moss", &ca, &ca_key).unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            Self {
                ca,
                cert,
                key,
                caller: ::pem::parse(caller).unwrap().into_contents(),
                now,
            }
        }

        fn proof(&self, validity: u64, issued_at: u64) -> Vec<u8> {
            lib::transport_primitives::authorship::sign(
                &session_renewal_message(
                    ::pem::parse(&self.cert).unwrap().contents(),
                    &self.caller,
                    validity,
                    issued_at,
                ),
                &self.key,
            )
            .unwrap()
        }

        fn verify(
            &self,
            validity: u64,
            issued_at: u64,
            proof: &[u8],
            now: u64,
        ) -> Result<VerifiedSessionRenewal, String> {
            verify_session_renewal(
                &SessionRenewal {
                    cert_pem: &self.cert,
                    validity_secs: validity,
                    issued_at_unix_ms: issued_at,
                    proof,
                },
                &self.caller,
                &self.ca,
                now,
            )
        }
    }

    #[test]
    fn renewal_derives_owner_and_actor_from_the_signed_certificate() {
        let f = Fixture::new();
        let verified = f.verify(300, f.now, &f.proof(300, f.now), f.now).unwrap();
        assert_eq!(verified.owner_id, "alice");
        assert_eq!(verified.subject_id, "session-fixture");
        assert!(!verified.serial.is_empty());
    }

    #[test]
    fn renewal_rejects_wrong_key_and_changed_certificate_or_parameters() {
        let mut f = Fixture::new();
        let proof = f.proof(300, f.now);
        assert!(f.verify(299, f.now, &proof, f.now).is_err());
        assert!(f.verify(300, f.now + 1, &proof, f.now).is_err());
        let other = Fixture::new();
        assert!(f
            .verify(300, f.now, &other.proof(300, f.now), f.now)
            .is_err());
        f.cert = other.cert;
        assert!(f.verify(300, f.now, &proof, f.now).is_err());
    }

    #[test]
    fn renewal_proof_is_bound_to_the_minters_tls_leaf() {
        let mut f = Fixture::new();
        let proof = f.proof(300, f.now);
        f.caller = Fixture::new().caller;
        assert!(f.verify(300, f.now, &proof, f.now).is_err());
    }

    #[test]
    fn renewal_rejects_expired_credentials_and_stale_or_future_proofs() {
        let f = Fixture::new();
        for issued in [f.now - 30_001, f.now + 1_001] {
            assert!(f.verify(300, issued, &f.proof(300, issued), f.now).is_err());
        }
        let expired = f.now + 301_000;
        assert!(f
            .verify(300, expired, &f.proof(300, expired), expired)
            .is_err());
    }

    #[test]
    fn renewal_cannot_increase_the_signed_credential_lifetime() {
        let f = Fixture::new();
        for validity in [0, 301, u64::MAX] {
            assert!(f
                .verify(validity, f.now, &f.proof(validity, f.now), f.now)
                .is_err());
        }
    }

    #[test]
    fn renewal_requires_its_own_issuer_and_a_bounded_session_proof() {
        let mut f = Fixture::new();
        let proof = f.proof(300, f.now);
        f.ca = Fixture::new().ca;
        assert!(f.verify(300, f.now, &proof, f.now).is_err());
        let f = Fixture::new();
        assert!(f.verify(300, f.now, &[0; 129], f.now).is_err());
        let mut f = Fixture::new();
        f.cert = vec![0; 16 * 1024 + 1];
        assert!(f.verify(300, f.now, &proof, f.now).is_err());
    }
}
