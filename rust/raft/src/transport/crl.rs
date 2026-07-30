//! Agent-cert revocation via a CA-signed Certificate Revocation List.
//!
//! A valid CA chain does not settle revocation: a stolen agent key still chains
//! to the cluster CA, so `peer_identity` still resolves it. The CRL closes that,
//! and it rides the CA's own trust plane — NOT raft:
//!
//! * the founder holds the revoked-serial file ([`revoked_serials_path`]) and
//!   CA-signs a CRL over it on demand ([`generate_crl`]);
//! * every other node fetches that CRL and verifies it against the CA cert it
//!   already holds ([`crl_revoked_serials`]), so a forged CRL cannot un-revoke
//!   or falsely revoke;
//! * `auth revoke` appends a serial ([`add_revoked_serial`]); the running
//!   `GetCrl` endpoint reads it live, so revocation needs no restart.
//!
//! Because the CRL is self-authenticating (CA-signed), it can travel over the
//! plaintext enroll plane — the same plane that hands out the CA itself.

use std::path::{Path, PathBuf};

/// Validity window stamped into a CRL's `next_update`. Cosmetic to our own
/// verification (which trusts the CA signature, not the clock) but honest to
/// any standard CRL reader; nodes refresh far more often than this regardless.
const CRL_VALIDITY_DAYS: i64 = 30;

/// The raw serial-number bytes of a certificate (PEM in). An agent cert's
/// serial is what the CRL revokes and what `resolve` matches a presented cert
/// against, so the mint side (recording a serial) and the resolve side read it
/// back the same way here.
pub fn serial_from_cert_pem(cert_pem: &[u8]) -> Result<Vec<u8>, String> {
    use x509_parser::prelude::*;
    let pem = ::pem::parse(cert_pem).map_err(|e| format!("cert PEM: {e}"))?;
    let (_, cert) =
        X509Certificate::from_der(pem.contents()).map_err(|e| format!("cert DER: {e}"))?;
    Ok(cert.raw_serial().to_vec())
}

/// Build a CA-signed X.509 Certificate Revocation List over `revoked_serials`
/// (each an agent cert's raw serial bytes, as from [`serial_from_cert_pem`]).
///
/// Because it is signed by the cluster CA, any node holding only the CA cert
/// can verify it and read the revoked set (see [`crl_revoked_serials`]) — so it
/// distributes like the CA itself, orthogonal to raft. `crl_number` must only
/// grow across successive CRLs so a stale one is detectable.
pub fn generate_crl(
    revoked_serials: &[Vec<u8>],
    crl_number: u64,
    ca_cert_pem: &[u8],
    ca_key_pem: &[u8],
) -> Result<Vec<u8>, String> {
    use rcgen::{
        CertificateRevocationListParams, RevocationReason, RevokedCertParams, SerialNumber,
    };
    let ca_issuer = super::certgen::ca_issuer_from_pem(ca_cert_pem, ca_key_pem)?;
    let now = time::OffsetDateTime::now_utc();
    let revoked_certs = revoked_serials
        .iter()
        .map(|s| RevokedCertParams {
            serial_number: SerialNumber::from(s.clone()),
            revocation_time: now,
            reason_code: Some(RevocationReason::Unspecified),
            invalidity_date: None,
        })
        .collect();
    let params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + time::Duration::days(CRL_VALIDITY_DAYS),
        crl_number: SerialNumber::from(crl_number),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let crl = params
        .signed_by(&ca_issuer)
        .map_err(|e| format!("Failed to sign CRL: {e}"))?;
    Ok(crl.pem().map_err(|e| format!("CRL PEM: {e}"))?.into_bytes())
}

/// Verify a CRL against the cluster CA and return the revoked serials (raw
/// bytes). A CRL not signed by the CA is rejected — that signature is exactly
/// what lets a node trust a CRL fetched over the plaintext CA plane, the same
/// way it trusts a cert.
pub fn crl_revoked_serials(crl_pem: &[u8], ca_cert_pem: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    use x509_parser::prelude::*;
    let ca = ::pem::parse(ca_cert_pem).map_err(|e| format!("CA PEM: {e}"))?;
    let (_, ca_cert) =
        X509Certificate::from_der(ca.contents()).map_err(|e| format!("CA DER: {e}"))?;
    let crl = ::pem::parse(crl_pem).map_err(|e| format!("CRL PEM: {e}"))?;
    let (_, crl) = CertificateRevocationList::from_der(crl.contents())
        .map_err(|e| format!("CRL DER: {e}"))?;
    crl.verify_signature(ca_cert.public_key())
        .map_err(|e| format!("CRL not signed by cluster CA: {e}"))?;
    Ok(crl
        .iter_revoked_certificates()
        .map(|rc| rc.raw_serial().to_vec())
        .collect())
}

/// The founder's revoked-serial file: one revoked agent-cert serial per line
/// (base64). SSOT for revocation state, and the seam between the offline
/// `auth revoke` (which appends here) and the running founder's `GetCrl` (which
/// reads here to build the CRL) — so a revocation takes effect without a
/// daemon restart. Founder-side only; joiners learn revocations via the CRL.
pub fn revoked_serials_path(data_dir: &Path) -> PathBuf {
    data_dir.join("tls").join("revoked-serials")
}

/// Read the revoked serials (raw bytes) from the founder's revoked-serial file.
/// A missing file is an empty list, and an unparseable line is skipped rather
/// than fatal — an unreadable line must not crash the CRL endpoint (revocation
/// is append-only, so serving what parses never un-revokes a written serial).
pub fn read_revoked_serials(path: &Path) -> Vec<Vec<u8>> {
    use base64::Engine;
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| base64::engine::general_purpose::STANDARD.decode(l).ok())
        .collect()
}

/// Append one revoked serial (raw bytes) to the founder's revoked-serial file,
/// creating it if absent and skipping a serial already present (idempotent).
/// This is the offline `auth revoke` write.
pub fn add_revoked_serial(path: &Path, serial: &[u8]) -> Result<(), String> {
    use base64::Engine;
    let mut serials = read_revoked_serials(path);
    if serials.iter().any(|s| s == serial) {
        return Ok(());
    }
    serials.push(serial.to_vec());
    let body = serials
        .iter()
        .map(|s| base64::engine::general_purpose::STANDARD.encode(s))
        .collect::<Vec<_>>()
        .join("\n");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, format!("{body}\n")).map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::certgen::{generate_agent_cert, generate_zone_ca};

    /// The revocation round-trip: an agent cert's serial is recoverable, a
    /// CA-signed CRL over it verifies against the CA and yields that serial
    /// back, and a CRL signed by a foreign CA is rejected — the CA signature is
    /// the whole trust of the CRL, exactly as it is for a cert.
    #[test]
    fn crl_over_an_agent_serial_verifies_only_under_its_ca() {
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let (cert_pem, _key) = generate_agent_cert("win-ai", &ca, &ca_key).unwrap();
        let serial = serial_from_cert_pem(&cert_pem).expect("read the cert serial");
        assert!(!serial.is_empty(), "a cert carries a non-empty serial");

        let crl = generate_crl(&[serial.clone()], 1, &ca, &ca_key).expect("sign the CRL");
        let revoked = crl_revoked_serials(&crl, &ca).expect("verify under the CA");
        assert!(
            revoked.iter().any(|s| s == &serial),
            "the revoked serial round-trips through the CRL"
        );

        // A CRL minted by a foreign CA claiming the same serial is rejected —
        // only the cluster CA can author a CRL a node will honor.
        let (evil_ca, evil_key) = generate_zone_ca("evil").unwrap();
        let forged = generate_crl(&[serial], 1, &evil_ca, &evil_key).unwrap();
        assert!(
            crl_revoked_serials(&forged, &ca).is_err(),
            "a foreign-CA CRL fails signature verification against the cluster CA"
        );
    }

    /// The revoked-serial file round-trips through base64, dedups on re-add, and
    /// reads empty when absent — the SSOT the founder's CRL is built from.
    #[test]
    fn revoked_serial_file_round_trips_and_dedups() {
        let tmp = tempfile::tempdir().unwrap();
        let path = revoked_serials_path(tmp.path());
        assert!(read_revoked_serials(&path).is_empty(), "absent file is empty");

        add_revoked_serial(&path, &[1, 2, 3]).unwrap();
        add_revoked_serial(&path, &[4, 5, 6]).unwrap();
        add_revoked_serial(&path, &[1, 2, 3]).unwrap(); // idempotent

        let got = read_revoked_serials(&path);
        assert_eq!(got.len(), 2, "duplicate serial is not re-added");
        assert!(got.contains(&vec![1, 2, 3]) && got.contains(&vec![4, 5, 6]));
    }
}
