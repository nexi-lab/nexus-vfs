//! Shared validation of complete, direct-issuer X.509 CRLs.
//!
//! A valid signature is not freshness or rollback protection. Callers using
//! this for admission must also establish the current registered issuer and
//! authoritative snapshot, then enforce `check_freshness` at every admission.
//! This parser intentionally rejects delta/partitioned/indirect CRLs rather
//! than treating an incomplete revocation list as a complete one.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use x509_parser::{
    certificate::X509Certificate, extensions::ParsedExtension, prelude::FromDer,
    revocation_list::CertificateRevocationList,
};

const MAX_CRL_BYTES: usize = 1024 * 1024;
const MAX_REVOKED: usize = 16_384;
pub const CRL_MAXIMUM_AGE_SECS: u32 = 300;

/// Verified public CRL data. Only `verify_signed_crl` constructs it; no decode
/// path can turn caller-supplied fields into verified revocation evidence.
#[derive(Debug)]
pub struct VerifiedCrl {
    authority: [u8; 32],
    this_update: i64,
    next_update: i64,
    issuer_not_before: i64,
    issuer_not_after: i64,
    number: Vec<u8>,
    revoked: Vec<Vec<u8>>,
}

impl VerifiedCrl {
    pub fn authority(&self) -> &[u8; 32] {
        &self.authority
    }
    pub fn this_update(&self) -> i64 {
        self.this_update
    }
    pub fn next_update(&self) -> i64 {
        self.next_update
    }
    pub fn number(&self) -> &[u8] {
        &self.number
    }
    pub fn revoked_serials(&self) -> &[Vec<u8>] {
        &self.revoked
    }
    pub fn is_revoked(&self, serial: &[u8]) -> bool {
        self.revoked
            .iter()
            .any(|entry| unsigned(entry) == unsigned(serial))
    }

    /// Enforce a composition-root freshness budget, not a remote-request
    /// parameter. There is no clock-skew grace that extends revocation state.
    /// A fresh signed snapshot can still be a replay within this window; the
    /// authoritative source/rollback guard remains a separate prerequisite.
    pub fn check_freshness(&self, now_unix: i64, maximum_age_secs: u32) -> Result<(), String> {
        if maximum_age_secs == 0 || maximum_age_secs > CRL_MAXIMUM_AGE_SECS {
            return Err("CRL maximum age must be between 1 and 300 seconds".into());
        }
        if now_unix < self.issuer_not_before || now_unix > self.issuer_not_after {
            return Err("CRL issuer is not currently valid".into());
        }
        let age = now_unix
            .checked_sub(self.this_update)
            .ok_or("CRL clock difference overflow")?;
        if age < 0 || age > i64::from(maximum_age_secs) || now_unix >= self.next_update {
            return Err("CRL is future-dated, expired or outside the freshness budget".into());
        }
        Ok(())
    }
}

fn unsigned(serial: &[u8]) -> &[u8] {
    let first = serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or_else(|| serial.len().saturating_sub(1));
    &serial[first..]
}

/// Unsigned serial identity shared by signed CRLs and native revocation keys.
/// DER may add a leading zero octet to a positive INTEGER with its top bit set.
pub fn canonical_certificate_serial(serial: &[u8]) -> Result<&[u8], String> {
    let canonical = unsigned(serial);
    if serial.is_empty() || serial.len() > 21 || canonical.len() > 20 {
        return Err("certificate serial must be an unsigned integer of at most 20 octets".into());
    }
    Ok(canonical)
}

/// Address authority for an explicitly selected public CA. This digest is not
/// a trust grant or the complete-DER fingerprint used by the CA registry.
pub fn ca_spki_sha256(ca_pem: &[u8]) -> Result<[u8; 32], String> {
    if ca_pem.len() > 64 * 1024 {
        return Err("CA exceeds input bounds".into());
    }
    let der = super::foreign_ca::first_certificate_der(ca_pem, "CRL issuer")?;
    let (rest, ca) = X509Certificate::from_der(&der).map_err(|e| e.to_string())?;
    if !rest.is_empty() || !ca.is_ca() {
        return Err("expected one complete CA certificate".into());
    }
    Ok(Sha256::digest(ca.public_key().raw).into())
}

/// Verify under the explicitly selected public CA PEM. The CRL is bounded,
/// complete, single-issuer and signed; unknown critical or scope-changing
/// extensions refuse. This does not discover/trust an issuer from the CRL.
pub fn verify_signed_crl(crl_pem: &[u8], ca_pem: &[u8]) -> Result<VerifiedCrl, String> {
    if crl_pem.is_empty() || crl_pem.len() > MAX_CRL_BYTES || ca_pem.len() > 64 * 1024 {
        return Err("CRL or CA exceeds input bounds".into());
    }
    let ca_der = super::foreign_ca::first_certificate_der(ca_pem, "CRL issuer")?;
    let (rest, ca) = X509Certificate::from_der(&ca_der).map_err(|e| format!("CA DER: {e}"))?;
    if !rest.is_empty() || !ca.is_ca() {
        return Err("CRL issuer is not one complete CA certificate".into());
    }
    if !ca
        .key_usage()
        .map_err(|e| e.to_string())?
        .is_some_and(|usage| usage.value.crl_sign())
    {
        return Err("CRL issuer lacks cRLSign usage".into());
    }
    let blocks = ::pem::parse_many(crl_pem).map_err(|e| format!("CRL PEM: {e}"))?;
    if blocks.len() != 1 || blocks[0].tag() != "X509 CRL" {
        return Err("expected exactly one X509 CRL".into());
    }
    let (rest, crl) = CertificateRevocationList::from_der(blocks[0].contents())
        .map_err(|e| format!("CRL DER: {e}"))?;
    if !rest.is_empty()
        || crl.issuer() != ca.subject()
        || crl.signature_algorithm != crl.tbs_cert_list.signature
    {
        return Err("CRL issuer, signature algorithm or DER boundary mismatch".into());
    }
    crl.verify_signature(ca.public_key())
        .map_err(|e| format!("CRL signature: {e}"))?;
    let mut extensions = HashSet::new();
    for extension in crl.extensions() {
        let oid = extension.oid.to_id_string();
        if !extensions.insert(oid.clone())
            || matches!(oid.as_str(), "2.5.29.27" | "2.5.29.28" | "2.5.29.46")
            || extension.critical
            || matches!(
                extension.parsed_extension(),
                ParsedExtension::ParseError { .. }
            )
        {
            return Err("duplicate, unsupported or invalid CRL extension".into());
        }
    }
    let number = crl
        .crl_number()
        .ok_or("CRL number is required")?
        .to_bytes_be();
    if number.len() > 20 {
        return Err("CRL number exceeds 20 octets".into());
    }
    let this_update = crl.last_update().timestamp();
    let next_update = crl
        .next_update()
        .ok_or("CRL nextUpdate is required")?
        .timestamp();
    if next_update <= this_update {
        return Err("CRL update interval is empty or reversed".into());
    }
    let mut revoked = Vec::new();
    for entry in crl.iter_revoked_certificates() {
        if revoked.len() >= MAX_REVOKED || canonical_certificate_serial(entry.raw_serial()).is_err()
        {
            return Err("CRL revoked entries exceed bounds".into());
        }
        let mut extensions = HashSet::new();
        for extension in entry.extensions() {
            let oid = extension.oid.to_id_string();
            if !extensions.insert(oid.clone())
                || oid == "2.5.29.29"
                || extension.critical
                || matches!(
                    extension.parsed_extension(),
                    ParsedExtension::ParseError { .. }
                )
            {
                return Err("unsupported indirect or invalid CRL entry".into());
            }
        }
        if entry.reason_code().is_some_and(|(_, reason)| reason.0 == 8) {
            return Err("removeFromCRL is unsupported in a complete revocation snapshot".into());
        }
        revoked.push(entry.raw_serial().to_vec());
    }
    Ok(VerifiedCrl {
        authority: Sha256::digest(ca.public_key().raw).into(),
        this_update,
        next_update,
        number,
        revoked,
        issuer_not_before: ca.validity().not_before.timestamp(),
        issuer_not_after: ca.validity().not_after.timestamp(),
    })
}

#[cfg(test)]
mod tests;
