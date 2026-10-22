//! Prepare exact unsigned TBS bytes without access to the CA private key, then
//! sign ONLY a committed intent through the existing CA loader and rcgen signer.

use super::*;
use contracts::{AgentCertificateIntent, SignedAgentCertificate};
use rcgen::{PublicKeyData, SignatureAlgorithm, SigningKey, SubjectPublicKeyInfo};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Serialize the existing profile using the issuer's PUBLIC key only. The
/// callback refuses signing, so no valid candidate certificate is produced.
struct CaptureTbs {
    public_key: SubjectPublicKeyInfo,
    captured: RefCell<Option<Vec<u8>>>,
}

impl PublicKeyData for CaptureTbs {
    fn der_bytes(&self) -> &[u8] {
        self.public_key.der_bytes()
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.public_key.algorithm()
    }
}

impl SigningKey for CaptureTbs {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        if message.len() > 16 * 1024 {
            return Err(rcgen::Error::UnsupportedSignatureAlgorithm);
        }
        self.captured.replace(Some(message.to_vec()));
        Err(rcgen::Error::UnsupportedSignatureAlgorithm)
    }
}

/// Never let an encoder/profile change cause the CA to sign different TBS
/// bytes than the immutable winning intent. The check precedes key.sign().
struct CommittedTbsKey<'a> {
    key: &'a KeyPair,
    expected: &'a [u8],
}

impl PublicKeyData for CommittedTbsKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.key.der_bytes()
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.key.algorithm()
    }
}

impl SigningKey for CommittedTbsKey<'_> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        if message != self.expected {
            return Err(rcgen::Error::UnsupportedSignatureAlgorithm);
        }
        self.key.sign(message)
    }
}

fn public_issuer(ca_pem: &[u8]) -> Result<(Vec<u8>, SubjectPublicKeyInfo, i64), String> {
    if ca_pem.len() > 64 * 1024 {
        return Err("issuer certificate exceeds size bound".into());
    }
    let pem = ::pem::parse(ca_pem).map_err(|_| "invalid issuer certificate PEM")?;
    if pem.contents().len() > 16 * 1024 {
        return Err("issuer DER exceeds size bound".into());
    }
    let (rest, ca) = X509Certificate::from_der(pem.contents()).map_err(|_| "invalid issuer DER")?;
    if !rest.is_empty() || !ca.validity().is_valid() {
        return Err("issuer must be current".into());
    }
    if !ca
        .basic_constraints()
        .map_err(|_| "invalid issuer constraints")?
        .is_some_and(|v| v.value.ca)
    {
        return Err("issuer must be a CA".into());
    }
    if ca
        .key_usage()
        .map_err(|_| "invalid issuer usage")?
        .is_some_and(|v| !v.value.key_cert_sign())
    {
        return Err("issuer does not permit certificate signing".into());
    }
    let key = SubjectPublicKeyInfo::from_der(ca.public_key().raw)
        .map_err(|_| "unsupported issuer public key")?;
    let expiry = ca.validity().not_after.timestamp();
    Ok((pem.into_contents(), key, expiry))
}

fn params_for_intent(intent: &AgentCertificateIntent) -> Result<CertificateParams, String> {
    intent.validate_shape()?;
    let mut params =
        agent_certificate_params(&intent.agent_name, None, time::Duration::days(90), None)?;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&intent.serial));
    params.not_before = time::OffsetDateTime::from_unix_timestamp(intent.not_before_unix_s)
        .map_err(|_| "invalid intent start")?;
    params.not_after = time::OffsetDateTime::from_unix_timestamp(intent.not_after_unix_s)
        .map_err(|_| "invalid intent expiry")?;
    Ok(params)
}

/// Verify possession and prepare an unsigned ordinary-agent intent. Takes no
/// CA private key. The authorized name is issuer policy, never CSR policy.
/// Commit the result atomically BEFORE calling sign_committed_agent_intent.
pub fn prepare_agent_csr_intent(
    name: &str,
    csr_pem: &[u8],
    ca_pem: &[u8],
) -> Result<AgentCertificateIntent, String> {
    use rand::Rng;
    let key = verified_csr_key(csr_pem)?;
    let (ca_der, public_key, issuer_expiry) = public_issuer(ca_pem)?;
    let start = time::OffsetDateTime::now_utc().unix_timestamp();
    let expiry = (start + 90 * 86400).min(issuer_expiry);
    if expiry <= start {
        return Err("issuer has no remaining validity".into());
    }
    let mut serial = [0u8; 20];
    rand::rng().fill_bytes(&mut serial);
    serial[0] = (serial[0] & 0x7f) | 1;
    let mut intent = AgentCertificateIntent {
        version: 1,
        agent_name: name.into(),
        issuer_sha256: Sha256::digest(&ca_der).into(),
        subject_public_key_info_der: key.subject_public_key_info(),
        serial: serial.to_vec(),
        not_before_unix_s: start,
        not_after_unix_s: expiry,
        // Filled by the public-key-only serializer, never persisted as this placeholder.
        tbs_certificate_der: vec![0],
    };
    let params = params_for_intent(&intent)?;
    let capture = CaptureTbs {
        public_key,
        captured: RefCell::new(None),
    };
    let ca_str = std::str::from_utf8(ca_pem).map_err(|_| "invalid issuer PEM encoding")?;
    let issuer =
        Issuer::from_ca_cert_pem(ca_str, &capture).map_err(|_| "invalid issuer metadata")?;
    if params.signed_by(&key, &issuer).is_ok() {
        return Err("unsigned serializer unexpectedly signed".into());
    }
    drop(issuer);
    intent.tbs_certificate_der = capture
        .captured
        .into_inner()
        .ok_or("failed to serialize unsigned certificate")?;
    intent.validate_shape()?;
    Ok(intent)
}

/// The caller must have selected this exact intent through committed storage.
/// This adapter has no storage or RPC and cannot elect a different identity.
pub fn sign_committed_agent_intent(
    intent: &AgentCertificateIntent,
    ca_pem: &[u8],
    ca_key_pem: &[u8],
) -> Result<SignedAgentCertificate, String> {
    let params = params_for_intent(intent)?;
    let (ca_der, public_key, expiry) = public_issuer(ca_pem)?;
    let actual_fingerprint: [u8; 32] = Sha256::digest(&ca_der).into();
    if actual_fingerprint != intent.issuer_sha256 || intent.not_after_unix_s > expiry {
        return Err("committed intent issuer changed".into());
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if now < intent.not_before_unix_s || now >= intent.not_after_unix_s {
        return Err("committed intent is not current; operator recovery required".into());
    }
    let subject = SubjectPublicKeyInfo::from_der(&intent.subject_public_key_info_der)
        .map_err(|_| "invalid committed SPKI")?;
    if subject.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        return Err("committed subject must use P-256".into());
    }
    let ca = ca_issuer_from_pem(ca_pem, ca_key_pem)?;
    if ca.key().der_bytes() != public_key.der_bytes()
        || ca.key().algorithm() != public_key.algorithm()
    {
        return Err("issuer certificate and private key do not match".into());
    }
    let guarded = CommittedTbsKey {
        key: ca.key(),
        expected: &intent.tbs_certificate_der,
    };
    let ca_str = std::str::from_utf8(ca_pem).map_err(|_| "invalid issuer PEM encoding")?;
    let issuer =
        Issuer::from_ca_cert_pem(ca_str, guarded).map_err(|_| "invalid issuer metadata")?;
    let cert = params
        .signed_by(&subject, &issuer)
        .map_err(|_| "refused to sign changed committed TBS")?;
    let (_, parsed) =
        X509Certificate::from_der(cert.der().as_ref()).map_err(|_| "invalid signed intent")?;
    let (_, ca_x509) = X509Certificate::from_der(&ca_der).map_err(|_| "invalid CA DER")?;
    parsed
        .verify_signature(Some(ca_x509.public_key()))
        .map_err(|_| "signed intent issuer mismatch")?;
    if parsed.tbs_certificate.as_ref() != intent.tbs_certificate_der
        || parsed.raw_serial() != intent.serial
    {
        return Err("signed intent TBS or serial mismatch".into());
    }
    Ok(SignedAgentCertificate {
        certificate_der: cert.der().to_vec(),
        tbs_certificate_der: parsed.tbs_certificate.as_ref().to_vec(),
        serial: parsed.raw_serial().to_vec(),
    })
}

#[cfg(test)]
mod tests;
