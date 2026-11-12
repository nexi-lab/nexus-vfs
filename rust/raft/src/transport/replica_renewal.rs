//! Holder proof for an exact replica renewal intent. The issuer supplies the
//! predecessor's current control-zone view and separately authenticates the
//! actual TLS caller. Publication rechecks authority in the original Raft txn.

use contracts::replica_credential::{
    ReplicaCertificateIntent, ReplicaCredential, ReplicaIssuanceChange, ReplicaIssuanceRequest,
};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Transient proof supplied by the predecessor's key holder.
pub struct ReplicaRenewalProof<'a> {
    pub issued_at_unix_ms: u64,
    pub signature: &'a [u8],
}

fn renewal_intent(
    request: &ReplicaIssuanceRequest,
) -> Result<(&ReplicaCertificateIntent, &str), String> {
    request.validate()?;
    match &request.change {
        ReplicaIssuanceChange::Prepare {
            intent,
            renews: Some(previous),
        } => Ok((intent, previous)),
        _ => Err("replica renewal requires an exact preparation and predecessor".into()),
    }
}

/// Canonical proof bytes: domain, ordered length-prefixed identity fields,
/// fixed-width big-endian revisions/times, then certificate/key commitments.
/// Both producer and verifier use this function; durable request encoding stays
/// owned by the existing replica contract.
pub fn replica_renewal_message(
    request: &ReplicaIssuanceRequest,
    previous_cert_der: &[u8],
    caller_cert_der: &[u8],
    issued_at_unix_ms: u64,
) -> Result<Vec<u8>, String> {
    let (intent, previous) = renewal_intent(request)?;
    if previous_cert_der.is_empty()
        || previous_cert_der.len() > 20 * 1024
        || caller_cert_der.is_empty()
        || caller_cert_der.len() > 16 * 1024
    {
        return Err("replica renewal certificates exceed their size bounds".into());
    }
    let binding = &intent.binding;
    let certificate = &intent.certificate;
    let mut hash = Sha256::new();
    hash.update(b"nexus/replica-renewal/v1\0");
    for field in [
        request.operation_id.as_bytes(),
        previous.as_bytes(),
        binding.allocation.owner_id.as_bytes(),
        binding.allocation.allocation_id.as_bytes(),
        binding.storage.authority.as_bytes(),
        binding.storage.uid.as_bytes(),
        intent.subject_name.as_bytes(),
        certificate.serial.as_slice(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    for value in [
        binding.replica_id,
        binding.revision,
        binding.generation,
        intent.issuer_revision,
        issued_at_unix_ms,
    ] {
        hash.update(value.to_be_bytes());
    }
    hash.update(certificate.not_before_unix_s.to_be_bytes());
    hash.update(certificate.not_after_unix_s.to_be_bytes());
    hash.update(certificate.issuer_sha256);
    for bytes in [
        certificate.subject_public_key_info_der.as_slice(),
        certificate.tbs_certificate_der.as_slice(),
        previous_cert_der,
        caller_cert_der,
    ] {
        hash.update(Sha256::digest(bytes));
    }
    Ok(hash.finalize().to_vec())
}

/// Verify possession of the currently published predecessor's key, bound to
/// the original renewal operation, exact new intent and authenticated caller.
/// `previous` must come from `credential(previous_id)` at a current ReadIndex.
/// The issuer also checks the caller's policy and CRL before prepare/publication;
/// this pure proof verifier confers no controller or zone admission authority.
pub fn verify_replica_renewal(
    request: &ReplicaIssuanceRequest,
    previous_id: &str,
    previous: &ReplicaCredential,
    caller_cert_der: &[u8],
    ca_pem: &[u8],
    proof: &ReplicaRenewalProof<'_>,
    now_unix_ms: u64,
) -> Result<(), String> {
    let (intent, renews) = renewal_intent(request)?;
    previous.intent.validate_shape()?;
    if renews != previous_id
        || previous.revoked
        || previous.authority_denial.is_some()
        || previous.intent.binding != intent.binding
        || previous.intent.issuer_revision != intent.issuer_revision
        || previous.intent.subject_name != intent.subject_name
        || previous.intent.certificate.issuer_sha256 != intent.certificate.issuer_sha256
    {
        return Err("replica renewal requires the current original allocation and issuer".into());
    }
    let previous_der = previous
        .certificate_der
        .as_deref()
        .ok_or("replica renewal requires a published predecessor")?;
    if proof.signature.is_empty() || proof.signature.len() > 128 || ca_pem.len() > 64 * 1024 {
        return Err("replica renewal proof exceeds its size bound".into());
    }
    if proof.issued_at_unix_ms > now_unix_ms.saturating_add(1_000)
        || now_unix_ms.saturating_sub(proof.issued_at_unix_ms) > 30_000
    {
        return Err("replica renewal proof is outside its validity window".into());
    }
    let message = replica_renewal_message(
        request,
        previous_der,
        caller_cert_der,
        proof.issued_at_unix_ms,
    )?;
    let (rest, cert) = X509Certificate::from_der(previous_der)
        .map_err(|_| "invalid predecessor certificate DER")?;
    let (caller_rest, caller) = X509Certificate::from_der(caller_cert_der)
        .map_err(|_| "invalid replica controller certificate DER")?;
    let ca = ::pem::parse(ca_pem).map_err(|_| "invalid replica issuer PEM")?;
    let (ca_rest, ca_cert) =
        X509Certificate::from_der(ca.contents()).map_err(|_| "invalid replica issuer DER")?;
    let now = ASN1Time::from_timestamp(
        i64::try_from(now_unix_ms / 1_000).map_err(|_| "invalid replica renewal time")?,
    )
    .map_err(|_| "invalid replica renewal time")?;
    if !rest.is_empty()
        || !caller_rest.is_empty()
        || !ca_rest.is_empty()
        || !cert.validity().is_valid_at(now)
        || !caller.validity().is_valid_at(now)
        || !ca_cert.validity().is_valid_at(now)
        || Sha256::digest(ca.contents()).as_slice() != intent.certificate.issuer_sha256
    {
        return Err("replica renewal requires current exact certificate authorities".into());
    }
    let original = &previous.intent.certificate;
    if cert.tbs_certificate.as_ref() != original.tbs_certificate_der
        || cert.raw_serial() != original.serial
        || cert.public_key().raw != original.subject_public_key_info_der
        || cert.validity().not_before.timestamp() != original.not_before_unix_s
        || cert.validity().not_after.timestamp() != original.not_after_unix_s
        || lib::transport_primitives::authorship::owner_from_x509(&cert).as_deref()
            != Some(intent.binding.allocation.owner_id.as_str())
        || lib::transport_primitives::replica_node_id_from_x509(&cert)?
            != Some(intent.binding.replica_id)
    {
        return Err("replica renewal predecessor differs from its committed identity".into());
    }
    let lifetime = intent.certificate.not_after_unix_s - intent.certificate.not_before_unix_s;
    let previous_lifetime = original.not_after_unix_s - original.not_before_unix_s;
    if lifetime > previous_lifetime {
        return Err("replica renewal cannot increase credential lifetime".into());
    }
    let subject = lib::transport_primitives::authorship::verify_x509(
        &message,
        proof.signature,
        &cert,
        ca_pem,
    )?;
    if subject != intent.subject_name {
        return Err("replica renewal predecessor has another subject".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
