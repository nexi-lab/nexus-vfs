//! Durable caller-owned key/request, with no automatic RPC or replacement.
//! The native deploy adapter must first resolve this binding through its
//! owner-checked managed host. A path or receipt does not confer that authority.

use std::path::{Path, PathBuf};

use lib::transport_primitives::{
    create_secret, first_certificate_der, protect_secret, AgentCredential, CREDENTIAL_MANIFEST,
};
use prost::Message;
use rcgen::{CertificateParams, KeyPair, PublicKeyData, PKCS_ECDSA_P256_SHA256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::agent_minter::agent_csr_request_digest;
use crate::transport::proto::{AgentCsrRequest, AgentCsrResponse, AgentCsrState};

/// Resolved by the native owner-checked deployment path, never a frontend's
/// claim to a different Agent. The original operation ID survives uncertainty.
pub struct AgentCsrBinding<'a> {
    pub agent_name: &'a str,
    pub owner_id: &'a str,
    pub display_name: &'a str,
    pub operation_id: &'a str,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    request_protobuf: Vec<u8>,
    key_pem: String,
    ca_pem: Vec<u8>,
}

/// Intentionally has no Debug/Serialize implementation: it owns a private key.
pub struct PendingAgentCsr {
    request: AgentCsrRequest,
    key_pem: String,
    ca_pem: Vec<u8>,
}

fn request(
    binding: &AgentCsrBinding<'_>,
    csr: Vec<u8>,
    ca: &[u8],
) -> Result<AgentCsrRequest, String> {
    let der = first_certificate_der(ca, "expected Agent issuer")?;
    let request = AgentCsrRequest {
        agent_name: binding.agent_name.into(),
        owner_id: binding.owner_id.into(),
        display_name: binding.display_name.into(),
        operation_id: binding.operation_id.into(),
        csr_pem: csr,
        issuer_sha256: Sha256::digest(der).to_vec(),
    };
    agent_csr_request_digest(&request)?;
    Ok(request)
}

impl PendingAgentCsr {
    /// Creates a single owner-only document and syncs it before returning any
    /// request. Existing or partial files are refused, never overwritten.
    pub fn create(
        path: &Path,
        binding: &AgentCsrBinding<'_>,
        ca_pem: &[u8],
    ) -> Result<Self, String> {
        // Bound caller inputs before generating new key material.
        request(binding, vec![b'x'], ca_pem)?;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|_| "generate caller Agent key")?;
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .and_then(|csr| csr.pem())
            .map_err(|_| "serialize caller Agent CSR")?;
        let value = Self {
            request: request(binding, csr.into_bytes(), ca_pem)?,
            key_pem: key.serialize_pem(),
            ca_pem: ca_pem.to_vec(),
        };
        let document = Document {
            schema_version: 1,
            request_protobuf: value.request.encode_to_vec(),
            key_pem: value.key_pem.clone(),
            ca_pem: value.ca_pem.clone(),
        };
        let encoded = serde_json::to_vec(&document).map_err(|_| "encode pending Agent CSR")?;
        create_secret(path, &encoded).map_err(|e| format!("persist pending Agent CSR: {e}"))?;
        Ok(value)
    }

    /// Explicit recovery reads the original request/key. It refuses corruption,
    /// changed owner/name/operation/issuer and never generates replacement keys.
    pub fn load(path: &Path, binding: &AgentCsrBinding<'_>, ca_pem: &[u8]) -> Result<Self, String> {
        protect_secret(path).map_err(|e| format!("protect pending Agent CSR: {e}"))?;
        let mut file =
            std::fs::File::open(path).map_err(|e| format!("open pending Agent CSR: {e}"))?;
        let mut raw = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(&mut file, 128 * 1024 + 1),
            &mut raw,
        )
        .map_err(|e| format!("read pending Agent CSR: {e}"))?;
        if raw.len() > 128 * 1024 {
            return Err("pending Agent CSR exceeds size bound".into());
        }
        let stored: Document =
            serde_json::from_slice(&raw).map_err(|_| "invalid pending Agent CSR")?;
        if stored.schema_version != 1 {
            return Err("unsupported pending Agent CSR version".into());
        }
        let actual = AgentCsrRequest::decode(stored.request_protobuf.as_slice())
            .map_err(|_| "invalid pending Agent request protobuf")?;
        let expected = request(binding, actual.csr_pem.clone(), ca_pem)?;
        if actual != expected || stored.ca_pem != ca_pem {
            return Err("pending Agent CSR binding or issuer changed".into());
        }
        let key = KeyPair::from_pem(&stored.key_pem).map_err(|_| "invalid pending Agent key")?;
        let csr_key = crate::transport::verified_csr_key(&actual.csr_pem)?;
        if key.subject_public_key_info() != csr_key.subject_public_key_info() {
            return Err("pending Agent CSR and private key differ".into());
        }
        Ok(Self {
            request: actual,
            key_pem: stored.key_pem,
            ca_pem: stored.ca_pem,
        })
    }

    /// Borrow the exact persisted protobuf request for issue or read-only query.
    /// This type performs no network calls, retry or uncertainty classification.
    pub fn request(&self) -> &AgentCsrRequest {
        &self.request
    }

    /// Publish the native credential format only after validating the final
    /// authenticated issuer response. The manifest is created last. A repeated
    /// explicit publication accepts identical files; conflicts/partial bytes
    /// refuse without replacing them. This does not activate a managed runtime.
    pub fn publish(
        &self,
        response: &AgentCsrResponse,
        directory: &Path,
    ) -> Result<PathBuf, String> {
        let certificate = self.verify(response)?;
        let manifest = AgentCredential::for_bundle(&self.request.agent_name);
        std::fs::create_dir_all(directory)
            .map_err(|e| format!("create Agent bundle directory: {e}"))?;
        let exact_file = |name: &str, bytes: &[u8]| -> Result<(), String> {
            let path = directory.join(name);
            match create_secret(&path, bytes) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if std::fs::symlink_metadata(&path)
                        .map_err(|e| e.to_string())?
                        .file_type()
                        .is_symlink()
                        || std::fs::read(&path).map_err(|e| e.to_string())? != bytes
                    {
                        return Err(format!("conflicting or partial Agent bundle file: {name}"));
                    }
                    protect_secret(&path)
                        .map_err(|e| format!("protect recovered Agent bundle file: {e}"))?;
                    Ok(())
                }
                Err(e) => Err(format!("persist Agent bundle file {name}: {e}")),
            }
        };
        exact_file(&manifest.key, self.key_pem.as_bytes())?;
        exact_file(&manifest.cert, &certificate)?;
        exact_file(&manifest.ca, &self.ca_pem)?;
        exact_file(
            CREDENTIAL_MANIFEST,
            &serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
        )?;
        Ok(directory.join(CREDENTIAL_MANIFEST))
    }

    fn verify(&self, response: &AgentCsrResponse) -> Result<Vec<u8>, String> {
        if response.state != AgentCsrState::Finalized as i32
            || response.error.is_some()
            || response.agent_name != self.request.agent_name
            || response.owner_id != self.request.owner_id
            || response.operation_id != self.request.operation_id
            || response.request_sha256 != agent_csr_request_digest(&self.request)?
            || response.intent_sha256.len() != 32
            || response.serial.is_empty()
            || response.certificate_der.len() > 16 * 1024
        {
            return Err("Agent issuer response is not the bound finalized operation".into());
        }
        let ca_der = first_certificate_der(&self.ca_pem, "expected Agent issuer")?;
        if first_certificate_der(&response.ca_pem, "returned Agent issuer")? != ca_der {
            return Err("Agent issuer response changed the CA".into());
        }
        let (rest, ca) =
            X509Certificate::from_der(&ca_der).map_err(|_| "invalid Agent issuer DER")?;
        if !rest.is_empty()
            || !ca.validity().is_valid()
            || !ca
                .basic_constraints()
                .map_err(|_| "invalid issuer constraints")?
                .is_some_and(|v| v.value.ca)
            || ca
                .key_usage()
                .map_err(|_| "invalid issuer usage")?
                .is_some_and(|v| !v.value.key_cert_sign())
        {
            return Err("Agent issuer is not a current signing CA".into());
        }
        let (rest, leaf) = X509Certificate::from_der(&response.certificate_der)
            .map_err(|_| "invalid Agent certificate DER")?;
        let key = KeyPair::from_pem(&self.key_pem).map_err(|_| "invalid pending Agent key")?;
        if !rest.is_empty()
            || !leaf.validity().is_valid()
            || leaf.validity().not_after > ca.validity().not_after
            || leaf.raw_serial() != response.serial
            || leaf.public_key().raw != key.subject_public_key_info()
            || leaf
                .basic_constraints()
                .map_err(|_| "invalid Agent constraints")?
                .is_some_and(|v| v.value.ca)
        {
            return Err("Agent certificate does not match the current caller key/profile".into());
        }
        leaf.verify_signature(Some(ca.public_key()))
            .map_err(|_| "Agent certificate issuer signature differs")?;
        let san = leaf
            .subject_alternative_name()
            .map_err(|_| "invalid Agent SAN")?
            .ok_or("missing Agent SAN")?;
        let identity = lib::agent_identity::agent_identity_uri(&self.request.agent_name);
        if san.value.general_names.as_slice() != [GeneralName::URI(identity.as_str())] {
            return Err("Agent certificate has a different or privileged identity".into());
        }
        let usage = leaf
            .key_usage()
            .map_err(|_| "invalid Agent usage")?
            .ok_or("missing Agent usage")?;
        let extended = leaf
            .extended_key_usage()
            .map_err(|_| "invalid Agent extended usage")?
            .ok_or("missing Agent extended usage")?;
        if usage.value.flags != 1
            || !extended.value.client_auth
            || extended.value.server_auth
            || extended.value.any
            || extended.value.code_signing
            || extended.value.email_protection
            || extended.value.time_stamping
            || extended.value.ocsp_signing
            || !extended.value.other.is_empty()
        {
            return Err("Agent certificate carries an invalid or privileged usage".into());
        }
        Ok(::pem::encode(&::pem::Pem::new(
            "CERTIFICATE",
            response.certificate_der.clone(),
        ))
        .into_bytes())
    }
}

#[cfg(test)]
mod tests;
