//! Agent authorship — signing and verifying the unforgeable `from`.
//!
//! An agent signs its mailbox messages with the private key of its identity
//! cert; any consumer verifies the signature against the cluster CA. So a
//! message's authorship is provable **without trusting the node that ingested
//! it** — the cross-trust-domain property the signed-`from` design rests on: a
//! forged `from` (signed by a key that is not the named agent's, or presented
//! with a cert that does not chain to the CA) is rejected here no matter what
//! node accepted the write.
//!
//! Tier: this is a **tier-neutral library primitive** (like the TLS config
//! beside it), NOT a service or driver and NOT kernel policy. Signing is
//! client-side (the agent holds the key), verification is consumer-side; the
//! kernel only stores and replicates the opaque sealed bytes. A client (an
//! agent, a service) links this directly; the syscall boundary is unaffected
//! (`seal` → `sys_write` → … → `sys_read` → `open`).

use ring::signature::{
    EcdsaKeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING,
};

/// Sign `message` with an agent's EC P-256 private key (the PKCS#8 PEM
/// `certgen::generate_agent_cert` emits). Returns the ASN.1-DER signature.
pub fn sign(message: &[u8], key_pem: &[u8]) -> Result<Vec<u8>, String> {
    let key_der = ::pem::parse(key_pem)
        .map_err(|e| format!("agent key is not valid PEM: {e}"))?
        .into_contents();
    let rng = ring::rand::SystemRandom::new();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key_der, &rng)
        .map_err(|_| "agent key is not a valid P-256 PKCS#8 key".to_string())?;
    let sig = kp
        .sign(&rng, message)
        .map_err(|_| "signing failed".to_string())?;
    Ok(sig.as_ref().to_vec())
}

/// Verify that `message` was signed by the agent named in `cert_pem`, and that
/// `cert_pem` is a genuine agent identity cert issued by `ca_pem`. Returns the
/// agent name (the cert's `nexus://agent/{name}` SAN) on success.
///
/// Trusts **only** the cluster CA, not whoever delivered the message. Every
/// failure path returns `Err` (fail-closed).
pub fn verify(
    message: &[u8],
    sig: &[u8],
    cert_pem: &[u8],
    ca_pem: &[u8],
) -> Result<String, String> {
    use x509_parser::prelude::*;

    let cert_der = ::pem::parse(cert_pem)
        .map_err(|e| format!("agent cert is not valid PEM: {e}"))?
        .into_contents();
    let (_, cert) = X509Certificate::from_der(&cert_der)
        .map_err(|e| format!("agent cert does not parse: {e}"))?;
    let ca_der = ::pem::parse(ca_pem)
        .map_err(|e| format!("CA cert is not valid PEM: {e}"))?
        .into_contents();
    let (_, ca) =
        X509Certificate::from_der(&ca_der).map_err(|e| format!("CA cert does not parse: {e}"))?;

    // 1. The cert is a genuine agent cert issued by this cluster CA.
    cert.verify_signature(Some(ca.public_key()))
        .map_err(|_| "agent cert does not chain to the cluster CA".to_string())?;

    // 2. It names an agent (a `nexus://agent/{name}` SAN).
    let name = agent_name_from_x509(&cert)
        .ok_or_else(|| "cert carries no agent identity SAN".to_string())?;

    // 3. The signature over `message` is valid under the cert's public key.
    let public_key = cert.public_key().subject_public_key.data.as_ref();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, sig)
        .map_err(|_| "signature does not verify under the agent cert".to_string())?;

    Ok(name)
}

/// The `nexus://agent/{name}` SAN of a parsed cert, if any. Shared by [`verify`]
/// and `transport::peer_identity::from_der` so the agent-identity SAN is read
/// one way. `#[inline]` — a thin wrapper over `parse_agent_identity_uri` on the
/// per-connection auth path.
#[inline]
pub fn agent_name_from_x509(cert: &x509_parser::certificate::X509Certificate) -> Option<String> {
    use x509_parser::prelude::*;
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .and_then(|san| {
            san.value.general_names.iter().find_map(|gn| match gn {
                GeneralName::URI(uri) => crate::agent_identity::parse_agent_identity_uri(uri),
                _ => None,
            })
        })
}

/// Build a signed mailbox envelope: sign `content` with the agent's key and
/// wrap it as the JSON bytes a consumer can [`open`], carrying the signer's
/// `from` name, the signature, and the cert. `from` must be the agent's own
/// name (its cert SAN); [`open`] re-checks it against the cert.
///
/// The signature covers `content` only — `from` is bound by the cert SAN, which
/// `open` checks equals the envelope's `from` — so a stamp hook that (re)writes
/// `from` to the authenticated `agent_id` cannot invalidate the signature.
pub fn seal(
    from: &str,
    content: &[u8],
    key_pem: &[u8],
    cert_pem: &[u8],
) -> Result<Vec<u8>, String> {
    use base64::prelude::*;
    let sig = sign(content, key_pem)?;
    let envelope = serde_json::json!({
        "from": from,
        "content": BASE64_STANDARD.encode(content),
        "sig": BASE64_STANDARD.encode(sig),
        "cert": String::from_utf8_lossy(cert_pem),
    });
    serde_json::to_vec(&envelope).map_err(|e| format!("encode envelope: {e}"))
}

/// Verify and unwrap an envelope built by [`seal`]. Returns the verified
/// `(from, content)`: the cert chains to `ca_pem`, the signature over `content`
/// is valid under it, and its SAN name equals the envelope's `from`. Any
/// failure is `Err` (fail-closed) — this is the check that makes `from`
/// trustworthy without trusting whoever delivered the envelope.
pub fn open(envelope: &[u8], ca_pem: &[u8]) -> Result<(String, Vec<u8>), String> {
    use base64::prelude::*;
    let v: serde_json::Value =
        serde_json::from_slice(envelope).map_err(|e| format!("envelope is not JSON: {e}"))?;
    let from = v["from"].as_str().ok_or("envelope has no from")?;
    let content = BASE64_STANDARD
        .decode(v["content"].as_str().ok_or("envelope has no content")?)
        .map_err(|e| format!("content is not base64: {e}"))?;
    let sig = BASE64_STANDARD
        .decode(v["sig"].as_str().ok_or("envelope has no sig")?)
        .map_err(|e| format!("sig is not base64: {e}"))?;
    let cert = v["cert"].as_str().ok_or("envelope has no cert")?;

    let signer = verify(&content, &sig, cert.as_bytes(), ca_pem)?;
    if signer != from {
        return Err(format!(
            "envelope from={from:?} does not match the signing cert ({signer:?})"
        ));
    }
    Ok((from.to_string(), content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType,
        PKCS_ECDSA_P256_SHA256,
    };

    // Mint test certs with rcgen directly, so the authorship crypto is validated
    // without depending on the raft cert-gen driver (lib sits below raft).
    fn mint_ca(cn: &str) -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::default();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, cn);
        let ca = p.self_signed(&key).unwrap();
        (ca.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    fn mint_agent(name: &str, ca_pem: &[u8], ca_key_pem: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let ca_key = KeyPair::from_pem(std::str::from_utf8(ca_key_pem).unwrap()).unwrap();
        let issuer =
            Issuer::from_ca_cert_pem(std::str::from_utf8(ca_pem).unwrap(), ca_key).unwrap();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::default();
        p.subject_alt_names = vec![SanType::URI(
            crate::agent_identity::agent_identity_uri(name)
                .as_str()
                .try_into()
                .unwrap(),
        )];
        let cert = p.signed_by(&key, &issuer).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    #[test]
    fn a_signature_verifies_and_names_the_signer() {
        let (ca, ca_key) = mint_ca("z");
        let (cert, key) = mint_agent("win-ai", &ca, &ca_key);
        let msg = b"win-ai\x00hello from win";
        let sig = sign(msg, &key).unwrap();
        assert_eq!(verify(msg, &sig, &cert, &ca).unwrap(), "win-ai");
    }

    #[test]
    fn a_tampered_message_is_rejected() {
        let (ca, ca_key) = mint_ca("z");
        let (cert, key) = mint_agent("win-ai", &ca, &ca_key);
        let sig = sign(b"original", &key).unwrap();
        assert!(verify(b"tampered", &sig, &cert, &ca).is_err());
    }

    #[test]
    fn a_cert_from_a_foreign_ca_is_rejected() {
        let (ca, _ca_key) = mint_ca("z");
        let (foreign_ca, foreign_ca_key) = mint_ca("evil");
        let (cert, key) = mint_agent("win-ai", &foreign_ca, &foreign_ca_key);
        let msg = b"win-ai\x00hi";
        let sig = sign(msg, &key).unwrap();
        // Signed correctly, but its cert does not chain to OUR CA.
        assert!(verify(msg, &sig, &cert, &ca).is_err());
    }

    #[test]
    fn a_signature_from_another_agents_key_is_rejected() {
        let (ca, ca_key) = mint_ca("z");
        let (cert, _key) = mint_agent("win-ai", &ca, &ca_key);
        let (_other_cert, other_key) = mint_agent("mac-ai", &ca, &ca_key);
        let msg = b"win-ai\x00hi";
        // mac-ai signs, but win-ai's cert is presented -> the key does not match.
        let sig = sign(msg, &other_key).unwrap();
        assert!(verify(msg, &sig, &cert, &ca).is_err());
    }

    #[test]
    fn a_sealed_envelope_opens_to_its_signer_and_content() {
        let (ca, ca_key) = mint_ca("z");
        let (cert, key) = mint_agent("win-ai", &ca, &ca_key);
        let env = seal("win-ai", b"hello mac", &key, &cert).unwrap();
        let (from, content) = open(&env, &ca).unwrap();
        assert_eq!(from, "win-ai");
        assert_eq!(content, b"hello mac");
    }

    #[test]
    fn an_envelope_claiming_someone_elses_from_is_rejected() {
        let (ca, ca_key) = mint_ca("z");
        let (cert, key) = mint_agent("win-ai", &ca, &ca_key);
        // Sealed with win-ai's key + cert, but the envelope claims from=mac-ai.
        let env = seal("mac-ai", b"hi", &key, &cert).unwrap();
        assert!(open(&env, &ca).is_err(), "from must match the signing cert");
    }

    #[test]
    fn a_tampered_sealed_envelope_is_rejected() {
        use base64::prelude::*;
        let (ca, ca_key) = mint_ca("z");
        let (cert, key) = mint_agent("win-ai", &ca, &ca_key);
        let env = seal("win-ai", b"original", &key, &cert).unwrap();
        // Swap the content for different bytes; the signature no longer covers it.
        let mut v: serde_json::Value = serde_json::from_slice(&env).unwrap();
        v["content"] = serde_json::json!(BASE64_STANDARD.encode(b"tampered"));
        let tampered = serde_json::to_vec(&v).unwrap();
        assert!(open(&tampered, &ca).is_err());
    }
}
