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
//! This is the crypto core, generic over the signed bytes. The mailbox layer
//! decides *what* is signed and carries `{from, sig, cert}` in the envelope.

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
    let (_, ca) = X509Certificate::from_der(&ca_der)
        .map_err(|e| format!("CA cert does not parse: {e}"))?;

    // 1. The cert is a genuine agent cert issued by this cluster CA.
    cert.verify_signature(Some(ca.public_key()))
        .map_err(|_| "agent cert does not chain to the cluster CA".to_string())?;

    // 2. It names an agent (a `nexus://agent/{name}` SAN).
    let name = crate::peer_identity::agent_name_from_x509(&cert)
        .ok_or_else(|| "cert carries no agent identity SAN".to_string())?;

    // 3. The signature over `message` is valid under the cert's public key.
    let public_key = cert.public_key().subject_public_key.data.as_ref();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, sig)
        .map_err(|_| "signature does not verify under the agent cert".to_string())?;

    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_raft::transport::{generate_agent_cert, generate_zone_ca};

    fn agent(name: &str, ca_pem: &[u8], ca_key_pem: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let grants = contracts::AgentGrants {
            is_admin: false,
            zone_perms: vec![("z".into(), "rw".into())],
        };
        generate_agent_cert(name, &grants, ca_pem, ca_key_pem).unwrap()
    }

    #[test]
    fn a_signature_verifies_and_names_the_signer() {
        let (ca, ca_key) = generate_zone_ca("z").unwrap();
        let (cert, key) = agent("win-ai", &ca, &ca_key);
        let msg = b"win-ai\x00hello from win";
        let sig = sign(msg, &key).unwrap();
        assert_eq!(verify(msg, &sig, &cert, &ca).unwrap(), "win-ai");
    }

    #[test]
    fn a_tampered_message_is_rejected() {
        let (ca, ca_key) = generate_zone_ca("z").unwrap();
        let (cert, key) = agent("win-ai", &ca, &ca_key);
        let sig = sign(b"original", &key).unwrap();
        assert!(verify(b"tampered", &sig, &cert, &ca).is_err());
    }

    #[test]
    fn a_cert_from_a_foreign_ca_is_rejected() {
        let (ca, _ca_key) = generate_zone_ca("z").unwrap();
        let (foreign_ca, foreign_ca_key) = generate_zone_ca("evil").unwrap();
        let (cert, key) = agent("win-ai", &foreign_ca, &foreign_ca_key);
        let msg = b"win-ai\x00hi";
        let sig = sign(msg, &key).unwrap();
        // Signed correctly, but its cert does not chain to OUR CA.
        assert!(verify(msg, &sig, &cert, &ca).is_err());
    }

    #[test]
    fn a_signature_from_another_agents_key_is_rejected() {
        let (ca, ca_key) = generate_zone_ca("z").unwrap();
        let (cert, _key) = agent("win-ai", &ca, &ca_key);
        let (_other_cert, other_key) = agent("mac-ai", &ca, &ca_key);
        let msg = b"win-ai\x00hi";
        // mac-ai signs, but win-ai's cert is presented -> the key does not match.
        let sig = sign(msg, &other_key).unwrap();
        assert!(verify(msg, &sig, &cert, &ca).is_err());
    }
}
