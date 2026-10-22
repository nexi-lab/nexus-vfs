use super::*;
use lib::transport_primitives::authorship;
use rcgen::{CustomExtension, PublicKeyData, PKCS_ECDSA_P384_SHA384};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

fn request(params: CertificateParams, key: &KeyPair) -> Vec<u8> {
    params
        .serialize_request(key)
        .unwrap()
        .pem()
        .unwrap()
        .into_bytes()
}

fn caller() -> (KeyPair, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = request(CertificateParams::default(), &key);
    (key, csr)
}

fn issuer(adjust: impl FnOnce(&mut CertificateParams)) -> (Vec<u8>, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let now = time::OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + time::Duration::days(365);
    params
        .distinguished_name
        .push(DnType::CommonName, "isolated CSR fixture issuer");
    adjust(&mut params);
    let cert = params.self_signed(&key).unwrap();
    (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
}

fn untrusted_request(key: &KeyPair) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![
        SanType::URI("nexus://agent/forged".try_into().unwrap()),
        SanType::URI("nexus://owner/forged".try_into().unwrap()),
        SanType::URI("nexus://zone/forged/node/1".try_into().unwrap()),
        SanType::DnsName("attacker.invalid".try_into().unwrap()),
    ];
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::Any,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, "forged administrator");
    request(params, key)
}

fn assert_leaf(cert: &X509Certificate<'_>) {
    assert!(!cert
        .basic_constraints()
        .unwrap()
        .is_some_and(|bc| bc.value.ca));
    assert!(cert.validity().is_valid());
    assert!(
        cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp()
            <= 90 * 86400
    );
    let usage = cert.key_usage().unwrap().unwrap();
    assert!(usage.value.digital_signature());
    assert!(!usage.value.key_cert_sign());
    assert!(!usage.value.crl_sign());
}

#[test]
fn node_csr_uses_only_issuer_identity_and_reachability_policy() {
    let (ca_pem, ca_key) = generate_zone_ca("root").unwrap();
    let (key, _) = caller();
    let csr = untrusted_request(&key);
    let cert_pem = sign_node_csr(
        &csr,
        42,
        "trusted-zone",
        &ca_pem,
        &ca_key,
        &["approved.invalid".into(), "192.0.2.7".into()],
        Some("approved-host"),
    )
    .unwrap();
    let pem = ::pem::parse(&cert_pem).unwrap();
    let (_, cert) = X509Certificate::from_der(pem.contents()).unwrap();
    assert_leaf(&cert);
    assert_eq!(cert.public_key().raw, key.subject_public_key_info());
    assert_eq!(
        cert.subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap(),
        "nexus-zone-trusted-zone-node-approved-host"
    );
    let sans = cert.subject_alternative_name().unwrap().unwrap();
    assert_eq!(
        sans.value.general_names,
        vec![
            GeneralName::DNSName("nexus-node"),
            GeneralName::DNSName("localhost"),
            GeneralName::IPAddress(&[127, 0, 0, 1]),
            GeneralName::IPAddress(&Ipv6Addr::LOCALHOST.octets()),
            GeneralName::URI("nexus://zone/trusted-zone/node/42"),
            GeneralName::DNSName("approved.invalid"),
            GeneralName::IPAddress(&[192, 0, 2, 7]),
        ]
    );
    let eku = cert.extended_key_usage().unwrap().unwrap();
    assert!(eku.value.client_auth && eku.value.server_auth);
    assert!(!eku.value.any);
    let ca_der = ::pem::parse(&ca_pem).unwrap();
    let (_, ca) = X509Certificate::from_der(ca_der.contents()).unwrap();
    cert.verify_signature(Some(ca.public_key())).unwrap();
}

#[test]
fn agent_csr_cannot_request_node_owner_server_or_ca_authority() {
    let (ca_pem, ca_key) = generate_zone_ca("root").unwrap();
    let (key, _) = caller();
    let csr = untrusted_request(&key);
    let cert_pem = sign_agent_csr("trusted-agent", &csr, &ca_pem, &ca_key).unwrap();
    let pem = ::pem::parse(&cert_pem).unwrap();
    let (_, cert) = X509Certificate::from_der(pem.contents()).unwrap();
    assert_leaf(&cert);
    assert_eq!(cert.public_key().raw, key.subject_public_key_info());
    assert_eq!(
        cert.subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap(),
        "nexus-agent-trusted-agent"
    );
    assert_eq!(
        cert.subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names,
        vec![GeneralName::URI("nexus://agent/trusted-agent")]
    );
    let eku = cert.extended_key_usage().unwrap().unwrap();
    assert!(eku.value.client_auth);
    assert!(!eku.value.server_auth && !eku.value.any);
    assert!(!cert.key_usage().unwrap().unwrap().value.key_encipherment());

    // The caller's original key works with the existing mailbox authorship
    // verifier; the issuer has only received its public CSR.
    let message = b"isolated caller-owned credential proof";
    let signature = authorship::sign(message, key.serialize_pem().as_bytes()).unwrap();
    assert_eq!(
        authorship::verify(message, &signature, &cert_pem, &ca_pem).unwrap(),
        "trusted-agent"
    );
    let other_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let forged = authorship::sign(message, other_key.serialize_pem().as_bytes()).unwrap();
    assert!(authorship::verify(message, &forged, &cert_pem, &ca_pem).is_err());
}

#[test]
fn altered_csr_signature_is_rejected() {
    let (ca_pem, ca_key) = generate_zone_ca("root").unwrap();
    let (_, csr) = caller();
    let mut der = ::pem::parse(csr).unwrap().into_contents();
    *der.last_mut().unwrap() ^= 1;
    let altered = ::pem::encode(&::pem::Pem::new("CERTIFICATE REQUEST", der));
    assert!(sign_agent_csr("agent", altered.as_bytes(), &ca_pem, &ca_key).is_err());
}

#[test]
fn unsupported_key_curve_is_rejected() {
    let (ca_pem, ca_key) = generate_zone_ca("root").unwrap();
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let csr = request(CertificateParams::default(), &key);
    assert!(sign_agent_csr("agent", &csr, &ca_pem, &ca_key)
        .unwrap_err()
        .contains("P-256"));
}

#[test]
fn malformed_oversized_multiblock_and_trailing_der_requests_are_rejected() {
    let (ca_pem, ca_key) = generate_zone_ca("root").unwrap();
    let (_, csr) = caller();
    let der = ::pem::parse(&csr).unwrap().into_contents();
    let wrong_tag = ::pem::encode(&::pem::Pem::new("CERTIFICATE", der.clone())).into_bytes();
    let mut trailing = der;
    trailing.extend_from_slice(&[0, 0]);
    let trailing = ::pem::encode(&::pem::Pem::new("CERTIFICATE REQUEST", trailing)).into_bytes();
    let cases = [
        Vec::new(),
        vec![b'A'; MAX_CSR_PEM_BYTES + 1],
        vec![0xff],
        b"-----BEGIN CERTIFICATE REQUEST-----\n!\n-----END CERTIFICATE REQUEST-----".to_vec(),
        wrong_tag,
        [csr.clone(), csr.clone()].concat(),
        trailing,
        [b"untrusted prefix\n".to_vec(), csr.clone()].concat(),
        [csr, b"\nuntrusted suffix".to_vec()].concat(),
    ];
    for (index, bad) in cases.iter().enumerate() {
        assert!(
            sign_agent_csr("agent", bad, &ca_pem, &ca_key).is_err(),
            "case {index}"
        );
    }
}

#[test]
fn unknown_requested_extension_fails_closed() {
    let (ca_pem, ca_key) = generate_zone_ca("root").unwrap();
    let (key, _) = caller();
    let mut params = CertificateParams::default();
    params.custom_extensions = vec![CustomExtension::from_oid_content(
        &[1, 2, 3, 4, 5],
        vec![5, 0],
    )];
    let csr = request(params, &key);
    assert!(sign_agent_csr("agent", &csr, &ca_pem, &ca_key).is_err());
}

#[test]
fn issuer_certificate_and_key_must_match() {
    let (ca_pem, _) = generate_zone_ca("root").unwrap();
    let (_, wrong_key) = generate_zone_ca("other").unwrap();
    let (_, csr) = caller();
    assert!(sign_agent_csr("agent", &csr, &ca_pem, &wrong_key)
        .unwrap_err()
        .contains("do not match"));
}

#[test]
fn separate_certificates_for_one_public_key_have_distinct_revocation_serials() {
    let (ca_pem, ca_key) = generate_zone_ca("root").unwrap();
    let (_, csr) = caller();
    let first = ::pem::parse(sign_agent_csr("agent", &csr, &ca_pem, &ca_key).unwrap()).unwrap();
    let second = ::pem::parse(sign_agent_csr("agent", &csr, &ca_pem, &ca_key).unwrap()).unwrap();
    let (_, first) = X509Certificate::from_der(first.contents()).unwrap();
    let (_, second) = X509Certificate::from_der(second.contents()).unwrap();
    assert_ne!(first.raw_serial(), second.raw_serial());
    assert!(!first.raw_serial().is_empty() && first.raw_serial().len() <= 20);
    assert_eq!(first.raw_serial()[0] & 0x80, 0);
}

#[test]
fn issuer_must_have_ca_and_certificate_signing_authority() {
    let (_, csr) = caller();
    let (not_ca, key) = issuer(|p| {
        p.is_ca = IsCa::NoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    });
    assert!(sign_agent_csr("agent", &csr, &not_ca, &key)
        .unwrap_err()
        .contains("must be a CA"));
    let (not_signer, key) = issuer(|p| p.key_usages = vec![KeyUsagePurpose::DigitalSignature]);
    assert!(sign_agent_csr("agent", &csr, &not_signer, &key)
        .unwrap_err()
        .contains("does not permit"));
}

#[test]
fn expired_and_not_yet_valid_issuers_are_rejected() {
    let (_, csr) = caller();
    let now = time::OffsetDateTime::now_utc();
    for (start, end) in [(-120, -60), (60, 120)] {
        let (ca_pem, key) = issuer(|p| {
            p.not_before = now + time::Duration::seconds(start);
            p.not_after = now + time::Duration::seconds(end);
        });
        assert!(sign_agent_csr("agent", &csr, &ca_pem, &key)
            .unwrap_err()
            .contains("must be current"));
    }
}

#[test]
fn leaf_validity_never_exceeds_issuer_expiry() {
    let (ca_pem, key) =
        issuer(|p| p.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1));
    let (_, csr) = caller();
    for cert_pem in [
        sign_agent_csr("agent", &csr, &ca_pem, &key).unwrap(),
        sign_node_csr(&csr, 7, "root", &ca_pem, &key, &[], None).unwrap(),
    ] {
        let ca_der = ::pem::parse(&ca_pem).unwrap();
        let (_, ca) = X509Certificate::from_der(ca_der.contents()).unwrap();
        let der = ::pem::parse(cert_pem).unwrap();
        let (_, leaf) = X509Certificate::from_der(der.contents()).unwrap();
        assert_eq!(leaf.validity().not_after, ca.validity().not_after);
        assert!(leaf.validity().not_after > leaf.validity().not_before);
    }
}
