use super::*;
use x509_parser::certificate::TbsCertificate;

fn fixture() -> (AgentCertificateIntent, Vec<u8>, Vec<u8>) {
    let (ca, ca_key) = generate_zone_ca("isolated-intent-ca").unwrap();
    let caller = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut request = CertificateParams::default();
    request.subject_alt_names = vec![SanType::URI("nexus://owner/forged".try_into().unwrap())];
    request.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let csr = request.serialize_request(&caller).unwrap().pem().unwrap();
    let intent = prepare_agent_csr_intent("resolved-actor", csr.as_bytes(), &ca).unwrap();
    (intent, ca, ca_key)
}

#[test]
fn preparation_needs_only_public_ca_and_produces_unsigned_exact_tbs() {
    let (intent, _, _) = fixture();
    let (rest, tbs) = TbsCertificate::from_der(&intent.tbs_certificate_der).unwrap();
    assert!(rest.is_empty());
    assert_eq!(tbs.raw_serial(), intent.serial);
    assert_eq!(tbs.public_key().raw, intent.subject_public_key_info_der);
    assert_eq!(
        tbs.validity().not_before.timestamp(),
        intent.not_before_unix_s
    );
    assert_eq!(
        tbs.validity().not_after.timestamp(),
        intent.not_after_unix_s
    );
    assert_eq!(
        tbs.subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names,
        vec![x509_parser::extensions::GeneralName::URI(
            "nexus://agent/resolved-actor"
        )]
    );
    let eku = tbs.extended_key_usage().unwrap().unwrap();
    assert!(eku.value.client_auth && !eku.value.server_auth);
    // A TBSCertificate has no signature; it is not an issued certificate.
    assert!(X509Certificate::from_der(&intent.tbs_certificate_der).is_err());
}

#[test]
fn committed_tbs_is_identical_across_randomized_signatures() {
    let (intent, ca, key) = fixture();
    let first = sign_committed_agent_intent(&intent, &ca, &key).unwrap();
    let second = sign_committed_agent_intent(&intent, &ca, &key).unwrap();
    assert_eq!(first.serial, intent.serial);
    assert_eq!(second.serial, intent.serial);
    assert_eq!(first.tbs_certificate_der, intent.tbs_certificate_der);
    assert_eq!(second.tbs_certificate_der, intent.tbs_certificate_der);
    let (_, first) = X509Certificate::from_der(&first.certificate_der).unwrap();
    let (_, second) = X509Certificate::from_der(&second.certificate_der).unwrap();
    let ca_pem = ::pem::parse(ca).unwrap();
    let (_, ca_x509) = X509Certificate::from_der(ca_pem.contents()).unwrap();
    first.verify_signature(Some(ca_x509.public_key())).unwrap();
    second.verify_signature(Some(ca_x509.public_key())).unwrap();
}

#[test]
fn changed_policy_key_time_serial_or_tbs_is_not_signed() {
    let (intent, ca, key) = fixture();
    let mut mutations = vec![];
    let mut changed = intent.clone();
    changed.agent_name = "different-actor".into();
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.serial[0] ^= 2;
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.not_before_unix_s -= 1;
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.not_after_unix_s -= 1;
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.version += 1;
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.tbs_certificate_der[0] ^= 1;
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.issuer_sha256[0] ^= 1;
    mutations.push(changed);
    let other = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut changed = intent.clone();
    changed.subject_public_key_info_der = other.subject_public_key_info();
    mutations.push(changed);
    for (index, changed) in mutations.iter().enumerate() {
        assert!(
            sign_committed_agent_intent(changed, &ca, &key).is_err(),
            "mutation {index}"
        );
    }
}

#[test]
fn changed_or_mismatched_issuer_cannot_finalize_the_intent() {
    let (intent, ca, key) = fixture();
    let (other_ca, other_key) = generate_zone_ca("other-intent-ca").unwrap();
    assert!(sign_committed_agent_intent(&intent, &other_ca, &other_key).is_err());
    assert!(sign_committed_agent_intent(&intent, &ca, &other_key).is_err());
    assert!(sign_committed_agent_intent(&intent, &other_ca, &key).is_err());
}

#[test]
fn unsigned_and_signed_intents_enforce_size_and_validity_bounds() {
    let (intent, ca, key) = fixture();
    let mut too_large = intent.clone();
    too_large.tbs_certificate_der = vec![0; 16 * 1024 + 1];
    assert!(sign_committed_agent_intent(&too_large, &ca, &key).is_err());
    let mut too_large = intent.clone();
    too_large.subject_public_key_info_der = vec![0; 1025];
    assert!(sign_committed_agent_intent(&too_large, &ca, &key).is_err());
    let mut expired = intent.clone();
    expired.not_after_unix_s = expired.not_before_unix_s;
    assert!(sign_committed_agent_intent(&expired, &ca, &key).is_err());
    let mut extended = intent.clone();
    extended.not_after_unix_s = extended.not_before_unix_s + 90 * 86400 + 1;
    assert!(sign_committed_agent_intent(&extended, &ca, &key).is_err());
    let mut oversized_pem = ca.clone();
    oversized_pem.resize(64 * 1024 + 1, b' ');
    assert!(public_issuer(&oversized_pem).is_err());
    let issuer = ::pem::encode(&::pem::Pem::new("CERTIFICATE", vec![0; 16 * 1024 + 1]));
    assert!(public_issuer(issuer.as_bytes()).is_err());
}
