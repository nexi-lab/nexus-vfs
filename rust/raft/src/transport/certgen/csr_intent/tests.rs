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

fn replica_fixture() -> (ReplicaCertificateIntent, Vec<u8>, Vec<u8>) {
    use contracts::replica_binding::{ReplicaAllocation, ReplicaBindingState, ReplicaStorage};
    let (ca, ca_key) = generate_zone_ca("replica-intent-ca").unwrap();
    let (ca_der, _, _) = public_issuer(&ca).unwrap();
    let authority = ReplicaIssuerAuthority {
        revision: 3,
        issuer_sha256: Some(Sha256::digest(&ca_der).into()),
    };
    let binding = ReplicaBinding {
        allocation: ReplicaAllocation {
            owner_id: "owner-a".into(),
            allocation_id: "primary".into(),
        },
        storage: ReplicaStorage {
            authority: "storage-a".into(),
            uid: "pvc-uid-a".into(),
        },
        replica_id: 47,
        revision: 5,
        generation: 2,
        state: ReplicaBindingState::Active,
    };
    let holder = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut request = CertificateParams::default();
    request.subject_alt_names = vec![SanType::URI("nexus://node/1".try_into().unwrap())];
    request.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let csr = request.serialize_request(&holder).unwrap().pem().unwrap();
    let intent = prepare_replica_csr_intent(
        &binding,
        &authority,
        "replica-runtime",
        300,
        csr.as_bytes(),
        &ca,
    )
    .unwrap();
    (intent, ca, ca_key)
}

#[test]
fn replica_csr_uses_current_owner_profile_and_ignores_requested_privileges() {
    let (intent, ca, ca_key) = replica_fixture();
    let signed = sign_committed_replica_intent(&intent, &ca, &ca_key).unwrap();
    let (_, parsed) = X509Certificate::from_der(&signed.certificate_der).unwrap();
    assert_eq!(
        parsed.public_key().raw,
        intent.certificate.subject_public_key_info_der
    );
    assert_eq!(
        parsed.tbs_certificate.as_ref(),
        intent.certificate.tbs_certificate_der
    );
    assert_eq!(
        parsed.validity().not_after.timestamp() - parsed.validity().not_before.timestamp(),
        300
    );
    assert!(!parsed
        .basic_constraints()
        .unwrap()
        .is_some_and(|value| value.value.ca));
    let eku = parsed.extended_key_usage().unwrap().unwrap();
    assert!(eku.value.client_auth && eku.value.server_auth);
    let san = parsed.subject_alternative_name().unwrap().unwrap();
    let sans = &san.value.general_names;
    let dns = lib::transport_primitives::user_runtime_server_name("owner-a").unwrap();
    assert_eq!(
        sans,
        &vec![
            x509_parser::extensions::GeneralName::URI("nexus://agent/replica-runtime"),
            x509_parser::extensions::GeneralName::URI("nexus://owner/owner-a"),
            x509_parser::extensions::GeneralName::DNSName(&dns),
            x509_parser::extensions::GeneralName::URI("nexus://replica/47"),
        ]
    );
}

#[test]
fn replica_signature_cannot_change_owner_identity_or_committed_certificate() {
    let (intent, ca, key) = replica_fixture();
    let mut mutations = Vec::new();
    let mut changed = intent.clone();
    changed.binding.allocation.owner_id = "owner-b".into();
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.binding.replica_id += 1;
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.subject_name = "different-runtime".into();
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.certificate.serial[0] ^= 2;
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.certificate.issuer_sha256[0] ^= 1;
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.certificate.not_after_unix_s += 1;
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.certificate.tbs_certificate_der[0] ^= 1;
    mutations.push(changed);
    let mut changed = intent.clone();
    changed.binding.state = contracts::replica_binding::ReplicaBindingState::Retired;
    mutations.push(changed);
    for (index, changed) in mutations.iter().enumerate() {
        assert!(
            sign_committed_replica_intent(changed, &ca, &key).is_err(),
            "mutation {index}"
        );
    }
    let (other, other_key) = generate_zone_ca("other-replica-issuer").unwrap();
    assert!(sign_committed_replica_intent(&intent, &other, &other_key).is_err());
    assert!(sign_committed_replica_intent(&intent, &ca, &other_key).is_err());
}

#[test]
fn replica_preparation_requires_current_authority_and_short_lifetime() {
    let (intent, ca, _) = replica_fixture();
    let holder = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&holder)
        .unwrap()
        .pem()
        .unwrap();
    let authority = ReplicaIssuerAuthority {
        revision: intent.issuer_revision,
        issuer_sha256: Some(intent.certificate.issuer_sha256),
    };
    for seconds in [0, 301, u64::MAX] {
        assert!(prepare_replica_csr_intent(
            &intent.binding,
            &authority,
            &intent.subject_name,
            seconds,
            csr.as_bytes(),
            &ca
        )
        .is_err());
    }
    for authority in [
        ReplicaIssuerAuthority {
            revision: 0,
            ..authority.clone()
        },
        ReplicaIssuerAuthority {
            revision: 3,
            issuer_sha256: None,
        },
        ReplicaIssuerAuthority {
            revision: 3,
            issuer_sha256: Some([1; 32]),
        },
    ] {
        assert!(prepare_replica_csr_intent(
            &intent.binding,
            &authority,
            &intent.subject_name,
            300,
            csr.as_bytes(),
            &ca
        )
        .is_err());
    }
    assert!(prepare_replica_csr_intent(
        &intent.binding,
        &authority,
        &intent.subject_name,
        300,
        b"not a signed CSR",
        &ca
    )
    .is_err());
}

#[test]
fn ordinary_intent_keeps_the_existing_serialized_field_order() {
    let (intent, _, _) = fixture();
    // A tuple encodes the original v1 bincode field sequence independently of
    // the new borrowed crypto view.
    let original = bincode::serialize(&(
        intent.version,
        &intent.agent_name,
        intent.issuer_sha256,
        &intent.subject_public_key_info_der,
        &intent.serial,
        intent.not_before_unix_s,
        intent.not_after_unix_s,
        &intent.tbs_certificate_der,
    ))
    .unwrap();
    assert_eq!(bincode::serialize(&intent).unwrap(), original);
}
