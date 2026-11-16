use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa, Issuer,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};

const NOW: i64 = 1_700_000_000;

fn issuer(name: &str) -> (Vec<u8>, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_before = time::OffsetDateTime::from_unix_timestamp(NOW - 100).unwrap();
    params.not_after = time::OffsetDateTime::from_unix_timestamp(NOW + 10_000).unwrap();
    let ca = params.self_signed(&key).unwrap().pem().into_bytes();
    (ca, Issuer::new(params, key))
}

fn params(this: i64, next: i64) -> CertificateRevocationListParams {
    CertificateRevocationListParams {
        this_update: time::OffsetDateTime::from_unix_timestamp(this).unwrap(),
        next_update: time::OffsetDateTime::from_unix_timestamp(next).unwrap(),
        crl_number: SerialNumber::from(7u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: SerialNumber::from(vec![0x80, 0x01]),
            revocation_time: time::OffsetDateTime::from_unix_timestamp(this).unwrap(),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
}

fn signed(params: &CertificateRevocationListParams, issuer: &Issuer<'_, KeyPair>) -> Vec<u8> {
    params
        .signed_by(issuer)
        .unwrap()
        .pem()
        .unwrap()
        .into_bytes()
}

#[test]
fn signed_complete_crl_binds_issuer_and_normalizes_unsigned_serials() {
    let (ca, issuer) = issuer("native-root");
    let bytes = signed(&params(NOW, NOW + 300), &issuer);
    let verified = verify_signed_crl(&bytes, &ca).unwrap();
    assert_eq!(verified.this_update(), NOW);
    assert_eq!(verified.next_update(), NOW + 300);
    assert_eq!(verified.number(), &[7]);
    assert!(verified.is_revoked(&[0x80, 1]));
    assert!(verified.is_revoked(&[0, 0x80, 1]));
    assert!(!verified.is_revoked(&[0x80, 2]));
    assert!(!verified.is_revoked(&[]));
    assert_eq!(canonical_certificate_serial(&[0, 0]).unwrap(), &[0]);
    assert!(canonical_certificate_serial(&[]).is_err());
    verified.check_freshness(NOW, 60).unwrap();
    verified.check_freshness(NOW + 60, 60).unwrap();
    assert!(verified.check_freshness(NOW + 61, 60).is_err());
    assert!(verified.check_freshness(NOW - 1, 60).is_err());
    assert!(verified.check_freshness(NOW, 0).is_err());
    assert!(verified.check_freshness(NOW, 301).is_err());
    let (unrelated, _) = self::issuer("native-root");
    assert!(
        verify_signed_crl(&bytes, &unrelated).is_err(),
        "issuer DN is not key authority"
    );
}

#[test]
fn a_nonconforming_zero_serial_is_still_retained_as_a_revocation() {
    let (ca, issuer) = issuer("native-root");
    let mut zero = params(NOW, NOW + 300);
    zero.revoked_certs[0].serial_number = SerialNumber::from(0u64);
    let verified = verify_signed_crl(&signed(&zero, &issuer), &ca).unwrap();
    assert!(verified.is_revoked(&[0]));
    assert!(!verified.is_revoked(&[]));
}

#[test]
fn next_update_and_ca_expiry_cannot_be_extended_by_a_freshness_budget() {
    let (ca, issuer) = issuer("native-root");
    let verified = verify_signed_crl(&signed(&params(NOW, NOW + 5), &issuer), &ca).unwrap();
    assert!(verified.check_freshness(NOW + 5, 300).is_err());
    let verified =
        verify_signed_crl(&signed(&params(NOW + 10_000, NOW + 20_000), &issuer), &ca).unwrap();
    assert!(
        verified.check_freshness(NOW + 10_001, 300).is_err(),
        "expired issuer"
    );
    assert!(verified.check_freshness(i64::MIN, 300).is_err());
}

#[test]
fn incomplete_remove_from_crl_and_oversized_number_are_not_complete_snapshots() {
    let (ca, issuer) = issuer("native-root");
    let mut remove = params(NOW, NOW + 300);
    remove.revoked_certs[0].reason_code = Some(RevocationReason::RemoveFromCrl);
    assert!(verify_signed_crl(&signed(&remove, &issuer), &ca).is_err());
    let mut oversized = params(NOW, NOW + 300);
    oversized.crl_number = SerialNumber::from(vec![1; 21]);
    assert!(verify_signed_crl(&signed(&oversized, &issuer), &ca).is_err());
    let mut partitioned = params(NOW, NOW + 300);
    partitioned.issuing_distribution_point = Some(rcgen::CrlIssuingDistributionPoint {
        distribution_point: rcgen::CrlDistributionPoint {
            uris: vec!["https://issuer.invalid/part-one".into()],
        },
        scope: Some(rcgen::CrlScope::UserCertsOnly),
    });
    assert!(verify_signed_crl(&signed(&partitioned, &issuer), &ca).is_err());
}

#[test]
fn malformed_multiple_and_trailing_der_never_become_verified_crls() {
    let (ca, issuer) = issuer("native-root");
    let bytes = signed(&params(NOW, NOW + 300), &issuer);
    assert!(verify_signed_crl(&[bytes.clone(), bytes.clone()].concat(), &ca).is_err());
    let mut block = ::pem::parse(&bytes).unwrap();
    let mut der = block.contents().to_vec();
    der.push(0);
    block = ::pem::Pem::new("X509 CRL", der);
    assert!(verify_signed_crl(::pem::encode(&block).as_bytes(), &ca).is_err());
    assert!(verify_signed_crl(&vec![0; MAX_CRL_BYTES + 1], &ca).is_err());
    assert!(verify_signed_crl(b"not a CRL", &ca).is_err());
}

#[test]
fn a_number_identifies_one_signed_snapshot_across_pem_encodings() {
    let (ca, issuer) = issuer("native-root");
    let original = signed(&params(NOW, NOW + 300), &issuer);
    let current = verify_signed_crl(&original, &ca).unwrap();
    let crlf = String::from_utf8(original.clone())
        .unwrap()
        .replace("\r\n", "\n")
        .replace('\n', "\r\n");
    let reformatted = format!("\n{crlf}\n");
    assert_ne!(original, reformatted.as_bytes());
    let replay = verify_signed_crl(reformatted.as_bytes(), &ca).unwrap();
    assert_eq!(replay.signed_der_sha256(), current.signed_der_sha256());
    replay.check_successor(&current).unwrap();

    let mut changed = params(NOW, NOW + 300);
    changed.revoked_certs[0].serial_number = SerialNumber::from(9u64);
    let conflicting = verify_signed_crl(&signed(&changed, &issuer), &ca).unwrap();
    assert_eq!(conflicting.number(), current.number());
    assert_ne!(conflicting.signed_der_sha256(), current.signed_der_sha256());
    assert_eq!(
        conflicting.check_successor(&current).unwrap_err(),
        "CRL number already identifies another signed snapshot"
    );
}

#[test]
fn later_fresh_crl_cannot_replace_a_higher_number() {
    let (ca, issuer) = issuer("native-root");
    let current = verify_signed_crl(&signed(&params(NOW, NOW + 300), &issuer), &ca).unwrap();
    let mut stale = params(NOW + 1, NOW + 301);
    stale.crl_number = SerialNumber::from(6u64);
    let stale = verify_signed_crl(&signed(&stale, &issuer), &ca).unwrap();
    current.check_freshness(NOW + 1, 60).unwrap();
    stale.check_freshness(NOW + 1, 60).unwrap();
    assert_eq!(
        stale.check_successor(&current).unwrap_err(),
        "CRL number moved backwards"
    );
}

#[test]
fn successor_number_is_unsigned_and_can_exceed_u64() {
    let (ca, issuer) = issuer("native-root");
    let mut old = params(NOW, NOW + 300);
    old.crl_number = SerialNumber::from(vec![0xff; 8]);
    let old = verify_signed_crl(&signed(&old, &issuer), &ca).unwrap();
    let mut next = params(NOW + 1, NOW + 301);
    next.crl_number = SerialNumber::from(vec![1, 0, 0, 0, 0, 0, 0, 0, 0]);
    // The issuer may prune expired entries. The installer retains its own
    // irreversible tombstones when accepting this otherwise valid successor.
    next.revoked_certs.clear();
    let next = verify_signed_crl(&signed(&next, &issuer), &ca).unwrap();
    next.check_successor(&old).unwrap();
    assert!(next.revoked_serials().is_empty());
    assert_eq!(
        old.check_successor(&next).unwrap_err(),
        "CRL number moved backwards"
    );
}

#[test]
fn a_greater_number_does_not_authorize_an_older_time_or_another_issuer() {
    let (ca, issuer) = issuer("native-root");
    let original = verify_signed_crl(&signed(&params(NOW, NOW + 300), &issuer), &ca).unwrap();
    let mut future_number = params(NOW - 1, NOW + 299);
    future_number.crl_number = SerialNumber::from(8u64);
    let rollback = verify_signed_crl(&signed(&future_number, &issuer), &ca).unwrap();
    rollback.check_freshness(NOW, 60).unwrap();
    assert_eq!(
        rollback.check_successor(&original).unwrap_err(),
        "CRL issuance time moved backwards"
    );

    let (other_ca, other_issuer) = self::issuer("native-root");
    let unrelated = verify_signed_crl(&signed(&future_number, &other_issuer), &other_ca).unwrap();
    assert_eq!(
        unrelated.check_successor(&original).unwrap_err(),
        "CRL successor belongs to another signing authority"
    );
}
