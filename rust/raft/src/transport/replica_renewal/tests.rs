use super::*;
use contracts::{
    replica_binding::{ReplicaAllocation, ReplicaBinding, ReplicaBindingState, ReplicaStorage},
    replica_credential::{ReplicaIssuanceRejection, ReplicaIssuerAuthority},
};
use lib::transport_primitives::authorship::sign;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

struct Fixture {
    ca: Vec<u8>,
    key: Vec<u8>,
    caller: Vec<u8>,
    previous: ReplicaCredential,
    request: ReplicaIssuanceRequest,
    now: u64,
}

fn csr(key: &KeyPair) -> String {
    CertificateParams::default()
        .serialize_request(key)
        .unwrap()
        .pem()
        .unwrap()
}

impl Fixture {
    fn new() -> Self {
        Self::with_lifetime(300)
    }

    fn with_lifetime(validity_secs: u64) -> Self {
        let (ca, ca_key) = crate::transport::generate_zone_ca("renewal-ca").unwrap();
        let authority = ReplicaIssuerAuthority {
            revision: 3,
            issuer_sha256: Some(Sha256::digest(::pem::parse(&ca).unwrap().contents()).into()),
        };
        let binding = ReplicaBinding {
            allocation: ReplicaAllocation {
                owner_id: "alice".into(),
                allocation_id: "primary".into(),
            },
            storage: ReplicaStorage {
                authority: "cluster-a".into(),
                uid: "pvc-a".into(),
            },
            replica_id: 47,
            revision: 5,
            generation: 2,
            state: ReplicaBindingState::Active,
        };
        let holder = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let intent = crate::transport::prepare_replica_csr_intent(
            &binding,
            &authority,
            "session-replica",
            validity_secs,
            csr(&holder).as_bytes(),
            &ca,
        )
        .unwrap();
        let signed =
            crate::transport::sign_committed_replica_intent(&intent, &ca, &ca_key).unwrap();
        let next = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let renewed = crate::transport::prepare_replica_csr_intent(
            &binding,
            &authority,
            "session-replica",
            validity_secs,
            csr(&next).as_bytes(),
            &ca,
        )
        .unwrap();
        let (caller, _) =
            crate::transport::generate_agent_cert("controller", &ca, &ca_key).unwrap();
        Self {
            ca,
            key: holder.serialize_pem().into_bytes(),
            caller: ::pem::parse(caller).unwrap().into_contents(),
            previous: ReplicaCredential {
                intent,
                renews: None,
                certificate_der: Some(signed.certificate_der),
                revoked: false,
                authority_denial: None,
            },
            request: ReplicaIssuanceRequest {
                operation_id: "renew-original".into(),
                change: ReplicaIssuanceChange::Prepare {
                    intent: Box::new(renewed),
                    renews: Some("previous-original".into()),
                },
            },
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        }
    }

    fn message(&self, issued: u64) -> Vec<u8> {
        replica_renewal_message(
            &self.request,
            self.previous.certificate_der.as_deref().unwrap(),
            &self.caller,
            issued,
        )
        .unwrap()
    }

    fn proof(&self, issued: u64) -> Vec<u8> {
        sign(&self.message(issued), &self.key).unwrap()
    }

    fn verify(&self, signature: &[u8], issued: u64, now: u64) -> Result<(), String> {
        verify_replica_renewal(
            &self.request,
            "previous-original",
            &self.previous,
            &self.caller,
            &self.ca,
            &ReplicaRenewalProof {
                issued_at_unix_ms: issued,
                signature,
            },
            now,
        )
    }
}

#[test]
fn current_replica_holder_authorizes_exact_csr_key_rotation_and_original_retry() {
    let f = Fixture::new();
    let (intent, _) = renewal_intent(&f.request).unwrap();
    assert_ne!(
        intent.certificate.subject_public_key_info_der,
        f.previous.intent.certificate.subject_public_key_info_der
    );
    let proof = f.proof(f.now);
    f.verify(&proof, f.now, f.now).unwrap();
    f.verify(&proof, f.now, f.now).unwrap();
    let wrong = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let wrong_proof = sign(&f.message(f.now), wrong.serialize_pem().as_bytes()).unwrap();
    assert!(f
        .verify(&wrong_proof, f.now, f.now)
        .unwrap_err()
        .contains("signature"));
}

#[test]
fn proof_binds_original_operation_new_certificate_and_actual_tls_caller() {
    let mut f = Fixture::new();
    let proof = f.proof(f.now);
    let original = f.request.clone();
    f.request.operation_id = "another-operation".into();
    assert!(f
        .verify(&proof, f.now, f.now)
        .unwrap_err()
        .contains("signature"));
    f.request = original.clone();
    if let ReplicaIssuanceChange::Prepare { intent, .. } = &mut f.request.change {
        intent.certificate.subject_public_key_info_der = f
            .previous
            .intent
            .certificate
            .subject_public_key_info_der
            .clone();
    }
    assert!(f
        .verify(&proof, f.now, f.now)
        .unwrap_err()
        .contains("signature"));
    f.request = original.clone();
    if let ReplicaIssuanceChange::Prepare { intent, .. } = &mut f.request.change {
        intent.certificate.tbs_certificate_der[0] ^= 1;
    }
    assert!(f
        .verify(&proof, f.now, f.now)
        .unwrap_err()
        .contains("signature"));
    f.request = original;
    f.caller = Fixture::new().caller;
    assert!(f
        .verify(&proof, f.now, f.now)
        .unwrap_err()
        .contains("signature"));
}

#[test]
fn current_binding_issuer_revocation_and_publication_gate_renewal() {
    let mut f = Fixture::new();
    let proof = f.proof(f.now);
    let original = f.previous.clone();
    f.previous.revoked = true;
    assert!(f.verify(&proof, f.now, f.now).is_err());
    f.previous = original.clone();
    f.previous.authority_denial = Some(ReplicaIssuanceRejection::BindingChanged);
    assert!(f.verify(&proof, f.now, f.now).is_err());
    f.previous = original.clone();
    f.previous.authority_denial = Some(ReplicaIssuanceRejection::AuthorityChanged);
    assert!(f.verify(&proof, f.now, f.now).is_err());
    f.previous = original.clone();
    f.previous.certificate_der = None;
    assert!(f.verify(&proof, f.now, f.now).is_err());
    f.previous = original;
    if let ReplicaIssuanceChange::Prepare { renews, .. } = &mut f.request.change {
        *renews = Some("different-predecessor".into());
    }
    assert!(f.verify(&proof, f.now, f.now).is_err());
}

#[test]
fn valid_holder_cannot_transfer_storage_identity_or_increase_lifetime() {
    let mut f = Fixture::with_lifetime(120);
    let original = f.request.clone();
    for mutation in 0..7 {
        f.request = original.clone();
        if let ReplicaIssuanceChange::Prepare { intent, .. } = &mut f.request.change {
            match mutation {
                0 => intent.binding.storage.uid = "replacement-pvc".into(),
                1 => intent.binding.storage.authority = "another-cluster".into(),
                2 => intent.binding.allocation.owner_id = "bob".into(),
                3 => intent.binding.replica_id += 1,
                4 => intent.binding.revision += 1,
                5 => intent.issuer_revision += 1,
                6 => intent.certificate.not_after_unix_s += 1,
                _ => unreachable!(),
            }
        }
        let proof = f.proof(f.now);
        let expected = if mutation == 6 {
            "replica renewal cannot increase credential lifetime"
        } else {
            "replica renewal requires the current original allocation and issuer"
        };
        assert_eq!(
            f.verify(&proof, f.now, f.now).unwrap_err(),
            expected,
            "mutation {mutation}"
        );
    }
}

#[test]
fn proof_requires_current_predecessor_and_bounded_time_and_bytes() {
    let mut f = Fixture::new();
    for issued in [f.now - 30_001, f.now + 1_001] {
        assert!(f.verify(&f.proof(issued), issued, f.now).is_err());
    }
    let expired = f.now + 301_000;
    assert!(f.verify(&f.proof(expired), expired, expired).is_err());
    assert!(f.verify(&[0; 129], f.now, f.now).is_err());
    let proof = f.proof(f.now);
    f.previous.certificate_der.as_mut().unwrap().push(0);
    assert!(f.verify(&proof, f.now, f.now).is_err());
}

#[test]
fn certificate_and_session_proof_cannot_substitute_for_replica_renewal() {
    let mut f = Fixture::new();
    let session_message = crate::transport::session_renewal_message(
        f.previous.certificate_der.as_deref().unwrap(),
        &f.caller,
        300,
        f.now,
    );
    let session_proof = sign(&session_message, &f.key).unwrap();
    assert!(f
        .verify(&session_proof, f.now, f.now)
        .unwrap_err()
        .contains("signature"));
    let other = Fixture::new();
    f.previous.certificate_der = other.previous.certificate_der;
    f.key = other.key;
    assert!(f.verify(&f.proof(f.now), f.now, f.now).is_err());
}
