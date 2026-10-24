use super::*;
use crate::transport::{generate_zone_ca, prepare_agent_csr_intent, sign_committed_agent_intent};

fn binding() -> AgentCsrBinding<'static> {
    AgentCsrBinding {
        agent_name: "existing-product-agent",
        owner_id: "existing-owner",
        display_name: "原产品 Agent",
        operation_id: "original-deploy-operation",
    }
}

fn finalized(pending: &PendingAgentCsr, ca_key: &[u8]) -> AgentCsrResponse {
    let request = pending.request();
    let intent =
        prepare_agent_csr_intent(&request.agent_name, &request.csr_pem, &pending.ca_pem).unwrap();
    let signed = sign_committed_agent_intent(&intent, &pending.ca_pem, ca_key).unwrap();
    // Client validation requires the authenticated issuer's selected-F response.
    // This pure test supplies a real signature; the profile's real Raft/mTLS
    // fixture separately proves that selection and uses this same publisher.
    AgentCsrResponse {
        state: AgentCsrState::Finalized as i32,
        agent_name: request.agent_name.clone(),
        owner_id: request.owner_id.clone(),
        operation_id: request.operation_id.clone(),
        request_sha256: agent_csr_request_digest(request).unwrap().to_vec(),
        intent_sha256: vec![1; 32],
        serial: signed.serial,
        certificate_der: signed.certificate_der,
        ca_pem: pending.ca_pem.clone(),
        ..Default::default()
    }
}

#[test]
fn recovery_keeps_exact_key_request_and_operation_before_publishing_the_native_bundle() {
    let private = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("client-fixture").unwrap();
    let path = private.path().join("pending.json");
    let pending = PendingAgentCsr::create(&path, &binding(), &ca).unwrap();
    let persisted = std::fs::read(&path).unwrap();
    let original_request = pending.request().encode_to_vec();
    drop(pending);
    let pending = PendingAgentCsr::load(&path, &binding(), &ca).unwrap();
    assert_eq!(pending.request().encode_to_vec(), original_request);
    let mut reformatted_ca = ca.clone();
    reformatted_ca.extend_from_slice(b"\n");
    assert_eq!(
        PendingAgentCsr::load(&path, &binding(), &reformatted_ca)
            .unwrap()
            .request(),
        pending.request(),
        "issuer binding is the certificate DER, not PEM whitespace"
    );
    let response = finalized(&pending, &ca_key);
    let directory = private.path().join("bundle");
    let manifest = pending.publish(&response, &directory).unwrap();
    assert_eq!(pending.publish(&response, &directory).unwrap(), manifest);
    let loaded = AgentCredential::load(&manifest).unwrap();
    assert_eq!(loaded.agent, binding().agent_name);
    assert_eq!(loaded.key_pem, pending.key_pem.as_bytes());
    assert_eq!(loaded.ca_pem, ca);
    assert_eq!(std::fs::read(path).unwrap(), persisted);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [
            private.path().join("pending.json"),
            directory.join("agent-key.pem"),
        ] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn partial_pending_or_changed_binding_never_creates_a_replacement_operation() {
    let private = tempfile::tempdir().unwrap();
    let (ca, _) = generate_zone_ca("client-fixture").unwrap();
    let path = private.path().join("pending.json");
    PendingAgentCsr::create(&path, &binding(), &ca).unwrap();
    let original = std::fs::read(&path).unwrap();
    assert!(PendingAgentCsr::create(&path, &binding(), &ca).is_err());
    for field in 0..4 {
        let mut changed = binding();
        match field {
            0 => changed.agent_name = "another-agent",
            1 => changed.owner_id = "another-owner",
            2 => changed.display_name = "changed display",
            _ => changed.operation_id = "another-operation",
        }
        assert!(PendingAgentCsr::load(&path, &changed, &ca).is_err());
    }
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let partial = private.path().join("partial");
    std::fs::write(&partial, b"{").unwrap();
    assert!(PendingAgentCsr::load(&partial, &binding(), &ca).is_err());
    assert!(PendingAgentCsr::create(&partial, &binding(), &ca).is_err());
    assert_eq!(std::fs::read(partial).unwrap(), b"{");
}

#[test]
fn corrupt_or_swapped_pending_material_is_refused() {
    let private = tempfile::tempdir().unwrap();
    let (ca, _) = generate_zone_ca("client-fixture").unwrap();
    let path = private.path().join("pending.json");
    PendingAgentCsr::create(&path, &binding(), &ca).unwrap();
    let original = std::fs::read(&path).unwrap();
    let mut document: Document = serde_json::from_slice(&original).unwrap();
    document.key_pem = KeyPair::generate().unwrap().serialize_pem();
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    assert!(PendingAgentCsr::load(&path, &binding(), &ca).is_err());
    std::fs::write(&path, &original).unwrap();
    let (other_ca, _) = generate_zone_ca("another-issuer").unwrap();
    assert!(PendingAgentCsr::load(&path, &binding(), &other_ca).is_err());
    let mut json: serde_json::Value = serde_json::from_slice(&original).unwrap();
    json["unrecognized"] = true.into();
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert!(PendingAgentCsr::load(&path, &binding(), &ca).is_err());
}

#[test]
fn unknown_wrong_binding_wrong_key_and_privileged_certificates_publish_nothing() {
    let private = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("client-fixture").unwrap();
    let pending =
        PendingAgentCsr::create(&private.path().join("pending"), &binding(), &ca).unwrap();
    let valid = finalized(&pending, &ca_key);
    let directory = private.path().join("must-not-exist");
    for change in 0..8 {
        let mut reply = valid.clone();
        match change {
            0 => reply.state = AgentCsrState::Unknown as i32,
            1 => reply.owner_id = "another-owner".into(),
            2 => reply.request_sha256[0] ^= 1,
            3 => reply.serial[0] ^= 1,
            4 => reply.error = Some("issuer did not complete".into()),
            5 => {
                let other =
                    PendingAgentCsr::create(&private.path().join("another-key"), &binding(), &ca)
                        .unwrap();
                let other_reply = finalized(&other, &ca_key);
                reply.serial = other_reply.serial;
                reply.certificate_der = other_reply.certificate_der;
            }
            6 => {
                let issuer_key = KeyPair::from_pem(std::str::from_utf8(&ca_key).unwrap()).unwrap();
                let issuer =
                    rcgen::Issuer::from_ca_cert_pem(std::str::from_utf8(&ca).unwrap(), &issuer_key)
                        .unwrap();
                let subject = KeyPair::from_pem(&pending.key_pem).unwrap();
                let mut params = CertificateParams::default();
                params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
                params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);
                params.subject_alt_names = vec![rcgen::SanType::URI(
                    "nexus://zone/root/node/2".try_into().unwrap(),
                )];
                params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
                params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
                let certificate = params.signed_by(&subject, &issuer).unwrap();
                reply.certificate_der = certificate.der().to_vec();
                let (_, leaf) = X509Certificate::from_der(&reply.certificate_der).unwrap();
                reply.serial = leaf.raw_serial().to_vec();
            }
            _ => reply.ca_pem = generate_zone_ca("wrong-authority").unwrap().0,
        }
        assert!(
            pending.publish(&reply, &directory).is_err(),
            "accepted invalid response case {change}"
        );
        assert!(
            !directory.exists(),
            "invalid response created a partial bundle"
        );
    }
}

#[test]
fn interrupted_publication_refuses_conflicts_and_keeps_the_manifest_absent() {
    let private = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("client-fixture").unwrap();
    let pending =
        PendingAgentCsr::create(&private.path().join("pending"), &binding(), &ca).unwrap();
    let directory = private.path().join("bundle");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("agent-key.pem"), b"partial-key").unwrap();
    assert!(pending
        .publish(&finalized(&pending, &ca_key), &directory)
        .is_err());
    assert_eq!(
        std::fs::read(directory.join("agent-key.pem")).unwrap(),
        b"partial-key"
    );
    assert!(!directory.join(CREDENTIAL_MANIFEST).exists());
}

#[test]
fn observations_validate_binding_and_never_turn_an_unfinished_or_unknown_state_into_a_bundle() {
    let private = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("observation-fixture").unwrap();
    let pending =
        PendingAgentCsr::create(&private.path().join("pending"), &binding(), &ca).unwrap();
    let finalized = finalized(&pending, &ca_key);
    assert_eq!(
        pending.observe(&finalized).unwrap(),
        AgentCsrState::Finalized
    );
    let mut absent = finalized.clone();
    absent.state = AgentCsrState::NotObserved as i32;
    absent.certificate_der.clear();
    absent.serial.clear();
    absent.intent_sha256.clear();
    assert_eq!(
        pending.observe(&absent).unwrap(),
        AgentCsrState::NotObserved
    );
    absent.owner_id.push('!');
    assert!(pending.observe(&absent).is_err());
    let mut committed = finalized.clone();
    committed.state = AgentCsrState::IntentCommitted as i32;
    assert!(
        pending.observe(&committed).is_err(),
        "unfinished observation carried a certificate"
    );
    committed.certificate_der.clear();
    assert_eq!(
        pending.observe(&committed).unwrap(),
        AgentCsrState::IntentCommitted
    );
    committed.intent_sha256.pop();
    assert!(pending.observe(&committed).is_err());
    for state in [AgentCsrState::Unknown, AgentCsrState::NotSubmitted] {
        let failure = AgentCsrResponse {
            state: state as i32,
            error: Some("native refusal or uncertainty".into()),
            ..Default::default()
        };
        assert_eq!(pending.observe(&failure).unwrap(), state);
        assert!(pending
            .publish(&failure, &private.path().join("bundle"))
            .is_err());
    }
    assert!(pending
        .observe(&AgentCsrResponse {
            state: i32::MAX,
            ..Default::default()
        })
        .is_err());
    assert!(!private.path().join("bundle").exists());
}
