//! Source-only I/sign/F coordinator proofs. Real Raft CAS and read barriers,
//! original CSR keys, concurrent ECDSA finalizers, ambiguous replies and restart.
//! No RPC, deployment or production credential is enabled by this fixture.
use auth::agent_issuance::{
    commit_agent_intent, finalize_agent_issuance, query_agent_issuance, AgentIssuanceIntent,
    AgentIssuanceState, IssuanceAuthorizer, IssuanceBinding, IssuanceError,
};
use auth::{AuthKeyRecord, SubjectType};
use kernel::hal::auth_key_store::{AuthKeyStore, AuthKeyStoreError};
use kernel::kernel::Kernel;
use nexus_raft::auth_key_store::RaftAuthKeyStore;
use nexus_raft::raft::ZoneRaftRegistry;
use nexus_raft::transport::{
    generate_zone_ca, prepare_agent_csr_intent, sign_committed_agent_intent,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Barrier,
};
use x509_parser::prelude::{FromDer, X509Certificate};

struct CurrentAuthority;
impl IssuanceAuthorizer for CurrentAuthority {
    fn authorize(&self, _: &IssuanceBinding) -> Result<(), String> {
        Ok(())
    }
}
fn record(name: &str) -> AuthKeyRecord {
    AuthKeyRecord {
        key_id: format!("fixture-{name}"),
        name: name.into(),
        subject_type: SubjectType::Agent,
        subject_id: name.into(),
        is_admin: false,
        revoked: false,
        expires_at_ms: None,
        zone_perms: vec![],
    }
}
fn candidate(name: &str, operation: &str, ca: &[u8], request: u8) -> AgentIssuanceIntent {
    let caller_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&caller_key)
        .unwrap()
        .pem()
        .unwrap();
    let certificate = prepare_agent_csr_intent(name, csr.as_bytes(), ca).unwrap();
    AgentIssuanceIntent {
        schema_version: 2,
        binding: IssuanceBinding {
            issuer_sha256: certificate
                .issuer_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            caller_id: "fixture-node".into(),
            owner_id: "fixture-owner".into(),
            agent_name: name.into(),
            operation_id: operation.into(),
            request_sha256: [request; 32],
        },
        certificate,
    }
}
struct LoseOneReply {
    inner: Arc<dyn AuthKeyStore>,
    pending: AtomicBool,
}
impl AuthKeyStore for LoseOneReply {
    fn get(&self, k: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
        self.inner.get(k)
    }
    fn get_linearizable(&self, k: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
        self.inner.get_linearizable(k)
    }
    fn put(&self, k: &str, v: &[u8]) -> Result<(), AuthKeyStoreError> {
        self.inner.put(k, v)
    }
    fn put_if_absent_atomic(&self, k: &str, v: &[u8]) -> Result<bool, AuthKeyStoreError> {
        let result = self.inner.put_if_absent_atomic(k, v)?;
        if self.pending.swap(false, Ordering::SeqCst) {
            return Err(AuthKeyStoreError::Backend(
                "injected reply loss after real Raft apply".into(),
            ));
        }
        Ok(result)
    }
    fn delete(&self, k: &str) -> Result<bool, AuthKeyStoreError> {
        self.inner.delete(k)
    }
    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError> {
        self.inner.list()
    }
}
fn lose_reply(store: &Arc<dyn AuthKeyStore>) -> Arc<dyn AuthKeyStore> {
    Arc::new(LoseOneReply {
        inner: store.clone(),
        pending: AtomicBool::new(true),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsigned_winner_selected_der_and_all_crash_boundaries_survive_real_raft_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    let kernel = Arc::new(Kernel::new());
    kernel.set_auth_key_store(RaftAuthKeyStore::new_arc(node, runtime.clone()));
    let store = auth::KernelSlotStore::new_arc(kernel.clone());
    let (ca, ca_key) = generate_zone_ca("isolated-two-record-fixture").unwrap();

    let start = Arc::new(Barrier::new(8));
    let mut tasks = vec![];
    for n in 0..8 {
        // Each request possesses a distinct CSR key. No CA key is available
        // to preparation and no competing identity is signed before apply.
        let intent = candidate("racing-agent", &format!("race-op-{n}"), &ca, n);
        let store = store.clone();
        let start = start.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            start.wait();
            commit_agent_intent(&store, &CurrentAuthority, record("racing-agent"), intent)
        }));
    }
    let mut winner = None;
    let mut conflicts = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(result) => {
                assert!(!result.replayed);
                assert!(winner.replace(result.intent).is_none());
            }
            Err(IssuanceError::Conflict(_)) => conflicts += 1,
            other => panic!("unexpected race result: {other:?}"),
        }
    }
    assert_eq!(conflicts, 7);
    let winner = winner.unwrap();
    assert_eq!(store.list().unwrap().len(), 1);
    let stored = store
        .get_linearizable("agent:racing-agent")
        .unwrap()
        .unwrap();
    let old = AuthKeyRecord::decode(&stored).unwrap();
    assert!(old.is_expired(1));
    assert!(!old.revoked);
    assert!(auth::mint_agent_authz(&store, record("racing-agent"), true).is_err());
    assert!(auth::revoke_key_hash(&store, "agent:racing-agent").is_err());
    assert_eq!(
        store
            .get_linearizable("agent:racing-agent")
            .unwrap()
            .unwrap(),
        stored
    );

    let sign_barrier = Arc::new(Barrier::new(4));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut finalizers = vec![];
    for _ in 0..4 {
        let store = store.clone();
        let winner = winner.clone();
        let ca = ca.clone();
        let key = ca_key.clone();
        let barrier = sign_barrier.clone();
        let calls = calls.clone();
        finalizers.push(tokio::task::spawn_blocking(move || {
            finalize_agent_issuance(&store, &CurrentAuthority, &winner.binding, |committed| {
                assert_eq!(committed, &winner.certificate);
                calls.fetch_add(1, Ordering::SeqCst);
                barrier.wait();
                sign_committed_agent_intent(committed, &ca, &key)
            })
            .unwrap()
        }));
    }
    let mut selected = None;
    for finalizer in finalizers {
        let result = finalizer.await.unwrap();
        if let Some(previous) = &selected {
            assert_eq!(previous, &result);
        } else {
            selected = Some(result);
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    let selected = selected.unwrap();
    let (_, parsed) = X509Certificate::from_der(&selected.certificate_der).unwrap();
    assert_eq!(
        parsed.tbs_certificate.as_ref(),
        winner.certificate.tbs_certificate_der
    );
    let pem = ::pem::parse(&ca).unwrap();
    let (_, issuer) = X509Certificate::from_der(pem.contents()).unwrap();
    parsed.verify_signature(Some(issuer.public_key())).unwrap();
    // Legacy token deletion cannot remove the selected final record.
    for (key, _) in store.list().unwrap() {
        assert!(auth::revoke_key_hash(&store, &key).is_err());
    }

    // Crash after I apply but before its response: restart must observe I.
    let pending = candidate("unknown-agent", "unknown-op-1", &ca, 20);
    assert!(matches!(
        commit_agent_intent(
            &lose_reply(&store),
            &CurrentAuthority,
            record("unknown-agent"),
            pending.clone()
        ),
        Err(IssuanceError::Unknown(_))
    ));
    // Crash after sign and before F: only unsigned I is durable.
    let after_sign = candidate("after-sign-agent", "after-sign-op", &ca, 21);
    commit_agent_intent(
        &store,
        &CurrentAuthority,
        record("after-sign-agent"),
        after_sign.clone(),
    )
    .unwrap();
    assert!(matches!(
        finalize_agent_issuance(
            &store,
            &CurrentAuthority,
            &after_sign.binding,
            |committed| {
                let signed = sign_committed_agent_intent(committed, &ca, &ca_key)?;
                assert!(!signed.certificate_der.is_empty());
                Err("injected crash after sign and before F".into())
            }
        ),
        Err(IssuanceError::Unknown(_))
    ));
    // Crash after F apply but before response: exact selected DER is durable.
    let after_final = candidate("after-final-agent", "after-final-op", &ca, 22);
    commit_agent_intent(
        &store,
        &CurrentAuthority,
        record("after-final-agent"),
        after_final.clone(),
    )
    .unwrap();
    assert!(matches!(
        finalize_agent_issuance(
            &lose_reply(&store),
            &CurrentAuthority,
            &after_final.binding,
            |committed| sign_committed_agent_intent(committed, &ca, &ca_key)
        ),
        Err(IssuanceError::Unknown(_))
    ));
    let selected_after_final =
        query_agent_issuance(&store, &CurrentAuthority, &after_final.binding).unwrap();
    assert!(matches!(
        selected_after_final,
        AgentIssuanceState::Finalized { .. }
    ));
    let before = store.list().unwrap();
    assert_eq!(before.len(), 6);
    drop(store);
    drop(kernel);
    registry.shutdown_all();
    drop(registry);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let restarted = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
    let node = restarted
        .open_persisted_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    // campaign replies before Ready applies the leader entry; Raft 0.7
    // drops earlier ReadIndex. Await actual singleton apply readiness, with
    // no warm-up write or weakening of the production read barrier.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if node.is_leader() && node.applied_index() >= node.last_index() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("restarted singleton must apply its current-term leader entry");
    let kernel = Arc::new(Kernel::new());
    kernel.set_auth_key_store(RaftAuthKeyStore::new_arc(node, runtime));
    let store = auth::KernelSlotStore::new_arc(kernel);
    assert_eq!(
        query_agent_issuance(&store, &CurrentAuthority, &winner.binding).unwrap(),
        AgentIssuanceState::Finalized {
            intent: winner.clone(),
            certificate: selected.clone()
        }
    );
    assert_eq!(
        finalize_agent_issuance(&store, &CurrentAuthority, &winner.binding, |_| panic!(
            "must replay stored F"
        )),
        Ok(selected)
    );
    assert_eq!(
        query_agent_issuance(&store, &CurrentAuthority, &pending.binding).unwrap(),
        AgentIssuanceState::IntentCommitted(pending.clone())
    );
    assert_eq!(
        query_agent_issuance(&store, &CurrentAuthority, &after_sign.binding).unwrap(),
        AgentIssuanceState::IntentCommitted(after_sign.clone())
    );
    assert_eq!(
        query_agent_issuance(&store, &CurrentAuthority, &after_final.binding).unwrap(),
        selected_after_final
    );
    assert!(
        commit_agent_intent(&store, &CurrentAuthority, record("unknown-agent"), pending)
            .unwrap()
            .replayed
    );
    assert_eq!(store.list().unwrap(), before);
    // Recovery signs the same committed SPKI/serial/TBS, never a new identity.
    finalize_agent_issuance(
        &store,
        &CurrentAuthority,
        &after_sign.binding,
        |committed| sign_committed_agent_intent(committed, &ca, &ca_key),
    )
    .unwrap();
    assert!(matches!(
        query_agent_issuance(&store, &CurrentAuthority, &after_sign.binding).unwrap(),
        AgentIssuanceState::Finalized { .. }
    ));
    restarted.shutdown_all();
}
