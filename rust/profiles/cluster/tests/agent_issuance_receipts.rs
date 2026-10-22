//! Source-only issuance coordinator fixtures: real Raft CAS, lost commit reply,
//! late-bound kernel slot, disk reopen and legacy record compatibility. No RPC
//! or production enrollment is enabled by this test.

use auth::agent_issuance::{
    commit_agent_issuance, query_agent_issuance, AgentIssuanceReceipt, IssuanceBinding,
    IssuanceError,
};
use auth::{AuthKeyRecord, SubjectType};
use kernel::hal::auth_key_store::{AuthKeyStore, AuthKeyStoreError};
use kernel::kernel::Kernel;
use nexus_raft::auth_key_store::RaftAuthKeyStore;
use nexus_raft::raft::ZoneRaftRegistry;
use nexus_raft::transport::{generate_agent_cert, generate_zone_ca};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Barrier,
};
use x509_parser::prelude::{FromDer, X509Certificate};

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

fn candidate(name: &str, operation: &str, ca: &[u8], key: &[u8]) -> AgentIssuanceReceipt {
    let (cert_pem, _) = generate_agent_cert(name, ca, key).unwrap();
    let pem = ::pem::parse(cert_pem).unwrap();
    let (_, cert) = X509Certificate::from_der(pem.contents()).unwrap();
    AgentIssuanceReceipt {
        schema_version: 1,
        binding: IssuanceBinding {
            issuer_sha256: "a".repeat(64),
            caller_id: "fixture-node".into(),
            owner_id: "fixture-owner".into(),
            agent_name: name.into(),
            operation_id: operation.into(),
            request_sha256: [3; 32],
        },
        serial: cert.raw_serial().to_vec(),
        certificate_der: pem.into_contents(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_winner_and_unknown_result_survive_real_raft_restart() {
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
    let (ca, ca_key) = generate_zone_ca("isolated-fixture").unwrap();

    let start = Arc::new(Barrier::new(8));
    let mut tasks = vec![];
    for n in 0..8 {
        let candidate = candidate("racing-agent", &format!("race-op-{n}"), &ca, &ca_key);
        let store = store.clone();
        let start = start.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            start.wait();
            commit_agent_issuance(&store, record("racing-agent"), candidate)
        }));
    }
    let mut winner = None;
    let mut conflicts = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(result) => {
                assert!(!result.replayed);
                assert!(winner.replace(result.receipt).is_none());
            }
            Err(IssuanceError::Conflict(_)) => conflicts += 1,
            other => panic!("unexpected race result: {other:?}"),
        }
    }
    assert_eq!(conflicts, 7);
    let winner = winner.expect("exactly one Raft winner");
    let stored_winner = store
        .get_linearizable("agent:racing-agent")
        .unwrap()
        .unwrap();
    assert_eq!(
        AuthKeyRecord::decode(&stored_winner).unwrap(),
        record("racing-agent")
    );
    assert!(auth::mint_agent_authz(&store, record("racing-agent"), true).is_err());
    assert!(auth::revoke_key_hash(&store, "agent:racing-agent").is_err());
    assert_eq!(
        store
            .get_linearizable("agent:racing-agent")
            .unwrap()
            .unwrap(),
        stored_winner
    );

    let pending = candidate("unknown-agent", "unknown-op-1", &ca, &ca_key);
    let fault: Arc<dyn AuthKeyStore> = Arc::new(LoseOneReply {
        inner: store.clone(),
        pending: AtomicBool::new(true),
    });
    assert!(matches!(
        commit_agent_issuance(&fault, record("unknown-agent"), pending.clone()),
        Err(IssuanceError::Unknown(_))
    ));
    let before = store.list().unwrap();
    assert_eq!(before.len(), 2);
    drop(fault);
    drop(store);
    drop(kernel);
    registry.shutdown_all();
    drop(registry);
    // Transport tasks release their held redb handles after observing shutdown.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let restarted = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
    let node = restarted
        .open_persisted_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    let kernel = Arc::new(Kernel::new());
    kernel.set_auth_key_store(RaftAuthKeyStore::new_arc(node, runtime));
    let store = auth::KernelSlotStore::new_arc(kernel);
    assert_eq!(
        query_agent_issuance(&store, &winner.binding).unwrap(),
        Some(winner)
    );
    assert_eq!(
        query_agent_issuance(&store, &pending.binding).unwrap(),
        Some(pending.clone())
    );
    let replay = commit_agent_issuance(&store, record("unknown-agent"), pending).unwrap();
    assert!(replay.replayed);
    assert_eq!(store.list().unwrap(), before);
    restarted.shutdown_all();
}
