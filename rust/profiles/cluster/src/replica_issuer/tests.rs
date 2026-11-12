use super::*;
use contracts::replica_binding::{
    ReplicaAllocation, ReplicaBindingChange, ReplicaBindingOutcome, ReplicaBindingRequest,
    ReplicaStorage,
};
use nexus_raft::{
    replica_binding_store::ReplicaBindingError, transport::generate_zone_ca, ZoneManager,
};
use rcgen::{CertificateParams, Issuer, KeyPair, SanType};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

struct Fixture {
    manager: Arc<ZoneManager>,
    store: RaftReplicaBindingStore,
    ca: Vec<u8>,
    ca_pem: Vec<u8>,
    key: Vec<u8>,
    _root: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let root = tempfile::tempdir().unwrap();
        let manager = ZoneManager::isolated(root.path().to_str().unwrap()).unwrap();
        let zone = manager.create_zone("root").unwrap();
        assert!(zone.wait_for_leader(Duration::from_secs(5)));
        let store = RaftReplicaBindingStore::new(zone.consensus_node(), manager.runtime_handle());
        // Establish the real ReadIndex path before creating the short leaf.
        assert_eq!(store.issuer_authority().unwrap(), None);
        let (ca_pem, key) = generate_zone_ca("root").unwrap();
        let ca = pem::parse(&ca_pem).unwrap().into_contents();
        Self {
            manager,
            store,
            ca,
            ca_pem,
            key,
            _root: root,
        }
    }

    fn short_caller(&self) -> Vec<u8> {
        let issuer = Issuer::from_ca_cert_pem(
            std::str::from_utf8(&self.ca_pem).unwrap(),
            KeyPair::from_pem(std::str::from_utf8(&self.key).unwrap()).unwrap(),
        )
        .unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.not_before = (SystemTime::now() - Duration::from_secs(5)).into();
        params.not_after = (SystemTime::now() + Duration::from_secs(5)).into();
        params.subject_alt_names =
            vec![SanType::URI("nexus://zone/root/node/1".try_into().unwrap())];
        params
            .signed_by(&KeyPair::generate().unwrap(), &issuer)
            .unwrap()
            .der()
            .to_vec()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.manager.shutdown();
    }
}

fn expire_after_actual_operation(caller: &CurrentController<'_>) {
    // Require a valid caller after the actual Raft operation. Expiry before
    // admission or a failed/setup-only operation cannot satisfy this fixture.
    caller.check().unwrap();
    let (_, cert) = X509Certificate::from_der(caller.der).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while cert.validity().is_valid() {
        assert!(Instant::now() < deadline, "actual caller did not expire");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn caller_expiry_withholds_the_result_of_a_real_raft_read() {
    let fixture = Fixture::open();
    let leaf = fixture.short_caller();
    let caller = CurrentController {
        der: &leaf,
        ca: &fixture.ca,
    };
    assert_eq!(
        caller
            .observe(|| Ok(fixture.store.issuer_authority()?))
            .unwrap(),
        None
    );
    let mut read_completed = false;
    let result = caller.observe(|| {
        let original = fixture.store.issuer_authority()?;
        read_completed = true;
        expire_after_actual_operation(&caller);
        Ok(original)
    });
    assert!(read_completed);
    assert!(matches!(result, Err(ReplicaIssuerError::Refused(_))));
    let mut invoked = false;
    assert!(caller
        .observe(|| {
            invoked = true;
            Ok(())
        })
        .is_err());
    assert!(
        !invoked,
        "expired caller must fail before the next operation"
    );
}

#[test]
fn caller_expiry_preserves_unknown_and_the_original_committed_operation() {
    let fixture = Fixture::open();
    let leaf = fixture.short_caller();
    let caller = CurrentController {
        der: &leaf,
        ca: &fixture.ca,
    };
    let original = ReplicaBindingRequest {
        operation_id: "original-before-expiry".into(),
        allocation: ReplicaAllocation {
            owner_id: "owner-a".into(),
            allocation_id: "primary".into(),
        },
        change: ReplicaBindingChange::Register {
            storage: ReplicaStorage {
                authority: "storage-a".into(),
                uid: "pvc-a".into(),
            },
            replica_id: 47,
        },
    };
    let mut committed = None;
    let result = caller.commit(|| {
        let outcome = fixture.store.apply(&original)?;
        assert!(matches!(outcome, ReplicaBindingOutcome::Applied(_)));
        committed = Some(outcome.clone());
        expire_after_actual_operation(&caller);
        Ok(outcome)
    });
    assert!(committed.is_some());
    assert!(matches!(
        result,
        Err(ReplicaIssuerError::Store(ReplicaBindingError::Unknown(_)))
    ));
    // The original operation remains durable; the late refusal cannot roll it
    // back or imply permission to choose another allocation or operation ID.
    assert_eq!(fixture.store.reconcile(&original).unwrap(), committed);
    let mut submitted = false;
    assert!(caller
        .commit(|| {
            submitted = true;
            Ok(())
        })
        .is_err());
    assert!(
        !submitted,
        "expired caller must not submit another proposal"
    );
}
