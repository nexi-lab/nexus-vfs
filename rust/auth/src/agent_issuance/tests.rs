use super::*;
use crate::{mint_agent_authz, revoke_key_hash};
use parking_lot::Mutex;
use std::collections::{btree_map::Entry, BTreeMap};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
struct Memory {
    rows: Mutex<BTreeMap<String, Vec<u8>>>,
    lose_next_reply: AtomicBool,
    insert_after_legacy_read: Mutex<Option<Vec<u8>>>,
}

impl AuthKeyStore for Memory {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
        let result = self.rows.lock().get(key).cloned();
        if let Some(bytes) = self.insert_after_legacy_read.lock().take() {
            self.rows.lock().insert(key.into(), bytes);
        }
        Ok(result)
    }
    fn get_linearizable(&self, key: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
        Ok(self.rows.lock().get(key).cloned())
    }
    fn put(&self, key: &str, value: &[u8]) -> Result<(), AuthKeyStoreError> {
        self.rows.lock().insert(key.into(), value.to_vec());
        Ok(())
    }
    fn put_if_absent(&self, key: &str, value: &[u8]) -> Result<bool, AuthKeyStoreError> {
        self.put_if_absent_atomic(key, value)
    }
    fn put_if_absent_atomic(&self, key: &str, value: &[u8]) -> Result<bool, AuthKeyStoreError> {
        let inserted = match self.rows.lock().entry(key.into()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(value.to_vec());
                true
            }
        };
        if self.lose_next_reply.swap(false, Ordering::SeqCst) {
            return Err(AuthKeyStoreError::Backend(
                "injected lost reply AFTER commit".into(),
            ));
        }
        Ok(inserted)
    }
    fn delete(&self, key: &str) -> Result<bool, AuthKeyStoreError> {
        Ok(self.rows.lock().remove(key).is_some())
    }
    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError> {
        Ok(self
            .rows
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

fn authorization() -> AuthKeyRecord {
    AuthKeyRecord {
        key_id: "fixture-agent-claim".into(),
        name: "fixture agent".into(),
        subject_type: SubjectType::Agent,
        subject_id: "fixture-agent".into(),
        is_admin: false,
        revoked: false,
        expires_at_ms: None,
        zone_perms: vec![],
    }
}

fn candidate() -> AgentIssuanceReceipt {
    AgentIssuanceReceipt {
        schema_version: 1,
        binding: IssuanceBinding {
            issuer_sha256: "a".repeat(64),
            caller_id: "node-1".into(),
            owner_id: "owner-1".into(),
            agent_name: "fixture-agent".into(),
            operation_id: "fixture-op-1".into(),
            request_sha256: [7; 32],
        },
        // Schema fixtures; the real Raft integration fixture signs an actual
        // X.509 candidate. Crypto verification belongs to the minter/helper.
        certificate_der: vec![0x30, 1, 0],
        serial: vec![1],
    }
}

fn memory() -> (Arc<Memory>, Arc<dyn AuthKeyStore>) {
    let concrete = Arc::new(Memory::default());
    let store: Arc<dyn AuthKeyStore> = concrete.clone();
    (concrete, store)
}

#[test]
fn claim_and_public_receipt_share_one_legacy_readable_record() {
    let (_, store) = memory();
    let receipt = candidate();
    let committed = commit_agent_issuance(&store, authorization(), receipt.clone()).unwrap();
    assert!(!committed.replayed);
    assert_eq!(committed.receipt, receipt);
    let rows = store.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "agent:fixture-agent");
    assert_eq!(AuthKeyRecord::decode(&rows[0].1).unwrap(), authorization());
    assert_eq!(
        query_agent_issuance(&store, &receipt.binding).unwrap(),
        Some(receipt)
    );
}

#[test]
fn same_operation_replays_committed_bytes_not_the_losing_candidate() {
    let (_, store) = memory();
    let first = candidate();
    commit_agent_issuance(&store, authorization(), first.clone()).unwrap();
    let mut different_signature = first.clone();
    different_signature.certificate_der = vec![0x30, 2, 42];
    different_signature.serial = vec![99];
    let replay = commit_agent_issuance(&store, authorization(), different_signature).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.receipt, first);
}

#[test]
fn changed_operation_or_request_is_a_typed_conflict() {
    let (_, store) = memory();
    commit_agent_issuance(&store, authorization(), candidate()).unwrap();
    for (change_op, expected) in [
        (true, IssuanceConflict::DifferentOperation),
        (false, IssuanceConflict::DifferentRequest),
    ] {
        let mut changed = candidate();
        if change_op {
            changed.binding.operation_id.push_str("-competing");
        } else {
            changed.binding.request_sha256[0] ^= 1;
        }
        assert_eq!(
            commit_agent_issuance(&store, authorization(), changed),
            Err(IssuanceError::Conflict(expected))
        );
    }
}

#[test]
fn knowing_the_operation_does_not_authorize_receipt_query() {
    let (_, store) = memory();
    commit_agent_issuance(&store, authorization(), candidate()).unwrap();
    for field in ["issuer", "caller", "owner"] {
        let mut expected = candidate().binding;
        match field {
            "issuer" => expected.issuer_sha256 = "b".repeat(64),
            "caller" => expected.caller_id = "node-2".into(),
            _ => expected.owner_id = "owner-2".into(),
        }
        assert_eq!(
            query_agent_issuance(&store, &expected),
            Err(IssuanceError::NotAuthorized)
        );
    }
}

#[test]
fn committed_then_lost_reply_is_unknown_and_recovered_by_same_binding() {
    let (concrete, store) = memory();
    concrete.lose_next_reply.store(true, Ordering::SeqCst);
    let first = candidate();
    assert!(matches!(
        commit_agent_issuance(&store, authorization(), first.clone()),
        Err(IssuanceError::Unknown(_))
    ));
    assert_eq!(
        query_agent_issuance(&store, &first.binding).unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        commit_agent_issuance(&store, authorization(), first)
            .unwrap()
            .receipt,
        candidate()
    );
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn absent_query_does_not_create_or_authorize_a_new_operation() {
    let (_, store) = memory();
    assert_eq!(
        query_agent_issuance(&store, &candidate().binding).unwrap(),
        None
    );
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn legacy_rotation_cannot_erase_a_managed_receipt() {
    let (_, store) = memory();
    commit_agent_issuance(&store, authorization(), candidate()).unwrap();
    let before = store.get("agent:fixture-agent").unwrap();
    assert!(mint_agent_authz(&store, authorization(), true).is_err());
    assert!(mint_agent_authz(&store, authorization(), false).is_err());
    assert_eq!(store.get("agent:fixture-agent").unwrap(), before);
    assert!(revoke_key_hash(&store, "agent:fixture-agent").is_err());
    assert_eq!(store.get("agent:fixture-agent").unwrap(), before);
}

#[test]
fn absent_legacy_rotation_cannot_overwrite_a_concurrent_managed_insert() {
    let (concrete, store) = memory();
    let winning = serde_json::to_vec(&ManagedAgentRecord {
        authorization: authorization(),
        credential_lifecycle: candidate(),
    })
    .unwrap();
    *concrete.insert_after_legacy_read.lock() = Some(winning.clone());
    assert!(mint_agent_authz(&store, authorization(), true).is_err());
    assert_eq!(store.get("agent:fixture-agent").unwrap(), Some(winning));
}

#[test]
fn existing_legacy_rotation_stays_compatible_and_cannot_be_adopted() {
    let (_, store) = memory();
    mint_agent_authz(&store, authorization(), false).unwrap();
    let mut rotated = authorization();
    rotated.key_id = "new-legacy-key".into();
    mint_agent_authz(&store, rotated.clone(), true).unwrap();
    assert_eq!(
        AuthKeyRecord::decode(&store.get("agent:fixture-agent").unwrap().unwrap()).unwrap(),
        rotated
    );
    assert_eq!(
        commit_agent_issuance(&store, authorization(), candidate()),
        Err(IssuanceError::Conflict(
            IssuanceConflict::LegacyNameOccupied
        ))
    );
    assert!(revoke_key_hash(&store, "agent:fixture-agent").is_err());
}

#[test]
fn malformed_and_future_receipt_markers_fail_closed_for_legacy_rotation() {
    let (_, store) = memory();
    for marker in [
        serde_json::Value::Null,
        serde_json::json!({"schema_version":99}),
    ] {
        let mut row = serde_json::to_value(authorization()).unwrap();
        row[MARKER] = marker;
        let bytes = serde_json::to_vec(&row).unwrap();
        store.put("agent:fixture-agent", &bytes).unwrap();
        assert!(mint_agent_authz(&store, authorization(), true).is_err());
        assert_eq!(store.get("agent:fixture-agent").unwrap(), Some(bytes));
        assert!(matches!(
            query_agent_issuance(&store, &candidate().binding),
            Err(IssuanceError::Unknown(_))
        ));
    }
}

#[test]
fn invalid_or_privileged_claims_never_reach_the_store() {
    let (_, store) = memory();
    let mut privileged = authorization();
    privileged.is_admin = true;
    assert!(matches!(
        commit_agent_issuance(&store, privileged, candidate()),
        Err(IssuanceError::Invalid(_))
    ));
    let mut bad = candidate();
    bad.binding.operation_id = "bad/op".into();
    assert!(matches!(
        commit_agent_issuance(&store, authorization(), bad),
        Err(IssuanceError::Invalid(_))
    ));
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn unsupported_backend_does_not_fall_back_to_nonatomic_creation_or_stale_query() {
    let store = kernel::hal::auth_key_store::NoopAuthKeyStore::arc();
    assert!(matches!(
        commit_agent_issuance(&store, authorization(), candidate()),
        Err(IssuanceError::Unknown(_))
    ));
    assert!(matches!(
        query_agent_issuance(&store, &candidate().binding),
        Err(IssuanceError::Unknown(_))
    ));
}
