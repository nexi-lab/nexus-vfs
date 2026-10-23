use super::*;
use crate::{mint_agent_authz, revoke_key_hash};
use parking_lot::Mutex;
use std::collections::{btree_map::Entry, BTreeMap};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Barrier,
};

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

#[derive(Default)]
struct Policy {
    revoked: AtomicBool,
}
impl IssuanceAuthorizer for Policy {
    fn authorize(&self, _: &IssuanceBinding) -> Result<(), String> {
        if self.revoked.load(Ordering::SeqCst) {
            Err("current caller CRL/authority refused".into())
        } else {
            Ok(())
        }
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
fn candidate() -> AgentIssuanceIntent {
    AgentIssuanceIntent {
        schema_version: 2,
        binding: IssuanceBinding {
            issuer_sha256: "aa".repeat(32),
            caller_id: "node-1".into(),
            owner_id: "owner-1".into(),
            agent_name: "fixture-agent".into(),
            operation_id: "fixture-op-1".into(),
            request_sha256: [7; 32],
        },
        // Structural storage fixtures only. The raft crypto and cluster
        // composition fixtures use real verified CSR, TBS and CA signatures.
        certificate: AgentCertificateIntent {
            version: 1,
            agent_name: "fixture-agent".into(),
            issuer_sha256: [0xaa; 32],
            subject_public_key_info_der: vec![0x30, 1],
            serial: vec![1],
            not_before_unix_s: 10,
            not_after_unix_s: 100,
            tbs_certificate_der: vec![0x30, 2],
        },
    }
}
fn signed(intent: &AgentCertificateIntent, variant: u8) -> SignedAgentCertificate {
    SignedAgentCertificate {
        certificate_der: vec![0x30, 3, variant],
        tbs_certificate_der: intent.tbs_certificate_der.clone(),
        serial: intent.serial.clone(),
    }
}
fn memory() -> (Arc<Memory>, Arc<dyn AuthKeyStore>) {
    let concrete = Arc::new(Memory::default());
    let store: Arc<dyn AuthKeyStore> = concrete.clone();
    (concrete, store)
}
fn commit(store: &Arc<dyn AuthKeyStore>, policy: &Policy) -> AgentIssuanceIntent {
    commit_agent_intent(store, policy, authorization(), candidate())
        .unwrap()
        .intent
}

#[test]
fn atomic_unsigned_intent_is_legacy_readable_but_never_authenticating() {
    let (_, store) = memory();
    let policy = Policy::default();
    let intent = commit(&store, &policy);
    let rows = store.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "agent:fixture-agent");
    let legacy = AuthKeyRecord::decode(&rows[0].1).unwrap();
    let mut sentinel = authorization();
    sentinel.expires_at_ms = Some(0);
    assert_eq!(legacy, sentinel);
    assert!(legacy.is_expired(1));
    assert!(!legacy.revoked);
    let json: serde_json::Value = serde_json::from_slice(&rows[0].1).unwrap();
    assert!(json[MARKER].get("certificate_der").is_none());
    assert_eq!(
        query_agent_issuance(&store, &policy, &intent.binding).unwrap(),
        AgentIssuanceState::IntentCommitted(intent)
    );
}

#[test]
fn same_operation_reuses_winning_identity_not_new_serial_or_time() {
    let (_, store) = memory();
    let policy = Policy::default();
    let intent = commit(&store, &policy);
    let mut losing = candidate();
    losing.certificate.serial = vec![99];
    losing.certificate.not_after_unix_s = 99;
    let replay = commit_agent_intent(&store, &policy, authorization(), losing).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.intent, intent);
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn changed_operation_or_request_is_a_typed_conflict() {
    let (_, store) = memory();
    let policy = Policy::default();
    commit(&store, &policy);
    for (op, expected) in [
        (true, IssuanceConflict::DifferentOperation),
        (false, IssuanceConflict::DifferentRequest),
    ] {
        let mut changed = candidate();
        if op {
            changed.binding.operation_id.push_str("-competing");
        } else {
            changed.binding.request_sha256[0] ^= 1;
        }
        assert_eq!(
            commit_agent_intent(&store, &policy, authorization(), changed),
            Err(IssuanceError::Conflict(expected))
        );
    }
}

#[test]
fn known_op_never_bypasses_bound_identity_or_current_operator_revocation() {
    let (_, store) = memory();
    let policy = Policy::default();
    let intent = commit(&store, &policy);
    let selected =
        finalize_agent_issuance(&store, &policy, &intent.binding, |i| Ok(signed(i, 1))).unwrap();
    for field in ["issuer", "caller", "owner"] {
        let mut expected = intent.binding.clone();
        match field {
            "issuer" => expected.issuer_sha256 = "bb".repeat(32),
            "caller" => expected.caller_id = "node-2".into(),
            _ => expected.owner_id = "owner-2".into(),
        }
        assert_eq!(
            query_agent_issuance(&store, &policy, &expected),
            Err(IssuanceError::NotAuthorized)
        );
    }
    policy.revoked.store(true, Ordering::SeqCst);
    assert_eq!(
        query_agent_issuance(&store, &policy, &intent.binding),
        Err(IssuanceError::NotAuthorized)
    );
    assert_eq!(
        commit_agent_intent(&store, &policy, authorization(), intent.clone()),
        Err(IssuanceError::NotAuthorized)
    );
    assert_eq!(
        finalize_agent_issuance(&store, &policy, &intent.binding, |_| panic!(
            "revoked signer called"
        )),
        Err(IssuanceError::NotAuthorized)
    );
    // The expiry sentinel never overrides current auth or erases the final.
    policy.revoked.store(false, Ordering::SeqCst);
    assert_eq!(
        finalize_agent_issuance(&store, &policy, &intent.binding, |_| panic!(
            "already finalized"
        )),
        Ok(selected)
    );
}

#[test]
fn revocation_during_signing_prevents_final_commit() {
    let (_, store) = memory();
    let policy = Policy::default();
    let intent = commit(&store, &policy);
    assert_eq!(
        finalize_agent_issuance(&store, &policy, &intent.binding, |i| {
            policy.revoked.store(true, Ordering::SeqCst);
            Ok(signed(i, 1))
        }),
        Err(IssuanceError::NotAuthorized)
    );
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn crash_at_intent_sign_final_and_response_boundaries_reuses_original_operation() {
    let (concrete, store) = memory();
    let policy = Policy::default();
    concrete.lose_next_reply.store(true, Ordering::SeqCst);
    assert!(matches!(
        commit_agent_intent(&store, &policy, authorization(), candidate()),
        Err(IssuanceError::Unknown(_))
    ));
    let intent = match query_agent_issuance(&store, &policy, &candidate().binding).unwrap() {
        AgentIssuanceState::IntentCommitted(i) => i,
        other => panic!("{other:?}"),
    };
    // Crash after signing but before F: no signed candidate is persisted.
    let generated = signed(&intent.certificate, 1);
    assert!(matches!(
        finalize_agent_issuance(&store, &policy, &intent.binding, |_| {
            assert!(!generated.certificate_der.is_empty());
            Err("crash after signing, before F".into())
        }),
        Err(IssuanceError::Unknown(_))
    ));
    assert_eq!(store.list().unwrap().len(), 1);
    // F applies, its reply is lost. Query and replay recover that exact DER.
    concrete.lose_next_reply.store(true, Ordering::SeqCst);
    assert!(matches!(
        finalize_agent_issuance(&store, &policy, &intent.binding, |i| Ok(signed(i, 2))),
        Err(IssuanceError::Unknown(_))
    ));
    let selected = match query_agent_issuance(&store, &policy, &intent.binding).unwrap() {
        AgentIssuanceState::Finalized {
            intent: stored,
            certificate,
        } => {
            assert_eq!(stored, intent);
            certificate
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(
        selected.certificate_der,
        signed(&intent.certificate, 2).certificate_der
    );
    let before = store.list().unwrap();
    assert_eq!(
        finalize_agent_issuance(&store, &policy, &intent.binding, |_| panic!(
            "must not re-sign"
        )),
        Ok(selected)
    );
    assert_eq!(store.list().unwrap(), before);
}

#[test]
fn concurrent_finalizers_all_return_only_selected_stored_der() {
    let (_, store) = memory();
    let policy = Arc::new(Policy::default());
    let intent = commit(&store, &policy);
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = vec![];
    for variant in 0..8 {
        let store = store.clone();
        let policy = policy.clone();
        let intent = intent.clone();
        let barrier = barrier.clone();
        tasks.push(std::thread::spawn(move || {
            finalize_agent_issuance(&store, policy.as_ref(), &intent.binding, |i| {
                barrier.wait();
                Ok(signed(i, variant))
            })
            .unwrap()
        }));
    }
    let results: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(results.iter().all(|r| r == &results[0]));
    let bytes = store
        .get_linearizable(&final_key(&intent).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<FinalAgentCertificate>(&bytes).unwrap(),
        results[0]
    );
    assert_eq!(store.list().unwrap().len(), 2);
}

#[test]
fn no_intent_or_mismatched_signer_output_cannot_publish_a_final() {
    let (_, store) = memory();
    let policy = Policy::default();
    assert!(matches!(
        finalize_agent_issuance(&store, &policy, &candidate().binding, |_| panic!(
            "no intent"
        )),
        Err(IssuanceError::Unknown(_))
    ));
    let intent = commit(&store, &policy);
    for serial in [true, false] {
        assert!(matches!(
            finalize_agent_issuance(&store, &policy, &intent.binding, |i| {
                let mut result = signed(i, 1);
                if serial {
                    result.serial = vec![2]
                } else {
                    result.tbs_certificate_der.push(9)
                }
                Ok(result)
            }),
            Err(IssuanceError::Invalid(_))
        ));
    }
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn absent_query_is_only_not_observed_and_does_not_sign_or_elect() {
    let (_, store) = memory();
    let policy = Policy::default();
    assert_eq!(
        query_agent_issuance(&store, &policy, &candidate().binding).unwrap(),
        AgentIssuanceState::NotObserved
    );
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn legacy_name_creation_never_uses_a_backends_weaker_default_cas() {
    struct AtomicOnly;
    impl AuthKeyStore for AtomicOnly {
        fn get(&self, _: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
            Ok(None)
        }
        fn put(&self, _: &str, _: &[u8]) -> Result<(), AuthKeyStoreError> {
            panic!("legacy get-then-put would erase I")
        }
        fn put_if_absent_atomic(&self, _: &str, _: &[u8]) -> Result<bool, AuthKeyStoreError> {
            Ok(false)
        }
        fn delete(&self, _: &str) -> Result<bool, AuthKeyStoreError> {
            unreachable!()
        }
        fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError> {
            unreachable!()
        }
    }
    let store: Arc<dyn AuthKeyStore> = Arc::new(AtomicOnly);
    assert!(mint_agent_authz(&store, authorization(), false).is_err());
    assert!(mint_agent_authz(&store, authorization(), true).is_err());
    let unsupported = kernel::hal::auth_key_store::NoopAuthKeyStore::arc();
    assert!(mint_agent_authz(&unsupported, authorization(), false).is_err());
    assert!(mint_agent_authz(&unsupported, authorization(), true).is_err());
}

#[test]
fn legacy_upsert_and_token_delete_cannot_erase_intent_final_or_future_reserved_keys() {
    let (_, store) = memory();
    let policy = Policy::default();
    let intent = commit(&store, &policy);
    finalize_agent_issuance(&store, &policy, &intent.binding, |i| Ok(signed(i, 1))).unwrap();
    for key in [
        "credential-renewal-intent:future",
        "credential-future:unknown",
    ] {
        store.put(key, b"reserved future fixture").unwrap();
    }
    let before = store.list().unwrap();
    assert!(mint_agent_authz(&store, authorization(), true).is_err());
    assert!(mint_agent_authz(&store, authorization(), false).is_err());
    for (key, _) in &before {
        assert!(revoke_key_hash(&store, key).is_err(), "{key}");
    }
    assert_eq!(store.list().unwrap(), before);
    // Ordinary token-hash deletion still works.
    store.put("ordinary-token-hash", b"fixture").unwrap();
    assert!(revoke_key_hash(&store, "ordinary-token-hash").unwrap());
    assert_eq!(store.list().unwrap(), before);
}

#[test]
fn absent_legacy_rotation_cannot_overwrite_a_concurrent_intent_insert() {
    let (concrete, store) = memory();
    let policy = Policy::default();
    let mut sentinel = authorization();
    sentinel.expires_at_ms = Some(0);
    let winning = serde_json::to_vec(&ManagedAgentRecord {
        authorization: sentinel,
        credential_lifecycle: candidate(),
    })
    .unwrap();
    *concrete.insert_after_legacy_read.lock() = Some(winning.clone());
    assert!(mint_agent_authz(&store, authorization(), true).is_err());
    assert_eq!(store.get("agent:fixture-agent").unwrap(), Some(winning));
    assert!(matches!(
        query_agent_issuance(&store, &policy, &candidate().binding),
        Ok(AgentIssuanceState::IntentCommitted(_))
    ));
}

#[test]
fn existing_legacy_rotation_remains_compatible_and_cannot_be_adopted() {
    let (_, store) = memory();
    let policy = Policy::default();
    mint_agent_authz(&store, authorization(), false).unwrap();
    let mut rotated = authorization();
    rotated.key_id = "new-legacy-key".into();
    mint_agent_authz(&store, rotated.clone(), true).unwrap();
    assert_eq!(
        AuthKeyRecord::decode(&store.get("agent:fixture-agent").unwrap().unwrap()).unwrap(),
        rotated
    );
    assert_eq!(
        commit_agent_intent(&store, &policy, authorization(), candidate()),
        Err(IssuanceError::Conflict(
            IssuanceConflict::LegacyNameOccupied
        ))
    );
}

#[test]
fn malformed_or_future_managed_rows_and_final_records_fail_closed() {
    let (_, store) = memory();
    let policy = Policy::default();
    for marker in [
        serde_json::Value::Null,
        serde_json::json!({"schema_version":99}),
    ] {
        let mut row = serde_json::to_value(authorization()).unwrap();
        row[MARKER] = marker;
        let bytes = serde_json::to_vec(&row).unwrap();
        store.put("agent:fixture-agent", &bytes).unwrap();
        assert!(mint_agent_authz(&store, authorization(), true).is_err());
        assert!(matches!(
            query_agent_issuance(&store, &policy, &candidate().binding),
            Err(IssuanceError::Unknown(_))
        ));
        assert_eq!(store.get("agent:fixture-agent").unwrap(), Some(bytes));
    }
    let (_, store) = memory();
    let intent = commit(&store, &policy);
    store.put(&final_key(&intent).unwrap(), b"{}").unwrap();
    assert!(matches!(
        finalize_agent_issuance(&store, &policy, &intent.binding, |_| panic!("malformed F")),
        Err(IssuanceError::Unknown(_))
    ));
}

#[test]
fn legacy_token_provider_never_caches_incomplete_managed_prefix_as_authority() {
    use crate::provider::{hash_key, ApiKeyAuthProvider};
    use transport::auth::{AuthCredentials, AuthProvider};
    let (_, store) = memory();
    let policy = Policy::default();
    let intent = commit(&store, &policy);
    let token = "sk-mac-ai-0123456789abcdef0123456789";
    let secret = "isolated-fixture-secret";
    let token_hash = hash_key(secret, token);
    // Deliberately expose the same prefix through the real legacy token
    // reader; real managed claims live at agent:<name>, never token hashes.
    let bytes = store.get("agent:fixture-agent").unwrap().unwrap();
    store.put(&token_hash, &bytes).unwrap();
    let provider = ApiKeyAuthProvider::with_cache_ttl(
        store.clone(),
        secret,
        std::time::Duration::from_secs(3600),
    );
    for _ in 0..2 {
        assert!(provider
            .resolve(&AuthCredentials::from_token(token))
            .is_err());
    }
    finalize_agent_issuance(&store, &policy, &intent.binding, |i| Ok(signed(i, 1))).unwrap();
    assert!(provider
        .resolve(&AuthCredentials::from_token(token))
        .is_err());
    // Old valid rows remain readable, and revocation with cache eviction wins.
    let mut old = authorization();
    old.zone_perms = vec![("sharedzone".into(), "rw".into())];
    store.put(&token_hash, &old.encode().unwrap()).unwrap();
    assert!(provider
        .resolve(&AuthCredentials::from_token(token))
        .is_ok());
    old.revoked = true;
    store.put(&token_hash, &old.encode().unwrap()).unwrap();
    provider.invalidate(&token_hash);
    assert!(provider
        .resolve(&AuthCredentials::from_token(token))
        .is_err());
}

#[test]
fn invalid_or_privileged_claims_and_unsupported_backends_fail_closed() {
    let (_, store) = memory();
    let policy = Policy::default();
    let mut privileged = authorization();
    privileged.is_admin = true;
    assert!(matches!(
        commit_agent_intent(&store, &policy, privileged, candidate()),
        Err(IssuanceError::Invalid(_))
    ));
    let mut bad = candidate();
    bad.binding.operation_id = "bad/op".into();
    assert!(matches!(
        commit_agent_intent(&store, &policy, authorization(), bad),
        Err(IssuanceError::Invalid(_))
    ));
    assert!(store.list().unwrap().is_empty());
    let store = kernel::hal::auth_key_store::NoopAuthKeyStore::arc();
    assert!(matches!(
        commit_agent_intent(&store, &policy, authorization(), candidate()),
        Err(IssuanceError::Unknown(_))
    ));
    assert!(matches!(
        query_agent_issuance(&store, &policy, &candidate().binding),
        Err(IssuanceError::Unknown(_))
    ));
}
