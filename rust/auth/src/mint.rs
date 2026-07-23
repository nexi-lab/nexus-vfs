//! Minting and revoking keys — the `useradd` / `passwd` side of the policy.
//!
//! Management tooling only. It never runs on the authentication path, and
//! it is the only place a key exists in the clear: the caller is handed the
//! `sk-` string exactly once, and what lands in the store is its HMAC. There
//! is no way back — a lost key is reissued, not recovered.

use std::sync::Arc;

use kernel::hal::auth_key_store::{AuthKeyStore, AuthKeyStoreError};
use rand::Rng; // `rand_core::Rng` — the CSPRNG core trait, `fill_bytes` lives here.

use crate::provider::{hash_key, API_KEY_PREFIX};
use crate::record::{AuthKeyRecord, SubjectType};

/// Random bytes in the secret half of a key. 32 hex chars ⇒ 128 bits, which
/// puts the key comfortably over the length floor and far out of reach of a
/// guessing attack.
const KEY_RANDOM_BYTES: usize = 16;

/// A freshly minted credential. The `key` field is the only copy that will
/// ever exist in the clear.
pub struct MintedKey {
    /// Hand this to the holder, once.
    pub key: String,
    /// What the store is keyed by. Safe to log, safe to hand the
    /// cache-invalidation observer.
    pub key_hash: String,
    /// What was written.
    pub record: AuthKeyRecord,
}

/// Generate `sk-<32 hex chars>` from the OS CSPRNG.
fn generate_key() -> String {
    let mut bytes = [0u8; KEY_RANDOM_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    let mut key = String::with_capacity(API_KEY_PREFIX.len() + KEY_RANDOM_BYTES * 2);
    key.push_str(API_KEY_PREFIX);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(key, "{byte:02x}");
    }
    key
}

/// Mint a key for `record`'s subject and commit it to the store.
///
/// `record.key_id` is the caller's to choose (tooling usually uses a uuid);
/// everything else about the credential — subject, zones, expiry, admin — is
/// whatever the caller put in the record. The commit goes through the node's
/// root-zone raft, which is **per-node SOLO** (the credential store is
/// node-local, not federated), so the key resolves on *this* node: each node
/// mints and validates its own agents, and an agent authenticates against its
/// local node.
///
/// A subject's identity must be unique so the `from` guarantee holds:
/// `subject_id` becomes the `agent_id` the mailbox hook stamps into an
/// envelope's `from`, so letting two credentials claim one
/// `(subject_type, subject_id)` would let either holder author the other's
/// mail. `mint_key` enforces that **within this node's store** — it refuses a
/// subject that already holds an active key unless `allow_existing` is set (the
/// deliberate escape for key rotation). Cross-node uniqueness is a naming
/// concern (agent names are machine-anchored, so they cannot collide across
/// nodes), the store being per-node.
pub fn mint_key(
    store: &Arc<dyn AuthKeyStore>,
    secret: &str,
    record: AuthKeyRecord,
    allow_existing: bool,
) -> Result<MintedKey, AuthKeyStoreError> {
    // The store is keyed by key-hash, not by subject, so uniqueness is a
    // mint-layer policy (this crate owns the record schema; the raft store keeps
    // records opaque bytes) enforced by scanning the active records. `auth mint`
    // is offline admin tooling with a single writer, so the list→put window is
    // not a real race and the raft log stays the SSOT.
    if !allow_existing {
        if let Some(clash_id) = find_active_subject(store, record.subject_type, &record.subject_id)?
        {
            return Err(AuthKeyStoreError::Backend(format!(
                "subject {}:{} already has an active key (key_id={clash_id}); \
                 revoke it, or pass --allow-existing to add another key for the \
                 same subject (rotation)",
                record.subject_type.as_str(),
                record.subject_id,
            )));
        }
    }

    let key = generate_key();
    let key_hash = hash_key(secret, &key);
    let bytes = record.encode().map_err(|e| {
        AuthKeyStoreError::Backend(format!("encode auth record {}: {e}", record.key_id))
    })?;
    store.put(&key_hash, &bytes)?;
    Ok(MintedKey {
        key,
        key_hash,
        record,
    })
}

/// The `key_id` of an active (non-revoked) key already bound to
/// `(subject_type, subject_id)`, if any — the uniqueness guard `mint_key`
/// consults so one identity cannot be claimed by two credentials.
fn find_active_subject(
    store: &Arc<dyn AuthKeyStore>,
    subject_type: SubjectType,
    subject_id: &str,
) -> Result<Option<String>, AuthKeyStoreError> {
    for (_hash, bytes) in store.list()? {
        // A record this build cannot decode still binds a subject, but it can
        // only have been written by a newer schema; skip it (as `auth list`
        // does) rather than abort every mint on one unreadable row. Worst case
        // is a missed dedup against that row, never a wrong rejection.
        let Ok(rec) = AuthKeyRecord::decode(&bytes) else {
            continue;
        };
        if !rec.revoked && rec.subject_type == subject_type && rec.subject_id == subject_id {
            return Ok(Some(rec.key_id));
        }
    }
    Ok(None)
}

/// Revoke a key by its clear-text value — the shape a holder uses to retire
/// their own credential.
///
/// Returns whether a record was there to remove.
pub fn revoke_key(
    store: &Arc<dyn AuthKeyStore>,
    secret: &str,
    key: &str,
) -> Result<bool, AuthKeyStoreError> {
    store.delete(&hash_key(secret, key))
}

/// Revoke by hash — the shape an admin uses, working from the audit view
/// (`/__sys__/auth/keys/`) rather than from a key they do not hold.
pub fn revoke_key_hash(
    store: &Arc<dyn AuthKeyStore>,
    key_hash: &str,
) -> Result<bool, AuthKeyStoreError> {
    store.delete(key_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{is_well_formed, ApiKeyAuthProvider};
    use crate::record::SubjectType;
    use parking_lot::Mutex;
    use std::collections::BTreeMap;
    use transport::auth::{AuthCredentials, AuthProvider};

    const SECRET: &str = "mint-test-secret";

    #[derive(Default)]
    struct MemStore {
        records: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl AuthKeyStore for MemStore {
        fn get(&self, key_hash: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
            Ok(self.records.lock().get(key_hash).cloned())
        }
        fn put(&self, key_hash: &str, record: &[u8]) -> Result<(), AuthKeyStoreError> {
            self.records
                .lock()
                .insert(key_hash.to_string(), record.to_vec());
            Ok(())
        }
        fn delete(&self, key_hash: &str) -> Result<bool, AuthKeyStoreError> {
            Ok(self.records.lock().remove(key_hash).is_some())
        }
        fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError> {
            Ok(self
                .records
                .lock()
                .iter()
                .map(|(h, r)| (h.clone(), r.clone()))
                .collect())
        }
    }

    fn record() -> AuthKeyRecord {
        AuthKeyRecord {
            key_id: "key-1".into(),
            name: "mac-ai".into(),
            subject_type: SubjectType::Agent,
            subject_id: "mac-ai".into(),
            is_admin: false,
            revoked: false,
            expires_at_ms: None,
            zone_perms: vec![("sharedzone".into(), "rw".into())],
        }
    }

    /// The full lifecycle, exercised end to end through the real provider:
    /// mint → the minted key authenticates as its subject → revoke → it
    /// authenticates as nobody. Each step consumes the previous step's output.
    #[test]
    fn a_minted_key_authenticates_and_a_revoked_one_does_not() {
        let store: Arc<dyn AuthKeyStore> = Arc::new(MemStore::default());
        let minted = mint_key(&store, SECRET, record(), false).expect("mint");

        // The key is well-formed by construction — it must clear the very
        // format gate the provider applies.
        assert!(
            is_well_formed(&minted.key),
            "minted key must be well-formed"
        );
        assert!(minted.key.starts_with("sk-"));

        // Nothing but the hash was stored: the clear-text key is nowhere in
        // the record bytes.
        let stored = store.get(&minted.key_hash).unwrap().expect("record stored");
        let stored_text = String::from_utf8_lossy(&stored);
        assert!(
            !stored_text.contains(&minted.key),
            "the clear-text key must never be written to the store"
        );

        // It authenticates as its subject.
        let provider = ApiKeyAuthProvider::new(Arc::clone(&store), SECRET);
        let ctx = provider
            .resolve(&AuthCredentials::from_token(&minted.key))
            .expect("minted key authenticates");
        assert_eq!(ctx.agent_id.as_deref(), Some("mac-ai"));

        // Revoke it, evict the cached context the way the apply-observer will.
        assert!(revoke_key(&store, SECRET, &minted.key).expect("revoke"));
        provider.invalidate(&minted.key_hash);

        assert!(
            provider
                .resolve(&AuthCredentials::from_token(&minted.key))
                .is_err(),
            "a revoked key authenticates as nobody"
        );
        // Revoking again is idempotent and reports there was nothing left.
        assert!(!revoke_key(&store, SECRET, &minted.key).expect("re-revoke"));
    }

    /// An admin working from the audit view holds a hash, not a key.
    #[test]
    fn an_admin_can_revoke_by_hash_alone() {
        let store: Arc<dyn AuthKeyStore> = Arc::new(MemStore::default());
        let minted = mint_key(&store, SECRET, record(), false).expect("mint");

        assert!(revoke_key_hash(&store, &minted.key_hash).expect("revoke by hash"));
        assert!(store.get(&minted.key_hash).unwrap().is_none());
    }

    #[test]
    fn every_minted_key_is_distinct() {
        let store: Arc<dyn AuthKeyStore> = Arc::new(MemStore::default());
        let a = mint_key(&store, SECRET, record(), false).expect("mint a");
        // Same subject a second time is rotation — `allow_existing` is required.
        let b = mint_key(&store, SECRET, record(), true).expect("mint b");
        assert_ne!(a.key, b.key);
        assert_ne!(a.key_hash, b.key_hash);
        assert_eq!(store.list().unwrap().len(), 2);
    }

    /// An agent's identity is unique cluster-wide: a second key for a subject
    /// that already holds one is refused, and the refusal names the clash.
    #[test]
    fn a_duplicate_subject_is_refused_by_default() {
        let store: Arc<dyn AuthKeyStore> = Arc::new(MemStore::default());
        mint_key(&store, SECRET, record(), false).expect("first mint");
        // `MintedKey` holds the clear-text key and deliberately isn't `Debug`,
        // so match rather than `expect_err` (which would need `Ok: Debug`).
        let msg = match mint_key(&store, SECRET, record(), false) {
            Ok(_) => panic!("a second key for the same subject must be refused"),
            Err(e) => format!("{e}"),
        };
        assert!(
            msg.contains("already has an active key") && msg.contains("mac-ai"),
            "the refusal must name the clash: {msg}"
        );
        // The rejected mint wrote nothing — only the first key lives.
        assert_eq!(store.list().unwrap().len(), 1);
    }

    /// `allow_existing` is the deliberate escape for rotation: a second live
    /// key for one subject, both resolving as that subject.
    #[test]
    fn allow_existing_permits_a_second_key_for_rotation() {
        let store: Arc<dyn AuthKeyStore> = Arc::new(MemStore::default());
        let a = mint_key(&store, SECRET, record(), false).expect("first mint");
        let b = mint_key(&store, SECRET, record(), true).expect("rotation mint");
        assert_ne!(a.key, b.key, "rotation issues a distinct key");
        assert_eq!(store.list().unwrap().len(), 2, "both keys stay live");
    }

    /// Revoking frees the identity: once the record is gone a plain mint (no
    /// `allow_existing`) succeeds, so a retired agent name can be reissued.
    #[test]
    fn a_revoked_subject_no_longer_blocks_reminting() {
        let store: Arc<dyn AuthKeyStore> = Arc::new(MemStore::default());
        let a = mint_key(&store, SECRET, record(), false).expect("first mint");
        assert!(revoke_key_hash(&store, &a.key_hash).expect("revoke"));
        mint_key(&store, SECRET, record(), false).expect("re-mint after revoke");
    }

    /// Uniqueness is per `(subject_type, subject_id)`: a user and an agent may
    /// share an id — they are different principals and only the agent carries
    /// an `agent_id`.
    #[test]
    fn the_same_id_under_a_different_subject_type_coexists() {
        let store: Arc<dyn AuthKeyStore> = Arc::new(MemStore::default());
        mint_key(&store, SECRET, record(), false).expect("agent mint");
        let mut as_user = record();
        as_user.subject_type = SubjectType::User;
        mint_key(&store, SECRET, as_user, false).expect("a user with the same id is distinct");
        assert_eq!(store.list().unwrap().len(), 2);
    }
}
