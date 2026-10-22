//! `KernelSlotStore` — reach the record store through the kernel's §3.B.3
//! slot instead of holding it directly.
//!
//! ## Why the indirection exists
//!
//! The boot path builds the gRPC routes — and therefore the `AuthProvider` —
//! *before* it bootstraps the zones, so the root zone's consensus (which the
//! real `RaftAuthKeyStore` is built from) does not exist yet at the moment
//! the provider is constructed.
//!
//! Rather than reorder boot around auth, or teach the provider to be
//! late-initialised, this reads the kernel's `auth_key_store` slot on every
//! call. The slot is the late-binding seam the kernel already has: it boots
//! as `NoopAuthKeyStore` (resolves nothing — fail-closed, so a request that
//! arrives before the store is installed authenticates as nobody), and the
//! boot path swaps in `RaftAuthKeyStore` once the root zone is up. The
//! provider picks that up with no further wiring.
//!
//! The cost is one `RwLock` read plus an `Arc` clone per *cache miss* — the
//! authentication hot path is served from the provider's own cache and never
//! reaches this.

use std::sync::Arc;

use kernel::hal::auth_key_store::{AuthKeyStore, AuthKeyStoreError};
use kernel::kernel::Kernel;

/// An `AuthKeyStore` that forwards to whatever store the kernel currently
/// holds in its §3.B.3 slot.
pub struct KernelSlotStore {
    kernel: Arc<Kernel>,
}

impl KernelSlotStore {
    pub fn new(kernel: Arc<Kernel>) -> Self {
        Self { kernel }
    }

    /// Ready to hand to [`crate::ApiKeyAuthProvider::new`].
    pub fn new_arc(kernel: Arc<Kernel>) -> Arc<dyn AuthKeyStore> {
        Arc::new(Self::new(kernel))
    }
}

impl AuthKeyStore for KernelSlotStore {
    fn get(&self, key_hash: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
        self.kernel.auth_key_store().get(key_hash)
    }

    fn get_linearizable(&self, key_hash: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
        self.kernel.auth_key_store().get_linearizable(key_hash)
    }

    fn put(&self, key_hash: &str, record: &[u8]) -> Result<(), AuthKeyStoreError> {
        self.kernel.auth_key_store().put(key_hash, record)
    }

    fn put_if_absent(&self, key_hash: &str, record: &[u8]) -> Result<bool, AuthKeyStoreError> {
        self.kernel.auth_key_store().put_if_absent(key_hash, record)
    }

    fn put_if_absent_atomic(
        &self,
        key_hash: &str,
        record: &[u8],
    ) -> Result<bool, AuthKeyStoreError> {
        self.kernel
            .auth_key_store()
            .put_if_absent_atomic(key_hash, record)
    }

    fn delete(&self, key_hash: &str) -> Result<bool, AuthKeyStoreError> {
        self.kernel.auth_key_store().delete(key_hash)
    }

    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError> {
        self.kernel.auth_key_store().list()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{hash_key, ApiKeyAuthProvider};
    use crate::record::{AuthKeyRecord, SubjectType};
    use parking_lot::Mutex;
    use std::collections::BTreeMap;
    use transport::auth::{AuthCredentials, AuthProvider};

    const SECRET: &str = "slot-test-secret";
    const KEY: &str = "sk-mac-ai-0123456789abcdef0123456789";

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
        fn put_if_absent(&self, key_hash: &str, record: &[u8]) -> Result<bool, AuthKeyStoreError> {
            let mut rows = self.records.lock();
            if rows.contains_key(key_hash) {
                return Ok(false);
            }
            rows.insert(key_hash.into(), record.to_vec());
            Ok(true)
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

    /// The boot-order property this type exists for: a provider built
    /// against an *empty* kernel slot authenticates nobody (fail-closed),
    /// and starts resolving the moment the boot path installs the real
    /// store — with no re-wiring of the provider.
    #[test]
    fn a_provider_built_before_the_store_exists_picks_it_up_on_install() {
        let kernel = Arc::new(Kernel::new());
        // Zero cache TTL: this test is about the slot, not the cache.
        let provider = ApiKeyAuthProvider::with_cache_ttl(
            KernelSlotStore::new_arc(Arc::clone(&kernel)),
            SECRET,
            std::time::Duration::ZERO,
        );

        // Boot default is NoopAuthKeyStore — nothing resolves. A request
        // arriving before the store is installed is nobody, not everybody.
        assert!(
            provider.resolve(&AuthCredentials::from_token(KEY)).is_err(),
            "an unwired store must authenticate no one"
        );

        // Boot path: mint the key, install the store.
        let store = Arc::new(MemStore::default());
        store
            .put(&hash_key(SECRET, KEY), &record().encode().unwrap())
            .unwrap();
        kernel.set_auth_key_store(store);

        let ctx = provider
            .resolve(&AuthCredentials::from_token(KEY))
            .expect("the provider must see the newly installed store");
        assert_eq!(ctx.agent_id.as_deref(), Some("mac-ai"));
    }

    #[test]
    fn slot_preserves_atomic_and_consistent_backend_operations() {
        // A backend can refuse a CAS even when a local GET sees absence.
        // Get-then-put would incorrectly report success and overwrite it.
        struct BarrierStore;
        impl AuthKeyStore for BarrierStore {
            fn get(&self, _: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
                Ok(None)
            }
            fn put(&self, _: &str, _: &[u8]) -> Result<(), AuthKeyStoreError> {
                panic!("CAS must not degrade to put")
            }
            fn put_if_absent(&self, _: &str, _: &[u8]) -> Result<bool, AuthKeyStoreError> {
                Ok(false)
            }
            fn put_if_absent_atomic(&self, _: &str, _: &[u8]) -> Result<bool, AuthKeyStoreError> {
                Ok(false)
            }
            fn get_linearizable(&self, _: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
                Ok(Some(b"committed-winner".to_vec()))
            }
            fn delete(&self, _: &str) -> Result<bool, AuthKeyStoreError> {
                unreachable!()
            }
            fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError> {
                unreachable!()
            }
        }
        let kernel = Arc::new(Kernel::new());
        let slot = KernelSlotStore::new_arc(kernel.clone());
        assert!(slot.put_if_absent_atomic("agent:a", b"candidate").is_err());
        assert!(slot.get_linearizable("agent:a").is_err());
        kernel.set_auth_key_store(Arc::new(BarrierStore));
        assert!(!slot.put_if_absent("agent:a", b"candidate").unwrap());
        assert!(!slot.put_if_absent_atomic("agent:a", b"candidate").unwrap());
        assert_eq!(
            slot.get_linearizable("agent:a").unwrap(),
            Some(b"committed-winner".to_vec())
        );
    }
}
