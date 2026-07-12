//! `/__sys__/auth/keys` — the credential procfs view.
//!
//! Linux `/proc/keys`. Credential records are a kernel-internal primitive
//! living in their own raft tree (§3.B.3), deliberately off the
//! `sys_read` / `readdir` path so no path walk reaches one and no
//! `sys_write` forges one. This gives back the introspection surface the
//! records would otherwise have had as files — read-only, admin-gated,
//! and with no way through it to the store.

use crate::core::procfs::ProcfsProvider;
use crate::kernel::Kernel;

/// Entry type reported per key. `DT_REG` — a hash projects as a leaf.
const DT_REG: u8 = 0;

pub struct AuthKeysProcfs;

impl ProcfsProvider for AuthKeysProcfs {
    fn prefix(&self) -> &str {
        contracts::AUTH_KEYS_PATH_PREFIX
    }

    /// Enumerating credentials is admin-only. A non-admin gets an empty
    /// listing rather than an error, so the view never answers "does this
    /// hash exist?" to a caller who may not ask.
    fn admin_only(&self) -> bool {
        true
    }

    /// Hashes only — never a record's bytes. Records are opaque to the
    /// kernel, so it *cannot* leak a grant here even in principle; a tool
    /// that needs to decode one goes through the store and the provider
    /// that owns the schema.
    ///
    /// `sub_path` narrows by hash prefix, so `readdir("…/auth/keys/ab")`
    /// lists the hashes starting `ab`.
    fn readdir(&self, kernel: &Kernel, sub_path: &str) -> Vec<(String, u8)> {
        match kernel.auth_key_store().list() {
            Ok(records) => records
                .into_iter()
                .map(|(hash, _record)| hash)
                .filter(|hash| hash.starts_with(sub_path))
                .map(|hash| (hash, DT_REG))
                .collect(),
            Err(e) => {
                // The readdir result has no error channel, so an empty
                // listing is the fail-closed answer — but a store that is
                // down must not pass silently as "no credentials exist".
                tracing::warn!(
                    error = %e,
                    "readdir {} — auth key store unavailable; listing empty",
                    contracts::AUTH_KEYS_PATH_PREFIX
                );
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::auth_key_store::{AuthKeyStore, AuthKeyStoreError};
    use crate::kernel::WriteRequest;
    use contracts::{OperationContext, AUTH_KEYS_PATH_PREFIX};
    use parking_lot::Mutex;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// In-memory stand-in for `RaftAuthKeyStore` — the view only reads
    /// `list`, so the consensus round-trip is not what is under test.
    #[derive(Default)]
    struct MemAuthKeyStore {
        records: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl MemAuthKeyStore {
        fn with(entries: &[(&str, &[u8])]) -> Arc<Self> {
            let store = Arc::new(Self::default());
            for (hash, record) in entries {
                store
                    .records
                    .lock()
                    .insert((*hash).to_string(), record.to_vec());
            }
            store
        }
    }

    impl AuthKeyStore for MemAuthKeyStore {
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

    /// A store that is present but unreachable — a follower whose
    /// consensus read failed, say.
    struct BrokenAuthKeyStore;

    impl AuthKeyStore for BrokenAuthKeyStore {
        fn get(&self, _: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
            Err(AuthKeyStoreError::Backend("down".into()))
        }
        fn put(&self, _: &str, _: &[u8]) -> Result<(), AuthKeyStoreError> {
            Err(AuthKeyStoreError::Backend("down".into()))
        }
        fn delete(&self, _: &str) -> Result<bool, AuthKeyStoreError> {
            Err(AuthKeyStoreError::Backend("down".into()))
        }
        fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError> {
            Err(AuthKeyStoreError::Backend("down".into()))
        }
    }

    fn names(result: &crate::kernel::ReadDirResult) -> Vec<String> {
        result.items.iter().map(|(name, _)| name.clone()).collect()
    }

    #[test]
    fn admin_sees_every_key_hash() {
        let k = Kernel::new();
        k.set_auth_key_store(MemAuthKeyStore::with(&[
            ("beef02", b"record-b"),
            ("abcd01", b"record-a"),
            ("cafe03", b"record-c"),
        ]));

        let listed = k.readdir_paged(AUTH_KEYS_PATH_PREFIX, "root", true, 0, None);
        assert_eq!(names(&listed), vec!["abcd01", "beef02", "cafe03"]);
        // Hashes only — a record's grants never cross this surface.
        assert!(listed
            .items
            .iter()
            .all(|(_, entry_type)| *entry_type == DT_REG));
    }

    #[test]
    fn non_admin_sees_nothing_at_all() {
        let k = Kernel::new();
        k.set_auth_key_store(MemAuthKeyStore::with(&[("abcd01", b"record-a")]));

        // Empty rather than an error: a non-admin must not learn whether
        // a given hash exists, and an error would answer exactly that.
        let listed = k.readdir_paged(AUTH_KEYS_PATH_PREFIX, "root", false, 0, None);
        assert!(names(&listed).is_empty());
        assert!(!listed.has_more);
    }

    #[test]
    fn a_sub_path_narrows_by_hash_prefix() {
        let k = Kernel::new();
        k.set_auth_key_store(MemAuthKeyStore::with(&[
            ("abcd01", b"a"),
            ("abcd02", b"b"),
            ("cafe03", b"c"),
        ]));

        let listed = k.readdir_paged(
            &format!("{AUTH_KEYS_PATH_PREFIX}/abcd"),
            "root",
            true,
            0,
            None,
        );
        assert_eq!(names(&listed), vec!["abcd01", "abcd02"]);
    }

    #[test]
    fn an_unreachable_store_lists_empty_rather_than_guessing() {
        let k = Kernel::new();
        k.set_auth_key_store(Arc::new(BrokenAuthKeyStore));

        // The result shape has no error channel, so empty is the
        // fail-closed answer. It must never fabricate entries or panic.
        let listed = k.readdir_paged(AUTH_KEYS_PATH_PREFIX, "root", true, 0, None);
        assert!(names(&listed).is_empty());
    }

    #[test]
    fn an_unwired_kernel_lists_empty() {
        // Boot default is NoopAuthKeyStore: no federation, no records.
        let k = Kernel::new();
        let listed = k.readdir_paged(AUTH_KEYS_PATH_PREFIX, "root", true, 0, None);
        assert!(names(&listed).is_empty());
    }

    /// The view is a projection, not a door. Writing at its path lands
    /// (at most) an inert entry in the file tree — credentials live in
    /// the raft auth tree, reachable only through the HAL slot — so a
    /// `sys_write` cannot mint one. This is the invariant that lets the
    /// view exist while the general `/__sys__` write gate is still open.
    #[test]
    fn writing_at_the_view_cannot_forge_a_credential() {
        let k = Kernel::new();
        let store = MemAuthKeyStore::with(&[]);
        k.set_auth_key_store(store.clone());

        let ctx = OperationContext::new("attacker", "root", true, None, true);
        let forged = format!("{AUTH_KEYS_PATH_PREFIX}/forged-admin-key");
        // Whatever sys_write makes of this path — succeed, fail, route
        // nowhere — the credential store must be untouched.
        let _ = k.sys_write(
            &[WriteRequest {
                path: forged,
                content: br#"{"is_admin":true}"#.to_vec(),
                offset: 0,
            }],
            &ctx,
        );

        assert_eq!(
            store.get("forged-admin-key").expect("store get"),
            None,
            "a write at the view path must not mint a credential"
        );
        assert!(
            store.list().expect("store list").is_empty(),
            "the credential store must stay empty after a write at the view path"
        );
        // And the view still shows nothing — the forged file is not a key.
        let listed = k.readdir_paged(AUTH_KEYS_PATH_PREFIX, "root", true, 0, None);
        assert!(names(&listed).is_empty());
    }
}
