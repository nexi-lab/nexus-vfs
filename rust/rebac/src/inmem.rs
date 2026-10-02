//! In-memory tuple store for tests and process-local fixtures.
//! Mutations advance one revision while holding the entries write lock.

use std::collections::HashMap;

use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::store::{ReBACTupleStore, ReBACTupleStoreError};

/// In-memory tuple store.  Wraps a `RwLock<HashMap>`; every method
/// takes the lock briefly and returns owned data (no borrow-across-
/// caller).
///
#[derive(Debug, Default)]
pub struct InMemoryReBACTupleStore {
    entries: RwLock<HashMap<String, Vec<u8>>>,
    revision: AtomicU64,
}

impl InMemoryReBACTupleStore {
    /// Fresh empty store.  Equivalent to `Default::default()` but
    /// spelled out for readable call-sites.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReBACTupleStore for InMemoryReBACTupleStore {
    fn put(&self, key: &str, value: &[u8]) -> Result<(), ReBACTupleStoreError> {
        let mut entries = self.entries.write();
        entries.insert(key.to_string(), value.to_vec());
        self.revision.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<bool, ReBACTupleStoreError> {
        let mut entries = self.entries.write();
        let existed = entries.remove(key).is_some();
        if existed {
            self.revision.fetch_add(1, Ordering::Release);
        }
        Ok(existed)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ReBACTupleStoreError> {
        Ok(self.entries.read().get(key).cloned())
    }

    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, ReBACTupleStoreError> {
        Ok(self
            .entries
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    fn revision(&self) -> Result<u64, ReBACTupleStoreError> {
        Ok(self.revision.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_returns_the_written_value() {
        let s = InMemoryReBACTupleStore::new();
        s.put("root|doc:a|reader|user|alice", b"grant")
            .expect("put");
        assert_eq!(
            s.get("root|doc:a|reader|user|alice").expect("get"),
            Some(b"grant".to_vec()),
        );
    }

    #[test]
    fn get_absent_key_returns_none() {
        let s = InMemoryReBACTupleStore::new();
        assert_eq!(s.get("root|missing|reader|user|alice").expect("get"), None);
    }

    #[test]
    fn delete_returns_true_when_key_existed() {
        let s = InMemoryReBACTupleStore::new();
        s.put("root|doc:a|reader|user|alice", b"grant")
            .expect("put");
        assert!(s.delete("root|doc:a|reader|user|alice").expect("delete"));
        assert!(!s
            .delete("root|doc:a|reader|user|alice")
            .expect("delete idempotent"));
    }

    #[test]
    fn list_returns_snapshot_of_all_entries() {
        let s = InMemoryReBACTupleStore::new();
        s.put("root|doc:a|reader|user|alice", b"1").expect("put a");
        s.put("shared|doc:b|writer|user|bob", b"2").expect("put b");
        let mut got = s.list().expect("list");
        got.sort();
        assert_eq!(
            got,
            vec![
                ("root|doc:a|reader|user|alice".to_string(), b"1".to_vec()),
                ("shared|doc:b|writer|user|bob".to_string(), b"2".to_vec()),
            ],
        );
    }

    #[test]
    fn put_advances_store_revision() {
        // The enforcer keys its per-zone graph cache on this
        // counter — a bump on write is what makes a stale cache
        // notice it needs to rebuild.  Regression pin: a delete
        // must also bump so a revoke invalidates every reader.
        let s = InMemoryReBACTupleStore::new();
        assert_eq!(s.revision().expect("rev0"), 0);

        s.put("root|doc:a|reader|user|alice", b"g").expect("put");
        let rev1 = s.revision().expect("rev1");
        assert!(rev1 > 0);

        s.put("root|doc:b|reader|user|alice", b"g")
            .expect("put again");
        let rev2 = s.revision().expect("rev2");
        assert!(rev2 > rev1);

        s.delete("root|doc:a|reader|user|alice").expect("del");
        let rev3 = s.revision().expect("rev3");
        assert!(rev3 > rev2);
    }

    #[test]
    fn delete_on_missing_key_keeps_revision() {
        // Idempotent delete + no-op cache bust — a caller that
        // retries a delete does not spuriously invalidate every
        // reader's cache in the zone.
        let s = InMemoryReBACTupleStore::new();
        assert_eq!(s.revision().expect("rev0"), 0);
        assert!(!s.delete("root|missing|reader|user|alice").expect("delete"));
        assert_eq!(
            s.revision().expect("rev unchanged"),
            0,
            "delete on missing key must NOT bump the revision — a retry \
             storm would otherwise invalidate every reader's cache in the zone",
        );
    }

    #[test]
    fn opaque_keys_also_advance_revision() {
        // Safe over-invalidate posture — a malformed key (no `|`)
        // is treated as a global cache bust rather than silently
        // dropped.  Real callers use the documented key shape;
        // this branch is a safety net.
        let s = InMemoryReBACTupleStore::new();
        s.put("legacy_no_zone_prefix", b"g").expect("put");
        assert_eq!(
            s.revision().expect("empty-zone rev"),
            1,
            "key without `|` must bump the empty-zone counter, not silently drop",
        );
    }

    #[test]
    fn concurrent_writes_from_multiple_threads_all_land() {
        // parking_lot RwLock serializes writers — every put lands.
        // Regression pin against a future refactor that
        // accidentally introduces a lock-free path with lost
        // updates.
        use std::sync::Arc;
        use std::thread;

        let s = Arc::new(InMemoryReBACTupleStore::new());
        let handles: Vec<_> = (0..8)
            .map(|w| {
                let s = Arc::clone(&s);
                thread::spawn(move || {
                    for i in 0..100 {
                        let key = format!("root|doc:{w}-{i}|reader|user|alice");
                        s.put(&key, b"g").expect("put");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread joined");
        }
        assert_eq!(
            s.list().expect("list").len(),
            8 * 100,
            "all 800 concurrent writes must land — no lost updates",
        );
    }
}
