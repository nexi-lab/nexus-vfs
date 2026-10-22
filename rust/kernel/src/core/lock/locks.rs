//! Local advisory-lock backend for the kernel's ``LockManager``.
//!
//! ``LocalLocks`` mutates the shared ``Arc<Mutex<LockState>>`` directly
//! — no replication. It is the kernel's default backend, used in
//! standalone deployments. A distributed kernel resolves its per-zone
//! backend through the coordinator instead of promoting this map into a
//! replicated zone. The trait boundary ``Arc<dyn contracts::Locks>`` keeps
//! the kernel free of any HAL-impl concrete type.

use std::sync::Arc;

use parking_lot::Mutex;

use contracts::lock_state::{LockInfo, LockState, Locks};

use crate::lock_manager::lock_now_secs;

/// Local-mode advisory lock backend: one Arc-wrapped ``LockState``
/// mutated directly on every call. Never proposes anything — used by
/// standalone deployments and as the kernel's default before any
/// replicated HAL backend installs.
pub struct LocalLocks {
    state: Arc<Mutex<LockState>>,
}

impl LocalLocks {
    /// Construct a LocalLocks that shares ``state`` with whoever owns
    /// the Arc (typically the embedded kernel's own ``LockManager``).
    /// A replicated zone owns its own state; these local holders are not
    /// imported into a distributed domain.
    pub fn new(state: Arc<Mutex<LockState>>) -> Self {
        Self { state }
    }

    /// Snapshot the shared state Arc — kept for symmetry with the
    /// trait method ``shared_state_arc``; both surface the same Arc.
    pub fn state(&self) -> Arc<Mutex<LockState>> {
        self.state.clone()
    }
}

impl Locks for LocalLocks {
    fn acquire(
        &self,
        path: &str,
        lock_id: &str,
        max_holders: u32,
        ttl_secs: u32,
        holder_info: &str,
    ) -> Result<bool, String> {
        let now = lock_now_secs();
        let mut guard = self.state.lock();
        let result = guard.apply_acquire(path, lock_id, max_holders, ttl_secs, holder_info, now);
        Ok(result.acquired)
    }

    fn release(&self, path: &str, lock_id: &str) -> Result<bool, String> {
        Ok(self.state.lock().apply_release(path, lock_id))
    }

    fn force_release(&self, path: &str) -> Result<bool, String> {
        Ok(self.state.lock().apply_force_release(path))
    }

    fn extend(&self, path: &str, lock_id: &str, ttl_secs: u32) -> Result<bool, String> {
        let now = lock_now_secs();
        Ok(self.state.lock().apply_extend(path, lock_id, ttl_secs, now))
    }

    fn get_lock(&self, path: &str) -> Option<LockInfo> {
        self.state.lock().get_lock(path)
    }

    fn list_locks(&self, prefix: &str, limit: usize) -> Vec<LockInfo> {
        self.state.lock().list_locks(prefix, limit)
    }

    fn shared_state_arc(&self) -> Arc<Mutex<LockState>> {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> LocalLocks {
        LocalLocks::new(Arc::new(Mutex::new(LockState::new())))
    }

    #[test]
    fn acquire_release_roundtrip() {
        let b = backend();
        assert!(b.acquire("/a", "h1", 1, 60, "agent").unwrap());
        assert!(b.release("/a", "h1").unwrap());
        assert!(b.get_lock("/a").is_none());
    }

    #[test]
    fn mutex_blocks_second_acquire() {
        let b = backend();
        assert!(b.acquire("/a", "h1", 1, 60, "agent").unwrap());
        assert!(!b.acquire("/a", "h2", 1, 60, "agent").unwrap());
    }

    #[test]
    fn semaphore_coexists_up_to_max() {
        let b = backend();
        assert!(b.acquire("/a", "h1", 2, 60, "agent").unwrap());
        assert!(b.acquire("/a", "h2", 2, 60, "agent").unwrap());
        // Third holder exceeds max_holders=2
        assert!(!b.acquire("/a", "h3", 2, 60, "agent").unwrap());
    }

    #[test]
    fn force_release_drops_all() {
        let b = backend();
        b.acquire("/a", "h1", 3, 60, "agent").unwrap();
        b.acquire("/a", "h2", 3, 60, "agent").unwrap();
        assert!(b.force_release("/a").unwrap());
        assert!(b.get_lock("/a").is_none());
    }

    #[test]
    fn extend_refreshes_ttl() {
        let b = backend();
        b.acquire("/a", "h1", 1, 1, "agent").unwrap();
        let before = b.get_lock("/a").unwrap().holders[0].expires_at;
        assert!(b.extend("/a", "h1", 3600).unwrap());
        let after = b.get_lock("/a").unwrap().holders[0].expires_at;
        assert!(after > before);
    }

    #[test]
    fn list_locks_filters_by_prefix() {
        let b = backend();
        b.acquire("/a/one", "h1", 1, 60, "agent").unwrap();
        b.acquire("/a/two", "h2", 1, 60, "agent").unwrap();
        b.acquire("/b/three", "h3", 1, 60, "agent").unwrap();
        let under_a = b.list_locks("/a/", 100);
        assert_eq!(under_a.len(), 2);
    }
}
