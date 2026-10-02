//! Synchronous tuple-store contract shared by authorization management and
//! enforcement. Async entry points call blocking store operations off-executor.

use std::error::Error;
use std::fmt;

/// Failure to reach the tuple store, or to commit a write to it.
///
/// One variant on purpose: every caller treats an error the same
/// way — **fail closed**.  A check that cannot read the store must
/// deny the permission rather than guess, and a grant tool that
/// cannot commit a `put` / `delete` must report the write as not
/// durable.
#[derive(Debug, thiserror::Error)]
pub enum ReBACTupleStoreError {
    /// The store could not be read, or the write was not committed
    /// (consensus rejected the proposal, this node is not the
    /// leader, or the underlying storage failed).  Carries the
    /// backend's message for the operator log.
    #[error("rebac tuple store backend error: {0}")]
    Backend(String),
}

/// Distinct owned-error type for cross-crate propagation — same
/// shape as `AuthKeyStore`'s `Box<dyn Error + Send + Sync>` bound
/// for the underlying source. Kept simple (one variant) so callers
/// do not need a match.
impl ReBACTupleStoreError {
    /// Wrap any error into the single `Backend` variant.  Used by
    /// impls that adapt a foreign error type (raft errors, redb
    /// errors).
    pub fn backend<E: Error + Send + Sync + 'static>(err: E) -> Self {
        ReBACTupleStoreError::Backend(err.to_string())
    }
}

/// Durable authorization tuples. Writes are idempotent. Successful writes are
/// visible to subsequent local reads, including writes forwarded by followers.
/// Reads observe locally applied state; replication lag can exist on peers.
/// `list` returns a consistent snapshot of this namespace.
pub trait ReBACTupleStore: Send + Sync {
    /// Write `value` at `key`.  Idempotent — same-value writes
    /// are no-ops at the storage layer, though they may bump the
    /// zone revision.  Returns Err only on storage failure, never
    /// on "already exists."
    fn put(&self, key: &str, value: &[u8]) -> Result<(), ReBACTupleStoreError>;

    /// Delete `key`.  Returns `Ok(true)` when the key existed,
    /// `Ok(false)` when it did not — idempotent; a delete on a
    /// missing key is not an error.
    fn delete(&self, key: &str) -> Result<bool, ReBACTupleStoreError>;

    /// Read the value at `key`, or `Ok(None)` when the key is
    /// absent.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ReBACTupleStoreError>;

    /// Full snapshot of the store's contents.  Callers rebuild the
    /// per-zone `lib::rebac::ReBACGraph` from this on cache miss;
    /// see the trait doc for the size-budget rationale.
    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, ReBACTupleStoreError>;

    /// Revision of the entire locally applied store. Cache entries can be reused
    /// only while this value matches. It changes after put/delete and snapshot
    /// restore; zero means revisions are unavailable and caching must be bypassed.
    /// The revision is derived state and must not be separately persisted.
    fn revision(&self) -> Result<u64, ReBACTupleStoreError> {
        Ok(0)
    }
}

/// Fail-closed default installed at boot before the real store
/// exists.  Every method is a no-op: `list` returns empty (so the
/// enforcer's graph is empty ⇒ no permissions granted ⇒ every
/// check denies), `put`/`delete` succeed silently (so a grant
/// tool that fires before the raft store is up records the write
/// but does not error — the write is lost, matching the "boot
/// order safety, real store swaps in when ready" pattern of
/// upstream `NoopAuthKeyStore`).
///
/// **NEVER install this in a real deployment** — the enforcer
/// backed by this will deny every permission check.  Compose the
/// real backend before the http-api service starts serving.
///
/// The one-shot `list` returning empty is the SAFE fail-closed
/// posture: a live enforcer reading an empty graph denies every
/// non-admin request, which surfaces the mis-wiring loudly (403 /
/// 401 chain) rather than silently admitting requests under a
/// missing store.
pub struct NoopReBACTupleStore;

impl ReBACTupleStore for NoopReBACTupleStore {
    fn put(&self, _key: &str, _value: &[u8]) -> Result<(), ReBACTupleStoreError> {
        Ok(())
    }

    fn delete(&self, _key: &str) -> Result<bool, ReBACTupleStoreError> {
        Ok(false)
    }

    fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, ReBACTupleStoreError> {
        Ok(None)
    }

    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, ReBACTupleStoreError> {
        Ok(Vec::new())
    }
}

/// Diagnostic Debug impl — `Arc<dyn ReBACTupleStore>` shows up in
/// service-state Debug output; a bare "NoopReBACTupleStore" tells
/// an operator immediately why every check denies.
impl fmt::Debug for NoopReBACTupleStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NoopReBACTupleStore")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_put_get_returns_none() {
        let s = NoopReBACTupleStore;
        s.put("k", b"v").expect("put ok");
        assert_eq!(s.get("k").expect("get ok"), None);
    }

    #[test]
    fn noop_delete_returns_false_on_missing_key() {
        // Idempotent delete — a caller that retries a delete never
        // sees Err on the "already gone" branch.
        let s = NoopReBACTupleStore;
        assert!(!s.delete("k").expect("delete ok"));
    }

    #[test]
    fn noop_list_returns_empty_vec() {
        // The fail-closed posture — enforcer builds an empty graph,
        // every non-admin check denies.  A test asserting >0 here
        // would surface a regression that made Noop silently admit
        // wrong tuples.
        let s = NoopReBACTupleStore;
        assert!(s.list().expect("list ok").is_empty());
    }

    #[test]
    fn noop_zone_revision_defaults_to_zero() {
        // 0 = "always stale" = safe fail-closed default for the
        // freshness key.  Real impls override.
        let s = NoopReBACTupleStore;
        assert_eq!(s.revision().expect("revision ok"), 0);
    }

    #[test]
    fn error_backend_wraps_arbitrary_source() {
        // Impls adapting foreign error types use `backend()` to
        // preserve the source's Display in the operator log.
        let src = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "eaccess");
        let e = ReBACTupleStoreError::backend(src);
        assert!(e.to_string().contains("eaccess"));
    }
}
