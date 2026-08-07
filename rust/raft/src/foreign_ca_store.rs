//! `RaftForeignCaStore` — the cross-org authorship trust anchors.
//!
//! A typed view over [`crate::control_state_store::ControlStateStore`] scoped to
//! [`contracts::CONTROL_NS_FOREIGN_CA`] — the same shared control-state layer
//! `RaftAuthKeyStore` wraps, so the `propose` / read-your-writes machinery lives
//! in exactly one place. This wrapper adds only what is specific to a foreign-CA
//! anchor:
//!   * it stores/loads the typed [`ForeignCaAnchor`] record (encode / decode), and
//!   * **registration is put-if-absent** — an anchor binds a foreign CA (a
//!     customer cluster's CA_B) to a trust domain, so re-pinning the same CA
//!     fingerprint under ANY domain is REJECTED ([`ForeignCaStoreError::AlreadyRegistered`]),
//!     never a silent relabel. To re-pin, an operator `unregister`s first.

use lib::transport_primitives::ForeignCaAnchor;

use crate::control_state_store::ControlStateStore;
use crate::prelude::{FullStateMachine, ZoneConsensus};

/// Why a foreign-CA store operation failed.
#[derive(Debug)]
pub enum ForeignCaStoreError {
    /// The underlying control-state store failed (consensus or read error).
    Backend(String),
    /// `register` hit an already-pinned fingerprint — the put-if-absent CAS
    /// refused the overwrite. The operator must `unregister` the existing anchor
    /// before re-pinning it under a different trust domain.
    AlreadyRegistered { fingerprint: String },
    /// A stored record failed to decode (schema drift / corruption).
    Corrupt(String),
}

impl std::fmt::Display for ForeignCaStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "foreign-ca store backend: {e}"),
            Self::AlreadyRegistered { fingerprint } => {
                write!(
                    f,
                    "foreign CA {fingerprint} is already registered (unregister it to re-pin)"
                )
            }
            Self::Corrupt(e) => write!(f, "foreign-ca anchor did not decode: {e}"),
        }
    }
}

impl std::error::Error for ForeignCaStoreError {}

/// Typed store for the foreign-CA authorship anchors.
pub struct RaftForeignCaStore {
    inner: ControlStateStore,
}

impl RaftForeignCaStore {
    /// Construct over the control-zone consensus — the same handle the auth key
    /// store is built from.
    pub fn new(node: ZoneConsensus<FullStateMachine>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            inner: ControlStateStore::new(node, runtime, contracts::CONTROL_NS_FOREIGN_CA),
        }
    }

    /// Register a foreign CA as a trust anchor. **Put-if-absent**: a fingerprint
    /// already pinned is [`ForeignCaStoreError::AlreadyRegistered`], never an
    /// overwrite (the anti-relabel guard — see the module docs).
    #[inline]
    pub fn register(&self, anchor: &ForeignCaAnchor) -> Result<(), ForeignCaStoreError> {
        let key = anchor.fingerprint_hex();
        let value = anchor
            .encode()
            .map_err(|e| ForeignCaStoreError::Backend(format!("encode {key}: {e}")))?;
        let stored = self
            .inner
            .put_if_absent(&key, &value)
            .map_err(ForeignCaStoreError::Backend)?;
        if !stored {
            return Err(ForeignCaStoreError::AlreadyRegistered { fingerprint: key });
        }
        Ok(())
    }

    /// Unregister an anchor by its `sha256:…` fingerprint (the inverse of
    /// [`Self::register`]). Idempotent; the bool reports whether one was present
    /// (advisory, for operator messages).
    #[inline]
    pub fn unregister(&self, fingerprint_hex: &str) -> Result<bool, ForeignCaStoreError> {
        self.inner
            .delete(fingerprint_hex)
            .map_err(ForeignCaStoreError::Backend)
    }

    /// Every registered anchor — the verifier's trust set. Order unspecified.
    /// The verifier rebuilds its set on an apply-observer cache-invalidation, not
    /// per handshake, so the decode cost here is off the connection hot path;
    /// `#[inline]` (matching the layer below) keeps the wrapper frame itself free.
    #[inline]
    pub fn list(&self) -> Result<Vec<ForeignCaAnchor>, ForeignCaStoreError> {
        self.inner
            .list()
            .map_err(ForeignCaStoreError::Backend)?
            .into_iter()
            .map(|(k, v)| {
                ForeignCaAnchor::decode(&v)
                    .map_err(|e| ForeignCaStoreError::Corrupt(format!("{k}: {e}")))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::ZoneRaftRegistry;
    use tempfile::TempDir;

    fn anchor(domain: &str, der: &[u8]) -> ForeignCaAnchor {
        ForeignCaAnchor::new(domain, der.to_vec())
    }

    /// Full lifecycle against a live 1-voter zone, from inside a multi-thread
    /// runtime — the shape every real caller has. Covers register → list →
    /// remove, the **put-if-absent re-pin rejection** (the cross-org-specific
    /// semantic), and that a removed anchor stops listing so a fail-closed
    /// verifier drops it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn anchors_roundtrip_and_re_pin_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let registry = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
        let runtime = tokio::runtime::Handle::current();
        let node = registry
            .create_zone("root", vec![], &runtime)
            .expect("create test zone");
        node.campaign().await.expect("campaign test zone");
        let store = RaftForeignCaStore::new(node, runtime);
        // The store has no get()-by-fingerprint (the verifier lists to build its
        // trust set); verify state through list(), the read a real caller uses.
        let find = |fp: &str| -> Option<ForeignCaAnchor> {
            store
                .list()
                .expect("list")
                .into_iter()
                .find(|x| x.fingerprint_hex() == fp)
        };

        let a = anchor("hospital-a", b"ca-a-der");
        let fp = a.fingerprint_hex();

        assert!(find(&fp).is_none(), "absent before register");

        store.register(&a).expect("register a");
        assert_eq!(find(&fp), Some(a.clone()));

        // Re-pinning the SAME CA under a DIFFERENT domain is rejected by the CAS,
        // and the original binding is untouched — the anti-relabel guard.
        let relabel = anchor("hospital-evil", b"ca-a-der");
        assert_eq!(relabel.fingerprint_hex(), fp, "same cert → same key");
        assert!(
            matches!(
                store.register(&relabel),
                Err(ForeignCaStoreError::AlreadyRegistered { .. })
            ),
            "re-pin must be rejected, not overwrite"
        );
        assert_eq!(
            find(&fp).unwrap().trust_domain_id,
            "hospital-a",
            "the rejected re-pin left the original binding intact"
        );

        // A distinct CA registers fine and both list.
        let b = anchor("hospital-b", b"ca-b-der");
        store.register(&b).expect("register b");
        let mut listed = store.list().expect("list");
        listed.sort_by(|l, r| l.trust_domain_id.cmp(&r.trust_domain_id));
        assert_eq!(listed, vec![a.clone(), b.clone()]);

        // Remove reports it removed one; the anchor stops listing; re-remove is
        // idempotent and reports nothing was there.
        assert!(store.unregister(&fp).expect("remove a"));
        assert!(find(&fp).is_none(), "gone after remove");
        assert!(!store.unregister(&fp).expect("re-remove a"));
        assert_eq!(store.list().expect("list after remove").len(), 1);

        registry.shutdown_all();
    }

    /// A corrupt/undecodable record under our namespace makes `list` fail LOUD
    /// (`Corrupt`), never silently skip the anchor — silently dropping one would
    /// quietly shrink the trust set (a foreign agent stops being recognised) with
    /// no signal. Inject garbage through the underlying control store, the only
    /// way bytes that `register` would never write can appear (schema drift).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_corrupt_record_fails_loud_not_silently_skipped() {
        let tmp = TempDir::new().unwrap();
        let registry = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
        let runtime = tokio::runtime::Handle::current();
        let node = registry
            .create_zone("root", vec![], &runtime)
            .expect("create test zone");
        node.campaign().await.expect("campaign test zone");

        crate::control_state_store::ControlStateStore::new(
            node.clone(),
            runtime.clone(),
            contracts::CONTROL_NS_FOREIGN_CA,
        )
        .put("sha256:whatever", b"not a valid anchor")
        .expect("inject garbage");

        let store = RaftForeignCaStore::new(node, runtime);
        assert!(
            matches!(store.list(), Err(ForeignCaStoreError::Corrupt(_))),
            "a corrupt anchor must surface as Corrupt, not be dropped"
        );

        registry.shutdown_all();
    }
}
