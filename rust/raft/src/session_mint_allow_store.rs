//! `RaftSessionMintAllowStore` — which agents may mint session credentials.
//!
//! A typed view over [`crate::control_state_store::ControlStateStore`] scoped to
//! [`contracts::CONTROL_NS_SESSION_MINT_ALLOW`], exactly as `RaftForeignCaStore`
//! and `RaftAuthKeyStore` are. The `propose` / read-your-writes machinery stays
//! in the one place that owns it; this wrapper adds only the key shape and the
//! policy semantics below.
//!
//! ## The key is a RESOLVED display id, never a bare name
//!
//! An entry names the delegate exactly as `resolve_verified_peer` will see it:
//! a local (cluster-CA) agent by its bare name, a foreign one by its
//! org-qualified `{trust_domain}/agent/{name}` — i.e. `PeerIdentity::display_id`.
//!
//! This is the same class of guard as the foreign-CA store's fingerprint check.
//! Allow-listing a bare `moss` would admit a `moss` minted by *any* registered
//! foreign CA, because a bare name is only unique within one CA's namespace.
//! The qualified form is what makes an entry name one identity and not a set of
//! them.
//!
//! ## Allowing is idempotent; the foreign-CA store's put-if-absent is not
//!
//! Re-pinning a CA fingerprint under a second trust domain is a silent relabel,
//! so that store rejects it. An entry here is a bare membership fact with no
//! payload to relabel: allowing an already-allowed id changes nothing, so it
//! succeeds rather than erroring at an operator who ran the command twice.
//!
//! ## Reading is fallible, and the CALLER fails closed
//!
//! [`Self::is_allowed`] returns `Result<bool>`: "the store could not answer" is
//! not the same fact as "this id is not allowed", and a store that collapsed
//! them would be lying to its caller. Turning an unreadable list into a denial
//! is the mint gate's job, where the decision belongs and where it can be
//! logged as the failure it is.

use std::sync::Arc;

use crate::control_state_store::ControlStateStore;
use crate::prelude::{FullStateMachine, ZoneConsensus};

/// Why a session-mint allow-list operation failed.
#[derive(Debug)]
pub enum SessionMintAllowError {
    /// The underlying control-state store failed (consensus or read error).
    Backend(String),
}

impl std::fmt::Display for SessionMintAllowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "session-mint allow-list backend: {e}"),
        }
    }
}

impl std::error::Error for SessionMintAllowError {}

/// Late-bindable handle to the allow-list.
///
/// The gate that reads it is constructed at boot, from the CA key; the control
/// zone it is replicated through is not ready until later. Mirrors
/// [`crate::agent_minter::AgentMinterSlot`], including the reason the slot
/// exists rather than the value. **Unbound means closed** — a gate that cannot
/// read its policy denies.
pub type SessionMintAllowSlot = Arc<parking_lot::RwLock<Option<Arc<RaftSessionMintAllowStore>>>>;

/// Construct an unbound slot — spelt once here so callers don't import
/// parking_lot (mirrors [`crate::agent_minter::new_agent_minter_slot`]).
pub fn new_session_mint_allow_slot() -> SessionMintAllowSlot {
    Arc::new(parking_lot::RwLock::new(None))
}

/// Typed store for the session-mint allow-list.
pub struct RaftSessionMintAllowStore {
    inner: ControlStateStore,
}

impl RaftSessionMintAllowStore {
    /// Construct over the control-zone consensus — the same handle the auth key
    /// and foreign-CA stores are built from.
    pub fn new(node: ZoneConsensus<FullStateMachine>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            inner: ControlStateStore::new(node, runtime, contracts::CONTROL_NS_SESSION_MINT_ALLOW),
        }
    }

    /// Permit `display_id` to mint session credentials. Idempotent — see the
    /// module docs for why this does not mirror the foreign-CA store's
    /// put-if-absent rejection.
    ///
    /// The value is empty on purpose: the key IS the fact, and a payload would
    /// be a second thing to keep true.
    #[inline]
    pub fn allow(&self, display_id: &str) -> Result<(), SessionMintAllowError> {
        self.inner
            .put(display_id, &[])
            .map_err(SessionMintAllowError::Backend)
    }

    /// Withdraw permission. Idempotent; the bool reports whether an entry was
    /// present (advisory, for operator messages).
    #[inline]
    pub fn deny(&self, display_id: &str) -> Result<bool, SessionMintAllowError> {
        self.inner
            .delete(display_id)
            .map_err(SessionMintAllowError::Backend)
    }

    /// Whether `display_id` may mint. A point read, not a list scan — the gate
    /// asks this once per mint and has one id in hand.
    #[inline]
    pub fn is_allowed(&self, display_id: &str) -> Result<bool, SessionMintAllowError> {
        Ok(self
            .inner
            .get(display_id)
            .map_err(SessionMintAllowError::Backend)?
            .is_some())
    }

    /// Every permitted id — for an operator listing the policy. Order
    /// unspecified.
    #[inline]
    pub fn list(&self) -> Result<Vec<String>, SessionMintAllowError> {
        Ok(self
            .inner
            .list()
            .map_err(SessionMintAllowError::Backend)?
            .into_iter()
            .map(|(k, _)| k)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::ZoneRaftRegistry;
    use tempfile::TempDir;

    /// Full lifecycle against a live 1-voter zone, from inside a multi-thread
    /// runtime — the shape every real caller has. Covers allow → is_allowed →
    /// list → deny, that allowing twice is a success rather than an error, and
    /// that a denied id stops answering `true` so the gate closes behind it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn entries_roundtrip_and_allowing_twice_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let registry = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
        let runtime = tokio::runtime::Handle::current();
        let node = registry
            .create_zone("root", vec![], &runtime)
            .expect("create test zone");
        node.campaign().await.expect("campaign test zone");
        let store = RaftSessionMintAllowStore::new(node, runtime);

        assert!(
            !store.is_allowed("moss").expect("read"),
            "closed by default"
        );

        store.allow("moss").expect("allow");
        assert!(store.is_allowed("moss").expect("read"));
        assert_eq!(store.list().expect("list"), vec!["moss".to_string()]);

        // Running the command twice is an operator habit, not an error.
        store.allow("moss").expect("allow is idempotent");
        assert_eq!(store.list().expect("list").len(), 1);

        assert!(store.deny("moss").expect("deny"), "reports it was present");
        assert!(
            !store.is_allowed("moss").expect("read"),
            "the gate closes behind a denied id"
        );
        assert!(!store.deny("moss").expect("deny is idempotent"));
    }

    /// An entry is the resolved display id, so a local agent and a foreign
    /// agent of the SAME bare name are different entries. Allowing the local
    /// one must never admit the foreign one — that is the whole reason the key
    /// is qualified.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_foreign_namesake_is_a_different_entry() {
        let tmp = TempDir::new().unwrap();
        let registry = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
        let runtime = tokio::runtime::Handle::current();
        let node = registry
            .create_zone("root", vec![], &runtime)
            .expect("create test zone");
        node.campaign().await.expect("campaign test zone");
        let store = RaftSessionMintAllowStore::new(node, runtime);

        store.allow("moss").expect("allow the local agent");
        assert!(
            !store
                .is_allowed("hospital-a/agent/moss")
                .expect("read the foreign namesake"),
            "allow-listing the local `moss` must not admit another org's `moss`"
        );
    }
}
