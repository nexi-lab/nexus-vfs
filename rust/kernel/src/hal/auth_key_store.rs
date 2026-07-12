//! `AuthKeyStore` HAL trait — Control-Plane HAL §3.B.3.
//!
//! The replicated store of API-key records: `key_hash → record`. The
//! kernel needs it (to synthesise the admin-only `/__sys__/auth/keys/`
//! view) but does not own it — the records live in the raft state
//! machine's dedicated `TREE_AUTH_KEYS` tree, so the concrete impl is
//! `nexus_raft::auth_key_store::RaftAuthKeyStore`, installed into this
//! slot by the host binary at boot. Same DI shape as §3.B.1
//! `DistributedCoordinator`: trait here, impl in the owner crate, slot
//! wired before any syscall fires.
//!
//! ## Who talks to it
//!
//! | Caller | Tier | Uses |
//! |---|---|---|
//! | API-key auth provider (`sk-` → identity) | services | `get` |
//! | `/__sys__/auth/keys/` readdir synthesiser | kernel | `list` |
//! | Key-minting / revocation tooling | services | `put`, `delete` |
//!
//! The provider is a **services-tier policy** (the PAM / `sshd`
//! analogue: credential → identity), and `services ⊥ raft` is a hard
//! invariant (`docs/KERNEL-ARCHITECTURE.md` § 6.1), so it cannot name
//! the raft impl. It reaches the store through this kernel-tier trait —
//! the same way every other out-of-kernel caller reaches replicated
//! state.
//!
//! ## What a record is (and is not)
//!
//! Values are **opaque bytes**: the store never interprets them; the
//! provider owns the schema. A record holds an HMAC of the key plus its
//! grants (subject, zones, expiry, revoked, admin), so it is a *lookup
//! artifact, not a secret* — possessing every record does not let you
//! mint a key. Keeping the bytes opaque is also what keeps this a
//! generic primitive rather than one provider's private table: a second
//! credential policy (JWT, OIDC) reuses the same store with its own
//! record schema.
//!
//! The HMAC **signing key** is the real secret and travels a different
//! path entirely — injected at the composition root (env, or the vault
//! plugin when loaded), never through this trait.
//!
//! ## Why records are not files
//!
//! They sit in their own raft tree, next to the other kernel-internal
//! primitives the VFS already carves out of "everything is a file"
//! (advisory locks, stream / pipe payloads). That keeps them off the
//! `sys_read` / `readdir` path — so no path-walk can reach a credential
//! record, and nothing can forge one by writing a file — and out of the
//! metadata tree, whose walkers assume every value is a `FileMetadata`
//! proto. The read-only `/__sys__/auth/keys/` view gives back the
//! introspection surface, synthesised from this trait, admin-gated, with
//! no write path. Exactly the `/__sys__/locks` model.
//!
//! ## Sync by design
//!
//! `AuthProvider::resolve` is synchronous and is the hot-path caller, so
//! the trait is too. Impls sitting on an async core bridge internally.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

/// Failure to reach the record store, or to commit a write to it.
///
/// One variant on purpose: every caller treats an error the same way —
/// **fail closed**. A provider that cannot read the store must reject
/// the credential rather than guess, and tooling that cannot commit a
/// `put` / `delete` must report the write as not durable.
#[derive(Debug)]
pub enum AuthKeyStoreError {
    /// The store could not be read, or the write was not committed
    /// (consensus rejected the proposal, this node is not the leader,
    /// or the underlying storage failed). Carries the backend's message
    /// for the operator log.
    Backend(String),
}

impl fmt::Display for AuthKeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(m) => write!(f, "auth key store unavailable: {m}"),
        }
    }
}

impl Error for AuthKeyStoreError {}

/// Read/write access to the replicated API-key records, keyed by
/// `key_hash` (hex HMAC of the presented key — the lookup key, not a
/// secret).
///
/// `Send + Sync` so one `Arc<dyn AuthKeyStore>` serves every gRPC
/// handler thread.
pub trait AuthKeyStore: Send + Sync {
    /// Look up one record. `Ok(None)` means "no such key" — a normal
    /// outcome for a bogus or revoked token, and distinct from `Err`
    /// ("could not tell"), which callers must fail closed on.
    fn get(&self, key_hash: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError>;

    /// Upsert a record. Key-minting tooling only, never the
    /// authentication hot path.
    fn put(&self, key_hash: &str, record: &[u8]) -> Result<(), AuthKeyStoreError>;

    /// Remove a record (revocation). Returns whether a record was
    /// present to remove.
    fn delete(&self, key_hash: &str) -> Result<bool, AuthKeyStoreError>;

    /// Enumerate every `(key_hash, record)` pair. Backs the admin-only
    /// `/__sys__/auth/keys/` view and key-management tooling — a full
    /// scan, not a hot path.
    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError>;
}

/// Default occupant of the kernel's slot: a store with no records.
///
/// A kernel booted without federation (or before the host binary wires
/// the raft impl) still has to answer. Reads resolve nothing and the
/// procfs view lists nothing, so a provider running against it
/// authenticates no one — fail-closed by construction. Writes, by
/// contrast, **fail loud**: a minted key that silently went nowhere is
/// far worse than a visible error, because the operator would hand out a
/// credential the cluster has never heard of.
pub struct NoopAuthKeyStore;

impl NoopAuthKeyStore {
    pub fn arc() -> Arc<dyn AuthKeyStore> {
        Arc::new(NoopAuthKeyStore)
    }

    fn no_store(op: &str) -> AuthKeyStoreError {
        AuthKeyStoreError::Backend(format!(
            "{op}: no auth key store installed (host binary did not wire one at boot)"
        ))
    }
}

impl AuthKeyStore for NoopAuthKeyStore {
    fn get(&self, _key_hash: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
        Ok(None)
    }

    fn put(&self, _key_hash: &str, _record: &[u8]) -> Result<(), AuthKeyStoreError> {
        Err(Self::no_store("put"))
    }

    fn delete(&self, _key_hash: &str) -> Result<bool, AuthKeyStoreError> {
        Err(Self::no_store("delete"))
    }

    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_resolves_nothing_and_refuses_writes() {
        let store = NoopAuthKeyStore;
        // Fail-closed reads: no credential resolves, nothing to list.
        assert_eq!(store.get("any-hash").expect("noop get"), None);
        assert!(store.list().expect("noop list").is_empty());
        // Fail-loud writes: never let a key mint look like it worked.
        assert!(store.put("any-hash", b"record").is_err());
        assert!(store.delete("any-hash").is_err());
    }
}
