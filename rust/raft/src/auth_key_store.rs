//! `kernel::hal::auth_key_store::AuthKeyStore` impl backed by a Raft
//! `ZoneConsensus` — the driver half of the §3.B.3 Control-Plane HAL
//! surface.
//!
//! The host binary installs this into the kernel's slot
//! (`Kernel::set_auth_key_store`) at boot. Both consumers then reach the
//! replicated records through that one seam without naming a raft type:
//! the kernel synthesises `/__sys__/auth/keys/` over it, and the
//! services-tier API-key provider — barred from raft by the
//! `services ⊥ raft` invariant (`docs/KERNEL-ARCHITECTURE.md` § 6.1) —
//! resolves credentials through it.
//!
//! Same shape as [`crate::zone_meta_store::ZoneMetaStore`]: writes go
//! through `propose` (Raft consensus, majority ACK) so a revocation is
//! durable and reaches every replica; reads hit the locally-applied
//! state machine directly, with no consensus round-trip, which is what
//! makes the provider's per-credential lookup cheap enough to sit behind
//! a cache miss.
//!
//! Unlike `ZoneMetaStore` there is **no path translation and no zone
//! scoping of the key space**: a `key_hash` is a global identity, not a
//! VFS path. Construct this against the **root zone's** consensus so the
//! whole cluster shares one auth namespace — see [`RaftAuthKeyStore::new`].

use std::sync::Arc;

use kernel::hal::auth_key_store::{AuthKeyStore, AuthKeyStoreError};

use crate::prelude::{Command, CommandResult, FullStateMachine, ZoneConsensus};
use crate::runtime_bridge::bridge_block_on;

/// How long `put` waits for its own write to become visible in the
/// local state machine before returning (read-your-writes). Matches the
/// budget `ZoneMetaStore::put` uses. Key minting is admin tooling, never
/// a hot path, so paying this is free in practice.
const READ_YOUR_WRITES_POLL_MS: u64 = 500;

/// Raft-backed store for the API-key records in `TREE_AUTH_KEYS`.
pub struct RaftAuthKeyStore {
    node: ZoneConsensus<FullStateMachine>,
    runtime: tokio::runtime::Handle,
}

impl RaftAuthKeyStore {
    /// Construct from a running `ZoneConsensus` + its tokio runtime.
    ///
    /// `node` must be the **root zone's** consensus. Credentials are a
    /// cluster-wide namespace: a key minted on one node has to resolve
    /// on every node, and the record's own `zones` grants — not the zone
    /// the record happens to be stored in — decide what it may reach.
    /// Binding this to a per-share zone instead would silently give each
    /// zone its own key namespace.
    pub fn new(node: ZoneConsensus<FullStateMachine>, runtime: tokio::runtime::Handle) -> Self {
        Self { node, runtime }
    }

    /// Return an `Arc<dyn AuthKeyStore>` ready to inject into the auth
    /// provider at the composition root.
    pub fn new_arc(
        node: ZoneConsensus<FullStateMachine>,
        runtime: tokio::runtime::Handle,
    ) -> Arc<dyn AuthKeyStore> {
        Arc::new(Self::new(node, runtime))
    }

    /// Read one record straight off the locally-applied state machine.
    fn read(&self, key_hash: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
        let key = key_hash.to_string();
        let fut = self
            .node
            .with_state_machine(move |sm: &FullStateMachine| sm.get_auth_key(&key));
        bridge_block_on(&self.runtime, fut)
            .map_err(|e| AuthKeyStoreError::Backend(format!("get_auth_key({key_hash}): {e}")))
    }

    /// Propose `command` and surface a state-machine rejection as an
    /// error — a write the cluster refused must never read as success.
    fn propose(&self, command: Command, what: &str) -> Result<(), AuthKeyStoreError> {
        let result = bridge_block_on(&self.runtime, self.node.propose(command))
            .map_err(|e| AuthKeyStoreError::Backend(format!("{what}: {e}")))?;
        match result {
            CommandResult::Error(e) => {
                Err(AuthKeyStoreError::Backend(format!("{what} rejected: {e}")))
            }
            _ => Ok(()),
        }
    }
}

impl AuthKeyStore for RaftAuthKeyStore {
    fn get(&self, key_hash: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
        self.read(key_hash)
    }

    fn put(&self, key_hash: &str, record: &[u8]) -> Result<(), AuthKeyStoreError> {
        let expected = record.to_vec();
        self.propose(
            Command::PutAuthKey {
                key_hash: key_hash.to_string(),
                record: expected.clone(),
            },
            &format!("put({key_hash})"),
        )?;
        // Read-your-writes: `propose` returns on commit, but the local
        // apply can lag it by up to a raft tick (always on a follower,
        // whose proposal was forwarded). Admin tooling that mints a key
        // and immediately lists must not see its own write missing.
        // SSOT stays the raft state machine — we only wait for it.
        let runtime = self.runtime.clone();
        let node = self.node.clone();
        let key = key_hash.to_string();
        let _ = self.node.wait_until(
            || {
                let poll_key = key.clone();
                let observed = bridge_block_on(
                    &runtime,
                    node.with_state_machine(move |sm: &FullStateMachine| {
                        sm.get_auth_key(&poll_key)
                    }),
                );
                matches!(&observed, Ok(Some(bytes)) if *bytes == expected)
            },
            READ_YOUR_WRITES_POLL_MS,
        );
        Ok(())
    }

    /// Revoke a record.
    ///
    /// The bool reports whether a record was present **at propose time**,
    /// read off this node's state machine. It is advisory: the delete
    /// itself is idempotent and the raft log is authoritative, so a
    /// concurrent revocation elsewhere can make a `true` racy. Callers
    /// use it to tell "revoked something" from "there was nothing to
    /// revoke" in an operator message, never to gate a security decision.
    fn delete(&self, key_hash: &str) -> Result<bool, AuthKeyStoreError> {
        let existed = self.read(key_hash)?.is_some();
        self.propose(
            Command::DeleteAuthKey {
                key_hash: key_hash.to_string(),
            },
            &format!("delete({key_hash})"),
        )?;
        Ok(existed)
    }

    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError> {
        let fut = self
            .node
            .with_state_machine(|sm: &FullStateMachine| sm.list_auth_keys());
        bridge_block_on(&self.runtime, fut)
            .map_err(|e| AuthKeyStoreError::Backend(format!("list_auth_keys: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::ZoneRaftRegistry;
    use kernel::meta_store::MetaStore;
    use tempfile::TempDir;

    /// Full lifecycle against a live 1-voter zone, exercised from inside
    /// a multi-thread tokio runtime — the shape every real caller has
    /// (the gRPC handler thread is a runtime worker), which is what the
    /// `block_in_place` bridge exists to survive.
    ///
    /// Covers mint → resolve → upsert → enumerate → revoke, and asserts
    /// the revoked key stops resolving. A provider that fails closed on
    /// `Ok(None)` therefore rejects a revoked token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn record_roundtrips_through_consensus() {
        let tmp = TempDir::new().unwrap();
        let registry = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
        let runtime = tokio::runtime::Handle::current();
        let node = registry
            .create_zone("root", vec![], &runtime)
            .expect("create test zone");
        node.campaign().await.expect("campaign test zone");
        let store = RaftAuthKeyStore::new(node, runtime);

        // Absent key: a normal `None`, not an error — the provider must
        // be able to tell "no such key" from "could not tell".
        assert_eq!(store.get("deadbeef").expect("get absent"), None);

        store.put("hash-a", b"record-a").expect("put a");
        assert_eq!(
            store.get("hash-a").expect("get a").as_deref(),
            Some(&b"record-a"[..])
        );

        // Upsert: same hash, new grants (e.g. a zone added to the key).
        store.put("hash-a", b"record-a-v2").expect("upsert a");
        assert_eq!(
            store.get("hash-a").expect("get a v2").as_deref(),
            Some(&b"record-a-v2"[..])
        );

        store.put("hash-b", b"record-b").expect("put b");
        let mut listed = store.list().expect("list");
        listed.sort_by(|l, r| l.0.cmp(&r.0));
        assert_eq!(
            listed,
            vec![
                ("hash-a".to_string(), b"record-a-v2".to_vec()),
                ("hash-b".to_string(), b"record-b".to_vec()),
            ]
        );

        // Revoke: reports it removed something, and the key stops
        // resolving. Revoking again is idempotent and reports nothing
        // was there.
        assert!(store.delete("hash-a").expect("revoke a"));
        assert_eq!(store.get("hash-a").expect("get a after revoke"), None);
        assert!(!store.delete("hash-a").expect("re-revoke a"));
        assert_eq!(store.list().expect("list after revoke").len(), 1);

        registry.shutdown_all();
    }

    /// Records are a kernel-internal primitive, not files: they live in
    /// `TREE_AUTH_KEYS`, so nothing that walks the file-metadata tree can
    /// reach them. Here that is pinned at the *store* boundary — a
    /// `ZoneMetaStore` over the same consensus cannot see a record under
    /// any plausible path spelling, and `list("/")` stays empty.
    ///
    /// (`state_machine.rs` pins the same invariant one layer down, at the
    /// tree boundary. Both matter: this is the layer an attacker actually
    /// has a handle to.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn records_are_unreachable_through_the_file_metadata_store() {
        let tmp = TempDir::new().unwrap();
        let registry = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
        let runtime = tokio::runtime::Handle::current();
        let node = registry
            .create_zone("root", vec![], &runtime)
            .expect("create test zone");
        node.campaign().await.expect("campaign test zone");

        let auth = RaftAuthKeyStore::new(node.clone(), runtime.clone());
        auth.put("hash-a", b"record-a").expect("put a");

        let files = crate::zone_meta_store::ZoneMetaStore::new(node, runtime, "/".to_string());
        for spelling in [
            "hash-a",
            "/hash-a",
            "/__sys__/auth/keys/hash-a",
            "/sm_auth_keys/hash-a",
        ] {
            assert!(
                files.get(spelling).expect("metastore get").is_none(),
                "auth record leaked into the file-metadata tree at {spelling}"
            );
        }
        assert!(
            files.list("/").expect("metastore list").is_empty(),
            "auth record leaked into a file-metadata listing"
        );

        registry.shutdown_all();
    }
}
