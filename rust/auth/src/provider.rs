//! `ApiKeyAuthProvider` — the `sk-` credential policy.
//!
//! The PAM / `sshd` analogue: it turns a presented credential into an
//! identity. It decides nothing about *permissions* — that is the kernel's
//! permission gate, working from the `OperationContext` this builds.
//!
//! ## Two planes, one decision
//!
//! * **Peer plane.** [`AuthCredentials::peer`] is `Some` ⇒ rustls already
//!   verified a client certificate against the cluster CA, so the caller is
//!   provably a cluster node. It gets a system context. This is what lets
//!   the provider reject empty tokens **without killing federation**, which
//!   sends `auth_token: ""` on every peer fan-out.
//! * **Token plane.** An `sk-` key, resolved against the replicated store.
//!   External clients only.
//!
//! A caller with neither is rejected.
//!
//! ## The gates, all fail-closed
//!
//! Ported from `nexus/src/nexus/bricks/auth/providers/database_key.py`,
//! which stays the reference for the exact semantics:
//!
//! 1. format — `sk-` prefix, minimum length;
//! 2. HMAC-SHA256 of the key under the signing secret → the store's lookup key;
//! 3. the record exists (an absent hash and a bad hash are indistinguishable);
//! 4. not revoked, not expired;
//! 5. **zoneless keys are reserved for global admins** — a non-admin key with
//!    no zone grants authenticates as nobody, because downstream code that
//!    defaults a missing zone to the root zone would otherwise hand it the
//!    whole namespace.
//!
//! A store error is a rejection, not a pass: "cannot tell" and "no" are the
//! same answer to a credential.
//!
//! ## The signing secret
//!
//! The HMAC key is the one real secret in this design, and it never travels
//! the record store — it is injected at the composition root (env
//! `NEXUS_API_KEY_SECRET`, or the vault plugin when one is loaded). Records
//! hold only HMAC *outputs*, so replicating them through the raft log and
//! listing their hashes in `/__sys__/auth/keys/` leaks nothing that lets an
//! attacker mint a key.
//!
//! ## Cache
//!
//! A store read plus an HMAC per RPC is too much for the hot path, so a
//! resolved context is cached under its hash with a TTL. Revocation must not
//! wait out that TTL: the composition root subscribes an apply-observer to
//! the raft log and calls [`ApiKeyAuthProvider::invalidate`] when a
//! `PutAuthKey` / `DeleteAuthKey` commits — on **every** replica, since the
//! command replicates. The TTL is the backstop, not the mechanism.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use hmac::{Hmac, KeyInit, Mac};
use kernel::hal::auth_key_store::AuthKeyStore;
use kernel::kernel::OperationContext;
use sha2::Sha256;
use tonic::Status;
use transport::auth::{AuthCredentials, AuthProvider, PeerIdentity};

use crate::record::{AuthKeyRecord, SubjectType};

/// Mandatory prefix. Mirrors Python's `API_KEY_PREFIX`.
pub const API_KEY_PREFIX: &str = "sk-";
/// Minimum total key length. Mirrors Python's `API_KEY_MIN_LENGTH`.
pub const API_KEY_MIN_LENGTH: usize = 32;
/// Default lifetime of a cached context. Short enough that a missed
/// invalidation self-heals in under a minute; long enough that a busy
/// client is not re-hashing on every call.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);

type HmacSha256 = Hmac<Sha256>;

/// Hex-encoded HMAC-SHA256 of `key` under `secret` — the store's lookup key.
///
/// Byte-compatible with Python's
/// `hmac.new(secret, key, sha256).hexdigest()`, so a key minted by either
/// tier resolves on the other.
pub fn hash_key(secret: &str, key: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(key.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// `sk-` prefix + minimum length. A malformed key is rejected before it ever
/// reaches the store, so a scanner cannot use timing against the key space.
pub fn is_well_formed(key: &str) -> bool {
    key.starts_with(API_KEY_PREFIX) && key.len() >= API_KEY_MIN_LENGTH
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct CachedContext {
    ctx: OperationContext,
    expires_at: Instant,
}

/// Resolves `sk-` API keys and mTLS peers into an `OperationContext`.
pub struct ApiKeyAuthProvider {
    store: Arc<dyn AuthKeyStore>,
    secret: String,
    cache: DashMap<String, CachedContext>,
    cache_ttl: Duration,
}

impl ApiKeyAuthProvider {
    pub fn new(store: Arc<dyn AuthKeyStore>, secret: impl Into<String>) -> Self {
        Self::with_cache_ttl(store, secret, DEFAULT_CACHE_TTL)
    }

    pub fn with_cache_ttl(
        store: Arc<dyn AuthKeyStore>,
        secret: impl Into<String>,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            store,
            secret: secret.into(),
            cache: DashMap::new(),
            cache_ttl,
        }
    }

    /// Drop one cached context. Called from the apply-observer when a
    /// `PutAuthKey` / `DeleteAuthKey` commits, so a revocation takes effect
    /// on every replica without waiting out the TTL.
    pub fn invalidate(&self, key_hash: &str) {
        self.cache.remove(key_hash);
    }

    /// Drop every cached context — for a store swap or a mass revocation.
    pub fn invalidate_all(&self) {
        self.cache.clear();
    }

    /// The hash a caller would need in order to invalidate `key`'s cache
    /// entry. Exposed so minting tooling can hand the observer a hash
    /// without re-deriving the HMAC scheme.
    pub fn key_hash(&self, key: &str) -> String {
        hash_key(&self.secret, key)
    }

    /// System context for a cryptographically verified cluster node.
    ///
    /// Peer certs are minted by the cluster CA, so holding one *is* the
    /// authorisation — the node is part of the cluster and raft has already
    /// been letting it replicate state. `user_id` names the node so an audit
    /// trail can tell one peer from another.
    fn peer_context(peer: &PeerIdentity) -> OperationContext {
        let mut ctx = OperationContext::new(
            &peer.display_id(),
            peer.zone_id.as_deref().unwrap_or(contracts::ROOT_ZONE_ID),
            /* is_admin */ true,
            /* agent_id */ None,
            /* is_system */ true,
        );
        ctx.subject_type = "node".to_string();
        ctx.subject_id = Some(peer.display_id());
        ctx
    }

    /// Build the caller's context from a record that has passed every gate.
    ///
    /// The mapping mirrors `nexus/src/nexus/server/dependencies.py`:
    ///
    /// * **`subject_type == Agent` ⇒ `agent_id = subject_id`.** This single
    ///   line is what makes an A2A envelope's `from` unforgeable: the mailbox
    ///   hook stamps `ctx.agent_id`, and the only way to get one is to hold
    ///   that agent's key.
    /// * A single-zone key routes to its zone; a multi-zone key routes to the
    ///   root zone so the context reflects its cross-zone scope; a zoneless
    ///   key belongs to a global admin, who routes at the root.
    /// * `is_system` stays **false**. An external client is never a system
    ///   caller — that flag short-circuits the permission gate entirely, and
    ///   handing it out over the network would undo every gate above.
    fn context_from_record(record: &AuthKeyRecord) -> OperationContext {
        let zone_id = match record.zone_perms.as_slice() {
            [(only_zone, _)] => only_zone.as_str(),
            _ => contracts::ROOT_ZONE_ID,
        };
        let agent_id = match record.subject_type {
            SubjectType::Agent => Some(record.subject_id.as_str()),
            _ => None,
        };
        let mut ctx = OperationContext::new(
            &record.subject_id,
            zone_id,
            record.is_admin,
            agent_id,
            /* is_system */ false,
        );
        ctx.subject_type = record.subject_type.as_str().to_string();
        ctx.subject_id = Some(record.subject_id.clone());
        ctx.zone_perms = record.zone_perms.clone();
        ctx
    }

    /// Resolve an `sk-` token, consulting the cache first.
    fn resolve_token(&self, token: &str) -> Result<OperationContext, Status> {
        if !is_well_formed(token) {
            // Deliberately vague to the caller: a client that learns *why*
            // it was rejected learns something about the key space.
            tracing::debug!("rejected: malformed API key");
            return Err(unauthenticated());
        }

        let hash = hash_key(&self.secret, token);

        if let Some(entry) = self.cache.get(&hash) {
            if Instant::now() < entry.expires_at {
                return Ok(entry.ctx.clone());
            }
        }
        // Expired (or absent) — drop the stale row and go to the store.
        self.cache.remove(&hash);

        let bytes = match self.store.get(&hash) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                tracing::debug!("rejected: no such API key");
                return Err(unauthenticated());
            }
            Err(e) => {
                // "Cannot tell" is not "yes". A store outage must not become
                // an open door, so this is a rejection — but a loud one, since
                // it is an operational failure and not a bad credential.
                tracing::warn!(error = %e, "auth key store unavailable; rejecting");
                return Err(Status::unavailable("auth key store unavailable"));
            }
        };

        let record = match AuthKeyRecord::decode(&bytes) {
            Ok(record) => record,
            Err(e) => {
                tracing::error!(error = %e, "auth key record failed to decode; rejecting");
                return Err(unauthenticated());
            }
        };

        if record.revoked {
            tracing::debug!(key_id = %record.key_id, "rejected: revoked key");
            return Err(unauthenticated());
        }
        if record.is_expired(now_ms()) {
            tracing::debug!(key_id = %record.key_id, "rejected: expired key");
            return Err(unauthenticated());
        }
        // Zoneless keys are reserved for global admins. Without this, a
        // non-admin key with no grants would fall through to the root zone
        // (the `zone_id` default below) and quietly hold the whole namespace.
        if record.zone_perms.is_empty() && !record.is_admin {
            tracing::warn!(
                key_id = %record.key_id,
                "rejected: non-admin key has no zone grants"
            );
            return Err(unauthenticated());
        }

        let ctx = Self::context_from_record(&record);
        self.cache.insert(
            hash,
            CachedContext {
                ctx: ctx.clone(),
                expires_at: Instant::now() + self.cache_ttl,
            },
        );
        Ok(ctx)
    }
}

/// One rejection message for every credential failure. Distinguishing
/// "no such key" from "expired" from "revoked" in the response would let a
/// caller probe the key space; the operator log carries the real reason.
fn unauthenticated() -> Status {
    Status::unauthenticated("invalid credentials")
}

impl AuthProvider for ApiKeyAuthProvider {
    fn resolve(&self, creds: &AuthCredentials<'_>) -> Result<OperationContext, Status> {
        // Peer plane first: a verified cluster node needs no token, which is
        // exactly why federation survives a strict provider.
        if let Some(peer) = creds.peer {
            return Ok(Self::peer_context(peer));
        }
        if creds.token.is_empty() {
            tracing::debug!("rejected: no credentials (no token, no peer cert)");
            return Err(unauthenticated());
        }
        self.resolve_token(creds.token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::hal::auth_key_store::AuthKeyStoreError;
    use parking_lot::Mutex;
    use std::collections::BTreeMap;

    const SECRET: &str = "test-signing-secret";
    /// 32+ chars so it clears the length gate.
    const AGENT_KEY: &str = "sk-mac-ai-0123456789abcdef0123456789";
    const USER_KEY: &str = "sk-alice-0123456789abcdef0123456789";

    #[derive(Default)]
    struct MemStore {
        records: Mutex<BTreeMap<String, Vec<u8>>>,
        fail: bool,
    }

    impl MemStore {
        fn arc() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn broken() -> Arc<Self> {
            Arc::new(Self {
                records: Mutex::new(BTreeMap::new()),
                fail: true,
            })
        }
    }

    impl AuthKeyStore for MemStore {
        fn get(&self, key_hash: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
            if self.fail {
                return Err(AuthKeyStoreError::Backend("down".into()));
            }
            Ok(self.records.lock().get(key_hash).cloned())
        }
        fn put(&self, key_hash: &str, record: &[u8]) -> Result<(), AuthKeyStoreError> {
            if self.fail {
                return Err(AuthKeyStoreError::Backend("down".into()));
            }
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

    fn agent_record() -> AuthKeyRecord {
        AuthKeyRecord {
            key_id: "key-agent".into(),
            name: "mac-ai".into(),
            subject_type: SubjectType::Agent,
            subject_id: "mac-ai".into(),
            is_admin: false,
            revoked: false,
            expires_at_ms: None,
            zone_perms: vec![("sharedzone".into(), "rw".into())],
        }
    }

    /// Mint `key` with `record` into `store`, the way admin tooling would.
    fn plant(store: &Arc<MemStore>, key: &str, record: &AuthKeyRecord) {
        store
            .put(&hash_key(SECRET, key), &record.encode().unwrap())
            .unwrap();
    }

    fn provider(store: Arc<MemStore>) -> ApiKeyAuthProvider {
        ApiKeyAuthProvider::new(store, SECRET)
    }

    // ── The identity that A2A rests on ───────────────────────────────

    /// The whole point: an agent key resolves to a context carrying that
    /// agent's id, which is what the mailbox hook stamps into `from`.
    #[test]
    fn an_agent_key_yields_the_agents_id() {
        let store = MemStore::arc();
        plant(&store, AGENT_KEY, &agent_record());

        let ctx = provider(store)
            .resolve(&AuthCredentials::from_token(AGENT_KEY))
            .expect("agent key resolves");

        assert_eq!(ctx.agent_id.as_deref(), Some("mac-ai"));
        assert_eq!(ctx.subject_type, "agent");
        assert_eq!(ctx.subject_id.as_deref(), Some("mac-ai"));
        assert_eq!(ctx.zone_id, "sharedzone");
        assert_eq!(ctx.zone_perms, vec![("sharedzone".into(), "rw".into())]);
        // An external caller is never a system caller — is_system would
        // short-circuit the permission gate entirely.
        assert!(!ctx.is_system);
        assert!(!ctx.is_admin);
    }

    /// A user key carries no `agent_id`, so its holder cannot author agent
    /// mail no matter what it writes into the envelope.
    #[test]
    fn a_user_key_carries_no_agent_id() {
        let store = MemStore::arc();
        let mut record = agent_record();
        record.key_id = "key-user".into();
        record.subject_type = SubjectType::User;
        record.subject_id = "alice".into();
        plant(&store, USER_KEY, &record);

        let ctx = provider(store)
            .resolve(&AuthCredentials::from_token(USER_KEY))
            .expect("user key resolves");
        assert_eq!(ctx.agent_id, None);
        assert_eq!(ctx.user_id, "alice");
    }

    // ── The gates ────────────────────────────────────────────────────

    #[test]
    fn a_malformed_key_never_reaches_the_store() {
        let store = MemStore::arc();
        plant(&store, AGENT_KEY, &agent_record());
        let p = provider(store);

        for bad in [
            "",                                     // nothing
            "mac-ai-0123456789abcdef0123456789012", // no sk- prefix
            "sk-short",                             // under the length floor
        ] {
            assert!(
                p.resolve(&AuthCredentials::from_token(bad)).is_err(),
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn an_unknown_key_is_rejected() {
        let p = provider(MemStore::arc());
        assert!(p.resolve(&AuthCredentials::from_token(AGENT_KEY)).is_err());
    }

    #[test]
    fn a_revoked_key_is_rejected() {
        let store = MemStore::arc();
        let mut record = agent_record();
        record.revoked = true;
        plant(&store, AGENT_KEY, &record);

        assert!(provider(store)
            .resolve(&AuthCredentials::from_token(AGENT_KEY))
            .is_err());
    }

    #[test]
    fn an_expired_key_is_rejected() {
        let store = MemStore::arc();
        let mut record = agent_record();
        record.expires_at_ms = Some(1); // 1970
        plant(&store, AGENT_KEY, &record);

        assert!(provider(store)
            .resolve(&AuthCredentials::from_token(AGENT_KEY))
            .is_err());
    }

    /// The privilege-escalation gate: a non-admin key with no zone grants
    /// would otherwise fall through to the root zone and hold everything.
    #[test]
    fn a_zoneless_non_admin_key_is_rejected() {
        let store = MemStore::arc();
        let mut record = agent_record();
        record.zone_perms.clear();
        record.is_admin = false;
        plant(&store, AGENT_KEY, &record);

        assert!(provider(store)
            .resolve(&AuthCredentials::from_token(AGENT_KEY))
            .is_err());
    }

    /// ...but a zoneless *admin* key is exactly how a global admin is spelled.
    #[test]
    fn a_zoneless_admin_key_resolves_at_the_root_zone() {
        let store = MemStore::arc();
        let mut record = agent_record();
        record.zone_perms.clear();
        record.is_admin = true;
        record.subject_type = SubjectType::User;
        record.subject_id = "root-admin".into();
        plant(&store, AGENT_KEY, &record);

        let ctx = provider(store)
            .resolve(&AuthCredentials::from_token(AGENT_KEY))
            .expect("zoneless admin resolves");
        assert!(ctx.is_admin);
        assert_eq!(ctx.zone_id, contracts::ROOT_ZONE_ID);
        assert!(!ctx.is_system, "admin over the wire is still not system");
    }

    /// A multi-zone key routes at the root so its context reflects the
    /// cross-zone scope, while `zone_perms` keeps the actual grants.
    #[test]
    fn a_multi_zone_key_routes_at_the_root_zone() {
        let store = MemStore::arc();
        let mut record = agent_record();
        record.zone_perms = vec![("eng".into(), "rw".into()), ("ops".into(), "r".into())];
        plant(&store, AGENT_KEY, &record);

        let ctx = provider(store)
            .resolve(&AuthCredentials::from_token(AGENT_KEY))
            .expect("multi-zone key resolves");
        assert_eq!(ctx.zone_id, contracts::ROOT_ZONE_ID);
        assert_eq!(ctx.zone_perms.len(), 2);
    }

    /// A store outage is a rejection, not a pass — and it is reported as
    /// `unavailable` rather than `unauthenticated`, because the caller's
    /// credential may well be fine and a retry is the right response.
    #[test]
    fn an_unreachable_store_rejects_rather_than_passes() {
        let status = provider(MemStore::broken())
            .resolve(&AuthCredentials::from_token(AGENT_KEY))
            .expect_err("must not pass");
        assert_eq!(status.code(), tonic::Code::Unavailable);
    }

    // ── The peer plane ───────────────────────────────────────────────

    /// The regression that would otherwise break federation: every peer
    /// fan-out sends `auth_token: ""`. A verified cert must authenticate on
    /// its own.
    #[test]
    fn a_verified_peer_authenticates_with_an_empty_token() {
        let peer = PeerIdentity {
            common_name: "win-node".into(),
            node_id: Some(42),
            zone_id: Some("sharedzone".into()),
        };
        let ctx = provider(MemStore::arc())
            .resolve(&AuthCredentials {
                token: "",
                peer: Some(&peer),
            })
            .expect("a verified peer needs no token");

        assert!(ctx.is_system, "a cluster node is a system caller");
        assert!(ctx.is_admin);
        assert_eq!(ctx.user_id, "node/42");
        assert_eq!(ctx.zone_id, "sharedzone");
    }

    /// No token and no cert is nobody.
    #[test]
    fn an_empty_token_without_a_peer_cert_is_rejected() {
        assert!(provider(MemStore::arc())
            .resolve(&AuthCredentials::from_token(""))
            .is_err());
    }

    // ── Cache ────────────────────────────────────────────────────────

    /// Revocation must not wait out the TTL. The composition root calls
    /// `invalidate` from the apply-observer when the delete commits; here we
    /// prove the cache actually honours it.
    #[test]
    fn invalidate_makes_a_revocation_take_effect_immediately() {
        let store = MemStore::arc();
        plant(&store, AGENT_KEY, &agent_record());
        // A long TTL, so nothing passes by expiry.
        let p =
            ApiKeyAuthProvider::with_cache_ttl(store.clone(), SECRET, Duration::from_secs(3600));

        assert!(p.resolve(&AuthCredentials::from_token(AGENT_KEY)).is_ok());

        // Revoke at the store, as `DeleteAuthKey` would.
        let hash = hash_key(SECRET, AGENT_KEY);
        store.delete(&hash).unwrap();

        // Still cached — this is precisely why the observer exists.
        assert!(
            p.resolve(&AuthCredentials::from_token(AGENT_KEY)).is_ok(),
            "the cache is a cache; without invalidation the key survives its TTL"
        );

        p.invalidate(&hash);
        assert!(
            p.resolve(&AuthCredentials::from_token(AGENT_KEY)).is_err(),
            "after invalidation the revoked key must stop resolving"
        );
    }

    #[test]
    fn a_cached_context_expires_on_its_own() {
        let store = MemStore::arc();
        plant(&store, AGENT_KEY, &agent_record());
        let p = ApiKeyAuthProvider::with_cache_ttl(store.clone(), SECRET, Duration::from_millis(1));

        assert!(p.resolve(&AuthCredentials::from_token(AGENT_KEY)).is_ok());
        store.delete(&hash_key(SECRET, AGENT_KEY)).unwrap();
        std::thread::sleep(Duration::from_millis(5));

        assert!(
            p.resolve(&AuthCredentials::from_token(AGENT_KEY)).is_err(),
            "the TTL is the backstop when an invalidation is missed"
        );
    }

    // ── Hashing ──────────────────────────────────────────────────────

    /// Pinned against Python's `hmac.new(secret, key, sha256).hexdigest()`,
    /// so a key minted by either tier resolves on the other. Regenerate with:
    ///   python -c "import hmac,hashlib;print(hmac.new(b'test-signing-secret',b'sk-mac-ai-0123456789abcdef0123456789',hashlib.sha256).hexdigest())"
    #[test]
    fn hashing_matches_the_python_scheme() {
        assert_eq!(
            hash_key(SECRET, AGENT_KEY),
            "4d5391a27eed57046d0b81406263586b009bb53e58ed9516441defc9cd26725f"
        );
    }

    #[test]
    fn a_different_secret_yields_a_different_hash() {
        assert_ne!(hash_key(SECRET, AGENT_KEY), hash_key("other", AGENT_KEY));
    }
}
