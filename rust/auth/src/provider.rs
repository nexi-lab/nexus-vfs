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

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
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
    /// Raw serials of revoked agent certs — the current cluster CRL, projected
    /// to a lookup set. `resolve` rejects an agent whose cert serial is in here.
    /// The composition root refreshes it from the CA-signed CRL (the CA's own
    /// trust plane, orthogonal to raft); empty until the first refresh.
    revoked_serials: RwLock<HashSet<Vec<u8>>>,
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
            revoked_serials: RwLock::new(HashSet::new()),
        }
    }

    /// Replace the revoked-serial set with the latest CRL projection. Called by
    /// the composition root's CRL refresh; a swap, so a `resolve` in flight
    /// sees either the whole old set or the whole new one.
    pub fn set_revoked_serials(&self, serials: HashSet<Vec<u8>>) {
        *self.revoked_serials.write().expect("revoked-serials lock") = serials;
    }

    /// Whether an agent cert with this serial has been revoked (is in the CRL).
    fn is_revoked(&self, serial: &[u8]) -> bool {
        self.revoked_serials
            .read()
            .expect("revoked-serials lock")
            .contains(serial)
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

    /// Resolve an `sk-` token: gate the format, then resolve its record by
    /// the HMAC store key.
    fn resolve_token(&self, token: &str) -> Result<OperationContext, Status> {
        if !is_well_formed(token) {
            // Deliberately vague to the caller: a client that learns *why*
            // it was rejected learns something about the key space.
            tracing::debug!("rejected: malformed API key");
            return Err(unauthenticated());
        }
        self.resolve_by_store_key(hash_key(&self.secret, token))
    }

    /// Resolve a cert-authenticated agent from the cert alone: identity from
    /// the verified SAN, and that identity IS the whole authorization. No
    /// credential-store lookup — the CA-signed cert is the single source, so
    /// this resolves the same on any node the CA reaches, which is what makes a
    /// cert-agent work cross-node. No cache either: with no store I/O and no
    /// topology read, building the context is cheaper than a cache round-trip.
    ///
    /// The cert is a pure identity (a DID); a valid agent cert carries NO zone
    /// grant, on purpose. An agent is not a zone tenant — it is a mailbox
    /// participant — so its authorization to write a mailbox is owned by the
    /// A2A stamp hook, which fail-closes on a missing `agent_id` and binds
    /// `from`: the one seam that both authorizes the write and makes authorship
    /// unforgeable. The zone ACL gate answers an orthogonal question (zone
    /// tenancy); expressing an agent in `zone_perms` would be shoehorning it
    /// into the wrong abstraction. So the context stays zoneless rather than
    /// fabricate a tenancy the agent does not have — if a deployment ever arms
    /// the zone gate, that gate composes with mailbox paths at its own layer.
    fn agent_context(name: &str) -> OperationContext {
        let record = AuthKeyRecord {
            key_id: String::new(),
            name: name.to_string(),
            subject_type: SubjectType::Agent,
            subject_id: name.to_string(),
            is_admin: false,
            revoked: false,
            expires_at_ms: None,
            zone_perms: Vec::new(),
        };
        Self::context_from_record(&record)
    }

    /// The `sk-` token resolution path: cache first, then the record's
    /// fail-closed gates (present, decodable, not revoked, not expired,
    /// zone-scoped unless admin), then cache the result. The `store_key` is the
    /// HMAC of the `sk-` token; it is also the cache key AND the value the
    /// apply-observer hands `invalidate`, so a `DeleteAuthKey` evicts here
    /// without waiting the TTL. (A cert-agent skips this path entirely — it
    /// resolves from the cert in `agent_context`, no store, no cache.)
    fn resolve_by_store_key(&self, store_key: String) -> Result<OperationContext, Status> {
        if let Some(entry) = self.cache.get(&store_key) {
            if Instant::now() < entry.expires_at {
                return Ok(entry.ctx.clone());
            }
        }
        // Expired (or absent) — drop the stale row and go to the store.
        self.cache.remove(&store_key);

        let bytes = match self.store.get(&store_key) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                tracing::debug!("rejected: no such credential");
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
            tracing::debug!(key_id = %record.key_id, "rejected: revoked credential");
            return Err(unauthenticated());
        }
        if record.is_expired(now_ms()) {
            tracing::debug!(key_id = %record.key_id, "rejected: expired credential");
            return Err(unauthenticated());
        }
        // Zoneless credentials are reserved for global admins. Without this, a
        // non-admin record with no grants would fall through to the root zone
        // (the `zone_id` default) and quietly hold the whole namespace.
        if record.zone_perms.is_empty() && !record.is_admin {
            tracing::warn!(
                key_id = %record.key_id,
                "rejected: non-admin credential has no zone grants"
            );
            return Err(unauthenticated());
        }

        let ctx = Self::context_from_record(&record);
        self.cache.insert(
            store_key,
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
            // An agent cert authenticates as its agent — identity from the
            // CA-verified SAN, which is its whole authorization (the stamp hook
            // gates its mailbox writes). No store lookup, so it resolves the
            // same on any node the CA reaches. A node cert is a cluster peer
            // (membership authorizes).
            if let Some(agent) = &peer.agent_name {
                // Revocation is the one thing a valid chain does not settle: a
                // stolen key still chains to the CA. The CRL closes that — an
                // agent whose serial the CA revoked is rejected on every node
                // that has refreshed the list.
                //
                // KNOWN GAP (G2): `is_revoked` checks THIS cluster's CRL, which
                // covers only cluster-CA agents. A foreign agent's cert is signed
                // by its org CA (CA_B), whose serials are not in our CRL, so a
                // single foreign agent cannot be revoked here — only coarse
                // whole-org removal (drop the foreign-CA anchor) blocks it.
                // Follow-up: an our-side, control-zone-backed per-serial denylist
                // (no foreign-CRL fetch dependency).
                //
                // KNOWN GAP (G4): revocation is not immediate for a LIVE foreign
                // connection. `classify_peer_cert` runs per-request, but neither a
                // dropped anchor nor a (future G2) denylist is re-checked here
                // mid-connection, so the interim whole-CA drop stops only NEW
                // connections. Same app-layer per-request-revocation bucket as G2.
                if self.is_revoked(&peer.serial) {
                    tracing::warn!(agent = %agent, "rejected: agent cert is revoked (in CRL)");
                    return Err(unauthenticated());
                }
                // A foreign agent (cert chained to a registered foreign CA, so
                // `classify_peer_cert` set `trust_domain`) authors under its
                // ORG-QUALIFIED id `{trust_domain}/agent/{name}` (= `display_id`),
                // so two orgs' same-named agents never collide in the mailbox
                // `from`. A local (cluster-CA) agent keeps its BARE name — the
                // cluster is one trust domain with mint-time-unique names, and
                // existing consumers parse bare local `from`s. A foreign cert can
                // never resolve to a bare local name (classify always sets its
                // `trust_domain`), so it cannot impersonate a local agent.
                let agent_id = match peer.trust_domain {
                    Some(_) => peer.display_id(),
                    None => agent.clone(),
                };
                // Carry the trust domain into the context so the permission
                // gate can contain a FOREIGN agent to its mailbox. A local
                // agent keeps `None` and is unaffected. SSOT: the value comes
                // from the classified `PeerIdentity`, never re-parsed from the
                // qualified `agent_id` string.
                let mut ctx = Self::agent_context(&agent_id);
                ctx.trust_domain = peer.trust_domain.clone();
                return Ok(ctx);
            }
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

    /// A cert-authenticated agent resolves to its id FROM THE CERT (identity in
    /// the SAN) with no store lookup, so it resolves the same on any node the CA
    /// reaches. The context carries the agent's id and NO zone grant — being a
    /// valid agent cert is the whole authorization; the stamp hook gates its
    /// mailbox writes. An agent is not a zone tenant.
    #[test]
    fn a_cert_agent_resolves_to_its_identity_with_no_zone_grant() {
        let peer = PeerIdentity {
            common_name: "nexus-agent-mac-ai".into(),
            node_id: None,
            zone_id: None,
            agent_name: Some("mac-ai".into()),
            trust_domain: None,
            serial: vec![1, 2, 3],
        };
        // The store is empty on purpose: resolution reads the cert, not a record.
        let ctx = provider(MemStore::arc())
            .resolve(&AuthCredentials {
                token: "",
                peer: Some(&peer),
            })
            .expect("cert agent resolves from its cert identity");

        assert_eq!(ctx.agent_id.as_deref(), Some("mac-ai"));
        assert_eq!(ctx.subject_type, "agent");
        assert!(
            ctx.zone_perms.is_empty(),
            "a cert-agent carries no zone grant — it is a mailbox participant, not a zone tenant"
        );
        assert!(!ctx.is_system, "an agent is never a system caller");
        assert!(!ctx.is_admin, "an agent is never an admin");
    }

    /// A FOREIGN agent (its cert chained to a registered foreign CA, so
    /// `classify_peer_cert` set `trust_domain`) authors under its org-QUALIFIED
    /// id `{trust_domain}/agent/{name}` — never the bare name a local agent of
    /// the same name uses. This is what stops two orgs' `cardio` agents from
    /// colliding in the mailbox `from`, and stops a foreign cert from
    /// impersonating a local agent (G1).
    #[test]
    fn a_foreign_cert_agent_resolves_to_an_org_qualified_id() {
        let peer = PeerIdentity {
            common_name: "nexus-agent-cardio".into(),
            node_id: None,
            zone_id: None,
            agent_name: Some("cardio".into()),
            trust_domain: Some("hospital-a".into()),
            serial: vec![7, 7, 7],
        };
        let ctx = provider(MemStore::arc())
            .resolve(&AuthCredentials {
                token: "",
                peer: Some(&peer),
            })
            .expect("a foreign cert agent resolves");

        assert_eq!(
            ctx.agent_id.as_deref(),
            Some("hospital-a/agent/cardio"),
            "a foreign agent's from is org-qualified, not the bare `cardio`"
        );
        assert_eq!(ctx.subject_id.as_deref(), Some("hospital-a/agent/cardio"));
        assert!(!ctx.is_system);
        assert!(!ctx.is_admin);
    }

    /// A CA-verified agent cert is rejected once its serial is in the CRL —
    /// a valid chain no longer suffices, which is the whole point of revocation
    /// (a stolen key still chains to the CA). Un-revoking (a later CRL without
    /// the serial) lets it back in.
    #[test]
    fn a_revoked_agent_cert_is_rejected() {
        let peer = PeerIdentity {
            common_name: "nexus-agent-mac-ai".into(),
            node_id: None,
            zone_id: None,
            agent_name: Some("mac-ai".into()),
            trust_domain: None,
            serial: vec![9, 9, 9],
        };
        let provider = provider(MemStore::arc());
        let creds = || AuthCredentials {
            token: "",
            peer: Some(&peer),
        };

        // Before revocation: the cert resolves.
        assert!(provider.resolve(&creds()).is_ok(), "a fresh cert resolves");

        // The CRL now names this serial → rejected on this node.
        provider.set_revoked_serials(HashSet::from([vec![9, 9, 9]]));
        assert!(
            provider.resolve(&creds()).is_err(),
            "a revoked serial is rejected even though the chain is valid"
        );

        // A different revoked serial does not touch this cert.
        provider.set_revoked_serials(HashSet::from([vec![1, 2, 3]]));
        assert!(
            provider.resolve(&creds()).is_ok(),
            "only the listed serial is revoked"
        );
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
            agent_name: None,
            trust_domain: None,
            serial: vec![],
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
