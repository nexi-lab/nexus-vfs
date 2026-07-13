//! `auth` — the `sk-` API-key credential policy.
//!
//! ## What this is, and what it deliberately is not
//!
//! This crate answers exactly one question: **who is calling?** It turns a
//! presented credential into an [`kernel::kernel::OperationContext`]. It is
//! the PAM / `sshd` of the system — a *policy*, swappable for a JWT or OIDC
//! policy without any other tier noticing.
//!
//! It answers nothing about **what the caller may do**. That is the kernel's
//! permission gate plus the ReBAC engine, working from the context this
//! builds. The two concerns stay orthogonal on purpose: the kernel cannot
//! authenticate anyone, and this crate cannot authorise anything.
//!
//! ## Where it sits
//!
//! | Concern | Surface | Impl |
//! |---|---|---|
//! | Credential *records*, replicated | `AuthKeyStore` (kernel HAL §3.B.3) | `raft::auth_key_store` |
//! | Credential → *identity* | `AuthProvider` (transport DI slot) | **this crate**, or `NoAuth` |
//! | Identity → *permission* | permission gate + ReBAC | kernel |
//! | Peer identity | `PeerIdentity` (mTLS) | transport |
//!
//! Nothing here is a kernel primitive and nothing here is a `RustService`.
//! It is a plain rlib that a profile binary links behind a Cargo feature and
//! installs into the `Arc<dyn AuthProvider>` slot at its composition root —
//! the same shape `RaftDistributedCoordinator` and `DefaultObjectStoreProvider`
//! take for their own slots.
//!
//! `nexusd-cluster` does **not** enable that feature: it keeps `NoAuth`, the
//! crate is never compiled into it, and its size gate is untouched. The
//! profile that terminates external client auth turns the feature on.
//!
//! ## Wiring it (composition root)
//!
//! ```rust,ignore
//! let store = RaftAuthKeyStore::new_arc(root_zone_consensus, runtime);
//! kernel.set_auth_key_store(Arc::clone(&store));   // for /__sys__/auth/keys/
//!
//! let secret = std::env::var("NEXUS_API_KEY_SECRET")?;  // the one real secret
//! let provider = Arc::new(ApiKeyAuthProvider::new(store, secret));
//!
//! // Revocation must not wait out the cache TTL: evict on the committed
//! // command, which fires on every replica.
//! consensus.register_apply_observer(Arc::new({
//!     let provider = Arc::clone(&provider);
//!     move |entry: &AppliedEntry| match entry.command {
//!         Command::PutAuthKey { key_hash, .. } | Command::DeleteAuthKey { key_hash } => {
//!             provider.invalidate(key_hash)
//!         }
//!         _ => {}
//!     }
//! }));
//!
//! let vfs_auth: Arc<dyn AuthProvider> = provider;
//! ```
//!
//! ## Reference implementation
//!
//! `nexus/src/nexus/bricks/auth/providers/database_key.py` is the semantic
//! reference — same `sk-` format, same HMAC, same fail-closed gates, and a
//! hash that is byte-compatible so a key minted by either tier resolves on
//! the other. Once this is wired, that Python store is a second auth SSOT and
//! must be retired.

pub mod mint;
pub mod provider;
pub mod record;

pub use mint::{mint_key, revoke_key, revoke_key_hash, MintedKey};
pub use provider::{
    hash_key, is_well_formed, ApiKeyAuthProvider, API_KEY_MIN_LENGTH, API_KEY_PREFIX,
    DEFAULT_CACHE_TTL,
};
pub use record::{AuthKeyRecord, SubjectType};
