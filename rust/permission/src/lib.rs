//! `permission` — the authorization policy sibling to `auth`.
//!
//! ## What this is, and what it deliberately is not
//!
//! `auth` answers "who is calling?" — it turns a credential into an
//! [`kernel::kernel::OperationContext`].  `permission` answers "what
//! may they do?" — given a context and a path, it returns
//! `Ok(())` or `Err(KernelError::PermissionDenied)`.
//!
//! Neither crate is a kernel primitive and neither is a `RustService`.
//! Both are plain rlibs that a profile binary links behind a Cargo
//! feature and installs into the corresponding kernel/transport slot
//! at its composition root.
//!
//! ## Where it sits
//!
//! | Concern | Surface | Impl |
//! |---|---|---|
//! | Credential records, replicated | `AuthKeyStore` (kernel HAL §3.B.3) | `raft::auth_key_store` |
//! | Credential → identity | `AuthProvider` (transport DI slot) | `auth` crate (or `NoAuth`) |
//! | Identity → **permission** | [`kernel::PermissionProvider`] (kernel DI slot) | **this crate** (or unregistered ⇒ no-op) |
//! | Peer identity | `PeerIdentity` (mTLS) | transport |
//!
//! `nexusd-cluster` does **not** enable the permission feature: the
//! kernel's `Arc<dyn PermissionProvider>` slot stays `None`, and every
//! `check_permission` call short-circuits to `Ok(())` in 3 lines of
//! kernel hook code.  The profile that terminates external client
//! authorization turns the feature on and installs an impl.
//!
//! ## Composition model — 1 slot, N impls
//!
//! The kernel holds **one** `Arc<dyn PermissionProvider>` slot, not a
//! multi-provider registry.  A profile that needs to combine multiple
//! policies (zone perms + ReBAC + role) builds a composite impl that
//! implements the same trait and fans out internally:
//!
//! ```rust,ignore
//! use kernel::PermissionProvider;
//!
//! struct CompositePermissionProvider {
//!     zone: permission::ZonePermsProvider,
//!     rebac: Option<Arc<LightweightRebacProvider>>,
//! }
//!
//! impl PermissionProvider for CompositePermissionProvider {
//!     fn check(&self, path, route, permission, ctx) -> Result<(), KernelError> {
//!         self.zone.check(path, route, permission, ctx)?;
//!         if let Some(r) = &self.rebac {
//!             r.check(path, route, permission, ctx)?;
//!         }
//!         Ok(())
//!     }
//! }
//! ```
//!
//! Keeps the kernel dispatch untouched as new policies come online.
//!
//! ## Wiring (composition root)
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use permission::ZonePermsProvider;
//!
//! let provider = Arc::new(ZonePermsProvider::new());
//! kernel.set_permission_provider(provider);
//! ```
//!
//! With no explicit wiring the kernel default remains a literal
//! `return Ok(())` in the gate — provable via the
//! `kernel_default_permission_provider_is_none_and_gate_is_no_op`
//! protective test in the kernel crate.

pub mod lease_cache;
pub mod zone_perms;

pub use lease_cache::PermissionLeaseCache;
pub use zone_perms::ZonePermsProvider;

// The `PermissionProvider` trait lives in the `kernel` crate (with its
// primary consumer, `Kernel::check_permission`) — the same convention
// `AuthProvider` follows (trait in `transport`, impls in `auth`).  This
// re-export exists so downstream composers can `use permission::PermissionProvider;`
// without also having to name the kernel crate for the trait alone.
pub use kernel::PermissionProvider;
