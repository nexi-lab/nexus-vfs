//! Auth-domain kernel-side wiring.
//!
//! The kernel does not authenticate anyone — that is a services-tier
//! policy (§3.B.3). What lives here is the kernel's half of the seam:
//!
//! * [`wiring`] — accessors for the `AuthKeyStore` slot the host binary
//!   installs at boot. The field itself sits on [`crate::kernel::Kernel`]
//!   next to the other slot declarations; only the accessors live here,
//!   the same split `federation/coordinator_wiring.rs` uses.
//! * [`synthetic_view`] — the read-only `/__sys__/auth/keys/` view over that
//!   slot.

pub mod synthetic_view;
pub mod wiring;

pub use synthetic_view::AuthKeysView;
