//! `nexus-core` — merged VFS tier crate (trim fork).
//!
//! Replaces upstream's 5 rlib tier-crates (`contracts`, `lib`, `kernel`,
//! `backends`, `services`) with a single library crate. Each top-level
//! module here corresponds to one of the original crates; their internal
//! layout is preserved.
//!
//! ```text
//! nexus_core::contracts   — tier-neutral types/traits/constants
//! nexus_core::util        — pure-Rust algorithms + transport_primitives
//!                           (was upstream `lib` crate; renamed because
//!                           "lib" collides with `src/lib.rs`)
//! nexus_core::kernel      — in-tree Rust API surface, VFS gRPC stubs
//! nexus_core::backends    — ObjectStore driver impls
//! nexus_core::services    — post-syscall services (audit/agents/etc)
//! ```

pub mod contracts;
pub mod util;
pub mod kernel;
pub mod backends;
pub mod services;
