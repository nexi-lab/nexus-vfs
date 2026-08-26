//! `lib` — portable Rust lib for Nexus.
//!
//! This crate contains WASM-safe computation extracted from `kernel`.
//! It compiles to `wasm32-unknown-unknown` and has zero CPython dependency.
//!
//! Modules:
//! - `types` — domain types (Entity, Permission, etc.)
//! - `rebac` — Relationship-Based Access Control engine
//! - `search` — line-oriented text search (literal + regex)
//! - `bloom` — Bloom filter for fast set-membership checks
//! - `hash` — BLAKE3 content hashing
//! - `glob` — Glob pattern matching
//! - `bitmap` — Roaring Bitmap operations
//! - `transport_primitives` — gRPC TLS / pool / addressing / TOFU trust
//!   store / `PeerBlobClient` trait. Behind the `transport` feature;
//!   brings tonic + tokio-light deps that pure-algo callers (WASM, edge
//!   profile) can skip.

/// Agent identity URI SAN helpers (`nexus://agent/{name}`) — pure, dep-free.
pub mod agent_identity;
pub mod bitmap;
pub mod bloom;
pub mod glob;
pub mod hash;
pub mod rebac;
pub mod search;
pub mod trigram;
pub mod types;

#[cfg(feature = "transport")]
pub mod transport_primitives;

/// Sync→async runtime bridge — `block_on_via` / `block_on_portable`, correct for
/// any ambient tokio runtime flavor. The single home for the "block_in_place
/// requires a multi-thread runtime" hazard (retired the per-site copies).
#[cfg(feature = "runtime-bridge")]
pub mod rt;
