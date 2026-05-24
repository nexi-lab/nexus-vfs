//! `nexus-cluster` — Raft consensus + VFS gRPC transport (merged trim).
//!
//! Replaces upstream's separate `raft` and `transport` rlib crates with
//! one library. Layout:
//!
//! ```text
//! nexus_cluster::raft       — consensus + embedded redb storage + federation
//!                             (was upstream `raft` crate, lib name `nexus_raft`)
//! nexus_cluster::transport  — VFS gRPC server + IPC + peer-blob client
//!                             (was upstream `transport` crate)
//! ```

pub mod raft;
pub mod transport;
