//! `nexus-vfs` — umbrella crate for the Nexus VFS project.
//!
//! The actual code lives in two component crates:
//!
//! * [`core`] — content-addressed VFS engine (was `nexus-vfs-core`)
//! * [`cluster`] (feature `cluster`) — Raft consensus + VFS gRPC server
//!   / federation client (was `nexus-vfs-cluster`)
//!
//! The packaged daemon binary is shipped separately as
//! [`nexus-vfsd`](https://crates.io/crates/nexus-vfsd) and can be
//! installed with `cargo install nexus-vfsd`.
//!
//! Add this umbrella to embed VFS in-process:
//!
//! ```toml
//! nexus-vfs = "0.1"                          # local VFS only
//! nexus-vfs = { version = "0.1", features = ["cluster"] }  # + Raft/gRPC
//! ```

pub use nexus_vfs_core as core;

#[cfg(feature = "cluster")]
pub use nexus_vfs_cluster as cluster;
