//! `nexusd-full` binary entry — delegates to `nexus_cluster::run()`.
//!
//! `nexus-full` is `nexus-cluster` with one additional `backends` feature
//! (`driver-s3`) enabled via Cargo feature unification (see this crate's
//! Cargo.toml). The shared library entry `nexus_cluster::run()` is
//! feature-agnostic: `DefaultObjectStoreProvider` inspects which
//! ObjectStore arms compiled in and dispatches accordingly. No per-binary
//! code duplication — this file exists solely so Cargo has a bin target.

fn main() -> anyhow::Result<()> {
    nexus_cluster::run()
}
