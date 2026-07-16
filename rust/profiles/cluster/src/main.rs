//! `nexusd-cluster` binary entry — delegates to `nexus_cluster::run()`.
//!
//! The library entry `pub fn run()` in `lib.rs` owns clap parsing, tokio
//! runtime construction, and subcommand dispatch. `nexus-full` reuses the
//! same `run()` verbatim; the only per-binary difference is which
//! `backends` features Cargo activates via feature unification. Keeping
//! the body in `lib.rs` means adding a dependency on the cluster profile
//! updates one crate, not two.

fn main() -> anyhow::Result<()> {
    nexus_cluster::run()
}
