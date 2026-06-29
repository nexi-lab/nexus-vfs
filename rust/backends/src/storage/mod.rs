//! Storage tier — composed `ObjectStore` impls.
//!
//! Each module here is a complete `ObjectStore` implementation that
//! plugs into the kernel via the `ObjectStoreProvider`.  The split is
//! by addressing strategy + transport flavour:
//!
//! * `cas_local`         — CAS addressing + local fs transport
//! * `path_local`        — path addressing + local fs transport
//! * `local_connector`   — reference-mode local folder mount
//! * `remote`            — RPC proxy ObjectStore (Python hub — `RemoteBackend`)
//!
//! Federation across nodes is NOT an ObjectStore concern — it is
//! routing/coordination and lives behind
//! `kernel::hal::DistributedCoordinator::peer_*` (impl in the raft
//! crate).  An earlier `federation_peer` ObjectStore impl tried to
//! shoehorn cross-node RPC into the storage pillar; it was never
//! wired in production and has been removed.

#[cfg(feature = "driver-cas-local")]
pub mod cas_local;
#[cfg(feature = "driver-local-connector")]
pub mod local_connector;
#[cfg(feature = "driver-remote")]
mod mount_path;
#[cfg(feature = "driver-path-local")]
pub mod path_local;
#[cfg(feature = "driver-remote")]
pub mod remote;
