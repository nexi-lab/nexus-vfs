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
//! * `federation_peer`   — typed RPC proxy ObjectStore (peer nexusd
//!   cluster — `FederationPeerBackend`).  Sibling of `remote` but
//!   different wire shape (typed `NexusVFSService` RPCs vs Call).

#[cfg(feature = "driver-cas-local")]
pub mod cas_local;
#[cfg(feature = "driver-federation-peer")]
pub mod federation_peer;
#[cfg(feature = "driver-local-connector")]
pub mod local_connector;
#[cfg(any(feature = "driver-federation-peer", feature = "driver-remote"))]
mod mount_path;
#[cfg(feature = "driver-path-local")]
pub mod path_local;
#[cfg(feature = "driver-remote")]
pub mod remote;
