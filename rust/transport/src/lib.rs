//! `transport` — network surface tier.
//!
//! Hosts NexusFS's external network surface, both directions:
//!
//! * In-bound (server side): VFS gRPC server on port 2028, IPC
//!   envelope helpers.
//! * Out-bound (driver-side clients): peer-blob fetch client
//!   implementing `lib::transport_primitives::PeerBlobClient`,
//!   federation peer client (`PyFederationClient`) for discover/join
//!   flows.
//!
//! Module layout:
//!
//! ```text
//! transport/
//!   grpc.rs         — Rust-native VFS gRPC server (in-bound, pure Rust)
//!   ipc.rs          — IPC message envelope helpers
//!   peer_blob.rs    — peer-blob fetch client (out-bound)
//!   federation.rs   — federation peer client (out-bound)
//!   python/
//!     mod.rs        — register() + install_transport_wiring
//! ```
//!
//! Direction: `transport -> {kernel, lib, raft, services}`. Transport
//! names raft's wire-format proto stubs directly through the federation
//! client (same shape as a Postgres client crate referencing libpq);
//! raft does not import transport, so no cycle. The VFS gRPC client
//! (`RpcTransport`) lives in the kernel crate where the kernel-internal
//! `RemoteMetaStore` / `RemotePipeBackend` / `RemoteStreamBackend`
//! wrappers wrap it directly — re-exported here under
//! [`vfs::RpcTransport`] for the canonical out-bound name.

/// `AuthProvider` trait + kernel-default `NoAuth` impl. Consumed by
/// `transport::grpc::VfsServiceImpl`. Other auth impls (API-key,
/// JWT, OIDC, …) live in the deployment-tier service that introduces
/// them, not here.
pub mod auth;
/// Generic `Call` RPC dispatcher — JSON in, kernel syscall, JSON out.
pub mod call_dispatch;
/// Federation peer client — discover/join RPCs for cross-zone membership.
pub mod federation;
/// VFS gRPC server (in-bound). Always compiled.
pub mod grpc;
/// Plugin-as-gRPC-service proxy — routes cdylib plugin services onto
/// the same tonic `Routes` as the built-in VFS server.  See module
/// docs for the dispatch contract.
pub mod grpc_plugin_proxy;
pub mod peer_blob;
/// Post-transport substrate observability.  Dual of
/// [`peer_blob`]: peer_blob does cross-node blob fetches,
/// transport_observer classifies which substrate path each fetch
/// actually took (Tailscale direct vs DERP relay vs unknown) and
/// warns operators when their bytes traverse a third-party relay.
pub mod transport_observer;

/// Out-bound VFS gRPC client. Re-exported from `kernel::rpc_transport`
/// where the type is declared (kernel-internal `RemoteMetaStore`
/// wrappers wrap the same struct).
pub mod vfs {
    pub use kernel::rpc_transport::{RpcTransport, TlsConfig as VfsTlsConfig};
}

// Re-export low-level primitive types under the transport crate's
// namespace so existing call sites keep working.
pub use lib::transport_primitives::{
    create_channel, hostname_to_node_id, ClientConfig, ConnectionPool, NodeAddress, PeerAddress,
    ServerConfig, TlsConfig, TransportError,
};
pub type Result<T> = lib::transport_primitives::Result<T>;
