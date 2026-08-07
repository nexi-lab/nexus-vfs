//! Transport primitives — TLS / pool / addressing / TOFU trust store /
//! `PeerBlobClient` trait. Lowest shared utilities in the workspace
//! dep graph: pure-Rust, zero peer-crate deps. Consumed by every
//! peer crate that speaks raft or VFS gRPC (raft itself, transport,
//! and the kernel rlib through the peer-client slot).
//!
//! Lives under `lib` per §6 — `lib` is the tier-neutral implementation
//! crate, mirror of `src/nexus/lib/`.

pub mod authorship;
mod channel;
mod config;
mod error;
mod federated_tls;
mod foreign_ca;
mod peer;
mod peer_blob_client;
mod pool;
mod server_limits;
mod tofu;

pub use channel::{create_channel, ensure_crypto_provider};
pub use config::{ClientConfig, ServerConfig, TlsConfig};
pub use error::{Result, TransportError};
pub use federated_tls::{
    federated_mtls_incoming, federated_tls_incoming, server_config, FederatedClientCertVerifier,
};
pub use foreign_ca::{CaFingerprint, ForeignCaAnchor};
pub use peer::{hostname_to_node_id, NodeAddress, PeerAddress};
pub use peer_blob_client::{NoopPeerBlobClient, PeerBlobClient, PeerBlobResult};
pub use pool::ConnectionPool;
pub use server_limits::apply_server_limits;
pub use tofu::{cert_fingerprint, TofuError, TofuResult, TofuTrustStore, TrustedZone};
