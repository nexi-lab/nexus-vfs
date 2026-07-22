//! gRPC transport layer for Raft consensus.
//!
//! This module provides the network transport for Raft messages using gRPC.
//! It is built on [tonic](https://github.com/hyperium/tonic), a pure Rust
//! gRPC implementation.
//!
//! # Why gRPC?
//!
//! - **Streaming**: Native support for bidirectional streams (ideal for heartbeats)
//! - **Efficiency**: HTTP/2 multiplexing, long-lived connections
//! - **Code generation**: Less boilerplate than manual HTTP
//! - **Compatibility**: Works with tikv/raft-rs message patterns
//!
//! # Architecture
//!
//! All raft-rs message types (~15 types including votes, heartbeats, appends)
//! are multiplexed through a single `StepMessage` RPC as opaque protobuf v2
//! bytes (etcd/tikv pattern). EC replication uses a separate `ReplicateEntries`
//! RPC for async peer sync.
//!
//! # Example
//!
//! ```rust,ignore
//! use nexus_raft::transport::{RaftClient, ClientConfig};
//!
//! // Create a client to talk to another node
//! let mut client = RaftClient::connect("http://10.0.0.2:2026", ClientConfig::default()).await?;
//!
//! // Send a raw raft-rs message via step_message
//! client.step_message(message_bytes, "my-zone".to_string()).await?;
//! ```
//!
//! # Feature Flag
//!
//! This module requires the `grpc` feature:
//!
//! ```toml
//! [dependencies]
//! nexus_raft = { version = "0.1", features = ["grpc"] }
//! ```

#[cfg(all(feature = "grpc", has_protos))]
pub(crate) mod certgen;
#[cfg(all(feature = "grpc", has_protos))]
pub use certgen::{
    bootstrap_tls, generate_join_token, generate_node_cert, generate_zone_ca, node_identity_uri,
    parse_node_identity_uri, BootstrapTls,
};
#[cfg(all(feature = "grpc", has_protos))]
mod client;
#[cfg(all(feature = "grpc", has_protos))]
mod server;
#[cfg(all(feature = "grpc", has_protos))]
mod transport_loop;

#[cfg(all(feature = "grpc", has_protos))]
pub use client::{
    call_delete_zone, call_discover_zones_rpc, call_join_cluster, call_join_zone_rpc,
    call_remove_voter_rpc, ClientConfig, ClusterInfoResult, DiscoveredZone, JoinClusterResult,
    JoinZoneResult, ProposeResult, QueryResult, RaftApiClient, RaftClient, RaftClientPool,
    RemoveVoterResult,
};
#[cfg(all(feature = "grpc", has_protos))]
pub use server::{RaftGrpcServer, RaftWitnessServer, ServerConfig, WitnessZoneRegistry};
#[cfg(all(feature = "grpc", has_protos))]
pub use transport_loop::TransportLoop;

/// Forward a Raft proposal to a leader node via gRPC Propose RPC.
///
/// Used by `ZoneConsensus::propose()` when the local node is a follower.
/// Serializes the command with bincode and sends as `raw_command` bytes
/// in `ProposeRequest` — avoids double serialization (bincode→proto→bincode).
///
/// `cached_client` provides a reusable `RaftApiClient` across calls.
/// On first use (or after eviction), a new connection is established and
/// cached. On transport error, the cached client is evicted so the next
/// call reconnects.
#[cfg(all(feature = "grpc", has_protos))]
pub(crate) async fn forward_propose(
    client_pool: &RaftClientPool,
    leader_addr: &NodeAddress,
    command: crate::raft::Command,
    zone_id: &str,
    cached_client: &tokio::sync::Mutex<Option<(String, RaftApiClient)>>,
) -> crate::raft::Result<crate::raft::CommandResult> {
    use crate::raft::RaftError;

    let raw_bytes =
        bincode::serialize(&command).map_err(|e| RaftError::Serialization(e.to_string()))?;

    // Get or create a cached API client. Evict if the leader endpoint changed.
    let mut api_client = {
        let mut guard = cached_client.lock().await;
        match guard.take() {
            Some((endpoint, client)) if endpoint == leader_addr.endpoint => client,
            _ => {
                // Connect with short timeouts — fail fast on unreachable leader.
                let mut forward_config = client_pool.config().clone();
                forward_config.connect_timeout = std::time::Duration::from_secs(2);
                forward_config.request_timeout = std::time::Duration::from_secs(5);

                RaftApiClient::connect(&leader_addr.endpoint, forward_config)
                    .await
                    .map_err(|e| RaftError::Transport(e.to_string()))?
            }
        }
    };

    let request = tonic::Request::new(proto::nexus::raft::ProposeRequest {
        command: None,
        request_id: String::new(),
        zone_id: zone_id.to_string(),
        raw_command: raw_bytes,
        forwarded: true,
    });

    let result = api_client
        .inner_mut()
        .propose(request)
        .await
        .map_err(|e| RaftError::Transport(e.to_string()));

    match result {
        Ok(response) => {
            // Success — cache the client for reuse.
            let mut guard = cached_client.lock().await;
            *guard = Some((leader_addr.endpoint.clone(), api_client));

            let resp = response.into_inner();
            if !resp.success {
                if let Some(ref err) = resp.error {
                    if err.contains("Not the leader") || err.contains("not leader") {
                        return Err(RaftError::NotLeader { leader_hint: None });
                    } else {
                        return Err(RaftError::Raft(err.clone()));
                    }
                }
                return Err(RaftError::Raft("Propose failed".to_string()));
            }

            // Decode the typed RaftResponse so lock/metadata commands see
            // the same CommandResult variant the leader computed. Without
            // this, AcquireLock/ReleaseLock/ExtendLock would hit an
            // "Unexpected result type" branch on the caller side.
            Ok(proto_result_to_command_result(resp.result))
        }
        Err(e) => {
            // Transport error — evict cached client (already taken above).
            // Next call will reconnect.
            Err(e)
        }
    }
}

/// Decode a proto `RaftResponse` back into an internal `CommandResult`.
///
/// Only the variants that the server actually emits (Success / LockResult)
/// are handled; other commands carry no typed result and collapse to
/// `Success`, matching the old single-node path.
#[cfg(all(feature = "grpc", has_protos))]
fn proto_result_to_command_result(
    result: Option<proto::nexus::raft::RaftResponse>,
) -> crate::raft::CommandResult {
    use crate::raft::{CommandResult, HolderInfo, LockAcquireResult};
    use proto::nexus::raft::raft_response::Result as ProtoVariant;

    let Some(resp) = result else {
        return CommandResult::Success;
    };

    match resp.result {
        Some(ProtoVariant::LockResult(lr)) => {
            let holders = if lr.acquired {
                vec![HolderInfo {
                    lock_id: String::new(),
                    holder_info: lr.current_holder.clone().unwrap_or_default(),
                    acquired_at: 0,
                    expires_at: (lr.expires_at_ms / 1000) as u64,
                }]
            } else {
                Vec::new()
            };
            CommandResult::LockResult(LockAcquireResult {
                acquired: lr.acquired,
                current_holders: holders.len() as u32,
                max_holders: 0,
                holders,
            })
        }
        Some(ProtoVariant::ValueResult(bytes)) => CommandResult::Value(bytes),
        Some(ProtoVariant::MetadataResult(_)) | None => CommandResult::Success,
    }
}

// ---------------------------------------------------------------------------
// Re-export shared transport types from transport.
// These were previously defined locally but are now canonical in transport.
// The entire `transport` module is behind `#[cfg(feature = "grpc")]` in lib.rs,
// so `transport` is always available here.
// ---------------------------------------------------------------------------
#[cfg(feature = "grpc")]
pub use lib::transport_primitives::{
    hostname_to_node_id, NodeAddress, PeerAddress, TlsConfig, TransportError,
};
#[cfg(feature = "grpc")]
pub type Result<T> = lib::transport_primitives::Result<T>;

/// The transport peer address book for one zone — the dial addresses of the
/// **other** nodes in the cluster.
///
/// ## Invariant: self is never a peer (enforced by construction)
///
/// Under the opaque-ID contract (PR #3996) a node is a *member* of its own
/// ConfState, not a *transport peer* of itself — it never dials itself. Several
/// independent paths write this map: runtime `learn_peer_address` (from an
/// inbound message's `sender_address`), `add_peer` (post-ConfChange), and the
/// raft ConfChange-apply loop in `RaftNode` (which shares this very `Arc`). A
/// stray self-entry from any of them — a self-`from` message under churn, or
/// self appearing in a ConfChange context — would round-trip through
/// `persist_peers` into `identity.json`, and a later restart would then trip
/// the boot-time self-exclusion.
///
/// Rather than repeat an `if id == self.node_id` guard at every writer (fragile
/// — a new writer silently reintroduces the bug), this type owns `self_id` and
/// drops a self-entry inside [`PeerMap::insert`]. The invariant then holds no
/// matter which path writes. Mutation is possible ONLY through `insert`/`remove`;
/// reads go through a read-only [`Deref`](std::ops::Deref) to the inner map (no
/// `DerefMut`), so the guard cannot be bypassed.
#[derive(Debug)]
pub struct PeerMap {
    self_id: u64,
    inner: std::collections::HashMap<u64, NodeAddress>,
}

impl PeerMap {
    /// Empty book for the node identified by `self_id`.
    pub fn new(self_id: u64) -> Self {
        Self {
            self_id,
            inner: std::collections::HashMap::new(),
        }
    }

    /// Seed the book from an initial peer set. Any self-entry in `peers` is
    /// dropped, so the invariant holds even for a pre-poisoned seed (e.g. an
    /// `identity.json` written before this type existed).
    pub fn with_peers(self_id: u64, peers: std::collections::HashMap<u64, NodeAddress>) -> Self {
        let mut map = Self::new(self_id);
        for (id, addr) in peers {
            map.insert(id, addr);
        }
        map
    }

    /// Insert or update a peer's dial address.
    ///
    /// A self-entry (`id == self_id`) is silently dropped — self is not a
    /// transport peer. Returns `true` if the map changed (a real peer was
    /// inserted or its address updated), `false` if the entry was self.
    pub fn insert(&mut self, id: u64, addr: NodeAddress) -> bool {
        if id == self.self_id {
            tracing::debug!(
                self_id = self.self_id,
                "peer map: dropped self-entry (self is a ConfState member, not a transport peer)"
            );
            return false;
        }
        self.inner.insert(id, addr);
        true
    }

    /// Remove a peer (e.g. on ConfChange `RemoveNode`).
    pub fn remove(&mut self, id: &u64) -> Option<NodeAddress> {
        self.inner.remove(id)
    }

    /// Clone out the inner address book (self already excluded by the invariant).
    pub fn snapshot(&self) -> std::collections::HashMap<u64, NodeAddress> {
        self.inner.clone()
    }
}

/// Read-only view of the address book. Mutation is intentionally NOT exposed
/// (no `DerefMut`) so every write funnels through `insert`/`remove` and the
/// self-exclusion invariant cannot be bypassed.
impl std::ops::Deref for PeerMap {
    type Target = std::collections::HashMap<u64, NodeAddress>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Shared peer map that can be updated at runtime (e.g., when new nodes join via ConfChange).
///
/// Uses `std::sync::RwLock` (not tokio) because:
/// - Read/write operations are very fast (HashMap insert/lookup)
/// - Accessed from both sync (DashMap guard) and async (transport loop) contexts
/// - Write-rarely, read-often pattern — no contention in practice
pub type SharedPeerMap = std::sync::Arc<std::sync::RwLock<PeerMap>>;

// Re-export generated types when grpc feature is enabled and protos were compiled
#[cfg(all(feature = "grpc", has_protos))]
pub mod proto {
    //! Generated protobuf types and gRPC services.
    //!
    //! This module contains the Rust types generated from proto files.
    //! Structure mirrors the proto package hierarchy:
    //!   - nexus::core - FileMetadata, PaginatedResult
    //!   - nexus::raft - ZoneTransportService, ZoneApiService, commands, transport messages

    /// Core types (FileMetadata, etc.)
    pub mod nexus {
        pub mod core {
            include!(concat!(env!("OUT_DIR"), "/nexus.core.rs"));
        }
        #[allow(
            clippy::large_enum_variant,
            reason = "generated proto code; will configure prost boxing when variants are stabilized"
        )]
        pub mod raft {
            include!(concat!(env!("OUT_DIR"), "/nexus.raft.rs"));
        }
    }

    // Re-export for convenience
    pub use nexus::core::*;
    pub use nexus::raft::*;
}

// Tests for PeerAddress, NodeAddress, hostname_to_node_id now live in transport.

#[cfg(test)]
mod peer_map_tests {
    use super::{NodeAddress, PeerMap};

    const SELF_ID: u64 = 1001;

    fn addr(id: u64) -> NodeAddress {
        NodeAddress::new(id, format!("http://node-{id}:9000"))
    }

    #[test]
    fn insert_keeps_other_peers() {
        let mut m = PeerMap::new(SELF_ID);
        assert!(m.insert(2002, addr(2002)), "a real peer is stored");
        assert!(m.insert(3003, addr(3003)));
        assert_eq!(m.len(), 2);
        assert!(m.get(&2002).is_some());
        assert!(m.get(&3003).is_some());
    }

    #[test]
    fn insert_drops_self() {
        let mut m = PeerMap::new(SELF_ID);
        // Self is a ConfState member, not a transport peer — dropped on insert,
        // no matter which caller (learn_peer_address, add_peer, ConfChange apply)
        // hands it to us.
        assert!(
            !m.insert(SELF_ID, addr(SELF_ID)),
            "self returns 'unchanged'"
        );
        assert!(m.is_empty(), "self never enters the book");
        assert!(m.get(&SELF_ID).is_none());
    }

    #[test]
    fn with_peers_filters_a_pre_poisoned_seed() {
        // A seed built from a stale identity.json that already contains self
        // (written before this invariant existed) must not brick the node.
        let seed = std::collections::HashMap::from([
            (SELF_ID, addr(SELF_ID)),
            (2002, addr(2002)),
            (3003, addr(3003)),
        ]);
        let m = PeerMap::with_peers(SELF_ID, seed);
        assert_eq!(m.len(), 2, "self filtered out of the seed");
        assert!(m.get(&SELF_ID).is_none());
        assert!(m.get(&2002).is_some());
    }

    #[test]
    fn remove_and_snapshot() {
        let mut m = PeerMap::new(SELF_ID);
        m.insert(2002, addr(2002));
        m.insert(3003, addr(3003));
        assert!(m.remove(&2002).is_some());
        let snap = m.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(snap.contains_key(&3003));
        assert!(!snap.contains_key(&SELF_ID));
    }

    #[test]
    fn conf_change_self_add_is_a_noop() {
        // Mirrors the raft ConfChange-apply path (node.rs): AddNode for self
        // must not land self in the transport book. The type enforces it — the
        // apply loop does `peer_map.write().unwrap().insert(id, addr)` with no
        // self-guard of its own.
        let mut m = PeerMap::new(SELF_ID);
        m.insert(2002, addr(2002));
        let changed = m.insert(SELF_ID, addr(SELF_ID)); // ConfChange::AddNode(self)
        assert!(!changed);
        assert_eq!(m.len(), 1);
    }
}
