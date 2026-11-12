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
//! ```text
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

mod node_authority;
pub use node_authority::{
    current_local_node_certificate, local_node_identity, LocalNodeCertificate,
};

#[cfg(all(feature = "grpc", has_protos))]
pub(crate) mod certgen;
#[cfg(all(feature = "grpc", has_protos))]
pub(crate) use certgen::verified_csr_key;
pub use certgen::{
    append_join_token_hash, bootstrap_tls, generate_agent_cert, generate_join_token,
    generate_node_cert, generate_session_agent_cert, generate_user_replica_cert,
    generate_user_runtime_cert, generate_zone_ca, join_token_hash_path, node_identity_uri,
    parse_node_identity_uri, prepare_agent_csr_intent, prepare_replica_csr_intent,
    read_join_token_hashes, sign_agent_csr, sign_committed_agent_intent,
    sign_committed_replica_intent, sign_node_csr, BootstrapTls,
};
/// Re-exported so a caller that already depends on this crate can name a
/// session subject without taking a direct dependency on `lib` — the cluster
/// profile keeps `lib` dev-only on purpose, to hold the shipped binary to the
/// deps `transport` already pulls. The definition stays the one in
/// `lib::agent_identity`; this is a pass-through, not a second copy.
#[cfg(all(feature = "grpc", has_protos))]
pub use lib::agent_identity::session_agent_name;
#[cfg(all(feature = "grpc", has_protos))]
pub use lib::transport_primitives::{user_runtime_server_name, USER_RUNTIME_MAX_VALIDITY_SECS};
/// Re-exported for the same reason as [`session_agent_name`]: the mint that writes
/// an agent bundle and the clients that read one both need the credential layout,
/// and it has one definition in `lib::transport_primitives::agent_credential`.
#[cfg(all(feature = "grpc", has_protos))]
pub use lib::transport_primitives::{AgentCredential, LoadedCredential, CREDENTIAL_MANIFEST};
#[cfg(all(feature = "grpc", has_protos))]
mod replica_renewal;
#[cfg(all(feature = "grpc", has_protos))]
mod session_renewal;
#[cfg(all(feature = "grpc", has_protos))]
pub use replica_renewal::{replica_renewal_message, verify_replica_renewal, ReplicaRenewalProof};
#[cfg(all(feature = "grpc", has_protos))]
pub use session_renewal::{
    session_renewal_message, verify_session_renewal, VerifiedSessionRenewal,
};
#[cfg(all(feature = "grpc", has_protos))]
pub(crate) mod crl;
#[cfg(all(feature = "grpc", has_protos))]
pub use crl::{
    add_revoked_serial, add_revoked_serial_with_expiry, crl_revoked_serials, generate_crl,
    prune_expired_serials, read_revoked_entries, read_revoked_serials,
    read_revoked_serials_checked, revoked_serials_path, serial_from_cert_pem,
    with_unrevoked_serial, RevokedEntry,
};
#[cfg(all(feature = "grpc", has_protos))]
mod client;
#[cfg(all(feature = "grpc", has_protos))]
mod server;
#[cfg(all(feature = "grpc", has_protos))]
mod transport_loop;

#[cfg(all(feature = "grpc", has_protos))]
pub use client::{
    call_allow_session_minter_rpc, call_delete_zone, call_deny_session_minter_rpc,
    call_discover_zones_rpc, call_get_crl, call_join_cluster, call_join_zone_rpc,
    call_list_foreign_cas_rpc, call_list_keys_rpc, call_list_session_minters_rpc,
    call_mint_agent_rpc, call_mint_key_rpc, call_mint_session_agent_rpc,
    call_register_foreign_ca_rpc, call_remove_voter_rpc, call_renew_session_agent_rpc,
    call_revoke_agent_cert_rpc, call_revoke_key_rpc, call_unregister_foreign_ca_rpc, ClientConfig,
    ClusterInfoResult, DiscoveredZone, JoinClusterResult, JoinZoneResult, MintAgentResult,
    MintKeyArgs, MintSessionAgentResult, ProposeResult, QueryResult, RaftApiClient, RaftClient,
    RaftClientPool, RemoveVoterResult,
};
#[cfg(all(feature = "grpc", has_protos))]
pub use server::{
    serve_node_enrollment, RaftGrpcServer, RaftWitnessServer, ServerConfig, WitnessZoneRegistry,
};
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
    command: &crate::raft::Command,
    zone_id: &str,
    deadline: tokio::time::Instant,
    cached_client: &tokio::sync::Mutex<Option<(String, RaftApiClient)>>,
) -> crate::raft::Result<crate::raft::CommandResult> {
    use crate::raft::RaftError;

    let request = propose_request(command, zone_id, true, deadline)?;

    // Get or create a cached API client. Evict if the leader endpoint changed.
    let mut api_client = {
        let mut guard = cached_client.lock().await;
        match guard.take() {
            Some((endpoint, client)) if endpoint == leader_addr.endpoint => client,
            _ => connect_proposer(client_pool.config(), &leader_addr.endpoint).await?,
        }
    };

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

            decode_propose_response(response.into_inner())
        }
        Err(e) => {
            // Transport error — evict cached client (already taken above).
            // Next call will reconnect.
            Err(e)
        }
    }
}

/// Submit `command` to the node at `endpoint` as an original request
/// (`forwarded=false`): that node admits it as coming from this node and may
/// forward it to its own leader. One connection per call — for rare control
/// writes such as a member's self-registration.
#[cfg(all(feature = "grpc", has_protos))]
pub(crate) async fn propose_to(
    config: &ClientConfig,
    endpoint: &str,
    command: &crate::raft::Command,
    zone_id: &str,
    deadline: tokio::time::Instant,
) -> crate::raft::Result<crate::raft::CommandResult> {
    let request = propose_request(command, zone_id, false, deadline)?;
    let mut client = connect_proposer(config, endpoint).await?;
    let response = client
        .inner_mut()
        .propose(request)
        .await
        .map_err(|e| crate::raft::RaftError::Transport(e.to_string()))?;
    decode_propose_response(response.into_inner())
}

/// A Propose RPC carrying `command` as `raw_command`, bounded by `deadline`.
#[cfg(all(feature = "grpc", has_protos))]
fn propose_request(
    command: &crate::raft::Command,
    zone_id: &str,
    forwarded: bool,
    deadline: tokio::time::Instant,
) -> crate::raft::Result<tonic::Request<proto::nexus::raft::ProposeRequest>> {
    let raw_command = bincode::serialize(command)
        .map_err(|e| crate::raft::RaftError::Serialization(e.to_string()))?;
    let mut request = tonic::Request::new(proto::nexus::raft::ProposeRequest {
        command: None,
        request_id: String::new(),
        zone_id: zone_id.to_string(),
        raw_command,
        forwarded,
    });
    request.set_timeout(deadline.saturating_duration_since(tokio::time::Instant::now()));
    Ok(request)
}

/// Connect a proposal client with short timeouts — fail fast on an
/// unreachable node.
#[cfg(all(feature = "grpc", has_protos))]
async fn connect_proposer(
    config: &ClientConfig,
    endpoint: &str,
) -> crate::raft::Result<RaftApiClient> {
    let mut config = config.clone();
    config.connect_timeout = std::time::Duration::from_secs(2);
    config.request_timeout = std::time::Duration::from_secs(crate::raft::PROPOSAL_TIMEOUT_SECS);
    RaftApiClient::connect(endpoint, config)
        .await
        .map_err(|e| crate::raft::RaftError::Transport(e.to_string()))
}

#[cfg(all(feature = "grpc", has_protos))]
pub(super) const NOT_LEADER_ERROR: &str = "Not the leader";

#[cfg(all(feature = "grpc", has_protos))]
fn decode_propose_response(
    response: proto::nexus::raft::ProposeResponse,
) -> crate::raft::Result<crate::raft::CommandResult> {
    use crate::raft::RaftError;

    if response.success {
        return Ok(proto_result_to_command_result(response.result));
    }
    match response.error {
        Some(error)
            if error == NOT_LEADER_ERROR
                && response.result.is_none()
                && response.applied_index == 0 =>
        {
            Err(RaftError::NotLeader {
                leader_hint: response.leader_address,
            })
        }
        Some(error) => Err(RaftError::ProposalOutcomeUnknown(error)),
        None => Err(RaftError::ProposalOutcomeUnknown(
            "remote proposal returned no result or refusal reason".into(),
        )),
    }
}

/// Decode a proto `RaftResponse` back into an internal `CommandResult`.
///
/// The server encodes a leader-computed refusal (`CommandResult::Error`) as
/// the inner `success: false` + `error` pair (the outer `ProposeResponse`
/// stays `success: true` for any applied command), so a follower replaying a
/// forwarded propose through this decoder must surface that pair as `Error`
/// — collapsing it to `Success` would report a CAS rejection as an insert
/// win (the zone-op journal's single-executor guarantee rides on this).
/// `LockResult` / `ValueResult` round-trip through `result`; commands with
/// no typed result collapse to `Success`, matching the old single-node path.
#[cfg(all(feature = "grpc", has_protos))]
fn proto_result_to_command_result(
    result: Option<proto::nexus::raft::RaftResponse>,
) -> crate::raft::CommandResult {
    use crate::raft::{CommandResult, HolderInfo, LockAcquireResult};
    use proto::nexus::raft::raft_response::Result as ProtoVariant;

    let Some(resp) = result else {
        return CommandResult::Success;
    };
    if !resp.success {
        return CommandResult::Error(
            resp.error
                .unwrap_or_else(|| "raft command refused".to_string()),
        );
    }

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
    hostname_to_node_id, ForeignCaAnchor, NodeAddress, PeerAddress, TlsConfig, TransportError,
};
#[cfg(feature = "grpc")]
pub type Result<T> = lib::transport_primitives::Result<T>;

/// Open a zone's state-machine store, in the transport layer's error vocabulary.
///
/// Every zone opening — data node and witness alike — goes through here, so "another
/// process holds this data dir" keeps its own error variant instead of collapsing into
/// a generic connection failure at one call site and not the other. The conversion
/// lives with the vocabulary it produces: storage classifies
/// ([`crate::storage::StorageError::is_data_dir_locked`]), transport names.
#[cfg(feature = "grpc")]
pub(crate) fn open_zone_store(sm_path: std::path::PathBuf) -> Result<crate::storage::RedbStore> {
    crate::storage::RedbStore::open(&sm_path).map_err(|e| {
        if e.is_data_dir_locked() {
            TransportError::DataDirLocked(sm_path.display().to_string())
        } else {
            TransportError::Connection(format!("Failed to open store: {e}"))
        }
    })
}

/// The transport route book for one zone — how this node dials each OTHER
/// member. A cache derived from two sources (`docs/member-address.md`):
///
/// * **registered** — the zone's applied member-address records, replaced
///   wholesale by the zone's consensus driver from its state machine
///   ([`Self::set_registered`]); nothing else writes this layer;
/// * **observed** — the `sender_address` of authenticated inbound Raft
///   messages ([`Self::observe`]), held in memory only. An id's observation is
///   cleared when its registered record changes.
///
/// [`Self::route`] prefers the observation, then the record. Self is never a
/// peer: this type owns `self_id` and both writers drop a self-entry.
#[derive(Debug)]
pub struct PeerMap {
    self_id: u64,
    registered: std::collections::HashMap<u64, NodeAddress>,
    observed: std::collections::HashMap<u64, NodeAddress>,
}

impl PeerMap {
    /// Empty book for the node identified by `self_id`.
    pub fn new(self_id: u64) -> Self {
        Self {
            self_id,
            registered: std::collections::HashMap::new(),
            observed: std::collections::HashMap::new(),
        }
    }

    /// The dial address for `id`: its observation, else its record.
    #[inline]
    pub fn route(&self, id: u64) -> Option<&NodeAddress> {
        self.observed.get(&id).or_else(|| self.registered.get(&id))
    }

    /// Every routed peer once, as `(id, route)`.
    pub fn routes(&self) -> impl Iterator<Item = (u64, &NodeAddress)> {
        self.observed
            .iter()
            .map(|(id, address)| (*id, address))
            .chain(
                self.registered
                    .iter()
                    .filter(|(id, _)| !self.observed.contains_key(id))
                    .map(|(id, address)| (*id, address)),
            )
    }

    /// Whether no peer is routed.
    pub fn is_empty(&self) -> bool {
        self.observed.is_empty() && self.registered.is_empty()
    }

    /// Number of routed peers.
    pub fn len(&self) -> usize {
        self.routes().count()
    }

    /// Clone out the routes (self excluded by the invariant).
    pub fn snapshot(&self) -> std::collections::HashMap<u64, NodeAddress> {
        self.routes()
            .map(|(id, address)| (id, address.clone()))
            .collect()
    }

    /// Replace the registered layer with `records` — the zone driver's only
    /// write, made from the applied member-address records. A self-entry is
    /// dropped, and every id whose record changed loses its observation.
    pub(crate) fn set_registered(
        &mut self,
        mut records: std::collections::HashMap<u64, NodeAddress>,
    ) {
        records.remove(&self.self_id);
        let observed = &mut self.observed;
        for (id, address) in &records {
            if self.registered.get(id) != Some(address) {
                observed.remove(id);
            }
        }
        for id in self.registered.keys() {
            if !records.contains_key(id) {
                observed.remove(id);
            }
        }
        self.registered = records;
    }

    /// Record `address` observed for `id` on an authenticated inbound
    /// message. Returns `true` if the route changed; a self-entry, or an
    /// address the route already has, changes nothing.
    pub fn observe(&mut self, id: u64, address: NodeAddress) -> bool {
        if id == self.self_id
            || self
                .route(id)
                .is_some_and(|route| route.endpoint == address.endpoint)
        {
            return false;
        }
        self.observed.insert(id, address);
        true
    }
}

/// Shared route book: written by its zone's driver (registered layer) and by
/// inbound authentication (observed layer), read by every send path.
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

    include!("proto_binding.rs");

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
    use std::collections::HashMap;

    const SELF_ID: u64 = 1001;

    fn addr(id: u64, port: u16) -> NodeAddress {
        NodeAddress::new(id, format!("http://node-{id}:{port}"))
    }

    fn records(entries: &[(u64, u16)]) -> HashMap<u64, NodeAddress> {
        entries
            .iter()
            .map(|&(id, port)| (id, addr(id, port)))
            .collect()
    }

    #[test]
    fn an_observation_outranks_the_record_until_the_record_changes() {
        let mut m = PeerMap::new(SELF_ID);
        m.set_registered(records(&[(2002, 9000), (3003, 9000)]));
        assert_eq!(m.route(2002), Some(&addr(2002, 9000)));

        assert!(m.observe(2002, addr(2002, 9100)), "a new address routes");
        assert_eq!(m.route(2002), Some(&addr(2002, 9100)));
        assert!(!m.observe(2002, addr(2002, 9100)), "repeat is unchanged");
        assert_eq!(m.len(), 2, "each peer routes once");

        // Re-installing identical records keeps the observation.
        m.set_registered(records(&[(2002, 9000), (3003, 9000)]));
        assert_eq!(m.route(2002), Some(&addr(2002, 9100)));

        // A changed record clears that peer's observation, and only that one.
        assert!(m.observe(3003, addr(3003, 9300)));
        m.set_registered(records(&[(2002, 9200), (3003, 9000)]));
        assert_eq!(m.route(2002), Some(&addr(2002, 9200)));
        assert_eq!(m.route(3003), Some(&addr(3003, 9300)));

        // A removed record clears its observation too.
        m.set_registered(records(&[(2002, 9200)]));
        assert_eq!(m.route(3003), None);
        assert_eq!(m.snapshot(), records(&[(2002, 9200)]));
    }

    #[test]
    fn self_is_never_a_peer() {
        let mut m = PeerMap::new(SELF_ID);
        assert!(!m.observe(SELF_ID, addr(SELF_ID, 9000)));
        m.set_registered(records(&[(SELF_ID, 9000), (2002, 9000)]));
        assert_eq!(m.route(SELF_ID), None);
        assert_eq!(m.len(), 1);
        assert!(!m.snapshot().contains_key(&SELF_ID));
    }

    #[test]
    fn an_observation_routes_a_peer_without_a_record() {
        let mut m = PeerMap::new(SELF_ID);
        assert!(m.is_empty());
        assert!(m.observe(4004, addr(4004, 9000)));
        assert!(!m.is_empty());
        assert_eq!(m.route(4004), Some(&addr(4004, 9000)));
        // An observation equal to the record adds nothing to hold.
        m.set_registered(records(&[(5005, 9000)]));
        assert!(!m.observe(5005, addr(5005, 9000)));
        assert_eq!(m.len(), 2);
    }
}

#[cfg(all(test, feature = "grpc", has_protos))]
mod decode_tests {
    use super::proto::nexus::raft::RaftResponse;
    use super::proto_result_to_command_result;
    use crate::raft::CommandResult;

    #[test]
    fn inner_refusal_decodes_to_error() {
        // The exact shape command_result_to_proto emits for
        // CommandResult::Error: inner success:false + error, no typed result
        // (the outer ProposeResponse stays success:true for any applied
        // command). A follower replaying a forwarded CAS conflict through
        // this decoder must see the refusal — collapsing it to Success would
        // claim the insert and defeat the journal's single-executor grant.
        let resp = RaftResponse {
            success: false,
            error: Some("control state z/k already exists".to_string()),
            result: None,
        };
        let decoded = proto_result_to_command_result(Some(resp));
        assert!(matches!(
            decoded,
            CommandResult::Error(ref e) if e == "control state z/k already exists"
        ));
    }

    #[test]
    fn absent_result_decodes_to_success() {
        let resp = RaftResponse {
            success: true,
            error: None,
            result: None,
        };
        assert!(matches!(
            proto_result_to_command_result(Some(resp)),
            CommandResult::Success
        ));
        // No inner response at all — the old single-node shape.
        assert!(matches!(
            proto_result_to_command_result(None),
            CommandResult::Success
        ));
    }

    #[test]
    fn only_a_definite_pre_submission_refusal_can_redirect_a_write() {
        use super::proto::nexus::raft::ProposeResponse;
        use super::{decode_propose_response, NOT_LEADER_ERROR};
        use crate::raft::RaftError;

        let refused = ProposeResponse {
            success: false,
            error: Some(NOT_LEADER_ERROR.into()),
            leader_address: Some("127.0.0.1:9000".into()),
            result: None,
            applied_index: 0,
        };
        let error = decode_propose_response(refused.clone()).unwrap_err();
        assert!(
            matches!(error, RaftError::NotLeader { leader_hint: Some(ref address) }
            if address == "127.0.0.1:9000")
        );
        for response in [
            ProposeResponse {
                error: Some("Proposal failed: not leader after an uncertain operation".into()),
                ..refused.clone()
            },
            ProposeResponse {
                applied_index: 42,
                ..refused.clone()
            },
            ProposeResponse {
                result: Some(RaftResponse {
                    success: true,
                    error: None,
                    result: None,
                }),
                ..refused
            },
        ] {
            let error = decode_propose_response(response).unwrap_err();
            assert!(!matches!(error, RaftError::NotLeader { .. }));
            assert!(error.proposal_outcome_unknown());
        }
    }
}
