//! gRPC server for Raft transport.
//!
//! All Raft zones (including single-zone setups) are served through
//! `ZoneRaftRegistry`. There is no separate "single-zone" code path —
//! a single-zone deployment is simply a registry with one zone.

use super::proto::nexus::raft::{
    node_enrollment_service_server::{NodeEnrollmentService, NodeEnrollmentServiceServer},
    raft_command::Command as ProtoCommandVariant,
    raft_query::Query as ProtoQueryVariant,
    raft_query_response::Result as ProtoQueryResultVariant,
    raft_response::Result as ProtoResponseResultVariant,
    zone_api_service_server::{ZoneApiService, ZoneApiServiceServer},
    zone_transport_service_server::{ZoneTransportService, ZoneTransportServiceServer},
    AllowSessionMinterRequest, AllowSessionMinterResponse, ClusterConfig as ProtoClusterConfig,
    DeleteZoneRequest, DeleteZoneResponse, DenySessionMinterRequest, DenySessionMinterResponse,
    DiscoverZonesRequest, DiscoverZonesResponse, EcReplicationEntry, FederationZoneInfo,
    ForeignCaEntry, GetClusterInfoRequest, GetClusterInfoResponse, GetCrlRequest, GetCrlResponse,
    GetMetadataResult, GetSearchCapabilitiesRequest, JoinClusterRequest, JoinClusterResponse,
    JoinZoneRequest, JoinZoneResponse, ListForeignCasRequest, ListForeignCasResponse,
    ListKeysRequest, ListKeysResponse, ListMetadataResult, ListSessionMintersRequest,
    ListSessionMintersResponse, ListedKey, LockInfoResult, LockResult, MintAgentRequest,
    MintAgentResponse, MintKeyRequest, MintKeyResponse, MintSessionAgentRequest,
    MintSessionAgentResponse, NodeInfo as ProtoNodeInfo, PrepareReplicaControlReaderRequest,
    PrepareReplicaControlReaderResponse, ProposeRequest, ProposeResponse, QueryRequest,
    QueryResponse, RaftCommand, RaftQueryResponse, RaftResponse, ReadBlobRequest, ReadBlobResponse,
    ReadZoneBlobRequest, RegisterForeignCaRequest, RegisterForeignCaResponse, RemoveVoterRequest,
    RemoveVoterResponse, RenewLocalNodeCertificateRequest, RenewLocalNodeCertificateResponse,
    RenewNodeCertificateRequest, RenewNodeCertificateResponse, RenewSessionAgentRequest,
    ReplicateEntriesRequest, ReplicateEntriesResponse, RevokeAgentCertRequest,
    RevokeAgentCertResponse, RevokeKeyRequest, RevokeKeyResponse, SearchCapabilities,
    SnapshotChunkRequest, SnapshotChunkResponse, SnapshotEcStateRequest, SnapshotEcStateResponse,
    StepMessageRequest, StepMessageResponse, UnregisterForeignCaRequest,
    UnregisterForeignCaResponse,
};
use super::{NodeAddress, Result, SharedPeerMap, TransportError};
use crate::blob_fetcher::BlobFetcherSlot;
use crate::ca_issuer::{AgentBundle, CaIssuerSlot, LocalNodeRenewerSlot, NOT_CA_HOLDER};
use crate::foreign_ca_registrar::ForeignCaRegistrarSlot;
use crate::key_minter::{KeyMinterSlot, MintKeyParams};

fn session_credential_response(
    result: std::result::Result<AgentBundle, String>,
) -> Response<MintSessionAgentResponse> {
    Response::new(match result {
        Ok(bundle) => MintSessionAgentResponse {
            success: true,
            error: None,
            agent_cert_pem: bundle.cert_pem,
            agent_key_pem: bundle.key_pem,
            ca_pem: bundle.ca_pem,
            subject_id: bundle.subject_id,
        },
        Err(error) => MintSessionAgentResponse {
            success: false,
            error: Some(error),
            agent_cert_pem: Vec::new(),
            agent_key_pem: Vec::new(),
            ca_pem: Vec::new(),
            subject_id: String::new(),
        },
    })
}
use crate::raft::{
    Command, CommandResult, FullStateMachine, RaftError, WitnessStateMachine, ZoneConsensus,
    ZoneRaftRegistry,
};
use bincode::Options;
use dashmap::DashMap;
use prost::Message;
use protobuf::Message as ProtobufV2Message;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tonic::{Request, Response, Status};

/// Configuration for Raft transport server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to bind to (e.g., "0.0.0.0:2026").
    pub bind_address: SocketAddr,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Optional TLS configuration for mTLS. None = plain HTTP/2.
    pub tls: Option<super::TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:2026".parse().unwrap(),
            max_connections: 100,
            tls: None,
        }
    }
}

// =============================================================================
// Raft gRPC Server (zone-routed, serves all zones on one port)
// =============================================================================

/// A gRPC server that routes requests to Raft zones via `ZoneRaftRegistry`.
///
/// All setups — single-zone and multi-zone — use this server.
/// A single-zone deployment is just a registry with one zone.
pub struct RaftGrpcServer {
    config: ServerConfig,
    registry: Arc<ZoneRaftRegistry>,
    /// Slot the kernel binds a `BlobFetcher` into after its root mount
    /// backend is wired. `None` while the slot is empty —
    /// `ReadBlob` returns `NotFound` until the kernel installs one.
    blob_fetcher_slot: Option<BlobFetcherSlot>,
    search_capabilities_slot: Option<crate::search_capabilities::SearchCapabilitiesSlot>,
    /// Slot the cluster profile binds an `CaIssuer` into on the founder
    /// (CA holder) at boot. `None` on a joiner — `MintAgent` returns
    /// success=false there ("not the CA holder").
    ca_issuer_slot: Option<CaIssuerSlot>,
    /// Slot the cluster profile binds a `KeyMinter` into on every auth-on
    /// daemon at boot. `None` under `--no-tls` — `MintKey`/`RevokeKey` return
    /// success=false there (auth-off has no sk- plane).
    key_minter_slot: Option<KeyMinterSlot>,
    /// Slot the cluster profile binds a `ForeignCaRegistrar` into on every
    /// auth-on daemon. `None` under `--no-tls` — the RegisterForeignCa RPCs
    /// return success=false there (no cross-org trust plane).
    foreign_ca_registrar_slot: Option<ForeignCaRegistrarSlot>,
    session_mint_admin_slot: Option<crate::session_mint_admin::SessionMintAdminSlot>,
    local_node_renewer_slot: Option<LocalNodeRenewerSlot>,
    /// Federated mTLS client-cert verifier — the client-auth trust roots as a
    /// hot-swappable set (cluster CA + any runtime-registered foreign CAs), so a
    /// cross-org CA registered live is trusted without a restart. Shared with the
    /// cross-org apply-observer, which calls `set_foreign_cas` on it. `None` (or
    /// `--no-tls`) → the serve path builds a cluster-only verifier from the CA in
    /// `config.tls` (base mTLS, no foreign hot-swap).
    foreign_ca_verifier: Option<Arc<lib::transport_primitives::FederatedClientCertVerifier>>,
    /// Additional gRPC services co-hosted on the same port.
    /// Constructed externally (e.g. VFS gRPC by the cluster binary)
    /// and passed in as type-erased `tonic::service::Routes` so this
    /// crate has no dependency on the transport crate.
    extra_services: Option<tonic::service::Routes>,
}

type GuardedRaftService =
    super::node_authority::NodeControlService<ZoneTransportServiceServer<ZoneTransportServiceImpl>>;
type GuardedApiService =
    super::node_authority::NodeControlService<ZoneApiServiceServer<ZoneApiServiceImpl>>;

pub(crate) struct PreparedRaftListener {
    policy: super::node_authority::NodeControlPolicy,
    tls: Option<lib::transport_primitives::SharedTlsListener>,
}

fn listener_credentials(
    source: lib::transport_primitives::SharedTlsConfig,
    configured: Option<&super::TlsConfig>,
) -> Result<lib::transport_primitives::SharedTlsConfig> {
    let snapshot = source.snapshot();
    let current = snapshot
        .configured_material()
        .map_err(|e| TransportError::Connection(e.into()))?;
    if current != configured {
        return Err(TransportError::Connection(
            "listener and registry TLS configuration differ".into(),
        ));
    }
    Ok(source)
}

impl RaftGrpcServer {
    pub(crate) fn prepare_listener(
        credentials: lib::transport_primitives::SharedTlsConfig,
        configured: Option<&super::TlsConfig>,
        verifier: Option<Arc<lib::transport_primitives::FederatedClientCertVerifier>>,
    ) -> Result<PreparedRaftListener> {
        let original = credentials.snapshot();
        listener_credentials(credentials.clone(), configured)?;
        let policy = super::node_authority::NodeControlPolicy::from_shared_tls(credentials.clone())
            .map_err(TransportError::Connection)?;
        let tls = configured
            .map(|_| {
                lib::transport_primitives::SharedTlsListener::prepare(credentials.clone(), verifier)
                    .map_err(TransportError::Connection)
            })
            .transpose()?;
        if !credentials.snapshot().same_installation(&original) {
            return Err(TransportError::Connection(
                "listener credentials changed during preparation".into(),
            ));
        }
        Ok(PreparedRaftListener { policy, tls })
    }

    fn guarded_services(
        &self,
        policy: super::node_authority::NodeControlPolicy,
    ) -> (GuardedRaftService, GuardedApiService) {
        use super::node_authority::{NodeControlService, AGENT_CREDENTIAL_METHODS};
        let raft = ZoneTransportServiceImpl {
            registry: self.registry.clone(),
            snapshots: Default::default(),
        };
        let api = ZoneApiServiceImpl {
            registry: self.registry.clone(),
            blob_fetcher_slot: self.blob_fetcher_slot.clone(),
            search_capabilities_slot: self.search_capabilities_slot.clone(),
            ca_issuer_slot: self.ca_issuer_slot.clone(),
            key_minter_slot: self.key_minter_slot.clone(),
            foreign_ca_registrar_slot: self.foreign_ca_registrar_slot.clone(),
            session_mint_admin_slot: self.session_mint_admin_slot.clone(),
            local_node_renewer_slot: self.local_node_renewer_slot.clone(),
        };
        (
            NodeControlService::new(
                bounded!(ZoneTransportServiceServer::new(raft)),
                policy.clone(),
                &[],
            )
            .with_owner_replica_data(),
            NodeControlService::new(
                bounded!(ZoneApiServiceServer::new(api)),
                policy,
                AGENT_CREDENTIAL_METHODS,
            )
            .with_owner_replica_data(),
        )
    }
    pub fn new(registry: Arc<ZoneRaftRegistry>, config: ServerConfig) -> Self {
        Self {
            config,
            registry,
            blob_fetcher_slot: None,
            search_capabilities_slot: None,
            ca_issuer_slot: None,
            key_minter_slot: None,
            foreign_ca_registrar_slot: None,
            session_mint_admin_slot: None,
            local_node_renewer_slot: None,
            foreign_ca_verifier: None,
            extra_services: None,
        }
    }

    /// Attach the late-bindable `BlobFetcher` slot so
    /// `ZoneApiService::read_blob` can serve CAS reads once the kernel
    /// installs an impl. Callers typically share the slot with the
    /// owning `ZoneManager` so both halves reach the same `Arc`.
    pub fn with_blob_fetcher_slot(mut self, slot: BlobFetcherSlot) -> Self {
        self.blob_fetcher_slot = Some(slot);
        self
    }

    pub fn with_search_capabilities_slot(
        mut self,
        slot: crate::search_capabilities::SearchCapabilitiesSlot,
    ) -> Self {
        self.search_capabilities_slot = Some(slot);
        self
    }

    /// Attach the late-bindable `CaIssuer` slot so `ZoneApiService::mint_agent`
    /// can sign agent certs once the founder installs an impl. Installed only on
    /// the CA holder; a joiner leaves it empty and rejects `MintAgent`.
    pub fn with_ca_issuer_slot(mut self, slot: CaIssuerSlot) -> Self {
        self.ca_issuer_slot = Some(slot);
        self
    }

    /// Attach the late-bindable `KeyMinter` slot so `ZoneApiService::mint_key` /
    /// `revoke_key` can mint/revoke sk- credentials once the daemon installs an
    /// impl. Installed on every auth-on node; left empty under `--no-tls`.
    pub fn with_key_minter_slot(mut self, slot: KeyMinterSlot) -> Self {
        self.key_minter_slot = Some(slot);
        self
    }

    /// Attach the late-bindable `ForeignCaRegistrar` slot so
    /// `ZoneApiService::register_foreign_ca` (+ siblings) can record cross-org CA
    /// anchors once the daemon installs an impl. Installed on every auth-on node;
    /// empty under `--no-tls`.
    pub fn with_foreign_ca_registrar_slot(mut self, slot: ForeignCaRegistrarSlot) -> Self {
        self.foreign_ca_registrar_slot = Some(slot);
        self
    }

    /// Attach the late-bindable `SessionMintAdmin` slot so the allow-list RPCs
    /// can serve once the daemon installs an impl. Installed on every auth-on
    /// node; empty under `--no-tls`, where there is no agent-cert plane to
    /// allow-list.
    pub fn with_session_mint_admin_slot(
        mut self,
        slot: crate::session_mint_admin::SessionMintAdminSlot,
    ) -> Self {
        self.session_mint_admin_slot = Some(slot);
        self
    }

    /// Attach the late-bindable renewer of this daemon's own Node certificate,
    /// so `RenewLocalNodeCertificate` serves once the daemon installs it.
    pub fn with_local_node_renewer_slot(mut self, slot: LocalNodeRenewerSlot) -> Self {
        self.local_node_renewer_slot = Some(slot);
        self
    }

    /// Attach the shared federated client-cert verifier (from `ZoneManager`), so
    /// the serve path's mTLS client-auth roots are the same `Arc` the cross-org
    /// apply-observer hot-swaps. `None` → the serve path builds a cluster-only
    /// verifier from the configured CA.
    pub fn with_foreign_ca_verifier(
        mut self,
        verifier: Option<Arc<lib::transport_primitives::FederatedClientCertVerifier>>,
    ) -> Self {
        self.foreign_ca_verifier = verifier;
        self
    }

    /// Co-host additional gRPC services on the same port.
    ///
    /// The caller builds the services externally (e.g. VFS gRPC via
    /// `transport::grpc::build_vfs_service`) and passes them as
    /// type-erased `tonic::service::Routes`. This avoids a circular
    /// dependency between `raft` and `transport` crates.
    pub fn with_extra_services(mut self, routes: tonic::service::Routes) -> Self {
        self.extra_services = Some(routes);
        self
    }

    /// Get the bind address.
    pub fn bind_address(&self) -> SocketAddr {
        self.config.bind_address
    }

    /// Prepare the listener and run it until termination.
    pub fn serve(self) -> impl std::future::Future<Output = Result<()>> + Send {
        self.serve_with_shutdown(std::future::pending())
    }

    /// Prepare trust and service policy before the returned future is scheduled.
    /// Live credential replacement remains visible to handshakes and requests.
    pub fn serve_with_shutdown(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let prepared = Self::prepare_listener(
            self.registry.shared_tls(),
            self.config.tls.as_ref(),
            self.foreign_ca_verifier.clone(),
        );
        async move {
            let prepared = prepared?;
            let listener = tokio::net::TcpListener::bind(self.config.bind_address)
                .await
                .map_err(|e| TransportError::Connection(e.to_string()))?;
            self.serve_listener(prepared, listener, shutdown).await
        }
    }

    /// Serve a socket and trust policy prepared before opening runtime storage.
    pub(crate) async fn serve_prepared(
        self,
        prepared: PreparedRaftListener,
        listener: std::net::TcpListener,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        let listener = tokio::net::TcpListener::from_std(listener)
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        self.serve_listener(prepared, listener, shutdown).await
    }

    async fn serve_listener(
        self,
        prepared: PreparedRaftListener,
        listener: tokio::net::TcpListener,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        let (raft_service, client_service) = self.guarded_services(prepared.policy);
        tracing::info!(
            "Starting Raft gRPC server on {} (zones={}, tls={})",
            self.config.bind_address,
            self.registry.list_zones().len(),
            prepared.tls.is_some(),
        );
        let mut builder =
            lib::transport_primitives::apply_server_limits(tonic::transport::Server::builder());
        let router = if let Some(extra) = self.extra_services {
            builder
                .add_routes(extra)
                .add_service(raft_service)
                .add_service(client_service)
        } else {
            builder
                .add_service(raft_service)
                .add_service(client_service)
        };
        if let Some(tls) = prepared.tls {
            router
                .serve_with_incoming_shutdown(tls.incoming(listener), shutdown)
                .await
                .map_err(TransportError::Tonic)?;
        } else {
            let incoming =
                tonic::transport::server::TcpIncoming::from(listener).with_nodelay(Some(true));
            router
                .serve_with_incoming_shutdown(incoming, shutdown)
                .await
                .map_err(TransportError::Tonic)?;
        }
        Ok(())
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Convert milliseconds to seconds using ceiling division.
///
/// Prevents sub-second TTLs from silently truncating to zero.
/// E.g., 999ms → 1s, 1000ms → 1s, 1001ms → 2s.
/// Negative values clamp to 0.
fn ms_to_secs_ceil(ms: i64) -> u32 {
    if ms <= 0 {
        return 0;
    }
    (ms as u64).div_ceil(1000) as u32
}

/// Convert protobuf RaftCommand to internal Command enum.
fn proto_command_to_internal(proto: RaftCommand) -> Option<Command> {
    match proto.command? {
        ProtoCommandVariant::PutMetadata(pm) => {
            let metadata = pm.metadata?;
            let key = metadata.path.clone();
            Some(Command::SetMetadata {
                key,
                value: prost::Message::encode_to_vec(&metadata),
            })
        }
        ProtoCommandVariant::DeleteMetadata(dm) => Some(Command::DeleteMetadata { key: dm.path }),
        ProtoCommandVariant::AcquireLock(al) => Some(Command::AcquireLock {
            path: al.lock_id.clone(),
            lock_id: al.holder_id.clone(),
            max_holders: 1, // Default to mutex
            ttl_secs: ms_to_secs_ceil(al.ttl_ms),
            holder_info: al.holder_id,
            now_secs: crate::prelude::FullStateMachine::now(),
        }),
        ProtoCommandVariant::ReleaseLock(rl) => Some(Command::ReleaseLock {
            path: rl.lock_id.clone(),
            lock_id: rl.holder_id,
        }),
        ProtoCommandVariant::ExtendLock(el) => Some(Command::ExtendLock {
            path: el.lock_id.clone(),
            lock_id: el.holder_id,
            new_ttl_secs: ms_to_secs_ceil(el.ttl_ms),
            now_secs: crate::prelude::FullStateMachine::now(),
        }),
    }
}

/// Look up a zone's ZoneConsensus from the registry, or return a gRPC error.
#[allow(clippy::result_large_err)]
fn get_zone_node(
    registry: &ZoneRaftRegistry,
    zone_id: &str,
) -> std::result::Result<ZoneConsensus<FullStateMachine>, Status> {
    registry.get_node(zone_id).ok_or_else(|| {
        Status::not_found(format!(
            "zone '{}' not found on this node",
            if zone_id.is_empty() {
                "<empty>"
            } else {
                zone_id
            }
        ))
    })
}

/// Convert internal CommandResult to proto RaftResponse.
fn command_result_to_proto(result: &CommandResult) -> RaftResponse {
    match result {
        CommandResult::Success => RaftResponse {
            success: true,
            error: None,
            result: None,
        },
        CommandResult::Value(v) => RaftResponse {
            success: true,
            error: None,
            result: Some(ProtoResponseResultVariant::ValueResult(v.clone())),
        },
        CommandResult::LockResult(lock_state) => {
            let first_holder = lock_state.holders.first();
            RaftResponse {
                success: true,
                error: None,
                result: Some(ProtoResponseResultVariant::LockResult(LockResult {
                    acquired: lock_state.acquired,
                    current_holder: first_holder.map(|h| h.holder_info.clone()),
                    expires_at_ms: first_holder
                        .map(|h| (h.expires_at * 1000) as i64)
                        .unwrap_or(0),
                })),
            }
        }
        CommandResult::CasResult { success, .. } => RaftResponse {
            success: *success,
            error: if *success {
                None
            } else {
                Some("CAS conflict".to_string())
            },
            result: None,
        },
        CommandResult::Error(e) => RaftResponse {
            success: false,
            error: Some(e.clone()),
            result: None,
        },
        CommandResult::ConditionalMetadata { .. }
        | CommandResult::ProtectedMetadata { .. }
        | CommandResult::ConditionalMetadataUnsupported => RaftResponse {
            success: false,
            error: Some("versioned metadata is not supported by this legacy response".into()),
            result: None,
        },
    }
}

/// Decode once for both sender admission and consensus execution.
fn parse_raft_message(
    bytes: &[u8],
) -> std::result::Result<raft::eraftpb::Message, StepMessageResponse> {
    raft::eraftpb::Message::parse_from_bytes(bytes).map_err(|error| StepMessageResponse {
        success: false,
        error: Some(format!("Failed to deserialize raft message: {error}")),
    })
}

/// Only an explicitly commissioned member may exchange namespace-format traffic.
fn namespace_step_zone<S: crate::raft::StateMachine + 'static>(
    node: Option<ZoneConsensus<S>>,
    protocol: crate::raft::RaftMessageProtocol,
) -> std::result::Result<Option<ZoneConsensus<S>>, Status> {
    let namespace = node
        .as_ref()
        .is_some_and(ZoneConsensus::is_atomic_namespace_member);
    if namespace != (protocol == crate::raft::RaftMessageProtocol::AtomicNamespaceV2) {
        return Err(Status::failed_precondition(
            "incompatible Raft namespace reader",
        ));
    }
    Ok(node)
}

/// Step an admitted message with the same full-node and witness semantics.
async fn step_raft_message<S: crate::raft::StateMachine + Send + Sync + 'static>(
    node: &ZoneConsensus<S>,
    mut msg: raft::eraftpb::Message,
    zone_id: &str,
    log_prefix: &str,
    protocol: crate::raft::RaftMessageProtocol,
) -> std::result::Result<Response<StepMessageResponse>, Status> {
    tracing::trace!(
        "{} StepMessage [zone={}]: type={:?}, from={}, to={}, term={}",
        log_prefix,
        zone_id,
        msg.get_msg_type(),
        msg.from,
        msg.to,
        msg.term,
    );

    // raft-rs asserts when a heartbeat/append carries a committed index
    // beyond the follower's local log. Fresh full-node auto-join can see
    // exactly that window: the leader has compacted and will send a snapshot,
    // but ordinary heartbeats/appends may arrive first. Clamp the commit hint
    // to the highest index this message/local handle can actually account for;
    // the later snapshot or append will advance commit normally.
    //
    // A clamp alone is not news: a learner of a zone whose voters commit
    // without it sees the leader's commit ahead of its own log on every
    // message while entries are in flight. It is news once this replica's
    // applied index has stood still behind the leader for
    // `REPLICATION_STALL` — the stall `doctor --live` reports as
    // REPLICA_LAGGING — so only then is it a warning.
    if matches!(
        msg.get_msg_type(),
        raft::eraftpb::MessageType::MsgAppend | raft::eraftpb::MessageType::MsgHeartbeat
    ) {
        let local_last = node.last_index();
        let msg_last = msg.get_entries().last().map(|e| e.index).unwrap_or(0);
        let safe_commit = local_last.max(msg_last).max(node.applied_index());
        if msg.get_commit() > safe_commit {
            let stalled_for = node.replication().stalled_for;
            if stalled_for >= crate::raft::REPLICATION_STALL {
                tracing::warn!(
                    zone = %zone_id,
                    from = msg.from,
                    to = msg.to,
                    msg_type = ?msg.get_msg_type(),
                    leader_commit = msg.get_commit(),
                    safe_commit,
                    local_last,
                    msg_last,
                    stalled_secs = stalled_for.as_secs(),
                    "Clamping inbound raft commit hint: this replica has applied nothing \
                     behind the leader's commit for {}s, so it is not receiving entries",
                    stalled_for.as_secs(),
                );
            } else {
                tracing::debug!(
                    zone = %zone_id,
                    from = msg.from,
                    leader_commit = msg.get_commit(),
                    safe_commit,
                    local_last,
                    msg_last,
                    "Clamping inbound raft commit hint while entries are in flight",
                );
            }
            msg.set_commit(safe_commit);
        }
    }

    if let Err(e) = node.step_transport(msg, protocol).await {
        return Ok(Response::new(StepMessageResponse {
            success: false,
            error: Some(format!("Failed to step message: {}", e)),
        }));
    }

    Ok(Response::new(StepMessageResponse {
        success: true,
        error: None,
    }))
}

// =============================================================================
// ZoneTransportService (internal node-to-node transport)
// =============================================================================

/// Full nodes and witnesses acknowledge the same durable driver operation.
async fn prepare_replica_control_reader<S: crate::raft::StateMachine + Send + Sync + 'static>(
    node: ZoneConsensus<S>,
) -> std::result::Result<Response<PrepareReplicaControlReaderResponse>, Status> {
    node.prepare_replica_control_reader()
        .await
        .map_err(|error| {
            Status::failed_precondition(format!("reader preparation failed: {error}"))
        })?;
    Ok(Response::new(PrepareReplicaControlReaderResponse {
        replica_control_transport_v1: true,
    }))
}

/// Zone-routed implementation of the ZoneTransportService gRPC trait.
///
/// All raft-rs message types (~15 types including votes, heartbeats, appends)
/// are multiplexed through `step_message` as opaque protobuf v2 bytes
/// (etcd/tikv pattern).
struct ZoneTransportServiceImpl {
    registry: Arc<ZoneRaftRegistry>,
    /// Raft snapshots being received through `snapshot_chunk`.
    snapshots: snapshot_assembly::SnapshotAssembly,
}

/// Both EC transfer paths acknowledge only commands this reader understood and
/// applied. A refusal retains the sender's position for a compatible retry.
async fn apply_ec_entry(
    node: &ZoneConsensus<FullStateMachine>,
    entry: &EcReplicationEntry,
) -> std::result::Result<(), String> {
    let command = bincode::options()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(&entry.command)
        .map_err(|error| format!("decode EC entry {}: {error}", entry.seq))?;
    match node.apply_ec_from_peer(command, entry.timestamp).await {
        Ok(CommandResult::Error(error)) => Err(format!("apply EC entry {}: {error}", entry.seq)),
        Ok(_) => Ok(()),
        Err(error) => Err(format!("apply EC entry {}: {error}", entry.seq)),
    }
}

impl ZoneTransportServiceImpl {
    // Zone creation is synchronous setup. Keep its allocations and error paths
    // outside the future polled for every Raft message on both wire versions.
    #[cold]
    #[inline(never)]
    fn join_step_zone(
        &self,
        zone_id: &str,
    ) -> std::result::Result<ZoneConsensus<FullStateMachine>, Status> {
        if !self.registry.permits_automatic_zone_join() {
            return Err(Status::not_found("zone is not admitted on this runtime"));
        }
        if self.registry.is_auto_join_suppressed(zone_id) {
            return Err(Status::not_found(format!(
                "zone '{zone_id}' was recently removed on this node"
            )));
        }
        if !self.registry.is_resident(contracts::ROOT_ZONE_ID) {
            return Err(Status::not_found(format!(
                "zone '{zone_id}' not found on this node"
            )));
        }
        // The transport authenticates the sender; the registry applies zone
        // admission and membership rules.
        let handle = tokio::runtime::Handle::current();
        self.registry
            .join_zone(zone_id, false, &handle)
            .map_err(|e| Status::internal(format!("failed to auto-join zone '{zone_id}': {e}")))
    }

    /// Admit a caller at a step boundary, before its payload is parsed.
    #[allow(clippy::result_large_err)]
    fn admit_step_caller(
        &self,
        extensions: &tonic::codegen::http::Extensions,
        zone_id: &str,
        protocol: crate::raft::RaftMessageProtocol,
    ) -> std::result::Result<(), Status> {
        if protocol != crate::raft::RaftMessageProtocol::Legacy {
            super::node_authority::require_authenticated_control_node(extensions)?;
        }
        super::node_authority::authorize_data_zone(extensions, &self.registry, zone_id)
    }

    /// The zone a step is for, joined on first contact.
    #[allow(clippy::result_large_err)]
    fn step_zone(
        &self,
        zone_id: &str,
        protocol: crate::raft::RaftMessageProtocol,
    ) -> std::result::Result<ZoneConsensus<FullStateMachine>, Status> {
        match namespace_step_zone(self.registry.get_node(zone_id), protocol)? {
            Some(node) => Ok(node),
            None => self.join_step_zone(zone_id),
        }
    }

    /// Step a decoded message from an admitted caller. Every raft message
    /// reaches its zone's driver through here, whichever RPC carried it.
    async fn step_admitted(
        &self,
        extensions: &tonic::codegen::http::Extensions,
        zone_id: &str,
        sender_address: &str,
        message: raft::eraftpb::Message,
        protocol: crate::raft::RaftMessageProtocol,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        let peer = super::node_authority::authorize_raft_sender(extensions, &message)?;
        let node = self.step_zone(zone_id, protocol)?;
        self.snapshots.release_idle(std::time::Instant::now());

        // Observe the connected peer's address before stepping. Relayed
        // requests retain their logical origin in `from`; that origin does not
        // own the forwarder's advertised address. Authentication is the
        // transport layer's job (mTLS when enabled); the observation is a
        // route only, never membership.
        self.registry
            .learn_peer_address(zone_id, peer, sender_address);

        step_raft_message(&node, message, zone_id, "", protocol).await
    }

    async fn dispatch_step(
        &self,
        request: Request<StepMessageRequest>,
        protocol: crate::raft::RaftMessageProtocol,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        self.admit_step_caller(request.extensions(), &request.get_ref().zone_id, protocol)?;
        let message = match parse_raft_message(&request.get_ref().message) {
            Ok(message) => message,
            Err(response) => return Ok(Response::new(response)),
        };
        let (_, extensions, req) = request.into_parts();
        self.step_admitted(
            &extensions,
            &req.zone_id,
            &req.sender_address,
            message,
            protocol,
        )
        .await
    }
}

#[tonic::async_trait]
impl ZoneTransportService for ZoneTransportServiceImpl {
    async fn prepare_replica_control_reader_v1(
        &self,
        request: Request<PrepareReplicaControlReaderRequest>,
    ) -> std::result::Result<Response<PrepareReplicaControlReaderResponse>, Status> {
        super::node_authority::require_authenticated_control_node(request.extensions())?;
        let node = get_zone_node(&self.registry, &request.get_ref().zone_id)?;
        prepare_replica_control_reader(node).await
    }

    /// Handle a raw raft-rs message forwarded from another node.
    ///
    /// Routes by zone_id to the correct Raft group's ZoneConsensus.
    /// Unknown zones return `NotFound` — the local storage enumeration at
    /// `PyZoneManager::new` (R15.e) is the authority for which groups this
    /// node hosts. New dynamic zones arrive via `federation_create_zone`;
    /// new replicas of existing zones arrive via leader snapshot delivery
    /// after the ConfChange commits. No side-effectful auto-reopen from
    /// disk in the message hot path.
    async fn step_message(
        &self,
        request: Request<StepMessageRequest>,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        self.dispatch_step(request, crate::raft::RaftMessageProtocol::Legacy)
            .await
    }

    async fn step_storage_v1(
        &self,
        request: Request<StepMessageRequest>,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        self.dispatch_step(request, crate::raft::RaftMessageProtocol::Legacy)
            .await
    }

    async fn step_replica_control_v1(
        &self,
        request: Request<StepMessageRequest>,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        self.dispatch_step(request, crate::raft::RaftMessageProtocol::ReplicaControlV1)
            .await
    }

    async fn step_atomic_namespace_v2(
        &self,
        request: Request<StepMessageRequest>,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        self.dispatch_step(request, crate::raft::RaftMessageProtocol::AtomicNamespaceV2)
            .await
    }

    /// Receive one slice of a raft snapshot. The caller is admitted as the
    /// transfer's Step RPC admits it, and the completed `MsgSnapshot` takes
    /// that RPC's step path.
    async fn snapshot_chunk(
        &self,
        request: Request<SnapshotChunkRequest>,
    ) -> std::result::Result<Response<SnapshotChunkResponse>, Status> {
        let protocol = snapshot_assembly::boundary_protocol(request.get_ref())?;
        self.admit_step_caller(request.extensions(), &request.get_ref().zone_id, protocol)?;
        let (_, extensions, req) = request.into_parts();
        snapshot_assembly::receive_chunk(
            &self.snapshots,
            &extensions,
            &req,
            || self.step_zone(&req.zone_id, protocol).map(drop),
            |message| {
                self.step_admitted(
                    &extensions,
                    &req.zone_id,
                    &req.sender_address,
                    message,
                    protocol,
                )
            },
        )
        .await
    }

    /// Handle EC replication entries from a peer (Phase C).
    ///
    /// Deserializes each entry's command bytes and applies to the local state
    /// machine via `apply_ec_from_peer`. Returns the highest seq applied.
    async fn replicate_entries(
        &self,
        request: Request<ReplicateEntriesRequest>,
    ) -> std::result::Result<Response<ReplicateEntriesResponse>, Status> {
        super::node_authority::authorize_data_zone(
            request.extensions(),
            &self.registry,
            &request.get_ref().zone_id,
        )?;
        super::node_authority::authorize_declared_sender(
            request.extensions(),
            request.get_ref().sender_node_id,
        )?;
        let req = request.into_inner();
        let node = get_zone_node(&self.registry, &req.zone_id)?;
        node.require_ec_writes()
            .map_err(|error| Status::failed_precondition(error.to_string()))?;

        // EC replication membership: like step_message, the peer-map
        // is the runtime SSOT under the opaque-ID contract; a static
        // "sender in env-derived peer set" check rejected legit
        // post-JoinZone replicas before they could learn each
        // other's addresses.  Authentication is the transport
        // layer's job (mTLS).
        let mut max_applied: u64 = 0;

        for entry in &req.entries {
            match apply_ec_entry(&node, entry).await {
                Ok(()) => {
                    max_applied = max_applied.max(entry.seq);
                    tracing::trace!(
                        seq = entry.seq,
                        zone = req.zone_id,
                        from = req.sender_node_id,
                        "Applied EC entry from peer"
                    );
                }
                Err(e) => {
                    tracing::warn!(seq = entry.seq, "Failed to apply EC entry from peer: {}", e);
                    // Return what we've applied so far
                    return Ok(Response::new(ReplicateEntriesResponse {
                        success: false,
                        error: Some(format!("Failed at seq {}: {}", entry.seq, e)),
                        applied_up_to: max_applied,
                    }));
                }
            }
        }

        Ok(Response::new(ReplicateEntriesResponse {
            success: true,
            error: None,
            applied_up_to: max_applied,
        }))
    }

    /// Apply an EC state snapshot from a peer (anti-entropy catch-up).
    ///
    /// The sender re-materialized its CURRENT EC state as `SetMetadata`
    /// commands because this receiver fell behind the compacted WAL region.
    /// Apply each LWW-idempotently (same path as incremental replication) and
    /// echo `covering_seq` so the sender advances this peer's `acked_seq` past
    /// the compacted region in one step, then resumes incremental delivery.
    async fn snapshot_ec_state(
        &self,
        request: Request<SnapshotEcStateRequest>,
    ) -> std::result::Result<Response<SnapshotEcStateResponse>, Status> {
        super::node_authority::authorize_data_zone(
            request.extensions(),
            &self.registry,
            &request.get_ref().zone_id,
        )?;
        super::node_authority::authorize_declared_sender(
            request.extensions(),
            request.get_ref().sender_node_id,
        )?;
        let req = request.into_inner();
        let node = get_zone_node(&self.registry, &req.zone_id)?;
        node.require_ec_writes()
            .map_err(|error| Status::failed_precondition(error.to_string()))?;

        for entry in &req.entries {
            if let Err(e) = apply_ec_entry(&node, entry).await {
                tracing::warn!(seq = entry.seq, "EC snapshot refused: {}", e);
                return Ok(Response::new(SnapshotEcStateResponse {
                    success: false,
                    error: Some(format!("snapshot apply failed at seq {}: {}", entry.seq, e)),
                    acked_up_to: 0,
                }));
            }
        }

        Ok(Response::new(SnapshotEcStateResponse {
            success: true,
            error: None,
            acked_up_to: req.covering_seq,
        }))
    }
}

// =============================================================================
// ZoneApiService (client-facing: Propose/Query/GetClusterInfo)
// =============================================================================

/// The caller's verified mTLS client leaf cert (DER), or `None` for a plaintext
/// connection / no client cert. Forwarded opaquely to the mint impls, which gate
/// on it (a NODE peer). Shared by `mint_agent` / `mint_key` / `revoke_key` so the
/// extraction lives once.
fn peer_cert_der<T>(request: &Request<T>) -> Option<Vec<u8>> {
    request
        .extensions()
        .get::<tonic::transport::server::TlsConnectInfo<tonic::transport::server::TcpConnectInfo>>()
        .and_then(|tls| tls.peer_certs())
        .and_then(|certs| certs.first().map(|c| c.as_ref().to_vec()))
}

/// Each member's dial endpoint from the zone's member-address records — the
/// one source for addresses reported to clients, the local node's included.
fn member_endpoints(records: Vec<(u64, String)>, use_tls: bool) -> HashMap<u64, String> {
    records
        .into_iter()
        .filter_map(|(id, address)| {
            crate::raft::member_address::endpoint(id, &address, use_tls)
                .map(|route| (id, route.endpoint))
        })
        .collect()
}

async fn recorded_endpoints(
    node: &ZoneConsensus<FullStateMachine>,
    use_tls: bool,
) -> std::result::Result<HashMap<u64, String>, Status> {
    use crate::raft::StateMachine;
    let records = node
        .with_state_machine(|sm| sm.member_addresses())
        .await
        .map_err(|e| Status::unavailable(format!("read member addresses: {e}")))?
        .unwrap_or_default();
    Ok(member_endpoints(records, use_tls))
}

/// Voters and learners with their recorded addresses; a member without a
/// record carries an empty address.
fn cluster_config(
    addresses: &HashMap<u64, String>,
    voters: &[u64],
    learners: &[u64],
) -> ProtoClusterConfig {
    let info = |id: u64, role: i32| ProtoNodeInfo {
        id,
        address: addresses.get(&id).cloned().unwrap_or_default(),
        role,
    };
    ProtoClusterConfig {
        voters: voters.iter().map(|&id| info(id, 0)).collect(),
        learners: learners.iter().map(|&id| info(id, 1)).collect(),
        witnesses: vec![],
    }
}

/// Zone-routed implementation of the ZoneApiService gRPC trait.
///
/// This is the strict-mTLS DATA plane. Node enrollment (cert provisioning) is
/// NOT here — it lives in [`NodeEnrollmentServiceImpl`] on its own pre-mTLS
/// bootstrap listener, because a certless joiner cannot satisfy the client-cert
/// requirement this service is served behind.
struct ZoneApiServiceImpl {
    registry: Arc<ZoneRaftRegistry>,
    /// Optional late-bound `BlobFetcher` for `ReadBlob`. Empty slot
    /// (or `None` here) → `read_blob` returns `NotFound`.
    blob_fetcher_slot: Option<BlobFetcherSlot>,
    search_capabilities_slot: Option<crate::search_capabilities::SearchCapabilitiesSlot>,
    /// Optional late-bound `CaIssuer` for `MintAgent`. Present only on the
    /// CA holder (founder); `None` → `mint_agent` returns success=false.
    ca_issuer_slot: Option<CaIssuerSlot>,
    /// Optional late-bound `KeyMinter` for `MintKey`/`RevokeKey`. Present on
    /// every auth-on daemon; `None` (auth-off) → both return success=false.
    key_minter_slot: Option<KeyMinterSlot>,
    /// Optional late-bound `ForeignCaRegistrar` for `RegisterForeignCa` (+
    /// siblings). Present on every auth-on daemon; `None` (auth-off) → the RPCs
    /// return success=false.
    foreign_ca_registrar_slot: Option<ForeignCaRegistrarSlot>,
    session_mint_admin_slot: Option<crate::session_mint_admin::SessionMintAdminSlot>,
    /// Late-bound renewer of this daemon's own Node certificate; `None` (or
    /// empty) → `RenewLocalNodeCertificate` refuses.
    local_node_renewer_slot: Option<LocalNodeRenewerSlot>,
}

#[path = "server/replica_join.rs"]
mod replica_join;
mod snapshot_assembly;

impl ZoneApiServiceImpl {
    async fn blob_response(
        &self,
        zone_id: Option<&str>,
        content_id: &str,
    ) -> Response<ReadBlobResponse> {
        let fetcher = self
            .blob_fetcher_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned());
        let Some(fetcher) = fetcher else {
            return Response::new(ReadBlobResponse {
                content: Vec::new(),
                error: "blob fetcher not installed".to_string(),
            });
        };
        let result = match zone_id {
            Some(zone) => fetcher.read_in_zone(zone, content_id).await,
            None => fetcher.read(content_id).await,
        };
        Response::new(match result {
            Ok(content) => ReadBlobResponse {
                content,
                error: String::new(),
            },
            Err(error) => ReadBlobResponse {
                content: Vec::new(),
                error,
            },
        })
    }

    async fn replica_csr_response(
        &self,
        request: Request<super::proto::ReplicaCsrRequest>,
        query_only: bool,
    ) -> std::result::Result<Response<super::proto::ReplicaCsrResponse>, Status> {
        let caller = peer_cert_der(&request);
        let minter = self
            .ca_issuer_slot
            .as_ref()
            .and_then(|slot| slot.read().clone());
        let Some(minter) = minter else {
            return Ok(Response::new(super::proto::ReplicaCsrResponse {
                state: super::proto::ReplicaCsrState::Refused as i32,
                error: Some("allocation-bound replica issuer is unarmed on this node".into()),
                ..Default::default()
            }));
        };
        Ok(Response::new(
            minter
                .replica_csr_v1(caller, request.into_inner(), query_only)
                .await,
        ))
    }

    async fn agent_csr_response(
        &self,
        request: Request<super::proto::AgentCsrRequest>,
        query_only: bool,
    ) -> std::result::Result<Response<super::proto::AgentCsrResponse>, Status> {
        let caller = peer_cert_der(&request);
        let minter = self.ca_issuer_slot.as_ref().and_then(|s| s.read().clone());
        let Some(minter) = minter else {
            return Ok(Response::new(super::proto::AgentCsrResponse {
                state: super::proto::AgentCsrState::NotSubmitted as i32,
                error: Some("caller-owned Agent CSR issuer is unarmed on this node".into()),
                ..Default::default()
            }));
        };
        Ok(Response::new(
            minter
                .agent_csr_v1(caller, request.into_inner(), query_only)
                .await,
        ))
    }
}

#[tonic::async_trait]
impl ZoneApiService for ZoneApiServiceImpl {
    async fn control_replica_v1(
        &self,
        request: Request<super::proto::ReplicaControlRequest>,
    ) -> std::result::Result<Response<super::proto::ReplicaControlResponse>, Status> {
        let caller = peer_cert_der(&request);
        let minter = self
            .ca_issuer_slot
            .as_ref()
            .and_then(|slot| slot.read().clone());
        let Some(minter) = minter else {
            return Ok(Response::new(super::proto::ReplicaControlResponse {
                state: super::proto::ReplicaControlState::Refused as i32,
                error: Some("replica lifecycle controller is unarmed on this node".into()),
                ..Default::default()
            }));
        };
        Ok(Response::new(
            minter
                .replica_control_v1(caller, request.into_inner())
                .await,
        ))
    }

    async fn issue_replica_csr_v1(
        &self,
        request: Request<super::proto::ReplicaCsrRequest>,
    ) -> std::result::Result<Response<super::proto::ReplicaCsrResponse>, Status> {
        self.replica_csr_response(request, false).await
    }

    async fn query_replica_csr_v1(
        &self,
        request: Request<super::proto::ReplicaCsrRequest>,
    ) -> std::result::Result<Response<super::proto::ReplicaCsrResponse>, Status> {
        self.replica_csr_response(request, true).await
    }

    async fn get_agent_csr_capabilities(
        &self,
        _request: Request<super::proto::AgentCsrCapabilitiesRequest>,
    ) -> std::result::Result<Response<super::proto::AgentCsrCapabilitiesResponse>, Status> {
        let minter = self.ca_issuer_slot.as_ref().and_then(|s| s.read().clone());
        Ok(Response::new(
            minter.map_or_else(Default::default, |m| m.csr_capabilities()),
        ))
    }

    async fn issue_agent_csr_v1(
        &self,
        request: Request<super::proto::AgentCsrRequest>,
    ) -> std::result::Result<Response<super::proto::AgentCsrResponse>, Status> {
        self.agent_csr_response(request, false).await
    }

    async fn query_agent_csr_v1(
        &self,
        request: Request<super::proto::AgentCsrRequest>,
    ) -> std::result::Result<Response<super::proto::AgentCsrResponse>, Status> {
        self.agent_csr_response(request, true).await
    }

    /// Handle a client proposal (write operation).
    async fn propose(
        &self,
        request: Request<ProposeRequest>,
    ) -> std::result::Result<Response<ProposeResponse>, Status> {
        super::node_authority::authorize_data_zone(
            request.extensions(),
            &self.registry,
            &request.get_ref().zone_id,
        )?;
        let caller = super::node_authority::authenticated_node_id(request.extensions())?;
        let (_, extensions, req) = request.into_parts();
        let node = get_zone_node(&self.registry, &req.zone_id)?;

        tracing::debug!(
            "Received propose request: zone={}, id={:?}, forwarded={}",
            req.zone_id,
            req.request_id,
            req.forwarded,
        );

        // Deserialize command: prefer raw_command (bincode, from internal forwarding)
        // over proto command (from external clients).
        let namespace_forward = !req.namespace_command_v1.is_empty();
        let raw = if namespace_forward {
            if !req.forwarded || req.command.is_some() || !req.raw_command.is_empty() {
                return Err(Status::invalid_argument(
                    "namespace forward must carry a single command",
                ));
            }
            super::node_authority::require_authenticated_control_node(&extensions)?;
            if !node.is_atomic_namespace_member() {
                return Err(Status::failed_precondition(
                    "zone does not accept namespace-format writers",
                ));
            }
            if !caller.is_some_and(|id| node.is_replication_member(id)) {
                return Err(Status::permission_denied(
                    "namespace forward requires a zone member",
                ));
            }
            &req.namespace_command_v1
        } else {
            &req.raw_command
        };
        let cmd = if !raw.is_empty() {
            match bincode::deserialize::<Command>(raw) {
                Ok(c) => c,
                Err(e) => {
                    return Ok(Response::new(ProposeResponse {
                        success: false,
                        error: Some(format!("Failed to deserialize raw command: {}", e)),
                        leader_address: None,
                        result: None,
                        applied_index: None,
                    }));
                }
            }
        } else {
            let proto_cmd = match req.command {
                Some(cmd) => cmd,
                None => {
                    return Ok(Response::new(ProposeResponse {
                        success: false,
                        error: Some("No command provided".to_string()),
                        leader_address: None,
                        result: None,
                        applied_index: None,
                    }));
                }
            };

            match proto_command_to_internal(proto_cmd) {
                Some(c) => c,
                None => {
                    return Ok(Response::new(ProposeResponse {
                        success: false,
                        error: Some("Unsupported command type".to_string()),
                        leader_address: None,
                        result: None,
                        applied_index: None,
                    }));
                }
            }
        };

        // raw_command is also reachable over the generic public Propose RPC.
        // A missing dedicated file RPC does not isolate an enum variant. Return
        // a definite refusal before either direct or forwarded submission.
        if namespace_forward && !cmd.is_namespace_mutation() {
            return Err(Status::invalid_argument(
                "command is outside the namespace writer protocol",
            ));
        }
        if node.is_atomic_namespace_member() && cmd.is_namespace_mutation() && !namespace_forward {
            return Err(Status::failed_precondition(
                "zone requires the namespace writer protocol",
            ));
        }
        let forwarded_rename =
            namespace_forward && matches!(cmd, Command::RenameNamespaceV1 { .. });
        if !forwarded_rename && cmd.storage_protocol().is_some() {
            return Err(Status::unimplemented(
                "conditional metadata proposals are not activated",
            ));
        }
        crate::raft::member_address::admit_rpc(&cmd, req.forwarded, caller, |id| {
            node.is_replication_member(id)
        })
        .map_err(Status::permission_denied)?;
        // An admitted original registration is the caller's own statement of
        // how to reach it: route to it now, so members that restarted without
        // records can elect the leader that will commit them.
        if !req.forwarded {
            if let Some((node_id, address)) = crate::raft::member_address::registration(&cmd) {
                self.registry
                    .learn_peer_address(&req.zone_id, node_id, address);
            }
        }

        // Use submit_to_channel (leader-only, no forwarding) for forwarded
        // requests to prevent infinite loops. For direct requests, use
        // propose() which may forward to leader transparently.
        let result = if forwarded_rename {
            node.commit_namespace_rename(cmd).await
        } else if req.forwarded {
            // Forwarded request: must be handled locally (no re-forwarding)
            match node.submit_to_channel(&cmd) {
                Ok(rx) => {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(crate::raft::PROPOSAL_TIMEOUT_SECS),
                        rx,
                    )
                    .await
                    {
                        Ok(Ok(r)) => r,
                        Ok(Err(_)) => Err(RaftError::ProposalDropped),
                        Err(_) => Err(RaftError::Timeout(crate::raft::PROPOSAL_TIMEOUT_SECS)),
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            node.propose(cmd).await
        };

        // A success names the index this node had applied when the command
        // resolved, which covers the command's own entry: a forwarding
        // follower waits for its replica to apply through it before it tells
        // its caller the write is visible.
        let committed = match result {
            Ok(result) => Ok((result, Some(node.applied_index()))),
            // Relayed by this node for its caller: the commit is the answer;
            // this node's own replica lag is not the caller's.
            Err(RaftError::CommittedNotVisible { index, result, .. }) => Ok((*result, index)),
            Err(error) => Err(error),
        };
        match committed {
            Ok((result, applied_index)) => {
                let proto_result = command_result_to_proto(&result);
                Ok(Response::new(ProposeResponse {
                    success: true,
                    error: None,
                    leader_address: None,
                    result: Some(proto_result),
                    applied_index,
                }))
            }
            Err(RaftError::NotLeader { leader_hint }) => {
                // `leader_hint` is already the operator-form host:port
                // string of the known leader (or None); no peer_map
                // lookup needed.  See RaftError::NotLeader docstring.
                Ok(Response::new(ProposeResponse {
                    success: false,
                    error: Some(super::NOT_LEADER_ERROR.to_string()),
                    leader_address: leader_hint,
                    result: None,
                    applied_index: None,
                }))
            }
            Err(e) => Ok(Response::new(ProposeResponse {
                success: false,
                error: Some(format!("Proposal failed: {}", e)),
                leader_address: None,
                result: None,
                applied_index: None,
            })),
        }
    }

    /// Handle a client query (read operation).
    async fn query(
        &self,
        request: Request<QueryRequest>,
    ) -> std::result::Result<Response<QueryResponse>, Status> {
        super::node_authority::authorize_data_zone(
            request.extensions(),
            &self.registry,
            &request.get_ref().zone_id,
        )?;
        let req = request.into_inner();
        let node = get_zone_node(&self.registry, &req.zone_id)?;

        tracing::debug!(
            "Received query request: zone={}, read_from_leader={}",
            req.zone_id,
            req.read_from_leader
        );

        if req.read_from_leader && !node.is_leader() {
            let peers = self.registry.get_peers(&req.zone_id).unwrap_or_default();
            let leader_addr = node
                .leader_id()
                .and_then(|id| peers.get(&id))
                .map(|a| a.endpoint.clone());
            return Ok(Response::new(QueryResponse {
                success: false,
                error: Some("Not the leader".to_string()),
                leader_address: leader_addr,
                result: None,
            }));
        }

        let proto_query = match req.query {
            Some(q) => q,
            None => {
                return Ok(Response::new(QueryResponse {
                    success: false,
                    error: Some("No query provided".to_string()),
                    leader_address: None,
                    result: None,
                }));
            }
        };

        let evaluate = |sm: &FullStateMachine| match proto_query.query {
            Some(ProtoQueryVariant::GetMetadata(gm)) => match sm.get_metadata(&gm.path) {
                Ok(Some(data)) => {
                    let metadata =
                        super::proto::nexus::core::FileMetadata::decode(data.as_slice()).ok();
                    RaftQueryResponse {
                        success: true,
                        error: None,
                        result: Some(ProtoQueryResultVariant::GetMetadataResult(
                            GetMetadataResult { metadata },
                        )),
                    }
                }
                Ok(None) => RaftQueryResponse {
                    success: true,
                    error: None,
                    result: Some(ProtoQueryResultVariant::GetMetadataResult(
                        GetMetadataResult { metadata: None },
                    )),
                },
                Err(e) => RaftQueryResponse {
                    success: false,
                    error: Some(format!("Query failed: {}", e)),
                    result: None,
                },
            },
            Some(ProtoQueryVariant::ListMetadata(lm)) => match sm.list_metadata(&lm.prefix) {
                Ok(items) => {
                    let proto_items: Vec<_> = items
                        .into_iter()
                        .filter_map(|(_, data)| {
                            super::proto::nexus::core::FileMetadata::decode(data.as_slice()).ok()
                        })
                        .take(if lm.limit > 0 {
                            lm.limit as usize
                        } else {
                            usize::MAX
                        })
                        .collect();
                    RaftQueryResponse {
                        success: true,
                        error: None,
                        result: Some(ProtoQueryResultVariant::ListMetadataResult(
                            ListMetadataResult {
                                items: proto_items,
                                next_cursor: None,
                                has_more: false,
                            },
                        )),
                    }
                }
                Err(e) => RaftQueryResponse {
                    success: false,
                    error: Some(format!("List failed: {}", e)),
                    result: None,
                },
            },
            Some(ProtoQueryVariant::GetLockInfo(gli)) => match sm.get_lock(&gli.lock_id) {
                Ok(Some(lock_info)) => {
                    let first_holder = lock_info.holders.first();
                    RaftQueryResponse {
                        success: true,
                        error: None,
                        result: Some(ProtoQueryResultVariant::LockInfoResult(LockInfoResult {
                            exists: true,
                            holder_id: first_holder.map(|h| h.holder_info.clone()),
                            expires_at_ms: first_holder
                                .map(|h| (h.expires_at * 1000) as i64)
                                .unwrap_or(0),
                            max_holders: lock_info.max_holders as i32,
                            current_holders: lock_info.holders.len() as i32,
                        })),
                    }
                }
                Ok(None) => RaftQueryResponse {
                    success: true,
                    error: None,
                    result: Some(ProtoQueryResultVariant::LockInfoResult(LockInfoResult {
                        exists: false,
                        holder_id: None,
                        expires_at_ms: 0,
                        max_holders: 0,
                        current_holders: 0,
                    })),
                },
                Err(e) => RaftQueryResponse {
                    success: false,
                    error: Some(format!("Lock query failed: {}", e)),
                    result: None,
                },
            },
            None => RaftQueryResponse {
                success: false,
                error: Some("Unknown query type".to_string()),
                result: None,
            },
        };

        let query_result = if req.read_from_leader {
            tokio::time::timeout(
                crate::raft::REPLICA_READ_BUDGET,
                node.read_linearizable(evaluate),
            )
            .await
            .map_err(|_| Status::unavailable("zone query read barrier timed out"))?
            .map_err(|error| Status::unavailable(error.to_string()))?
        } else {
            node.with_state_machine(evaluate).await
        };

        let error = query_result.error.clone();
        Ok(Response::new(QueryResponse {
            success: query_result.success,
            error,
            leader_address: None,
            result: Some(query_result),
        }))
    }

    /// Get cluster information for a zone.
    async fn get_cluster_info(
        &self,
        request: Request<GetClusterInfoRequest>,
    ) -> std::result::Result<Response<GetClusterInfoResponse>, Status> {
        super::node_authority::authorize_data_zone(
            request.extensions(),
            &self.registry,
            &request.get_ref().zone_id,
        )?;
        let req = request.into_inner();
        let node = get_zone_node(&self.registry, &req.zone_id)?;
        let node_id = node.id();

        let is_leader = node.is_leader();
        let leader_id = node.leader_id().unwrap_or(0);
        let term = node.term();

        // Voters and learners come from one ProgressTracker view; their
        // addresses come from the zone's member-address records, so every
        // member — this node included — reports the address the zone
        // replicates for it, and a member without a record reports an
        // empty one. This is membership, not proof of reachability,
        // feature support or a ReadIndex barrier.
        let membership = node
            .membership()
            .await
            .map_err(|e| Status::unavailable(format!("read zone membership: {e}")))?;
        let addresses = recorded_endpoints(&node, self.registry.tls_enabled()).await?;
        let leader_addr = addresses.get(&leader_id).cloned();
        let config = cluster_config(&addresses, &membership.voters, &membership.learners);

        Ok(Response::new(GetClusterInfoResponse {
            node_id,
            leader_id,
            term,
            config: Some(config),
            is_leader,
            leader_address: leader_addr,
        }))
    }

    async fn join_zone(
        &self,
        request: Request<JoinZoneRequest>,
    ) -> std::result::Result<Response<JoinZoneResponse>, Status> {
        if let Some(replica_id) = super::node_authority::current_replica_id(request.extensions())? {
            return self.read_replica_join(request, replica_id).await;
        }
        let req = request.into_inner();
        let node = get_zone_node(&self.registry, &req.zone_id)?;

        // Only leader can process JoinZone — redirect followers
        if !node.is_leader() {
            let peers = self.registry.get_peers(&req.zone_id).unwrap_or_default();
            let leader_id = node.leader_id().unwrap_or(0);
            let leader_addr = peers.get(&leader_id).map(|a| a.endpoint.clone());
            return Ok(Response::new(JoinZoneResponse {
                success: false,
                error: Some("not leader".to_string()),
                leader_address: leader_addr,
                config: None,
                catching_up: false,
                commit_index: 0,
                applied_index: 0,
            }));
        }

        tracing::info!(
            zone = req.zone_id,
            peer_node_id = req.node_id,
            peer_addr = %req.node_address,
            "JoinZone request received",
        );

        // ── Learner-then-promote membership change (raft-canonical) ──
        //
        // A JoinZone-as-voter NEVER adds a voter directly.  A direct
        // `AddNode` grows the voter set — and hence the quorum — the
        // instant it commits, so if the joiner is unreachable (mis-bound
        // to loopback, dead, firewalled) the leader is stranded needing
        // an ack it can never get: the "not leader" deadlock + zombie
        // voter this path used to produce.  Instead we follow the raft
        // membership-change discipline:
        //   1. add the joiner as a LEARNER — quorum unchanged, so the
        //      leader stays available no matter what;
        //   2. wait, event-driven, until the leader has replicated up to
        //      it (`await_peer_caught_up`) — this PROVES the joiner is
        //      reachable AND caught up;
        //   3. only then promote it to voter.
        // If step 2 times out, the joiner stays a healthy learner (a
        // learner never affects quorum) and we fail loud with an
        // actionable error naming its advertise address — the joiner (or
        // operator) re-joins to promote once it is reachable.  An
        // explicitly-requested learner (`as_learner`) skips 2–3.
        //
        // (Historical note: JoinZone used to bump `i_links_count` here
        // under the old dynamic-bootstrap contract.  Under the opaque-ID
        // contract it is raft-membership only; the mount-reference count
        // lives at the DT_MOUNT entry, not here.)
        use raft::eraftpb::ConfChangeType;

        // How far the leader has replicated to one learner. Takes the pairs as
        // a slice — no `Membership` type in scope here.
        fn matched_for(learner_matched: &[(u64, u64)], node_id: u64) -> u64 {
            learner_matched
                .iter()
                .find(|(id, _)| *id == node_id)
                .map_or(0, |(_, matched)| *matched)
        }
        // Response configs carry the recorded member addresses, read after
        // any membership change this handler commits (the change writes the
        // joiner's record at its own index).
        let use_tls = self.registry.tls_enabled();
        let make_config = |voters: Vec<u64>, learners: Vec<u64>| {
            let node = node.clone();
            async move {
                recorded_endpoints(&node, use_tls)
                    .await
                    .map(|addresses| cluster_config(&addresses, &voters, &learners))
            }
        };
        // Turn a raft error into the redirect/failure response shape.
        let fail = |e: RaftError| match e {
            RaftError::NotLeader { leader_hint } => JoinZoneResponse {
                success: false,
                error: Some("not leader".to_string()),
                leader_address: leader_hint,
                config: None,
                catching_up: false,
                commit_index: 0,
                applied_index: 0,
            },
            other => JoinZoneResponse {
                success: false,
                error: Some(format!("JoinZone failed: {}", other)),
                leader_address: None,
                config: None,
                catching_up: false,
                commit_index: 0,
                applied_index: 0,
            },
        };

        let ctx = req.node_address.clone().into_bytes();

        // Classify the join off current membership (get-before-put, #139):
        // a blind AddLearnerNode on a sitting voter would DEMOTE it.
        let membership = match node.membership().await {
            Ok(m) => m,
            Err(e) => return Ok(Response::new(fail(e))),
        };

        // Idempotent: already a voter → nothing to change.
        if membership.is_voter(req.node_id) {
            return Ok(Response::new(JoinZoneResponse {
                success: true,
                error: None,
                leader_address: None,
                config: Some(
                    make_config(membership.voters.clone(), membership.learners.clone()).await?,
                ),
                catching_up: false,
                commit_index: 0,
                applied_index: 0,
            }));
        }

        // An explicitly-requested learner (`as_learner`): ensure it is a
        // learner and stop — the caller wants a read-along replica, never a
        // voter. Idempotent.
        if req.as_learner {
            if !membership.is_learner(req.node_id) {
                if let Err(e) = node
                    .propose_conf_change(ConfChangeType::AddLearnerNode, req.node_id, ctx)
                    .await
                {
                    return Ok(Response::new(fail(e)));
                }
                tracing::info!(
                    zone = req.zone_id,
                    peer_node_id = req.node_id,
                    "JoinZone: added as learner (explicit)",
                );
            }
            let m = node.membership().await.unwrap_or_default();
            return Ok(Response::new(JoinZoneResponse {
                success: true,
                error: None,
                leader_address: None,
                config: Some(make_config(m.voters.clone(), m.learners.clone()).await?),
                catching_up: false,
                commit_index: 0,
                applied_index: 0,
            }));
        }

        // Voter requested (and not yet a voter). Stateless, retry-driven
        // learner-then-promote — NO waiting inside this RPC:
        //   * not yet a learner → add it as a learner (quorum unchanged, so
        //     the leader stays available regardless of the joiner) and tell
        //     the joiner to re-join once we have replicated to it;
        //   * a learner that has CAUGHT UP (reachable AND replicated to our
        //     commit index) → promote it to voter;
        //   * a learner still behind → tell it to re-join.
        // The joiner's join loop re-calls us each round (it is the durable
        // owner of the "become a voter" intent — its `--as voter`), so an
        // unreachable joiner is simply never caught up, hence never promoted:
        // it stays a harmless learner and never strands quorum. No timeout,
        // no held RPC, no leader-side promotion state.
        if !membership.is_learner(req.node_id) {
            if let Err(e) = node
                .propose_conf_change(ConfChangeType::AddLearnerNode, req.node_id, ctx)
                .await
            {
                return Ok(Response::new(fail(e)));
            }
            tracing::info!(
                zone = req.zone_id,
                peer_node_id = req.node_id,
                peer_addr = %req.node_address,
                "JoinZone: added as learner; re-join to promote once replicated",
            );
            let m = node.membership().await.unwrap_or_default();
            return Ok(Response::new(JoinZoneResponse {
                success: false,
                error: Some(format!(
                    "added as learner in zone '{}' — catching up; re-join to promote to voter \
                     once the leader has replicated to advertise-addr {}",
                    req.zone_id, req.node_address
                )),
                leader_address: None,
                config: Some(make_config(m.voters.clone(), m.learners.clone()).await?),
                // Progress, not misconfiguration — see JoinZoneResponse.catching_up.
                catching_up: true,
                commit_index: m.commit_index,
                applied_index: matched_for(&m.learner_matched, req.node_id),
            }));
        }

        // Already a learner: promote to voter iff it has caught up (reachable
        // + replicated to our commit index). Otherwise ask it to re-join.
        if membership.is_caught_up_learner(req.node_id) {
            match node
                .propose_conf_change(ConfChangeType::AddNode, req.node_id, ctx)
                .await
            {
                Ok(conf_state) => {
                    tracing::info!(
                        zone = req.zone_id,
                        peer_node_id = req.node_id,
                        "JoinZone: caught-up learner promoted to voter",
                    );
                    let learners = node
                        .membership()
                        .await
                        .map(|m| m.learners)
                        .unwrap_or_default();
                    Ok(Response::new(JoinZoneResponse {
                        success: true,
                        error: None,
                        leader_address: None,
                        config: Some(make_config(conf_state.voters.clone(), learners).await?),
                        catching_up: false,
                        commit_index: 0,
                        applied_index: 0,
                    }))
                }
                Err(e) => Ok(Response::new(fail(e))),
            }
        } else {
            tracing::debug!(
                zone = req.zone_id,
                peer_node_id = req.node_id,
                peer_addr = %req.node_address,
                "JoinZone: learner not yet caught up; re-join to promote",
            );
            Ok(Response::new(JoinZoneResponse {
                success: false,
                error: Some(format!(
                    "learner in zone '{}' not yet caught up to the leader; re-join to promote \
                     (still replicating to advertise-addr {})",
                    req.zone_id, req.node_address
                )),
                leader_address: None,
                config: Some(
                    make_config(membership.voters.clone(), membership.learners.clone()).await?,
                ),
                catching_up: true,
                commit_index: membership.commit_index,
                applied_index: matched_for(&membership.learner_matched, req.node_id),
            }))
        }
    }

    /// Report the responder's local federation mount table.
    ///
    /// S3 Phase D fresh-joiner auto-discovery, Phase F SSOT
    /// tightening: read root zone's DT_MOUNT entries directly from
    /// the state machine at RPC time.  Pure sequential-consistency
    /// single-node read via
    /// [`crate::raft::ZoneConsensus::with_state_machine`] — root is
    /// per-node SOLO, so the local state machine is the authoritative
    /// SSOT; no leader round-trip needed.  Every call re-reads, so
    /// runtime `share` operations that add new DT_MOUNT entries are
    /// picked up automatically without any cache-invalidation
    /// plumbing.  Pure joiners (no root zone loaded) return an empty
    /// list.
    async fn discover_zones(
        &self,
        _request: Request<DiscoverZonesRequest>,
    ) -> std::result::Result<Response<DiscoverZonesResponse>, Status> {
        // The same read the boot summary logs — see
        // `ZoneRaftRegistry::published_federation_mounts` for why they share one
        // implementation.
        let zones: Vec<FederationZoneInfo> = self
            .registry
            .published_federation_mounts()
            .await
            .into_iter()
            .map(|(path, decl)| FederationZoneInfo {
                zone_id: decl.zone,
                mount_path: path,
                // So the joiner mounts what this founder DECLARED rather than
                // defaulting to the whole zone and diverging on every key.
                target_subtree: decl.subtree,
            })
            .collect();
        tracing::debug!(zone_count = zones.len(), "DiscoverZones request served");
        Ok(Response::new(DiscoverZonesResponse { zones }))
    }

    /// Prune a stale voter/learner from a zone's ConfState.
    ///
    /// Operator escape hatch for S3 Phase C voter wipe-rejoin.  After a
    /// voter's `data_dir` is wiped and the node reboots with a fresh
    /// `node_id` (rotate-on-wipe rule per PR #3996), the leader's
    /// `Progress[old_id]` remains a ghost — the next heartbeat carries
    /// `commit = min(Progress[old_id].matched, leader_committed)`, and
    /// any downstream heartbeat destined for a truly-fresh follower
    /// with `last_index = 0` would trip `RaftLog::commit_to`.  Prune
    /// the ghost with this RPC so operators can complete the wipe-
    /// rejoin flow without touching raft internals.
    async fn remove_voter(
        &self,
        request: Request<RemoveVoterRequest>,
    ) -> std::result::Result<Response<RemoveVoterResponse>, Status> {
        let req = request.into_inner();
        let node = get_zone_node(&self.registry, &req.zone_id)?;

        if !node.is_leader() {
            let peers = self.registry.get_peers(&req.zone_id).unwrap_or_default();
            let leader_id = node.leader_id().unwrap_or(0);
            let leader_addr = peers.get(&leader_id).map(|a| a.endpoint.clone());
            return Ok(Response::new(RemoveVoterResponse {
                success: false,
                error: Some("not leader".to_string()),
                leader_address: leader_addr,
            }));
        }

        tracing::info!(
            zone = req.zone_id,
            target_node_id = req.target_node_id,
            "RemoveVoter request received",
        );

        use raft::eraftpb::ConfChangeType;
        match node
            .propose_conf_change(ConfChangeType::RemoveNode, req.target_node_id, Vec::new())
            .await
        {
            Ok(_conf_state) => Ok(Response::new(RemoveVoterResponse {
                success: true,
                error: None,
                leader_address: None,
            })),
            Err(RaftError::NotLeader { leader_hint }) => Ok(Response::new(RemoveVoterResponse {
                success: false,
                error: Some("not leader".to_string()),
                leader_address: leader_hint,
            })),
            Err(e) => Ok(Response::new(RemoveVoterResponse {
                success: false,
                error: Some(format!("RemoveVoter failed: {}", e)),
                leader_address: None,
            })),
        }
    }

    /// Remove this node's local replica for a zone.
    ///
    /// This is intentionally local-only. The caller is responsible for
    /// coordinating peer fan-out; handling the RPC this way prevents recursive
    /// delete storms while still making remove→recreate safe for dynamic zones.
    async fn delete_zone(
        &self,
        request: Request<DeleteZoneRequest>,
    ) -> std::result::Result<Response<DeleteZoneResponse>, Status> {
        let req = request.into_inner();
        let zone_id = req.zone_id.trim();
        if zone_id.is_empty() {
            return Ok(Response::new(DeleteZoneResponse {
                success: false,
                error: Some("zone_id must not be empty".to_string()),
            }));
        }
        if contracts::RESERVED_ZONE_IDS.contains(&zone_id) {
            return Ok(Response::new(DeleteZoneResponse {
                success: false,
                error: Some(format!(
                    "reserved zone '{zone_id}' cannot be deleted by DeleteZone"
                )),
            }));
        }

        if self.registry.get_node(zone_id).is_none() {
            return Ok(Response::new(DeleteZoneResponse {
                success: true,
                error: None,
            }));
        }

        match self.registry.remove_zone(zone_id).await {
            Ok(()) => Ok(Response::new(DeleteZoneResponse {
                success: true,
                error: None,
            })),
            Err(e) => Ok(Response::new(DeleteZoneResponse {
                success: false,
                error: Some(e.to_string()),
            })),
        }
    }

    /// Return the current host's search capabilities for an existing zone.
    async fn get_search_capabilities(
        &self,
        request: Request<GetSearchCapabilitiesRequest>,
    ) -> std::result::Result<Response<SearchCapabilities>, Status> {
        super::node_authority::authorize_data_zone(
            request.extensions(),
            &self.registry,
            &request.get_ref().zone_id,
        )?;
        let zone_id = request.into_inner().zone_id;
        if !self.registry.hosts(&zone_id) {
            return Err(Status::not_found(format!("Zone '{}' not found", zone_id)));
        }
        let provider = self
            .search_capabilities_slot
            .as_ref()
            .and_then(|slot| slot.read().clone())
            .ok_or_else(|| Status::unavailable("search capability provider is not ready"))?;
        provider.capabilities(&zone_id).await.map(Response::new)
    }

    /// Serve a peer's content fetch — store-and-forward.
    ///
    /// One addressing mode: ``content_id`` is opaque to the kernel; the
    /// installed ``BlobFetcher`` impl drives the local read path which
    /// routes through ``VFSRouter`` exactly like a local ``sys_read``,
    /// letting each backend interpret ``content_id`` however it likes
    /// (CAS=hash, PAS=backend_path). No CAS-vs-PAS branch lives here.
    ///
    /// Delegates to the kernel-installed ``BlobFetcher``. The slot is
    /// late-bound: ``ZoneManager::new`` spawns the server before the
    /// kernel's root-mount backend is wired, so early calls arrive
    /// before the slot is populated. We treat every "no fetcher / not
    /// found" path as a ``NotFound`` result carried in ``error``.
    async fn read_blob(
        &self,
        request: Request<ReadBlobRequest>,
    ) -> std::result::Result<Response<ReadBlobResponse>, Status> {
        let req = request.into_inner();
        Ok(self.blob_response(None, &req.content_id).await)
    }

    async fn read_zone_blob(
        &self,
        request: Request<ReadZoneBlobRequest>,
    ) -> std::result::Result<Response<ReadBlobResponse>, Status> {
        super::node_authority::authorize_data_zone(
            request.extensions(),
            &self.registry,
            &request.get_ref().zone_id,
        )?;
        let req = request.into_inner();
        contracts::validate_zone_id_for(contracts::ZoneIdUse::TenantCreate, &req.zone_id)
            .map_err(|_| Status::invalid_argument("invalid data zone"))?;
        get_zone_node(&self.registry, &req.zone_id)?;
        Ok(self
            .blob_response(Some(&req.zone_id), &req.content_id)
            .await)
    }

    /// Sign an agent identity cert on the CA holder (founder) for a remote
    /// caller — the server half of a joiner's `auth mint --subject-type agent`
    /// routing to the founder. The verified mTLS client leaf cert is forwarded
    /// to the injected `CaIssuer`, which gates it to a NODE peer (an agent
    /// may not mint agents) before signing; raft applies no auth logic. A node
    /// with no minter installed (a joiner — not the CA holder) returns
    /// success=false so the caller can try the founder.
    async fn mint_agent(
        &self,
        request: Request<MintAgentRequest>,
    ) -> std::result::Result<Response<MintAgentResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let err_resp = |msg: String| {
            Response::new(MintAgentResponse {
                success: false,
                error: Some(msg),
                agent_cert_pem: Vec::new(),
                agent_key_pem: Vec::new(),
                ca_pem: Vec::new(),
            })
        };
        let minter = self
            .ca_issuer_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned());
        let Some(minter) = minter else {
            return Ok(err_resp(format!(
                "{NOT_CA_HOLDER}; mint agents against the founder"
            )));
        };
        match minter
            .mint(
                caller_cert_der,
                &req.subject_id,
                &req.display_name,
                req.allow_existing,
            )
            .await
        {
            Ok(bundle) => Ok(Response::new(MintAgentResponse {
                success: true,
                error: None,
                agent_cert_pem: bundle.cert_pem,
                agent_key_pem: bundle.key_pem,
                ca_pem: bundle.ca_pem,
            })),
            Err(e) => Ok(err_resp(e)),
        }
    }

    /// Sign a session credential for an allow-listed agent caller — the server
    /// half of a front door obtaining a per-session identity for a person.
    ///
    /// Same shape as `mint_agent`: the verified mTLS leaf is forwarded to the
    /// injected minter, which owns the gate, the CA and the allow-list. Raft
    /// applies no auth logic. A node with no minter is not the CA holder and
    /// says so.
    async fn mint_session_agent(
        &self,
        request: Request<MintSessionAgentRequest>,
    ) -> std::result::Result<Response<MintSessionAgentResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let minter = self
            .ca_issuer_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned());
        let Some(minter) = minter else {
            return Ok(session_credential_response(Err(format!(
                "{NOT_CA_HOLDER}; mint against the founder"
            ))));
        };
        Ok(session_credential_response(
            minter
                .mint_session(caller_cert_der, &req.owner_id, req.validity_secs)
                .await,
        ))
    }

    /// Issue one owner-bound TLS server identity through the same signing policy.
    async fn mint_user_runtime(
        &self,
        request: Request<MintSessionAgentRequest>,
    ) -> std::result::Result<Response<MintSessionAgentResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let minter = self
            .ca_issuer_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned());
        let result = match minter {
            Some(minter) => {
                minter
                    .mint_user_runtime(caller_cert_der, &req.owner_id, req.validity_secs)
                    .await
            }
            None => Err(format!("{NOT_CA_HOLDER}; mint against the founder")),
        };
        Ok(session_credential_response(result))
    }

    /// Renew a controller only after the CA holder verifies its current key.
    async fn renew_session_agent(
        &self,
        request: Request<RenewSessionAgentRequest>,
    ) -> std::result::Result<Response<MintSessionAgentResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let minter = self
            .ca_issuer_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned());
        let result = match minter {
            Some(minter) => {
                minter
                    .renew_session(
                        caller_cert_der,
                        crate::ca_issuer::SessionRenewal {
                            cert_pem: &req.agent_cert_pem,
                            validity_secs: req.validity_secs,
                            issued_at_unix_ms: req.issued_at_unix_ms,
                            proof: &req.proof,
                        },
                    )
                    .await
            }
            None => Err(format!("{NOT_CA_HOLDER}; renew against the founder")),
        };
        Ok(session_credential_response(result))
    }

    /// Record a certificate's serial in the CA-plane CRL.
    async fn revoke_agent_cert(
        &self,
        request: Request<RevokeAgentCertRequest>,
    ) -> std::result::Result<Response<RevokeAgentCertResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let err_resp = |msg: String| {
            Response::new(RevokeAgentCertResponse {
                success: false,
                error: Some(msg),
            })
        };
        let minter = self
            .ca_issuer_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned());
        let Some(minter) = minter else {
            return Ok(err_resp(format!(
                "{NOT_CA_HOLDER}; revoke against the founder"
            )));
        };
        match minter
            .revoke_cert(caller_cert_der, &req.agent_cert_pem)
            .await
        {
            Ok(()) => Ok(Response::new(RevokeAgentCertResponse {
                success: true,
                error: None,
            })),
            Err(e) => Ok(err_resp(e)),
        }
    }

    /// Re-issue the calling Node's certificate; the CA holder alone signs.
    async fn renew_node_certificate(
        &self,
        request: Request<RenewNodeCertificateRequest>,
    ) -> std::result::Result<Response<RenewNodeCertificateResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let minter = self
            .ca_issuer_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned());
        let result = match minter {
            Some(minter) => minter.renew_node(caller_cert_der, &req.csr_pem).await,
            None => Err(format!("{NOT_CA_HOLDER}; renew against the founder")),
        };
        Ok(Response::new(match result {
            Ok(node_cert_pem) => RenewNodeCertificateResponse {
                success: true,
                error: None,
                node_cert_pem,
            },
            Err(error) => RenewNodeCertificateResponse {
                success: false,
                error: Some(error),
                node_cert_pem: Vec::new(),
            },
        }))
    }

    /// Renew this daemon's own certificate now, for this same Node's operator.
    async fn renew_local_node_certificate(
        &self,
        request: Request<RenewLocalNodeCertificateRequest>,
    ) -> std::result::Result<Response<RenewLocalNodeCertificateResponse>, Status> {
        let caller = super::node_authority::authenticated_node_id(request.extensions())?;
        let result = if caller != Some(self.registry.node_id()) {
            Err("only this Node may ask its daemon to renew its certificate".to_string())
        } else {
            let renewer = self
                .local_node_renewer_slot
                .as_ref()
                .and_then(|slot| slot.read().as_ref().cloned());
            match renewer {
                Some(renewer) => renewer.renew_now().await,
                None => Err("this daemon serves no renewable Node certificate".to_string()),
            }
        };
        Ok(Response::new(match result {
            Ok(not_after_unix_s) => RenewLocalNodeCertificateResponse {
                success: true,
                error: None,
                not_after_unix_s,
            },
            Err(error) => RenewLocalNodeCertificateResponse {
                success: false,
                error: Some(error),
                not_after_unix_s: 0,
            },
        }))
    }

    async fn allow_session_minter(
        &self,
        request: Request<AllowSessionMinterRequest>,
    ) -> std::result::Result<Response<AllowSessionMinterResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let err_resp = |msg: String| {
            Response::new(AllowSessionMinterResponse {
                success: false,
                error: Some(msg),
            })
        };
        let Some(admin) = self
            .session_mint_admin_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned())
        else {
            return Ok(err_resp(
                "this node has no session-mint plane (auth-off)".to_string(),
            ));
        };
        match admin.allow(caller_cert_der, &req.agent_id).await {
            Ok(()) => Ok(Response::new(AllowSessionMinterResponse {
                success: true,
                error: None,
            })),
            Err(e) => Ok(err_resp(e)),
        }
    }

    async fn deny_session_minter(
        &self,
        request: Request<DenySessionMinterRequest>,
    ) -> std::result::Result<Response<DenySessionMinterResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let err_resp = |msg: String| {
            Response::new(DenySessionMinterResponse {
                success: false,
                error: Some(msg),
                was_present: false,
            })
        };
        let Some(admin) = self
            .session_mint_admin_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned())
        else {
            return Ok(err_resp(
                "this node has no session-mint plane (auth-off)".to_string(),
            ));
        };
        match admin.deny(caller_cert_der, &req.agent_id).await {
            Ok(was_present) => Ok(Response::new(DenySessionMinterResponse {
                success: true,
                error: None,
                was_present,
            })),
            Err(e) => Ok(err_resp(e)),
        }
    }

    async fn list_session_minters(
        &self,
        request: Request<ListSessionMintersRequest>,
    ) -> std::result::Result<Response<ListSessionMintersResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let err_resp = |msg: String| {
            Response::new(ListSessionMintersResponse {
                success: false,
                error: Some(msg),
                agent_ids: Vec::new(),
            })
        };
        let Some(admin) = self
            .session_mint_admin_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned())
        else {
            return Ok(err_resp(
                "this node has no session-mint plane (auth-off)".to_string(),
            ));
        };
        match admin.list(caller_cert_der).await {
            Ok(agent_ids) => Ok(Response::new(ListSessionMintersResponse {
                success: true,
                error: None,
                agent_ids,
            })),
            Err(e) => Ok(err_resp(e)),
        }
    }

    async fn mint_key(
        &self,
        request: Request<MintKeyRequest>,
    ) -> std::result::Result<Response<MintKeyResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let err_resp = |msg: String| {
            Response::new(MintKeyResponse {
                success: false,
                error: Some(msg),
                key: String::new(),
            })
        };
        let minter = self
            .key_minter_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned());
        let Some(minter) = minter else {
            return Ok(err_resp(
                "this node has no sk- key plane (auth-off); mint against an auth-on cluster"
                    .to_string(),
            ));
        };
        let params = MintKeyParams {
            subject_type: req.subject_type,
            subject_id: req.subject_id,
            zones: req.zones,
            admin: req.admin,
            expires_at_ms: req.expires_at_ms,
            name: req.name,
            allow_existing: req.allow_existing,
        };
        match minter.mint_key(caller_cert_der, params).await {
            Ok(key) => Ok(Response::new(MintKeyResponse {
                success: true,
                error: None,
                key,
            })),
            Err(e) => Ok(err_resp(e)),
        }
    }

    async fn revoke_key(
        &self,
        request: Request<RevokeKeyRequest>,
    ) -> std::result::Result<Response<RevokeKeyResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let err_resp = |msg: String| {
            Response::new(RevokeKeyResponse {
                success: false,
                error: Some(msg),
                removed: false,
            })
        };
        let minter = self
            .key_minter_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned());
        let Some(minter) = minter else {
            return Ok(err_resp(
                "this node has no sk- key plane (auth-off)".to_string(),
            ));
        };
        match minter
            .revoke_key(caller_cert_der, req.key, req.key_hash)
            .await
        {
            Ok(removed) => Ok(Response::new(RevokeKeyResponse {
                success: true,
                error: None,
                removed,
            })),
            Err(e) => Ok(err_resp(e)),
        }
    }

    async fn list_keys(
        &self,
        request: Request<ListKeysRequest>,
    ) -> std::result::Result<Response<ListKeysResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let err_resp = |msg: String| {
            Response::new(ListKeysResponse {
                success: false,
                error: Some(msg),
                keys: Vec::new(),
            })
        };
        let minter = self
            .key_minter_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned());
        let Some(minter) = minter else {
            return Ok(err_resp(
                "this node has no sk- key plane (auth-off)".to_string(),
            ));
        };
        match minter.list_keys(caller_cert_der).await {
            Ok(records) => Ok(Response::new(ListKeysResponse {
                success: true,
                error: None,
                keys: records
                    .into_iter()
                    .map(|(key_hash, record)| ListedKey { key_hash, record })
                    .collect(),
            })),
            Err(e) => Ok(err_resp(e)),
        }
    }

    async fn register_foreign_ca(
        &self,
        request: Request<RegisterForeignCaRequest>,
    ) -> std::result::Result<Response<RegisterForeignCaResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let err_resp = |msg: String| {
            Response::new(RegisterForeignCaResponse {
                success: false,
                error: Some(msg),
                fingerprint: String::new(),
            })
        };
        let Some(registrar) = self
            .foreign_ca_registrar_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned())
        else {
            return Ok(err_resp(
                "this node has no cross-org trust plane (auth-off)".to_string(),
            ));
        };
        match registrar
            .register(
                caller_cert_der,
                &req.trust_domain_id,
                &req.ca_cert_pem,
                &req.expected_fingerprint,
            )
            .await
        {
            Ok(fingerprint) => Ok(Response::new(RegisterForeignCaResponse {
                success: true,
                error: None,
                fingerprint,
            })),
            Err(e) => Ok(err_resp(e)),
        }
    }

    async fn unregister_foreign_ca(
        &self,
        request: Request<UnregisterForeignCaRequest>,
    ) -> std::result::Result<Response<UnregisterForeignCaResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let req = request.into_inner();
        let err_resp = |msg: String| {
            Response::new(UnregisterForeignCaResponse {
                success: false,
                error: Some(msg),
                removed: false,
            })
        };
        let Some(registrar) = self
            .foreign_ca_registrar_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned())
        else {
            return Ok(err_resp(
                "this node has no cross-org trust plane (auth-off)".to_string(),
            ));
        };
        match registrar
            .unregister(caller_cert_der, &req.fingerprint)
            .await
        {
            Ok(removed) => Ok(Response::new(UnregisterForeignCaResponse {
                success: true,
                error: None,
                removed,
            })),
            Err(e) => Ok(err_resp(e)),
        }
    }

    async fn list_foreign_cas(
        &self,
        request: Request<ListForeignCasRequest>,
    ) -> std::result::Result<Response<ListForeignCasResponse>, Status> {
        let caller_cert_der = peer_cert_der(&request);
        let err_resp = |msg: String| {
            Response::new(ListForeignCasResponse {
                success: false,
                error: Some(msg),
                anchors: Vec::new(),
            })
        };
        let Some(registrar) = self
            .foreign_ca_registrar_slot
            .as_ref()
            .and_then(|slot| slot.read().as_ref().cloned())
        else {
            return Ok(err_resp(
                "this node has no cross-org trust plane (auth-off)".to_string(),
            ));
        };
        match registrar.list(caller_cert_der).await {
            Ok(anchors) => Ok(Response::new(ListForeignCasResponse {
                success: true,
                error: None,
                anchors: anchors
                    .into_iter()
                    .map(|(trust_domain_id, fingerprint)| ForeignCaEntry {
                        trust_domain_id,
                        fingerprint,
                    })
                    .collect(),
            })),
            Err(e) => Ok(err_resp(e)),
        }
    }
}

// =============================================================================
// NodeEnrollmentService (pre-mTLS BOOTSTRAP plane: cert provisioning)
// =============================================================================

/// Token-gated cert provisioning for a brand-new node — the ONLY surface a
/// certless joiner reaches. Served on its own PLAINTEXT listener
/// ([`serve_node_enrollment`]), NOT on the strict-mTLS `ZoneApiService`: a
/// joiner has no client cert yet, so enrollment cannot live behind mTLS. The
/// join token authenticates the caller; the token also carries the CA
/// fingerprint (the caller pins it — `join_cluster_and_provision_tls`); the
/// channel is carried by the encrypted overlay.
struct NodeEnrollmentServiceImpl {
    /// Cluster CA cert (PEM) — returned to the joiner (pinned by the token's CA
    /// fingerprint) and used with `ca_key_pem` to sign its node cert.
    ca_pem: Option<Vec<u8>>,
    /// CA private key — held in memory to sign joiner certs; never leaves here.
    ca_key_pem: Option<Vec<u8>>,
    /// Path to the accepted join-token hash SET (`tls/join-token-hash`, one
    /// SHA-256 hex per line). Read LIVE per `JoinCluster` (like
    /// the current revoked membership is for `GetCrl`), so an offline
    /// `enroll-token` that appended a hash is accepted WITHOUT a founder
    /// restart. `None` ⇒ this node accepts no join requests.
    join_token_hash_path: Option<PathBuf>,
    /// Cluster API-key HMAC secret, served verbatim to the joiner over this
    /// same token-gated channel as the CA. Opaque here — the transport applies
    /// no auth logic to it (it already holds the far-more-sensitive CA private
    /// key), so this adds no raft↔auth coupling. `None` ⇒ founder is auth-off;
    /// the response omits it and the joiner stays auth-off. Read once at
    /// construction from `tls/api-key-secret` (the single SSOT).
    api_key_secret: Option<String>,
    /// Current revoked membership and durable CA-scoped CRL issuance receipts.
    crl_issuer: Option<Arc<super::crl::CrlIssuer>>,
}

#[tonic::async_trait]
impl NodeEnrollmentService for NodeEnrollmentServiceImpl {
    /// Provision a joining node: verify the join token, certify the key in its
    /// CSR with the cluster CA, return CA + cert. Neither private key — the CA's
    /// nor the joiner's — crosses this channel.
    async fn join_cluster(
        &self,
        request: Request<JoinClusterRequest>,
    ) -> std::result::Result<Response<JoinClusterResponse>, Status> {
        let req = request.into_inner();
        let err_resp = |msg: &str| {
            Response::new(JoinClusterResponse {
                success: false,
                error: Some(msg.to_string()),
                ca_pem: Vec::new(),
                node_cert_pem: Vec::new(),
                api_key_secret: None,
            })
        };

        tracing::info!(
            peer_node_id = req.node_id,
            peer_addr = %req.node_address,
            zone_id = req.zone_id,
            "JoinCluster request received",
        );

        // --- Token-based authentication (K3s-style) ---
        // Read the accepted-hash SET LIVE from disk (mirrors `get_crl` reading
        // `revoked_serials_path`), so an offline `enroll-token` that appended a
        // hash is accepted WITHOUT a founder restart. The file is the SSOT —
        // one SHA-256 hex per line; the boot token is line 1 (day-1 TLS
        // bootstrap). A live-read miss ⇒ no accepted tokens ⇒ reject.
        let accepted = match &self.join_token_hash_path {
            Some(p) => super::certgen::read_join_token_hashes(p),
            None => {
                return Ok(err_resp(
                    "This node does not accept join requests (no join token configured)",
                ));
            }
        };
        if accepted.is_empty() {
            return Ok(err_resp(
                "This node does not accept join requests (no join token configured)",
            ));
        }
        let candidate_hash = {
            use sha2::{Digest, Sha256};
            use std::fmt::Write;
            let digest = Sha256::digest(req.password.as_bytes());
            let mut hex = String::with_capacity(64);
            for byte in &digest[..] {
                let _ = write!(hex, "{:02x}", byte);
            }
            hex
        };
        if !accepted.iter().any(|h| h == &candidate_hash) {
            tracing::warn!(peer_node_id = req.node_id, "JoinCluster: invalid password");
            return Ok(err_resp("Invalid join token password"));
        }

        // --- Get CA material (static — set at startup) ---
        let (ca_pem, ca_key_pem) = match (&self.ca_key_pem, &self.ca_pem) {
            (Some(ca_key), Some(ca_pem)) => (ca_pem.clone(), ca_key.clone()),
            _ => {
                return Ok(err_resp("CA material not configured on this node"));
            }
        };

        // --- Certify the joiner's own key ---
        // The token authorizes the requested Node ID; the CSR contributes only
        // the proven public key. The joiner's private key never leaves it.
        let zone_id = if req.zone_id.is_empty() {
            contracts::ROOT_ZONE_ID
        } else {
            &req.zone_id
        };
        let extra_hostnames = super::certgen::extract_hostnames(&req.node_address);
        let peer_hostname = extra_hostnames.first().map(|s| s.as_str());
        let node_cert_pem = match super::certgen::sign_node_csr(
            &req.csr_pem,
            req.node_id,
            zone_id,
            &ca_pem,
            &ca_key_pem,
            &extra_hostnames,
            peer_hostname,
        ) {
            Ok(cert) => cert,
            Err(e) => {
                tracing::warn!(peer_node_id = req.node_id, error = %e, "JoinCluster: CSR refused");
                return Ok(err_resp(&format!("JoinCluster CSR refused: {e}")));
            }
        };

        tracing::info!(
            peer_node_id = req.node_id,
            peer_addr = %req.node_address,
            "JoinCluster: node certificate signed and provisioned successfully",
        );

        Ok(Response::new(JoinClusterResponse {
            success: true,
            error: None,
            ca_pem,
            node_cert_pem,
            api_key_secret: self.api_key_secret.clone(),
        }))
    }

    /// Serve the cluster's current signed CRL after its issuance receipt commits.
    /// The public CA signature lets nodes verify the refreshed revocation view.
    async fn get_crl(
        &self,
        _request: Request<GetCrlRequest>,
    ) -> std::result::Result<Response<GetCrlResponse>, Status> {
        let issuer = self
            .crl_issuer
            .clone()
            .ok_or_else(|| Status::failed_precondition("durable CRL authority not configured"))?;
        let crl_pem = tokio::task::spawn_blocking(move || issuer.issue())
            .await
            .map_err(|e| Status::unavailable(format!("CRL issuance worker: {e}")))?
            .map_err(Status::unavailable)?;
        Ok(Response::new(GetCrlResponse { crl_pem }))
    }
}

/// Serve ONLY [`NodeEnrollmentService`] on `addr` over PLAINTEXT h2c (no TLS),
/// until `shutdown` fires. The pre-cert bootstrap listener: a certless joiner
/// cannot complete the mTLS handshake the data-plane bind requires, so
/// enrollment gets a dedicated plaintext listener carried by the encrypted
/// overlay. Fail-safe: no data-plane service is registered here, so nothing but
/// enrollment is reachable without mTLS. Auth is the join token; integrity is
/// the CA fingerprint the joiner pins from the token.
pub async fn serve_node_enrollment(
    addr: SocketAddr,
    ca_pem: Vec<u8>,
    ca_key_pem: Vec<u8>,
    join_token_hash_path: PathBuf,
    api_key_secret: Option<String>,
    revoked_serials_path: Option<PathBuf>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let crl_issuer = revoked_serials_path
        .as_deref()
        .map(|path| super::crl::CrlIssuer::open(path, &ca_pem, &ca_key_pem))
        .transpose()
        .map_err(TransportError::Rpc)?
        .map(Arc::new);
    let svc = NodeEnrollmentServiceImpl {
        ca_pem: Some(ca_pem),
        ca_key_pem: Some(ca_key_pem),
        join_token_hash_path: Some(join_token_hash_path),
        api_key_secret,
        crl_issuer,
    };
    tracing::info!(
        %addr,
        "node-enrollment listener up (plaintext, token-gated, JoinCluster only)"
    );
    lib::transport_primitives::apply_server_limits(tonic::transport::Server::builder())
        .add_service(bounded!(NodeEnrollmentServiceServer::new(svc)))
        .serve_with_shutdown(addr, shutdown)
        .await
        .map_err(TransportError::Tonic)?;
    Ok(())
}

// =============================================================================
// Witness Zone Registry — multi-zone witness (mirrors ZoneRaftRegistry for
// FullStateMachine, but uses WitnessStateMachine and witness RaftConfig)
// =============================================================================

/// A single witness zone entry.
struct WitnessZoneEntry {
    node: ZoneConsensus<WitnessStateMachine>,
    /// Per-zone route book. A witness state machine holds no member-address
    /// records, so its routes are the observed senders.
    peers: SharedPeerMap,
    /// The transport loop and member-address registration running the zone.
    tasks: super::ZoneTasks,
}

/// Multi-zone registry for witness nodes.
///
/// Each zone gets its own `ZoneConsensus<WitnessStateMachine>` + `TransportLoop`.
/// The witness participates in leader election for every zone but never applies
/// state machine entries or serves reads.
pub struct WitnessZoneRegistry {
    zones: DashMap<String, WitnessZoneEntry>,
    base_path: PathBuf,
    node_id: u64,
    tls: lib::transport_primitives::SharedTlsConfig,
    /// Operator seed addresses: JoinZone and member-address registration targets.
    peers: Vec<NodeAddress>,
    /// This node's advertise address — carried in outbound StepMessage.
    self_address: String,
    /// Set by [`Self::shutdown`]: no zone opens, and boot joins stop.
    closed: std::sync::atomic::AtomicBool,
    /// Serializes ``auto_join_zone`` so concurrent step_messages from
    /// multiple data nodes for the same fresh zone don't both pass the
    /// ``zones.get()`` check, both call ``setup_witness_zone``, and
    /// race on opening the same redb file (second open fails with
    /// "Database already open. Cannot acquire lock.").
    ///
    /// Coarse-grained — serializes auto-join across ALL zones — but
    /// setup is just a few ms of I/O and the witness handles only
    /// raft-membership traffic, so per-zone scaling isn't worth the
    /// complexity. Held across the entire ``zones.get`` →
    /// ``setup_witness_zone`` → ``zones.insert`` window so concurrent
    /// callers serialize and the second one finds the zone already
    /// inserted.
    auto_join_lock: parking_lot::Mutex<()>,
}

impl WitnessZoneRegistry {
    pub fn shared_tls(&self) -> lib::transport_primitives::SharedTlsConfig {
        self.tls.clone()
    }

    /// Create a new empty witness zone registry.
    pub fn new(base_path: PathBuf, node_id: u64, tls: Option<super::TlsConfig>) -> Self {
        Self {
            zones: DashMap::new(),
            base_path,
            node_id,
            tls: lib::transport_primitives::SharedTlsConfig::new(tls),
            peers: Vec::new(),
            self_address: String::new(),
            closed: std::sync::atomic::AtomicBool::new(false),
            auto_join_lock: parking_lot::Mutex::new(()),
        }
    }

    /// Set the cluster peer addresses (called after parsing NEXUS_PEERS).
    pub fn set_peers(&mut self, peers: Vec<NodeAddress>) {
        self.peers = peers;
    }

    /// Set this node's advertise address — carried in outbound
    /// `StepMessageRequest.sender_address` so peers learn
    /// `(self.node_id -> address)` from inbound messages.
    pub fn set_self_address(&mut self, address: String) {
        self.self_address = address;
    }

    /// Get this node's advertise address (empty when unset).
    pub fn self_address(&self) -> &str {
        &self.self_address
    }

    /// Record a peer's advertise address observed on an inbound
    /// `StepMessage`, as `ZoneRaftRegistry::learn_peer_address` does.
    /// A witness holds no member-address records, so these observations
    /// are its routes.  Returns `true` if the route changed.
    pub fn learn_peer_address(&self, zone_id: &str, peer_id: u64, endpoint: &str) -> bool {
        let Some(entry) = self.zones.get(zone_id) else {
            return false;
        };
        super::observe_sender(
            &entry.peers,
            peer_id,
            endpoint,
            self.tls.snapshot().uses_tls(),
        )
    }

    /// Bootstrap or join a zone at boot time under the opaque-ID
    /// contract.  A zone this witness holds on disk resumes first (see
    /// [`Self::auto_join_zone`]).  Then sends `JoinZone` RPC against each
    /// configured peer until one succeeds, and registers the zone locally
    /// if it is not yet.  Looping is indefinite — misconfig (no reachable
    /// peer) surfaces as "witness stays up retrying" rather than a silent
    /// exit.
    ///
    /// Witness joins as a **voter** (`as_learner=false`) by default,
    /// matching TiKV's witness-as-voter pattern: votes in elections
    /// without applying state-machine entries (`is_witness=true` in
    /// the local RaftConfig).  Pass `as_learner=true` for log-shipping
    /// observers that don't count toward quorum.
    ///
    /// Returns the joined zone's `ZoneConsensus` handle.
    #[allow(clippy::result_large_err)]
    pub async fn bootstrap_or_join_zone(
        self: &Arc<Self>,
        zone_id: &str,
        as_learner: bool,
        timeout_secs: u64,
        retry_interval: std::time::Duration,
    ) -> Result<ZoneConsensus<WitnessStateMachine>> {
        // A zone this witness already holds resumes from its own raft
        // storage before the JoinZone below re-asserts its voter role: its
        // vote can be what elects the leader that answers, and the resumed
        // zone registers this witness's member address.
        if self.holds_zone(zone_id) {
            self.auto_join_zone(zone_id, &tokio::runtime::Handle::current())?;
        }

        // Its own entry in NEXUS_PEERS (a hostname-derived id) is never a target.
        let endpoints: Vec<String> = self
            .peers
            .iter()
            .filter(|peer| peer.id != self.node_id)
            .map(|peer| peer.endpoint.clone())
            .collect();
        loop {
            if self.is_closed() {
                return Err(TransportError::Connection(format!(
                    "witness shut down before zone '{zone_id}' joined"
                )));
            }
            if let super::JoinRound::Admitted { endpoint } = super::join_zone_round(
                endpoints.iter().cloned(),
                zone_id,
                self.node_id,
                &self.self_address,
                as_learner,
                &self.tls,
                timeout_secs,
            )
            .await
            {
                tracing::info!(
                    zone = %zone_id,
                    endpoint = %endpoint,
                    witness_id = self.node_id,
                    "Witness joined zone via leader",
                );
                return self.auto_join_zone(zone_id, &tokio::runtime::Handle::current());
            }
            tokio::time::sleep(retry_interval).await;
        }
    }

    /// Resume any legacy root from its own storage. Each data node owns its
    /// private root, so only named federation zones request voter admission.
    pub fn join_at_boot(
        self: &Arc<Self>,
        zones: Vec<String>,
        retry_interval: std::time::Duration,
    ) -> Vec<JoinHandle<()>> {
        let root = contracts::ROOT_ZONE_ID;
        if self.holds_zone(root) {
            if let Err(error) = self.auto_join_zone(root, &tokio::runtime::Handle::current()) {
                tracing::error!(zone = root, %error, "Could not resume stored witness root");
            }
        }
        zones
            .into_iter()
            .filter(|zone_id| zone_id != root)
            .map(|zone_id| {
                let registry = Arc::clone(self);
                tokio::spawn(async move {
                    match registry
                        .bootstrap_or_join_zone(&zone_id, false, 5, retry_interval)
                        .await
                    {
                        Ok(_) => tracing::info!(zone = %zone_id, "Witness joined zone"),
                        Err(_) if registry.is_closed() => {}
                        Err(error) => tracing::error!(
                            zone = %zone_id,
                            %error,
                            "Witness JoinZone failed permanently",
                        ),
                    }
                })
            })
            .collect()
    }

    /// Open a witness replica of `zone_id` — on an inbound Raft message for a
    /// zone not yet open, and for the boot join.
    ///
    /// A witness never founds a zone: the replica starts with
    /// `skip_bootstrap=true`, so its membership is the ConfState it stored
    /// for a zone it holds on disk, else empty until the leader's log or
    /// snapshot brings it — the raft-rs contract for a late-joining node.
    #[allow(clippy::result_large_err)]
    pub fn auto_join_zone(
        &self,
        zone_id: &str,
        runtime_handle: &tokio::runtime::Handle,
    ) -> Result<ZoneConsensus<WitnessStateMachine>> {
        use crate::raft::RaftConfig;

        // Fast path: zone already joined, no need to take the auto_join
        // lock. Lock acquisition still races on the bucket but DashMap
        // handles that, and the common case (subsequent step_messages
        // for an already-joined zone) stays uncontended.
        if let Some(existing) = self.zones.get(zone_id) {
            return Ok(existing.node.clone());
        }

        // Slow path: hold the auto-join lock across the entire
        // re-check + setup + insert sequence so two concurrent
        // step_messages for a fresh zone can't both reach
        // ``setup_witness_zone`` and race on the redb file lock.
        // Without this, the second caller hits "Database already
        // open" and the witness ends up with no entry for the zone
        // (subsequent step_messages keep retrying auto-join, never
        // landing in the registry, witness never votes).
        let _guard = self.auto_join_lock.lock();
        if let Some(existing) = self.zones.get(zone_id) {
            return Ok(existing.node.clone());
        }
        // Under the same lock `shutdown` drains under: no zone opens after it.
        if self.is_closed() {
            return Err(TransportError::Connection(format!(
                "witness is shut down; zone '{zone_id}' does not open"
            )));
        }

        self.setup_witness_zone(zone_id, RaftConfig::witness(self.node_id), runtime_handle)
    }

    /// Whether this witness holds `zone_id`'s raft state on disk.
    fn holds_zone(&self, zone_id: &str) -> bool {
        self.base_path.join(zone_id).join("raft").exists()
    }

    /// Internal: open storage, create ZoneConsensus + driver, start the zone
    /// (transport loop and member-address registration), register it.
    #[allow(clippy::result_large_err)]
    fn setup_witness_zone(
        &self,
        zone_id: &str,
        config: crate::raft::RaftConfig,
        runtime_handle: &tokio::runtime::Handle,
    ) -> Result<ZoneConsensus<WitnessStateMachine>> {
        use crate::raft::RaftStorage;

        // Zone-specific storage
        let zone_path = self.base_path.join(zone_id);
        let store = super::open_zone_store(zone_path.join("sm"))?;
        let raft_storage = RaftStorage::open(zone_path.join("raft")).map_err(|e| {
            TransportError::Connection(format!("Failed to open raft storage: {}", e))
        })?;
        let state_machine = WitnessStateMachine::new(&store).map_err(|e| {
            TransportError::Connection(format!("Failed to create witness state machine: {}", e))
        })?;

        let (mut handle, driver) = ZoneConsensus::new(config, raft_storage, state_machine, None)
            .map_err(|e| {
                TransportError::Connection(format!("Failed to create witness ZoneConsensus: {}", e))
            })?;

        let super::StartedZone {
            peers: shared_peers,
            tasks,
        } = super::start_zone(
            &mut handle,
            driver,
            zone_id,
            &self.tls,
            self.self_address.clone(),
            self.peers.clone(),
            runtime_handle,
        );

        tracing::info!(
            "Witness zone '{}' registered (node_id={})",
            zone_id,
            self.node_id,
        );

        self.zones.insert(
            zone_id.to_string(),
            WitnessZoneEntry {
                node: handle.clone(),
                peers: shared_peers,
                tasks,
            },
        );

        Ok(handle)
    }

    /// Get the ZoneConsensus handle for a zone.
    pub fn get_node(&self, zone_id: &str) -> Option<ZoneConsensus<WitnessStateMachine>> {
        self.zones.get(zone_id).map(|e| e.node.clone())
    }

    /// List all zone IDs.
    pub fn list_zones(&self) -> Vec<String> {
        self.zones.iter().map(|e| e.key().clone()).collect()
    }

    fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Stop every open zone; no zone opens afterwards and boot joins end.
    /// Await [`super::ZonesStopped::released`] to know the zones' tasks — and
    /// with them the registry's hold on their storage — are gone.
    pub fn shutdown(&self) -> super::ZonesStopped {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        let _guard = self.auto_join_lock.lock();
        let open: Vec<String> = self.zones.iter().map(|e| e.key().clone()).collect();
        let stopped = open
            .iter()
            .filter_map(|zone_id| self.zones.remove(zone_id))
            .map(|(_, entry)| entry.tasks.stop())
            .collect();
        tracing::info!("All witness zones shut down");
        stopped
    }
}

// =============================================================================
// Witness gRPC Server (zone-routed, serves all witness zones on one port)
// =============================================================================

/// A gRPC server for multi-zone Raft witness nodes.
///
/// Routes incoming `step_message` requests to the correct zone's
/// `ZoneConsensus<WitnessStateMachine>` by `zone_id`.
pub struct RaftWitnessServer {
    config: ServerConfig,
    registry: Arc<WitnessZoneRegistry>,
}

impl RaftWitnessServer {
    /// Create a witness server backed by a multi-zone registry.
    pub fn new(registry: Arc<WitnessZoneRegistry>, config: ServerConfig) -> Self {
        Self { config, registry }
    }

    /// Get the bind address.
    pub fn bind_address(&self) -> SocketAddr {
        self.config.bind_address
    }

    /// Prepare trust and service policy before scheduling the witness listener.
    pub fn serve_with_shutdown(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let addr = self.config.bind_address;
        let prepared = (|| {
            let credentials =
                listener_credentials(self.registry.shared_tls(), self.config.tls.as_ref())?;
            let policy =
                super::node_authority::NodeControlPolicy::from_shared_tls(credentials.clone())
                    .map_err(TransportError::Connection)?;
            let incoming =
                self.config.tls.is_some().then(|| {
                    lib::transport_primitives::shared_mtls_incoming(addr, credentials, None)
                });
            Ok::<_, TransportError>((policy, incoming))
        })();
        async move {
            let (policy, incoming) = prepared?;
            tracing::info!(
                "Starting Raft Witness gRPC server on {} (tls={}, zones={})",
                addr,
                incoming.is_some(),
                self.registry.list_zones().len(),
            );
            let service = WitnessServiceImpl {
                registry: self.registry.clone(),
                snapshots: Default::default(),
            };
            let mut builder =
                lib::transport_primitives::apply_server_limits(tonic::transport::Server::builder());
            let router = builder.add_service(super::node_authority::NodeControlService::new(
                bounded!(ZoneTransportServiceServer::new(service)),
                policy,
                &[],
            ));
            if let Some(incoming) = incoming {
                let incoming = incoming.await.map_err(TransportError::Connection)?;
                router
                    .serve_with_incoming_shutdown(incoming, shutdown)
                    .await
                    .map_err(TransportError::Tonic)?;
            } else {
                router
                    .serve_with_shutdown(addr, shutdown)
                    .await
                    .map_err(TransportError::Tonic)?;
            }
            Ok(())
        }
    }
}

/// Witness implementation of ZoneTransportService — routes by zone_id.
struct WitnessServiceImpl {
    registry: Arc<WitnessZoneRegistry>,
    /// Raft snapshots being received through `snapshot_chunk`.
    snapshots: snapshot_assembly::SnapshotAssembly,
}

impl WitnessServiceImpl {
    /// Admit a caller at a step boundary, before its payload is parsed.
    #[allow(clippy::result_large_err)]
    fn admit_step_caller(
        extensions: &tonic::codegen::http::Extensions,
        protocol: crate::raft::RaftMessageProtocol,
    ) -> std::result::Result<(), Status> {
        if protocol != crate::raft::RaftMessageProtocol::Legacy {
            super::node_authority::require_authenticated_control_node(extensions)?;
        }
        Ok(())
    }

    /// The zone a step is for. An unknown zone is joined on first contact
    /// (dynamic federation) with `skip_bootstrap=true`; the leader's
    /// snapshot brings its ConfState.
    #[allow(clippy::result_large_err)]
    fn step_zone(
        &self,
        zone_id: &str,
        protocol: crate::raft::RaftMessageProtocol,
    ) -> std::result::Result<ZoneConsensus<WitnessStateMachine>, Status> {
        if let Some(node) = namespace_step_zone(self.registry.get_node(zone_id), protocol)? {
            return Ok(node);
        }
        let handle = tokio::runtime::Handle::current();
        self.registry
            .auto_join_zone(zone_id, &handle)
            .map_err(|e| Status::internal(format!("Failed to auto-join zone '{zone_id}': {e}")))
    }

    /// Step a decoded message from an admitted caller. Every raft message
    /// reaches its zone's driver through here, whichever RPC carried it.
    async fn step_admitted(
        &self,
        extensions: &tonic::codegen::http::Extensions,
        zone_id: &str,
        sender_address: &str,
        message: raft::eraftpb::Message,
        protocol: crate::raft::RaftMessageProtocol,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        let peer = super::node_authority::authorize_raft_sender(extensions, &message)?;
        let node = self.step_zone(zone_id, protocol)?;
        self.snapshots.release_idle(std::time::Instant::now());

        // Learn the sender's advertise address from this inbound exchange.
        self.registry
            .learn_peer_address(zone_id, peer, sender_address);

        step_raft_message(&node, message, zone_id, "[Witness]", protocol).await
    }

    async fn dispatch_step(
        &self,
        request: Request<StepMessageRequest>,
        protocol: crate::raft::RaftMessageProtocol,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        Self::admit_step_caller(request.extensions(), protocol)?;
        let message = match parse_raft_message(&request.get_ref().message) {
            Ok(message) => message,
            Err(response) => return Ok(Response::new(response)),
        };
        let (_, extensions, req) = request.into_parts();
        self.step_admitted(
            &extensions,
            &req.zone_id,
            &req.sender_address,
            message,
            protocol,
        )
        .await
    }
}

#[tonic::async_trait]
impl ZoneTransportService for WitnessServiceImpl {
    async fn prepare_replica_control_reader_v1(
        &self,
        request: Request<PrepareReplicaControlReaderRequest>,
    ) -> std::result::Result<Response<PrepareReplicaControlReaderResponse>, Status> {
        super::node_authority::require_authenticated_control_node(request.extensions())?;
        let node = self
            .registry
            .get_node(&request.get_ref().zone_id)
            .ok_or_else(|| Status::not_found("zone is not hosted on this witness"))?;
        prepare_replica_control_reader(node).await
    }

    /// Handle a raw raft-rs message forwarded from another node.
    ///
    /// Routes to the correct zone's ZoneConsensus by `req.zone_id`.
    /// Auto-joins unknown zones (dynamic federation support).
    async fn step_message(
        &self,
        request: Request<StepMessageRequest>,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        self.dispatch_step(request, crate::raft::RaftMessageProtocol::Legacy)
            .await
    }

    async fn step_storage_v1(
        &self,
        request: Request<StepMessageRequest>,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        self.dispatch_step(request, crate::raft::RaftMessageProtocol::Legacy)
            .await
    }

    async fn step_replica_control_v1(
        &self,
        request: Request<StepMessageRequest>,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        self.dispatch_step(request, crate::raft::RaftMessageProtocol::ReplicaControlV1)
            .await
    }

    async fn step_atomic_namespace_v2(
        &self,
        request: Request<StepMessageRequest>,
    ) -> std::result::Result<Response<StepMessageResponse>, Status> {
        self.dispatch_step(request, crate::raft::RaftMessageProtocol::AtomicNamespaceV2)
            .await
    }

    /// Receive one slice of a raft snapshot, as a full node does.
    async fn snapshot_chunk(
        &self,
        request: Request<SnapshotChunkRequest>,
    ) -> std::result::Result<Response<SnapshotChunkResponse>, Status> {
        let protocol = snapshot_assembly::boundary_protocol(request.get_ref())?;
        Self::admit_step_caller(request.extensions(), protocol)?;
        let (_, extensions, req) = request.into_parts();
        snapshot_assembly::receive_chunk(
            &self.snapshots,
            &extensions,
            &req,
            || self.step_zone(&req.zone_id, protocol).map(drop),
            |message| {
                self.step_admitted(
                    &extensions,
                    &req.zone_id,
                    &req.sender_address,
                    message,
                    protocol,
                )
            },
        )
        .await
    }

    /// Witness nodes do not participate in EC replication.
    async fn replicate_entries(
        &self,
        _request: Request<ReplicateEntriesRequest>,
    ) -> std::result::Result<Response<ReplicateEntriesResponse>, Status> {
        Err(Status::unimplemented(
            "Witness nodes do not support EC replication",
        ))
    }

    async fn snapshot_ec_state(
        &self,
        _request: Request<SnapshotEcStateRequest>,
    ) -> std::result::Result<Response<SnapshotEcStateResponse>, Status> {
        Err(Status::unimplemented(
            "Witness nodes do not support EC snapshots",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(
            config.bind_address,
            "0.0.0.0:2026".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn test_zone_registry_server() {
        use tempfile::TempDir;

        let tmp_dir = TempDir::new().unwrap();
        let registry = Arc::new(ZoneRaftRegistry::new(tmp_dir.path().to_path_buf(), 1));

        let config = ServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };

        let server = RaftGrpcServer::new(registry, config);
        assert_eq!(
            server.bind_address(),
            "127.0.0.1:0".parse::<SocketAddr>().unwrap()
        );
    }

    /// R15.e: unknown zones must NOT be side-effectfully reopened on the
    /// message hot path. A step_message for a zone this node doesn't host
    /// returns NotFound without touching disk or mutating the registry.
    #[tokio::test]
    async fn test_step_message_unknown_zone_returns_not_found() {
        use tempfile::TempDir;

        let tmp_dir = TempDir::new().unwrap();
        let registry = Arc::new(ZoneRaftRegistry::new(tmp_dir.path().to_path_buf(), 1));
        let svc = super::ZoneTransportServiceImpl {
            registry: registry.clone(),
            snapshots: Default::default(),
        };

        let req = Request::new(StepMessageRequest {
            zone_id: "corp-eng".to_string(),
            message: Vec::new(),
            sender_address: String::new(),
        });
        let err = svc.step_message(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
        // Registry must remain empty — no side-effect reopen.
        assert!(registry.list_zones().is_empty());
    }

    /// A witness opening a zone it does not hold — even with seeds known —
    /// never founds it: no bootstrap entry, no ConfState of its own.
    #[test]
    fn a_witness_opening_a_fresh_zone_never_founds_it() {
        use tempfile::TempDir;

        let tmp_dir = TempDir::new().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let witness_id = NodeAddress::parse("witness:2126", false).unwrap().id;
        let mut registry = WitnessZoneRegistry::new(tmp_dir.path().to_path_buf(), witness_id, None);
        registry.set_peers(vec![
            NodeAddress::parse("nexus-1:2126", false).unwrap(),
            NodeAddress::parse("nexus-2:2126", false).unwrap(),
            NodeAddress::parse("witness:2126", false).unwrap(),
        ]);

        let node = registry
            .auto_join_zone("corp-eng", runtime.handle())
            .expect("witness opens the zone");

        assert!(node.config().skip_bootstrap);
        assert!(node.voters().is_empty(), "no ConfState of its own");
        assert_eq!(node.last_index(), 0, "no bootstrap entry");

        runtime.block_on(registry.shutdown().released());
    }

    // ---------------------------------------------------------------
    // TTL conversion boundary-value tests (Issue #3031 / 11A)
    // ---------------------------------------------------------------

    #[test]
    fn test_ms_to_secs_ceil_boundary_values() {
        // Zero stays zero
        assert_eq!(super::ms_to_secs_ceil(0), 0);

        // Sub-second values round UP to 1 (not down to 0)
        assert_eq!(super::ms_to_secs_ceil(1), 1);
        assert_eq!(super::ms_to_secs_ceil(500), 1);
        assert_eq!(super::ms_to_secs_ceil(999), 1);

        // Exact second boundary
        assert_eq!(super::ms_to_secs_ceil(1000), 1);

        // Just above boundary rounds up
        assert_eq!(super::ms_to_secs_ceil(1001), 2);
        assert_eq!(super::ms_to_secs_ceil(1500), 2);
        assert_eq!(super::ms_to_secs_ceil(1999), 2);
        assert_eq!(super::ms_to_secs_ceil(2000), 2);

        // Larger values
        assert_eq!(super::ms_to_secs_ceil(5000), 5);
        assert_eq!(super::ms_to_secs_ceil(5001), 6);
        assert_eq!(super::ms_to_secs_ceil(30_000), 30);

        // Negative values clamp to 0
        assert_eq!(super::ms_to_secs_ceil(-1), 0);
        assert_eq!(super::ms_to_secs_ceil(-1000), 0);
    }
}
