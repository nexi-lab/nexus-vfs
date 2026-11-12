//! Pure-Rust `ZoneManager` — multi-zone raft registry owner.
//!
//! Kernel-internal: the kernel crate owns an `Arc<ZoneManager>` and
//! reads env vars at `Kernel::new()` time to bootstrap federation.
//! Never exposed to Python.

#![cfg(all(feature = "grpc", has_protos))]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

#[allow(unused_imports)]
use crate::raft::StateMachine;
use crate::raft::{
    Command, CommandResult, FullStateMachine, RaftError, Result, ZoneConsensus, ZoneLoadPolicy,
    ZoneRaftRegistry,
};
use crate::transport::{
    call_delete_zone, call_join_cluster, hostname_to_node_id, NodeAddress, RaftGrpcServer,
    ServerConfig, TlsConfig,
};
use crate::zone_handle::ZoneHandle;
use lib::rt::block_on_via as bridge_block_on;
use lib::rt::OwnedRuntime;

/// Preserve storage admission failures across eager, lazy and join opens.
fn zone_open_error(
    error: crate::transport::TransportError,
    context: impl std::fmt::Display,
) -> RaftError {
    match error {
        crate::transport::TransportError::DataDirLocked(path) => RaftError::DataDirLocked(path),
        other => RaftError::Raft(format!("{context}: {other}")),
    }
}

// ── Federation mount helpers ─────────────────────────────────────────

/// DirEntryType codes — must match proto/nexus/core/metadata.proto and
/// Python constants in `src/nexus/contracts/metadata.py`.
pub(crate) const DT_REG: i32 = 0;
pub(crate) const DT_DIR: i32 = 1;
pub(crate) const DT_MOUNT: i32 = 2;

/// Raft counter key for a zone's POSIX i_links_count.
pub(crate) const I_LINKS_COUNT_KEY: &str = "__i_links_count__";

/// Encode a minimal `FileMetadata` proto for federation mount writes.
pub(crate) fn encode_file_metadata(
    path: &str,
    entry_type: i32,
    zone_id: &str,
    target_zone_id: &str,
) -> Vec<u8> {
    use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
    use prost::Message;

    let proto = ProtoFileMetadata {
        path: path.to_string(),
        entry_type,
        zone_id: zone_id.to_string(),
        target_zone_id: target_zone_id.to_string(),
        ..Default::default()
    };
    proto.encode_to_vec()
}

/// Encode a DT_MOUNT record, including WHICH subtree of the target zone it
/// exposes.
///
/// Separate from [`encode_file_metadata`] rather than a fifth positional
/// argument on it: of that function's eight callers only two write a mount, so
/// the other six would be passing `""` for a field that has no meaning for a
/// directory — and `encode_file_metadata(p, DT_DIR, z, "", "")` reads as two
/// mistakes rather than one intent.
///
/// `target_subtree` is `"/"` for the whole zone. A mount DECLARES it; deriving
/// it from `path` would make two nodes that mount one zone at different local
/// paths disagree about that zone's keys, which `join <peer>:/<zone> <local>`
/// permits.
pub use crate::raft::MountDecl;

pub(crate) fn encode_mount_metadata(
    path: &str,
    parent_zone_id: &str,
    target_zone_id: &str,
    target_subtree: &str,
) -> Vec<u8> {
    use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
    use prost::Message;

    let proto = ProtoFileMetadata {
        path: path.to_string(),
        entry_type: DT_MOUNT,
        zone_id: parent_zone_id.to_string(),
        target_zone_id: target_zone_id.to_string(),
        target_subtree: target_subtree.to_string(),
        ..Default::default()
    };
    proto.encode_to_vec()
}

/// Decode `FileMetadata` proto bytes.
pub(crate) fn decode_file_metadata(
    bytes: &[u8],
) -> std::result::Result<crate::transport::proto::nexus::core::FileMetadata, prost::DecodeError> {
    use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
    use prost::Message;
    ProtoFileMetadata::decode(bytes)
}

/// The prefix form the metadata scan and [`path_matches_prefix`] both expect.
///
/// One normalizer so a subtree means the same thing to every caller: trailing slashes
/// are noise (`/agents/` and `/agents` are one subtree), and `""` means the whole zone —
/// which only `"/"` may ask for, because an empty argument anywhere else is a caller
/// that lost its path, not a request to share everything.
fn normalize_subtree_prefix(prefix: &str) -> Result<String> {
    let normalized = prefix.trim_end_matches('/').to_string();
    if normalized.is_empty() && prefix != "/" {
        return Err(RaftError::InvalidState(format!(
            "subtree prefix is empty (got '{prefix}')"
        )));
    }
    Ok(normalized)
}

/// Is `path` either `normalized_prefix` or a descendant at `/` boundary?
pub(crate) fn path_matches_prefix(path: &str, normalized_prefix: &str) -> bool {
    if normalized_prefix.is_empty() {
        true
    } else {
        path == normalized_prefix || {
            path.len() > normalized_prefix.len()
                && path.starts_with(normalized_prefix)
                && path.as_bytes()[normalized_prefix.len()] == b'/'
        }
    }
}

fn propose_set_metadata(
    handle: &tokio::runtime::Handle,
    node: &ZoneConsensus<FullStateMachine>,
    key: &str,
    value: Vec<u8>,
) -> Result<()> {
    let cmd = Command::SetMetadata {
        key: key.to_string(),
        value,
    };
    match bridge_block_on(handle, node.propose(cmd))? {
        CommandResult::Success | CommandResult::Value(_) => Ok(()),
        CommandResult::Error(e) => Err(RaftError::Raft(e)),
        other => Err(RaftError::InvalidState(format!(
            "unexpected propose result: {:?}",
            other
        ))),
    }
}

pub(crate) fn propose_delete_metadata(
    handle: &tokio::runtime::Handle,
    node: &ZoneConsensus<FullStateMachine>,
    key: &str,
) -> Result<()> {
    let cmd = Command::DeleteMetadata {
        key: key.to_string(),
    };
    match bridge_block_on(handle, node.propose(cmd))? {
        CommandResult::Success | CommandResult::Value(_) => Ok(()),
        CommandResult::Error(e) => Err(RaftError::Raft(e)),
        other => Err(RaftError::InvalidState(format!(
            "unexpected propose result: {:?}",
            other
        ))),
    }
}

fn propose_adjust_counter(
    handle: &tokio::runtime::Handle,
    node: &ZoneConsensus<FullStateMachine>,
    key: &str,
    delta: i64,
) -> Result<i64> {
    let cmd = Command::AdjustCounter {
        key: key.to_string(),
        delta,
    };
    match bridge_block_on(handle, node.propose(cmd))? {
        CommandResult::Value(bytes) => {
            let arr: [u8; 8] = bytes.try_into().map_err(|_| {
                RaftError::InvalidState("invalid counter value encoding".to_string())
            })?;
            Ok(i64::from_be_bytes(arr))
        }
        // Forwarded to leader over gRPC: RaftResponse drops the
        // counter bytes, so the apply's Value(new_count) comes back
        // as Success. The counter mutation did land in state; we
        // just don't know the new value.
        CommandResult::Success => Ok(i64::MIN),
        CommandResult::Error(e) => Err(RaftError::Raft(e)),
        other => Err(RaftError::InvalidState(format!(
            "unexpected counter result: {:?}",
            other
        ))),
    }
}

// ── ZoneManager ─────────────────────────────────────────────────────

/// Aggregate cluster status for one zone — flat dict fields.
/// Returned by [`ZoneManager::cluster_status`].
#[derive(Debug, Clone)]
pub struct ClusterStatus {
    pub zone_id: String,
    pub node_id: u64,
    pub has_store: bool,
    pub is_leader: bool,
    pub leader_id: u64,
    pub term: u64,
    pub commit_index: u64,
    pub applied_index: u64,
    pub voter_count: usize,
    pub witness_count: usize,
    /// Milliseconds since this node last heard from its current leader —
    /// 0 on the leader, `None` before the first contact. Memory only.
    pub leader_contact_age_ms: Option<u64>,
}

/// Local presence ladder for a zone — see [`ZoneManager::zone_presence`].
/// The proto-side enum (`ZoneStatusResponse::Presence`) adds `DELETED` on
/// top of this via the deletion registry; the raft layer answers local
/// facts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZonePresence {
    /// Hosted in the catalog AND the raft runtime is live here.
    Resident,
    /// Catalogued as hosted, runtime not currently materialized (cold).
    HostedNotResident,
    /// This node has no knowledge of the zone at all.
    LocalNotFound,
}

/// TLS configuration for a `ZoneManager` (all three fields required together).
#[derive(Debug, Clone)]
pub struct TlsFiles {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: PathBuf,
    /// CA private key read once at startup for server-side cert signing
    /// during `JoinCluster` RPC handling.
    pub ca_key_path: Option<PathBuf>,
    /// SHA-256 hash of the join token password for verifying
    /// incoming `JoinCluster` requests.
    pub join_token_hash: Option<String>,
}

/// Is this bind failure "somebody else already has the address"?
///
/// Walks the source chain to an `io::Error` and reads its `kind`, rather than matching
/// the rendered message. The text is
/// `connection error: bind 0.0.0.0:2126: address already in use (os error 10048)` on
/// Windows and `(os error 98)` on Linux, so a string test would be platform-specific
/// and would go quiet the day tonic rewords it — while still compiling.
fn addr_in_use(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            return io.kind() == std::io::ErrorKind::AddrInUse;
        }
        cur = err.source();
    }
    false
}

/// Multi-zone raft registry owner (pure Rust, kernel-internal).
pub struct ZoneManager {
    registry: Arc<ZoneRaftRegistry>,
    /// The runtime every zone's `transport_loop` and the gRPC server run on.
    ///
    /// [`OwnedRuntime`] because dropping a runtime from an async context panics, and
    /// this manager is built and dropped on both sides of that line — the daemon's
    /// `#[tokio::main]` and sync tooling — including the constructor's own error
    /// paths, which drop it before there is a `ZoneManager` to have a `Drop` impl.
    runtime: OwnedRuntime,
    shutdown_tx: tokio::sync::Mutex<Option<tokio::sync::watch::Sender<bool>>>,
    node_id: u64,
    /// Late-bindable slot the kernel populates with a `BlobFetcher`
    /// once its root mount backend is ready. Shared with the gRPC
    /// server so `ZoneApiService::read_blob` serves once the kernel
    /// installs an impl. Stays empty on slim / no-federation runtimes
    /// (the RPC is still advertised but returns `NotFound`).
    blob_fetcher_slot: crate::blob_fetcher::BlobFetcherSlot,
    search_capabilities_slot: crate::search_capabilities::SearchCapabilitiesSlot,
    /// Shared with the gRPC server so `ZoneApiService::mint_agent` can sign
    /// agent certs once the founder installs an `CaIssuer`. Empty on a
    /// joiner (not the CA holder) — the RPC returns success=false there.
    ca_issuer_slot: crate::ca_issuer::CaIssuerSlot,
    /// Shared with the gRPC server so `ZoneApiService::mint_key`/`revoke_key`
    /// can mint/revoke sk- credentials once the daemon installs a `KeyMinter`.
    /// Empty under `--no-tls` (no sk- plane).
    key_minter_slot: crate::key_minter::KeyMinterSlot,
    /// Shared with the gRPC server so `ZoneApiService::register_foreign_ca` (+
    /// siblings) can record cross-org CA anchors once the daemon installs a
    /// `ForeignCaRegistrar`. Empty under `--no-tls`.
    foreign_ca_registrar_slot: crate::foreign_ca_registrar::ForeignCaRegistrarSlot,
    session_mint_admin_slot: crate::session_mint_admin::SessionMintAdminSlot,
    /// The federated mTLS client-cert verifier — the client-auth trust roots,
    /// hot-swappable so a foreign CA registered at runtime is trusted without a
    /// restart. Built eagerly from the cluster CA (the only root until the
    /// cross-org apply-observer calls `set_foreign_cas`); the SAME `Arc` is
    /// shared with the gRPC serve path and that observer. `None` under `--no-tls`.
    foreign_ca_verifier: Option<Arc<lib::transport_primitives::FederatedClientCertVerifier>>,
    /// Holders outside this manager that present the Node identity, told of
    /// every installed replacement.
    node_identity_holders: parking_lot::Mutex<Vec<NodeIdentityHolder>>,
    local_node_renewer_slot: crate::ca_issuer::LocalNodeRenewerSlot,
    /// Static topology mounts staged by `bootstrap_static`, drained
    /// incrementally by `apply_topology` as parent + target zones'
    /// leaders settle. BTreeMap so parent paths process before children.
    /// Empty when no static topology is configured.
    pending_mounts: parking_lot::Mutex<BTreeMap<String, MountDecl>>,
}

/// A holder of this Node's TLS identity outside the `ZoneManager` (an outbound
/// client with its own channel cache), handed each renewed identity.
pub type NodeIdentityHolder = Box<dyn Fn(&TlsConfig) + Send + Sync>;

#[derive(Clone, Copy)]
enum RuntimeProfile {
    Networked,
    NetworkedLocalRoot,
    IsolatedRoot,
}

impl ZoneManager {
    /// Create a new `ZoneManager`.
    ///
    /// Starts a tokio runtime + gRPC server. Indexes every previously-persisted
    /// zone from disk before the gRPC server accepts traffic (R15.e), and
    /// materializes each on first access.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hostname: &str,
        base_path: &str,
        peers: Vec<String>,
        bind_addr: &str,
        tls: Option<TlsFiles>,
    ) -> Result<Arc<Self>> {
        Self::with_node_id(
            hostname,
            hostname_to_node_id(hostname),
            base_path,
            peers,
            bind_addr,
            tls,
            None,
            None,
        )
    }

    /// Create a `ZoneManager` with an explicit node ID.
    ///
    /// Used by `RaftDistributedCoordinator::init_from_env` to bind the
    /// node ID returned by `read_or_mint_node_id` (opaque random u64
    /// persisted at `<NEXUS_DATA_DIR>/.node_id`).  `peers` are the
    /// operator seed addresses (`NEXUS_PEERS` / `--peers`): RPC targets for
    /// JoinZone and for self-registration, never zone routes and never
    /// ConfState — ConfState is mutated only by ConfChange driven by
    /// JoinZone.
    /// Callers that supply an explicit ID also supply its matching TLS identity.
    /// `self_address` is this node's advertise address (e.g.,
    /// `"http://10.0.0.3:2126"` or `"10.0.0.3:2126"`).  Carried in every
    /// outbound `StepMessageRequest.sender_address` so peers learn
    /// `(self.node_id -> self_address)` from inbound messages — the
    /// runtime SSOT for transport routing under the opaque-ID contract.
    /// `None` disables sender-address advertisement; use only for
    /// tests / sync-only deployments.
    #[allow(clippy::too_many_arguments)]
    pub fn with_node_id(
        hostname: &str,
        node_id: u64,
        base_path: &str,
        peers: Vec<String>,
        bind_addr: &str,
        tls: Option<TlsFiles>,
        self_address: Option<String>,
        extra_grpc_services: Option<tonic::service::Routes>,
    ) -> Result<Arc<Self>> {
        // Default: the daemon contract — every hosted zone is reachable, and
        // becomes resident when something asks for it.
        Self::with_node_id_opts(
            hostname,
            node_id,
            base_path,
            peers,
            bind_addr,
            tls,
            self_address,
            extra_grpc_services,
            ZoneLoadPolicy::OnDemand,
        )
    }

    /// [`Self::with_node_id`] plus an explicit [`ZoneLoadPolicy`] — lets offline
    /// tooling open only the zones it needs (e.g. `Only(["root"])`) and be
    /// structurally unable to reach any other, instead of spinning up federated
    /// zones as lone nodes. See [`ZoneLoadPolicy`].
    #[allow(clippy::too_many_arguments)]
    pub fn with_node_id_opts(
        hostname: &str,
        node_id: u64,
        base_path: &str,
        peers: Vec<String>,
        bind_addr: &str,
        tls: Option<TlsFiles>,
        self_address: Option<String>,
        extra_grpc_services: Option<tonic::service::Routes>,
        load_policy: ZoneLoadPolicy,
    ) -> Result<Arc<Self>> {
        Self::with_node_id_profile(
            hostname,
            node_id,
            base_path,
            peers,
            bind_addr,
            tls,
            self_address,
            extra_grpc_services,
            load_policy,
            RuntimeProfile::Networked,
        )
    }

    /// Host data-zone replicas alongside a root with fixed local membership.
    /// The root uses its existing `.node_id`; `node_id` identifies the network
    /// replica and never replaces the root's committed membership.
    /// The existing TLS, control authorization and per-zone Raft paths apply.
    #[allow(clippy::too_many_arguments)]
    pub fn with_local_root(
        hostname: &str,
        node_id: u64,
        base_path: &str,
        peers: Vec<String>,
        bind_addr: &str,
        tls: Option<TlsFiles>,
        self_address: Option<String>,
        extra_grpc_services: Option<tonic::service::Routes>,
    ) -> Result<Arc<Self>> {
        Self::with_node_id_profile(
            hostname,
            node_id,
            base_path,
            peers,
            bind_addr,
            tls,
            self_address,
            extra_grpc_services,
            ZoneLoadPolicy::OnDemand,
            RuntimeProfile::NetworkedLocalRoot,
        )
    }

    /// Open one local durable root zone without a peer or control-plane listener.
    /// The persisted node ID and ConfState retain the normal Raft restart contract.
    pub fn isolated(base_path: &str) -> Result<Arc<Self>> {
        let node_id = crate::distributed_coordinator::read_or_mint_node_id(base_path)
            .map_err(RaftError::Config)?;
        Self::with_node_id_profile(
            "user-runtime",
            node_id,
            base_path,
            Vec::new(),
            "127.0.0.1:0",
            None,
            None,
            None,
            ZoneLoadPolicy::Only(vec![contracts::ROOT_ZONE_ID.to_string()]),
            RuntimeProfile::IsolatedRoot,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_node_id_profile(
        hostname: &str,
        node_id: u64,
        base_path: &str,
        peers: Vec<String>,
        bind_addr: &str,
        tls: Option<TlsFiles>,
        self_address: Option<String>,
        extra_grpc_services: Option<tonic::service::Routes>,
        load_policy: ZoneLoadPolicy,
        profile: RuntimeProfile,
    ) -> Result<Arc<Self>> {
        // Initialize tracing once.
        static TRACING_INIT: std::sync::Once = std::sync::Once::new();
        TRACING_INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env()
                        .add_directive("info".parse().unwrap()),
                )
                .try_init();
        });

        let tls_config = if let Some(ref t) = tls {
            let cert_pem = std::fs::read(&t.cert_path).map_err(|e| {
                RaftError::Config(format!(
                    "Failed to read TLS cert '{}': {}",
                    t.cert_path.display(),
                    e
                ))
            })?;
            let key_pem = std::fs::read(&t.key_path).map_err(|e| {
                RaftError::Config(format!(
                    "Failed to read TLS key '{}': {}",
                    t.key_path.display(),
                    e
                ))
            })?;
            let ca_pem = std::fs::read(&t.ca_path).map_err(|e| {
                RaftError::Config(format!(
                    "Failed to read TLS CA '{}': {}",
                    t.ca_path.display(),
                    e
                ))
            })?;
            let certificate_id = match profile {
                RuntimeProfile::NetworkedLocalRoot => {
                    let cert_der =
                        lib::transport_primitives::first_certificate_der(&cert_pem, "peer")
                            .map_err(RaftError::Config)?;
                    let ca_der =
                        lib::transport_primitives::first_certificate_der(&ca_pem, "cluster CA")
                            .map_err(RaftError::Config)?;
                    crate::transport::current_local_replication_id(&cert_der, &ca_der)
                }
                RuntimeProfile::Networked | RuntimeProfile::IsolatedRoot => {
                    crate::transport::local_node_identity(&cert_pem, &ca_pem)
                        .map(|identity| identity.node_id)
                }
            }
            .map_err(RaftError::Config)?;
            if certificate_id != node_id {
                return Err(RaftError::Config(format!(
                    "peer certificate identifies {certificate_id}, but the configured Raft Node ID is {node_id}"
                )));
            }
            Some(TlsConfig {
                cert_pem,
                key_pem,
                ca_pem,
            })
        } else {
            None
        };

        let bind_socket: std::net::SocketAddr = bind_addr.parse().map_err(|e| {
            RaftError::Config(format!("Invalid bind address '{}': {}", bind_addr, e))
        })?;

        // This runtime hosts BOTH the tonic gRPC server (accept loop +
        // per-connection HTTP/2 handshakes for raft and VFS) and every
        // zone's `transport_loop` (which does synchronous redb disk I/O
        // in `advance`). A hardcoded 2-worker pool starves the
        // accept/handshake path under load — new connections finish the
        // TCP handshake but never get an HTTP/2 SETTINGS frame, so peers
        // see most join/replication dials time out while heartbeats on
        // established connections survive. Size to the host like the
        // outer daemon runtime, with a floor that keeps the accept path
        // live even on small multi-zone hosts.
        let worker_threads =
            contracts::recommended_worker_threads(contracts::MIN_SERVER_RUNTIME_WORKERS);
        // Owned from birth, not from `Ok(...)`: every `?` below this line is a path an
        // operator can reach (a data dir another process has open, unreadable TLS
        // material, a bind address that is not on this host), and each one drops this
        // runtime while unwinding — which must not panic over the error it carries.
        let runtime = OwnedRuntime::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(worker_threads)
                .enable_all()
                .thread_name("nexus-zone-mgr")
                .build()
                .map_err(|e| RaftError::Config(format!("Failed to create runtime: {}", e)))?,
        );

        let registry = Arc::new(match profile {
            RuntimeProfile::Networked => {
                ZoneRaftRegistry::with_tls(PathBuf::from(base_path), node_id, tls_config.clone())
            }
            RuntimeProfile::NetworkedLocalRoot => {
                let root_node_id = crate::distributed_coordinator::read_or_mint_node_id(base_path)
                    .map_err(RaftError::Config)?;
                ZoneRaftRegistry::with_local_root(
                    PathBuf::from(base_path),
                    node_id,
                    root_node_id,
                    tls_config.clone(),
                )
            }
            RuntimeProfile::IsolatedRoot => {
                ZoneRaftRegistry::isolated_root(PathBuf::from(base_path), node_id)
            }
        });
        if let Some(ref addr) = self_address {
            registry.set_self_address(addr.clone());
        }
        // Seeds are RPC targets (JoinZone, member-address registration),
        // never zone routes: those derive from member-address records.
        registry.set_seeds(
            peers
                .iter()
                .map(|s| {
                    NodeAddress::parse(s.trim(), tls_config.is_some())
                        .map_err(|e| RaftError::Config(format!("Invalid peer '{}': {}", s, e)))
                })
                .collect::<Result<Vec<_>>>()?,
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let config = ServerConfig {
            bind_address: bind_socket,
            tls: tls_config.clone(),
            ..Default::default()
        };
        let use_tls = tls_config.is_some();

        // Index what this node hosts BEFORE the gRPC server accepts traffic,
        // so an arriving vote / append / VFS call can never be told "no such
        // zone" about a zone that is sitting right there on disk. Opening it
        // is a separate question, answered on first access — see
        // `ZoneRaftRegistry::index_persisted_zones`. Boot therefore costs one
        // readdir instead of one raft-group opening per persisted zone, which
        // is what decouples restart time from zones-accumulated-over-a-year.
        //
        // Sync (no campaign, no nested runtime): calling it directly avoids the
        // `Handle::block_on` panic that hit `nexusd-cluster`'s `#[tokio::main]`
        // async path — the worker thread driving `ZoneManager::new` would
        // otherwise be parked on the inner runtime's block_on, which tokio
        // rejects to prevent deadlock.
        registry
            .index_persisted_zones()
            .map_err(|e| RaftError::Raft(format!("Failed to enumerate zones on startup: {}", e)))?;
        registry.arm_materialization(runtime.handle().clone(), load_policy.clone());
        // The zones that must be resident before anything can be served at
        // all: `root`, whose DT_MOUNT entries define the namespace, and — for
        // offline tooling — exactly the zone it was told to touch.
        let eager: Vec<String> = match &load_policy {
            ZoneLoadPolicy::OnDemand => vec![contracts::ROOT_ZONE_ID.to_string()],
            ZoneLoadPolicy::Only(zone_ids) => zone_ids.clone(),
        };
        registry
            .materialize_now(&eager, runtime.handle())
            .map_err(|e| {
                zone_open_error(e, format!("Failed to open zones {eager:?} on startup"))
            })?;

        let blob_fetcher_slot = crate::blob_fetcher::new_blob_fetcher_slot();
        let search_capabilities_slot = crate::search_capabilities::new_search_capabilities_slot();
        let ca_issuer_slot = crate::ca_issuer::new_ca_issuer_slot();
        let key_minter_slot = crate::key_minter::new_key_minter_slot();
        let foreign_ca_registrar_slot =
            crate::foreign_ca_registrar::new_foreign_ca_registrar_slot();
        let session_mint_admin_slot = crate::session_mint_admin::new_session_mint_admin_slot();
        // Build the federated client-cert verifier eagerly from the cluster CA
        // when TLS is on, so the serve path (below) and the cross-org
        // apply-observer (cluster profile, via `foreign_ca_verifier()`) share ONE
        // Arc — the observer's `set_foreign_cas` then reaches the live serving
        // verifier with no restart. Empty roots beyond the cluster CA until then,
        // so this is byte-equivalent to the old `client_ca_root(cluster_ca)`.
        let foreign_ca_verifier = match &tls_config {
            Some(t) => Some(
                lib::transport_primitives::FederatedClientCertVerifier::new(&t.ca_pem)
                    .map_err(|e| RaftError::Config(format!("build client-cert verifier: {e}")))?,
            ),
            None => None,
        };
        let local_node_renewer_slot = crate::ca_issuer::new_local_node_renewer_slot();
        let mut server = RaftGrpcServer::new(registry.clone(), config)
            .with_blob_fetcher_slot(blob_fetcher_slot.clone())
            .with_search_capabilities_slot(search_capabilities_slot.clone())
            .with_ca_issuer_slot(ca_issuer_slot.clone())
            .with_key_minter_slot(key_minter_slot.clone())
            .with_foreign_ca_registrar_slot(foreign_ca_registrar_slot.clone())
            .with_session_mint_admin_slot(session_mint_admin_slot.clone())
            .with_local_node_renewer_slot(local_node_renewer_slot.clone())
            .with_foreign_ca_verifier(foreign_ca_verifier.clone());
        // Node enrollment (JoinCluster cert provisioning) is NOT served here —
        // this bind is strict mTLS, which a certless joiner cannot reach. The
        // cluster daemon runs it on a separate plaintext listener via
        // `transport::serve_node_enrollment` when `--enroll-listen` is set.
        if let Some(extra) = extra_grpc_services {
            server = server.with_extra_services(extra);
        }
        let shutdown_rx_server = shutdown_rx.clone();
        // Owned: the failure message below names the address, and the task outlives
        // this borrow.
        let bind_for_error = bind_addr.to_string();
        if !matches!(profile, RuntimeProfile::IsolatedRoot) {
            runtime.spawn(async move {
                let shutdown = async move {
                    let mut rx = shutdown_rx_server;
                    let _ = rx.changed().await;
                };
                if let Err(e) = server.serve_with_shutdown(shutdown).await {
                    // gRPC bind failure (port in use, IP not assigned to any
                    // interface — e.g. Tailscale in NoState — TLS cert
                    // mismatch, etc.) leaves the daemon half-alive: raft
                    // driver + FUSE plugin + LocalConnector all up, but no
                    // one can talk to us over the wire.  Operators observed
                    // this as "everything looks fine locally, but peers
                    // never see me" for 30+ minutes before diagnosis.
                    //
                    // Fail loud: log at ERROR (visible in every launcher
                    // stdout) and exit(1) so the process supervisor / CI
                    // gate / operator's `echo $?` sees non-zero.  gRPC
                    // server startup is a strict prerequisite for
                    // federation and there is no recovery from within the
                    // process — bind is either possible or not.
                    // Name the one cause an operator can act on. "Someone else has this
                    // address" is a different instruction from "this address is not on any
                    // interface", and a one-shot subcommand hitting the first one used to
                    // read this daemon-shaped sentence and conclude its own federation was
                    // broken (#328).
                    if addr_in_use(&e) {
                        tracing::error!(
                            error = %e,
                            bind = %bind_for_error,
                            "another process already holds {bind_for_error}. This process has to \
                             be reachable THERE — a zone with other voters delivers their \
                             append/vote responses to the address its peers were told to \
                             dial, so an ephemeral port would leave it waiting forever. \
                             Stop whatever holds it, or run this against the data dir whose \
                             node owns that address",
                        );
                    } else {
                        tracing::error!(
                            error = %e,
                            bind = %bind_for_error,
                            "gRPC bind on {bind_for_error} failed for a reason other than the \
                             address being taken — an IP not assigned to any interface (a \
                             Tailscale address while the tunnel is down does this) or a TLS \
                             material mismatch. Nothing can reach this process until it \
                             binds, so there is no degraded mode to continue in",
                        );
                    }
                    std::process::exit(1);
                }
            });
        }

        tracing::info!(
            "ZoneManager local_node_id={} hostname={} started (bind={}, tls={})",
            node_id,
            hostname,
            bind_addr,
            use_tls,
        );

        Ok(Arc::new(Self {
            registry,
            runtime,
            shutdown_tx: tokio::sync::Mutex::new(Some(shutdown_tx)),
            node_id,
            blob_fetcher_slot,
            search_capabilities_slot,
            ca_issuer_slot,
            key_minter_slot,
            foreign_ca_registrar_slot,
            session_mint_admin_slot,
            foreign_ca_verifier,
            node_identity_holders: parking_lot::Mutex::new(Vec::new()),
            local_node_renewer_slot,
            pending_mounts: parking_lot::Mutex::new(BTreeMap::new()),
        }))
    }

    /// Hand the shared `BlobFetcher` slot back to the kernel so it
    /// can install a concrete fetcher once its root mount backend is
    /// wired. Clone-cheap (just an `Arc`).
    pub fn blob_fetcher_slot(&self) -> crate::blob_fetcher::BlobFetcherSlot {
        self.blob_fetcher_slot.clone()
    }

    pub fn search_capabilities_slot(&self) -> crate::search_capabilities::SearchCapabilitiesSlot {
        self.search_capabilities_slot.clone()
    }

    /// Hand the shared `CaIssuer` slot back so the cluster profile can
    /// install a concrete minter on the founder (CA holder). Clone-cheap.
    pub fn ca_issuer_slot(&self) -> crate::ca_issuer::CaIssuerSlot {
        self.ca_issuer_slot.clone()
    }

    /// Hand the shared `KeyMinter` slot back so the cluster profile can install a
    /// concrete minter on every auth-on daemon. Clone-cheap.
    pub fn key_minter_slot(&self) -> crate::key_minter::KeyMinterSlot {
        self.key_minter_slot.clone()
    }

    /// Hand the shared `ForeignCaRegistrar` slot back so the cluster profile can
    /// install a concrete registrar on every auth-on daemon. Clone-cheap.
    pub fn foreign_ca_registrar_slot(&self) -> crate::foreign_ca_registrar::ForeignCaRegistrarSlot {
        self.foreign_ca_registrar_slot.clone()
    }

    /// Hand back the session-mint admin slot so the cluster profile can install
    /// the impl once the control zone is up. Same late-binding shape as the
    /// foreign-CA registrar above, for the same reason: the store it administers
    /// rides the control-zone consensus, which is not ready at construction.
    pub fn session_mint_admin_slot(&self) -> crate::session_mint_admin::SessionMintAdminSlot {
        self.session_mint_admin_slot.clone()
    }

    /// Hand back the shared federated client-cert verifier so the cluster profile
    /// can wire the `CONTROL_NS_FOREIGN_CA` apply-observer to `set_foreign_cas`
    /// (hot-swap the trusted foreign-CA set on register/unregister). `None` under
    /// `--no-tls`. Clone-cheap (`Arc`).
    pub fn foreign_ca_verifier(
        &self,
    ) -> Option<Arc<lib::transport_primitives::FederatedClientCertVerifier>> {
        self.foreign_ca_verifier.clone()
    }

    /// This Node's current TLS identity (`None` under `--no-tls`).
    pub fn node_tls(&self) -> std::result::Result<Option<TlsConfig>, String> {
        self.registry.tls_config()
    }

    /// Serve and present a renewed Node identity everywhere, without a restart:
    /// the gRPC server's new connections, every pooled Raft client, then each
    /// registered [`NodeIdentityHolder`]. The bundle must name this Node and
    /// chain to the cluster CA it already uses, whose verifier is unchanged.
    pub fn install_node_identity(&self, tls: TlsConfig) -> std::result::Result<(), String> {
        let original = self.registry.shared_tls().snapshot();
        self.install_node_identity_from(&original, tls)
    }

    fn install_node_identity_from(
        &self,
        original: &lib::transport_primitives::TlsSnapshot,
        tls: TlsConfig,
    ) -> std::result::Result<(), String> {
        self.check_node_identity_from(original, &tls)?;
        let verifier = self
            .foreign_ca_verifier
            .as_ref()
            .ok_or("a plaintext node has no TLS identity to replace")?;
        // Validate the key/certificate pair before publishing the shared installation.
        lib::transport_primitives::server_config(
            Arc::clone(verifier),
            &tls.cert_pem,
            &tls.key_pem,
        )?;
        if !self.registry.shared_tls().replace_if_current(
            original,
            lib::transport_primitives::TlsPolicy::Configured(tls.clone()),
        ) {
            return Err("Node credential installation changed during renewal validation".into());
        }
        for holder in self.node_identity_holders.lock().iter() {
            holder(&tls);
        }
        tracing::info!(
            local_node_id = self.node_id,
            "renewed Node identity installed"
        );
        Ok(())
    }

    /// Whether `tls` may replace this Node's identity: a current leaf naming
    /// this Node, chained to the cluster CA it already uses.
    pub fn check_node_identity(&self, tls: &TlsConfig) -> std::result::Result<(), String> {
        self.check_node_identity_from(&self.registry.shared_tls().snapshot(), tls)
    }

    fn check_node_identity_from(
        &self,
        original: &lib::transport_primitives::TlsSnapshot,
        tls: &TlsConfig,
    ) -> std::result::Result<(), String> {
        let current = original
            .config()?
            .ok_or("a plaintext node has no TLS identity to replace")?;
        if tls.ca_pem != current.ca_pem {
            return Err("a renewed Node identity must chain to the same cluster CA".into());
        }
        let named = crate::transport::local_node_identity(&tls.cert_pem, &tls.ca_pem)?;
        if named.node_id != self.node_id {
            return Err(format!(
                "the renewed certificate names Node {}, not this Node {}",
                named.node_id, self.node_id
            ));
        }
        Ok(())
    }

    /// Register a holder outside this manager that presents the Node identity
    /// (an outbound client with its own channels); it receives each identity
    /// [`Self::install_node_identity`] installs.
    pub fn on_node_identity(&self, holder: NodeIdentityHolder) {
        self.node_identity_holders.lock().push(holder);
    }

    /// Hand back the slot the daemon binds its own Node certificate renewer into.
    pub fn local_node_renewer_slot(&self) -> crate::ca_issuer::LocalNodeRenewerSlot {
        self.local_node_renewer_slot.clone()
    }

    /// The operator seed addresses this node was started with, parsed with
    /// this node's TLS posture. A seed's `id` is derived from its hostname,
    /// which identifies only a witness.
    pub fn seed_peers(&self) -> Vec<NodeAddress> {
        self.registry.seeds()
    }

    /// Get an existing zone handle, or create the zone and return a handle to
    /// it. Called from `Kernel::sys_setattr(DT_MOUNT)` leader path.
    /// Idempotent: subsequent calls for an existing zone skip the raft
    /// ConfState bootstrap and return the cached node.
    pub fn get_or_create_zone(&self, zone_id: &str) -> Result<Arc<ZoneHandle>> {
        if let Some(h) = self.get_zone(zone_id) {
            return Ok(h);
        }
        self.create_zone(zone_id)
    }

    /// The network replica ID. Per-zone status reports the root's local ID.
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Tokio runtime handle — used by `ZoneHandle` construction + apply
    /// helpers that need to `block_on` raft proposals.
    pub fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.rt().handle().clone()
    }

    /// Internal runtime accessor.
    fn rt(&self) -> &tokio::runtime::Runtime {
        self.runtime.get()
    }

    /// The internal zone registry — kernel uses this for apply-cb
    /// installation (per v20.10 `install_federation_mount_coherence`).
    pub fn registry(&self) -> Arc<ZoneRaftRegistry> {
        self.registry.clone()
    }

    /// Every zone this node hosts, materialized or not.
    pub fn list_zones(&self) -> Vec<String> {
        self.registry.list_zones()
    }

    /// Does this node host `zone_id`? Catalog-only — never materializes.
    pub fn hosts_zone(&self, zone_id: &str) -> bool {
        self.registry.hosts(zone_id)
    }

    /// The replicated deletion epoch for `zone_id` (R12), via the
    /// registry's injected [`crate::zone_deletion_registry::DeletionEpochSource`].
    /// `None` = not deleted / source not wired — pre-R12 behavior.
    pub fn deletion_epoch(&self, zone_id: &str) -> Option<u64> {
        self.registry.deletion_epoch(zone_id)
    }

    /// R12's epoch comparison as the boot/guard facade: does the recorded
    /// deletion outrank this replica's on-disk `.creation-epoch`? Thin
    /// delegate to the registry's single implementation
    /// ([`ZoneRaftRegistry::deletion_outranks_disk`]) — every D9 guard and
    /// the CLI guard call THIS so the judgment cannot drift.
    pub fn deleted_newer_than_disk(&self, zone_id: &str) -> bool {
        self.registry.deletion_outranks_disk(zone_id)
    }

    /// `--force` escape hatch (R12/D9): stamp a FRESH creation epoch on this
    /// node's replica of `zone_id`, making any recorded deletion no longer
    /// outrank it. Called where a force boot chooses to resume/re-found a
    /// registry-deleted zone, so the operator's intent survives later
    /// sweeps WITHOUT depending on the boot sweep having deleted the stale
    /// dir first (which only happens when the local deletion record was
    /// already visible — a node whose control replica was behind would
    /// otherwise be torn down once it catches up).
    ///
    /// Best-effort, mirroring `setup_zone`'s marker write: a failure only
    /// degrades the resurrection check back to the old epoch. A missing
    /// zone dir is fine — the fresh-create path in `setup_zone` stamps the
    /// new epoch itself.
    pub fn bump_creation_epoch(&self, zone_id: &str) {
        // Wall-clock ms — the same epoch space `.creation-epoch` and the
        // replicated deletion epochs live in.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        match crate::raft::ZonePersistence::open(self.registry.base_path(), zone_id) {
            Ok(persistence) => {
                if let Err(e) = persistence.write_creation_epoch(now_ms) {
                    tracing::warn!(
                        zone = %zone_id,
                        error = %e,
                        "--force re-found: failed to bump creation-epoch (resurrection \
                         check keeps the old epoch for this replica)",
                    );
                } else {
                    tracing::info!(
                        zone = %zone_id,
                        "--force re-found: creation-epoch bumped — recorded deletion no \
                         longer outranks this replica",
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No dir yet: the fresh-create path stamps the epoch.
            }
            Err(e) => {
                tracing::warn!(
                    zone = %zone_id,
                    error = %e,
                    "--force re-found: could not open zone dir to bump creation-epoch",
                );
            }
        }
    }

    /// R12 sweep facade: run the deletion purge over the catalogued zones
    /// (see [`ZoneRaftRegistry::purge_deleted_zones`]). Boot and the
    /// daemon's periodic timer both go through this so the registry's
    /// internal interface stays behind the manager.
    pub fn purge_deleted_zones(&self) {
        self.registry.purge_deleted_zones(self.rt().handle());
    }

    /// Presence ladder for the typed ZoneStatus surface (R10): the registry
    /// distinguishes the durable catalog ("this node hosts the zone") from
    /// the runtime fact ("its raft group is currently resident"), and callers
    /// need both — `HOSTED_NOT_RESIDENT` is a healthy cold zone, not a
    /// missing one. DELETED is layered on by the deletion registry at the
    /// ZoneRuntimeBackend level; this method answers the local ladder only.
    pub fn zone_presence(&self, zone_id: &str) -> ZonePresence {
        if !self.registry.hosts(zone_id) {
            return ZonePresence::LocalNotFound;
        }
        if self.registry.is_resident(zone_id) {
            ZonePresence::Resident
        } else {
            ZonePresence::HostedNotResident
        }
    }

    /// Create a new zone (raft group) on this node, founded with this node
    /// as its sole voter. Idempotent — an existing zone returns its handle.
    pub fn create_zone(&self, zone_id: &str) -> Result<Arc<ZoneHandle>> {
        if let Some(existing) = self.get_zone(zone_id) {
            return Ok(existing);
        }
        let node = self
            .registry
            .create_zone(zone_id, self.rt().handle())
            .map_err(|e| zone_open_error(e, "Failed to create zone"))?;

        Ok(ZoneHandle::new(
            node,
            self.rt().handle().clone(),
            zone_id.to_string(),
        ))
    }

    /// Join an existing zone as a Voter (learner=false) or Learner (learner=true).
    ///
    /// Sets up the local Raft state machine with skip_bootstrap=true so the
    /// leader's snapshot installs the correct ConfState. The caller is
    /// responsible for sending a JoinZone RPC to the leader (via
    /// PyFederationClient::request_join_zone) with the same learner flag so
    /// the leader proposes AddNode vs AddLearnerNode accordingly.
    pub fn join_zone(&self, zone_id: &str, learner: bool) -> Result<Arc<ZoneHandle>> {
        // R12: the join path can never resurrect a deprovisioned zone —
        // a deletion epoch that outranks this replica's creation epoch
        // refuses the join outright (auto-rejoin against a stale identity
        // entry dies here, loudly). Escape hatch:
        // NEXUS_FORCE_DELETED_ZONE_RECREATE, which ALSO bumps the local
        // creation epoch so the operator's re-found survives later sweeps.
        if std::env::var_os("NEXUS_FORCE_DELETED_ZONE_RECREATE").is_some() {
            self.bump_creation_epoch(zone_id);
        } else if self.deleted_newer_than_disk(zone_id) {
            return Err(RaftError::InvalidState(format!(
                "Zone '{zone_id}' was deprovisioned (recorded deletion outranks this \
                 replica); refusing to join. Set NEXUS_FORCE_DELETED_ZONE_RECREATE=1 to \
                 override."
            )));
        }
        let node = self
            .registry
            .join_zone(zone_id, learner, self.rt().handle())
            .map_err(|e| zone_open_error(e, "Failed to join zone"))?;

        Ok(ZoneHandle::new(
            node,
            self.rt().handle().clone(),
            zone_id.to_string(),
        ))
    }

    /// Get an existing zone handle, or `None`.
    pub fn get_zone(&self, zone_id: &str) -> Option<Arc<ZoneHandle>> {
        self.registry
            .get_node(zone_id)
            .map(|node| ZoneHandle::new(node, self.rt().handle().clone(), zone_id.to_string()))
    }

    /// Static Day-1 cluster formation: idempotently create raft groups
    /// for every zone in the federation, then stage `mounts` for the
    /// next `apply_topology()` pass.
    ///
    /// All nodes in the cluster call this with identical parameters
    /// during startup. Each node initializes its own raft state machine
    /// for every zone (no cross-node consensus required at this stage —
    /// raft-rs handles election once peers can reach each other).
    ///
    /// `mounts` maps a global path to its target zone id (e.g.
    /// `{"/corp": "corp", "/corp/eng": "corp-eng"}`). Storage is purely
    /// in-memory; mounts are applied lazily by `apply_topology()` once
    /// the relevant parent + target leaders are reachable. Calling
    /// `bootstrap_static` again replaces the pending set.
    ///
    /// Mirrors Python `ZoneManager.bootstrap_static`. Idempotent.
    pub fn bootstrap_static(
        &self,
        zones: &[String],
        mounts: &BTreeMap<String, MountDecl>,
    ) -> Result<()> {
        // Zones skipped by the D9 guard below — mounts pointing at them are
        // dropped from the pending set, or the topology loop would chase a
        // target that never comes back (ensure_links_count fails forever,
        // apply_topology never converges, the data plane never reports
        // ready).
        let mut deprovisioned: std::collections::HashSet<String> = Default::default();
        for zone_id in zones {
            // Founding asks about EXISTENCE, not residency. A zone this node
            // already hosts needs nothing done to it, and materializing every
            // declared zone just to discover that would put the whole declared
            // topology back on the boot path — which is exactly the cost
            // on-demand materialization removes. A restart re-runs this with
            // the same `--cluster-init` list, so it is the hot case.
            if self.hosts_zone(zone_id) {
                tracing::debug!("Zone '{}' already hosted, skipping", zone_id);
                continue;
            }
            // D9 (R12): a zone whose recorded deletion outranks this
            // replica's creation epoch is NOT re-founded from a stale
            // topology declaration — skip it (fail-open, the rest of the
            // topology proceeds). Escape hatch:
            // NEXUS_FORCE_DELETED_ZONE_RECREATE=1, which also bumps the
            // local creation epoch so the re-found survives later sweeps.
            if std::env::var_os("NEXUS_FORCE_DELETED_ZONE_RECREATE").is_some() {
                self.bump_creation_epoch(zone_id);
            } else if self.deleted_newer_than_disk(zone_id) {
                tracing::error!(
                    zone = %zone_id,
                    "refusing to re-found a deprovisioned zone (fail-open: skipping this \
                     zone; set NEXUS_FORCE_DELETED_ZONE_RECREATE=1 to override)"
                );
                deprovisioned.insert(zone_id.clone());
                continue;
            }
            self.create_zone(zone_id)?;
        }
        let mut pending = self.pending_mounts.lock();
        pending.clear();
        for (path, decl) in mounts {
            if deprovisioned.contains(&decl.zone) {
                tracing::warn!(
                    path = %path,
                    target = %decl.zone,
                    "skipping declared mount: target zone was deprovisioned (D9 skip)"
                );
                continue;
            }
            // D9 for targets NOT declared in `zones`: `deprovisioned` above
            // only covers declared-and-skipped zones, so a
            // `--cluster-init-mount` pointing at an undeclared (already
            // deprovisioned) zone would otherwise stage a mount whose
            // write_mount_entry lands a dangling DT_MOUNT and whose
            // ensure_links_count defers forever — apply_topology never
            // converges. Same epoch comparison and same operator escape
            // hatch as the zones loop (no epoch bump here: this path does
            // not re-found the zone).
            else if std::env::var_os("NEXUS_FORCE_DELETED_ZONE_RECREATE").is_none()
                && self.deleted_newer_than_disk(&decl.zone)
            {
                tracing::warn!(
                    path = %path,
                    target = %decl.zone,
                    "skipping declared mount: target zone was deprovisioned (D9 skip)"
                );
                continue;
            }
            pending.insert(path.clone(), decl.clone());
        }
        Ok(())
    }

    /// Snapshot of mounts staged by `bootstrap_static` that have not
    /// yet been applied. Empty when topology has converged.
    pub fn pending_mounts(&self) -> BTreeMap<String, MountDecl> {
        self.pending_mounts.lock().clone()
    }

    /// Drive Day-1 topology toward convergence. Idempotent and
    /// crash-safe — every node calls this on a health-check tick;
    /// each writes only the zones for which it can reach the leader.
    /// Mirrors Python `ZoneManager._apply_topology` (the trickiest
    /// piece of the federation orchestrator).
    ///
    /// Steps:
    ///   1. Create the root "/" entry in `root_zone_id` if missing
    ///      (needs root-zone leader).
    ///   2. Walk pending mounts in path-depth order (parents first).
    ///      For each:
    ///        * Resolve the actual parent zone via longest-prefix
    ///          match against already-applied mounts (nested mount
    ///          handling: e.g. `/corp/eng` is owned by `corp`, not
    ///          root).
    ///        * Step 1 — DT_MOUNT write: write DT_DIR + DT_MOUNT in
    ///          the parent zone. Skipped if a DT_MOUNT to the same
    ///          target is already present (idempotency).
    ///        * Step 2 — link bump: bump the target zone's
    ///          `i_links_count` to reflect every pending mount
    ///          referencing it.
    ///   3. Per-mount errors leave that mount in `pending_mounts` for
    ///      the next call. Only `Ok(true)` indicates full convergence.
    pub fn apply_topology(&self, root_zone_id: &str) -> Result<bool> {
        // Root "/" entry must exist before any mount path resolution.
        if !self.ensure_root_entry(root_zone_id)? {
            return Ok(false);
        }

        let snapshot = self.pending_mounts.lock().clone();
        if snapshot.is_empty() {
            return Ok(true);
        }

        // Sort by path depth so a parent mount lands before its children
        // (longest-prefix nested mount resolution depends on it).
        let mut sorted: Vec<(String, MountDecl)> = snapshot.into_iter().collect();
        sorted.sort_by_key(|(path, _)| path.matches('/').count());

        // Per-target expected link counts: every pending mount pointing
        // at the same zone increments its i_links_count once.
        let mut expected: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        for (_, decl) in &sorted {
            *expected.entry(decl.zone.clone()).or_insert(0) += 1;
        }

        // `active` maps an applied mount path to the ZONE it mounts, which is
        // what longest-prefix parent resolution needs; `remaining` keeps the
        // whole declaration, because a retry must re-apply the same subtree.
        let mut active: BTreeMap<String, String> = BTreeMap::new();
        let mut remaining: BTreeMap<String, MountDecl> = BTreeMap::new();

        for (global_path, decl) in &sorted {
            let target_zone = decl.zone.as_str();
            // Resolve the parent zone via longest-prefix match against
            // already-applied mounts. Falls back to root.
            let mut parent_zone = root_zone_id.to_string();
            let mut local_path = global_path.clone();
            for (mp, mz) in active.iter().rev() {
                if global_path.len() > mp.len()
                    && global_path.starts_with(mp.as_str())
                    && global_path.as_bytes()[mp.len()] == b'/'
                {
                    parent_zone = mz.clone();
                    local_path = global_path[mp.len()..].to_string();
                    break;
                }
            }

            // Step 1: DT_MOUNT in parent zone, carrying the DECLARED subtree.
            // This is what keeps several mounts of one zone from aliasing.
            if let Err(err) =
                self.write_mount_entry(&parent_zone, &local_path, target_zone, &decl.subtree)
            {
                tracing::debug!(
                    "DT_MOUNT write deferred for {} (parent={} target={} subtree={}): {}",
                    global_path,
                    parent_zone,
                    target_zone,
                    decl.subtree,
                    err
                );
                remaining.insert(global_path.clone(), decl.clone());
                // Still treat as active so deeper mounts route correctly
                // once the DT_MOUNT write lands on a later tick.
                active.insert(global_path.clone(), target_zone.to_string());
                continue;
            }

            // Step 2: the subtree this mount exposes must exist as a directory
            // inside the target zone, or `readdir` of a mount with nothing
            // under it yet answers "not found" instead of "empty" — which
            // would make `agent_list` on a fresh cluster an error. The zone's
            // own `/` gets this from `ensure_root_entry`; before subtrees a
            // mount's listing landed there, so the guarantee held by accident.
            if decl.subtree != contracts::VFS_ROOT
                && !self.ensure_dir_entry(target_zone, &decl.subtree)?
            {
                remaining.insert(global_path.clone(), decl.clone());
                active.insert(global_path.clone(), target_zone.to_string());
                continue;
            }

            // Step 3: ensure target zone's i_links_count >= expected.
            let want = expected.get(target_zone).copied().unwrap_or(0);
            if let Err(err) = self.ensure_links_count(target_zone, want) {
                tracing::debug!(
                    "link-count bump deferred for {} (target={}): {}",
                    global_path,
                    target_zone,
                    err
                );
                remaining.insert(global_path.clone(), decl.clone());
                active.insert(global_path.clone(), target_zone.to_string());
                continue;
            }

            active.insert(global_path.clone(), target_zone.to_string());
        }

        let total = sorted.len();
        let pending_after = remaining.len();
        *self.pending_mounts.lock() = remaining;

        if pending_after == 0 {
            tracing::info!(
                "Static topology applied: {} mounts via raft consensus",
                total
            );
            Ok(true)
        } else {
            tracing::info!(
                "Topology progress: {}/{} mounts applied, {} pending",
                total - pending_after,
                total,
                pending_after,
            );
            Ok(false)
        }
    }

    /// Ensure the root `/` DT_DIR exists in `root_zone_id`. Returns
    /// `Ok(false)` if this node is not the leader yet (caller should
    /// retry on the next tick); `Ok(true)` once present.
    fn ensure_root_entry(&self, root_zone_id: &str) -> Result<bool> {
        self.ensure_dir_entry(root_zone_id, "/")
    }

    /// Ensure a DT_DIR exists at `key` in `zone_id`.
    ///
    /// `/` is the zone's own root ([`Self::ensure_root_entry`]); a non-root key
    /// is the root of the SUBTREE a mount exposes. Both need the same guarantee
    /// for the same reason: `readdir` of a directory that was never written
    /// answers "not found" rather than "empty", so a mount with nothing under
    /// it yet would make `agent_list` on a fresh cluster an error instead of an
    /// empty list.
    ///
    /// One function rather than two: before subtrees, a mount's listing landed
    /// on the zone root, which `ensure_root_entry` had already created — so the
    /// guarantee existed by accident of the key translation. Now that a mount
    /// keys under its own subtree, it has to be stated.
    ///
    /// Returns `Ok(false)` when this node cannot reach the leader yet; the
    /// topology tick retries.
    fn ensure_dir_entry(&self, zone_id: &str, key: &str) -> Result<bool> {
        let Some(node) = self.registry.get_node(zone_id) else {
            return Ok(false);
        };
        let handle = self.rt().handle().clone();

        let existing = bridge_block_on(
            &handle,
            node.with_state_machine(|sm: &FullStateMachine| sm.get_metadata(key)),
        )
        .map_err(|e| RaftError::Raft(format!("get metadata {key}: {}", e)))?;
        if existing.is_some() {
            return Ok(true);
        }

        // Try to write — propose forwards to leader if we're a follower
        // and reachable; errors mean leader unreachable / not elected.
        let bytes = encode_file_metadata(key, DT_DIR, zone_id, "");
        match propose_set_metadata(&handle, &node, key, bytes) {
            Ok(()) => {
                tracing::info!("'{key}' created in zone '{zone_id}'");
                Ok(true)
            }
            Err(err) => {
                tracing::debug!("'{key}' creation in zone '{zone_id}' deferred: {}", err);
                Ok(false)
            }
        }
    }

    /// Write a DT_MOUNT entry at `local_path` in `parent_zone`. No-op
    /// if a DT_MOUNT to the same `target_zone` is already present.
    /// Also auto-creates a DT_DIR placeholder if `local_path` is
    /// missing (mkdir -p semantics, matches `mount()` behavior).
    fn write_mount_entry(
        &self,
        parent_zone: &str,
        local_path: &str,
        target_zone: &str,
        target_subtree: &str,
    ) -> Result<()> {
        let parent_node = self.registry.get_node(parent_zone).ok_or_else(|| {
            RaftError::InvalidState(format!("Parent zone '{}' not found", parent_zone))
        })?;
        let handle = self.rt().handle().clone();

        let existing = bridge_block_on(
            &handle,
            parent_node.with_state_machine(|sm: &FullStateMachine| sm.get_metadata(local_path)),
        )
        .map_err(|e| RaftError::Raft(format!("get_metadata: {}", e)))?
        .map(|bytes| decode_file_metadata(&bytes))
        .transpose()
        .map_err(|e| RaftError::Raft(format!("decode existing: {}", e)))?;

        if let Some(ref meta) = existing {
            // The subtree is part of what this record SAYS, so a declaration
            // that changed it is not already applied. Comparing only the target
            // zone would silently keep an old whole-zone mount in place and the
            // aliasing with it.
            if meta.entry_type == DT_MOUNT
                && meta.target_zone_id == target_zone
                && meta.target_subtree == target_subtree
            {
                return Ok(());
            }
        } else {
            let dir_bytes = encode_file_metadata(local_path, DT_DIR, parent_zone, "");
            propose_set_metadata(&handle, &parent_node, local_path, dir_bytes)?;
        }

        let mount_bytes =
            encode_mount_metadata(local_path, parent_zone, target_zone, target_subtree);
        propose_set_metadata(&handle, &parent_node, local_path, mount_bytes)
    }

    /// Bump `target_zone`'s `i_links_count` if it is below `expected`.
    /// Idempotent: re-reads the counter after each propose so repeated
    /// calls converge without overshooting.
    fn ensure_links_count(&self, target_zone: &str, expected: i64) -> Result<()> {
        let target_node = self.registry.get_node(target_zone).ok_or_else(|| {
            RaftError::InvalidState(format!("Target zone '{}' not found", target_zone))
        })?;
        let handle = self.rt().handle().clone();
        let key = I_LINKS_COUNT_KEY.to_string();

        loop {
            let bytes = bridge_block_on(&handle, {
                let key = key.clone();
                let node = target_node.clone();
                async move {
                    node.with_state_machine(|sm: &FullStateMachine| sm.get_metadata(&key))
                        .await
                }
            })
            .map_err(|e| RaftError::Raft(format!("get_metadata: {}", e)))?;
            let current = bytes
                .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
                .map(i64::from_be_bytes)
                .unwrap_or(0);
            if current >= expected {
                return Ok(());
            }
            propose_adjust_counter(&handle, &target_node, I_LINKS_COUNT_KEY, expected - current)?;
            // Loop re-reads to confirm convergence (counter forwarding
            // returns Success without the new value, so we can't trust
            // the propose return).
        }
    }

    /// Read a zone's POSIX `i_links_count` (mount references).
    ///
    /// Returns `0` for zones that have never been mounted (key absent).
    /// Returns `Ok(None)` if the zone itself is not registered locally.
    pub fn get_links_count(&self, zone_id: &str) -> Result<Option<i64>> {
        let Some(node) = self.registry.get_node(zone_id) else {
            return Ok(None);
        };
        let key = I_LINKS_COUNT_KEY.to_string();
        let bytes = bridge_block_on(self.rt().handle(), async move {
            node.with_state_machine(|sm: &FullStateMachine| sm.get_metadata(&key))
                .await
        })?;
        let count = bytes
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(i64::from_be_bytes)
            .unwrap_or(0);
        Ok(Some(count))
    }

    /// Linearizable twin of [`Self::get_links_count`]: the ReadIndex barrier
    /// guarantees the value observes every write committed cluster-wide
    /// before the call (a plain local read on a FOLLOWER host lags the
    /// leader's apply by a raft tick — the same lag `poll_until_visible`
    /// exists for), so a guard decision made on it cannot miss an
    /// already-committed mount. One leader heartbeat round-trip, no log
    /// write — the same primitive `ControlStateStore::read_barrier` uses.
    pub fn get_links_count_linearizable(&self, zone_id: &str) -> Result<Option<i64>> {
        let Some(node) = self.registry.get_node(zone_id) else {
            return Ok(None);
        };
        let key = I_LINKS_COUNT_KEY.to_string();
        let bytes = bridge_block_on(self.rt().handle(), async move {
            node.read_linearizable(|sm: &FullStateMachine| sm.get_metadata(&key))
                .await?
        })?;
        let count = bytes
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(i64::from_be_bytes)
            .unwrap_or(0);
        Ok(Some(count))
    }

    /// Remove a zone — shut down transport loop, delete on-disk dir.
    ///
    /// POSIX semantics: when `force` is false, refuses removal while
    /// `i_links_count > 0` (i.e. the zone is still mounted somewhere).
    /// Mirrors Python `ZoneManager.remove_zone(force=...)`.
    pub fn remove_zone(&self, zone_id: &str, force: bool) -> Result<()> {
        // R12 entry guard — the registry's `remove_zone` re-checks this
        // (defense in depth), but refusing HERE keeps the reserved zone's
        // peer fan-out from ever starting.
        if contracts::RESERVED_ZONE_IDS.contains(&zone_id) {
            return Err(RaftError::InvalidState(format!(
                "Zone '{zone_id}' is reserved and cannot be removed"
            )));
        }
        if !force {
            if let Some(count) = self.get_links_count(zone_id)? {
                if count > 0 {
                    return Err(RaftError::InvalidState(format!(
                        "Zone '{}' still has {} reference(s) (i_links_count > 0); \
                         unmount all references first, or pass force=true.",
                        zone_id, count
                    )));
                }
            }
        }

        let peers = self.registry.get_peers(zone_id).unwrap_or_default();
        let self_id = self.registry.node_id();
        bridge_block_on(self.rt().handle(), async {
            for (peer_id, peer) in peers {
                if peer_id == self_id || peer.hostname.to_ascii_lowercase().starts_with("witness") {
                    continue;
                }
                let tls = self.registry.tls_config().map_err(RaftError::Config)?;
                call_delete_zone(&peer.endpoint, zone_id, force, tls, 10)
                    .await
                    .map_err(|e| {
                        RaftError::Raft(format!(
                            "Failed to remove zone '{zone_id}' from peer {}: {e}",
                            peer.endpoint
                        ))
                    })?;
            }
            Ok::<(), RaftError>(())
        })?;

        bridge_block_on(self.rt().handle(), self.registry.remove_zone(zone_id))
            .map_err(|e| RaftError::Raft(format!("Failed to remove zone: {}", e)))
    }

    /// R12 deprovision leg 1: best-effort peer fan-out of the local-destroy
    /// `DeleteZone` RPC. Unlike [`Self::remove_zone`]'s fail-hard fan-out,
    /// an unreachable peer is EXPECTED — a replica that was down when the
    /// zone was deprovisioned self-cleans at boot from the deletion epoch
    /// (the epoch is the authority; this call is only the fast path).
    pub(crate) fn fan_out_delete_best_effort(&self, zone_id: &str, force: bool) {
        let peers = self.registry.get_peers(zone_id).unwrap_or_default();
        let self_id = self.registry.node_id();
        let zid = zone_id.to_string();
        let handle = self.rt().handle().clone();
        bridge_block_on(&handle, async move {
            for (peer_id, peer) in peers {
                if peer_id == self_id || peer.hostname.to_ascii_lowercase().starts_with("witness") {
                    continue;
                }
                let tls = match self.registry.tls_config() {
                    Ok(tls) => tls,
                    Err(error) => {
                        tracing::warn!(zone = %zid, error = %error, "deprovision credentials unavailable");
                        return;
                    }
                };
                if let Err(e) = call_delete_zone(&peer.endpoint, &zid, force, tls, 10).await {
                    tracing::warn!(
                        zone = %zid,
                        peer = %peer.endpoint,
                        error = %e,
                        "deprovision fan-out missed a peer (it self-cleans from the \
                         deletion epoch at next boot)",
                    );
                }
            }
        });
    }

    /// R12 deprovision leg 2: LOCAL teardown only — no peer fan-out (the
    /// deprovision path fans out separately and best-effort, so an offline
    /// peer can never block the founder's own teardown).
    pub fn remove_local_zone(&self, zone_id: &str) -> Result<()> {
        if contracts::RESERVED_ZONE_IDS.contains(&zone_id) {
            return Err(RaftError::InvalidState(format!(
                "Zone '{zone_id}' is reserved and cannot be removed"
            )));
        }
        bridge_block_on(self.rt().handle(), self.registry.remove_zone(zone_id))
            .map_err(|e| RaftError::Raft(format!("Failed to remove zone: {}", e)))
    }

    /// Peer roster for a zone: `(id, hostname, endpoint, is_witness)`.
    /// Empty list if zone unknown. Witness = hostname starts with
    /// `witness` (convention).
    pub fn zone_peers(&self, zone_id: &str) -> Vec<(u64, String, String, bool)> {
        match self.registry.get_peers(zone_id) {
            None => Vec::new(),
            Some(peers) => peers
                .into_values()
                .map(|p| {
                    let is_witness = p.hostname.to_ascii_lowercase().starts_with("witness");
                    (p.id, p.hostname, p.endpoint, is_witness)
                })
                .collect(),
        }
    }

    /// One-shot authoritative status snapshot for one zone. See
    /// `ClusterStatus` docs.
    pub fn cluster_status(&self, zone_id: &str) -> ClusterStatus {
        let Some(node) = self.registry.get_node(zone_id) else {
            return ClusterStatus {
                zone_id: zone_id.to_string(),
                node_id: self.registry.node_id_for_zone(zone_id),
                has_store: false,
                is_leader: false,
                leader_id: 0,
                term: 0,
                commit_index: 0,
                applied_index: 0,
                voter_count: 0,
                witness_count: 0,
                leader_contact_age_ms: None,
            };
        };
        // Membership SSOT is raft's ConfState (the authoritative voter set),
        // NOT the transport peer address book. Iterate `node.voters()` —
        // learners are already excluded (they never count toward quorum). The
        // peer map is consulted only to classify each voter as witness-vs-full
        // by advertised hostname. Self is a voter but is never in the peer map
        // (PeerMap invariant — self is a ConfState member, not a transport
        // peer), and a ZoneManager node is never a witness, so self — and any
        // voter whose address is not yet learned — counts as a full voter.
        let (mut voter_count, mut witness_count) = (0usize, 0usize);
        let peers = self.registry.get_peers(zone_id).unwrap_or_default();
        for id in node.voters() {
            let is_witness = peers
                .get(&id)
                .map(|p| p.hostname.to_ascii_lowercase().starts_with("witness"))
                .unwrap_or(false);
            if is_witness {
                witness_count += 1;
            } else {
                voter_count += 1;
            }
        }
        ClusterStatus {
            zone_id: zone_id.to_string(),
            node_id: node.id(),
            has_store: true,
            is_leader: node.is_leader(),
            leader_id: node.leader_id().unwrap_or(0),
            term: node.term(),
            commit_index: node.commit_index(),
            applied_index: node.applied_index(),
            voter_count,
            witness_count,
            leader_contact_age_ms: node.leader_contact_age().map(|age| age.as_millis() as u64),
        }
    }

    /// Find which zone stores metadata for `path`; `(zone_id, bytes)`.
    /// Iterates the live registry; used by federation join / nested
    /// mount resolution where a root-only lookup would miss.
    pub fn lookup_path(&self, path: &str) -> Result<Option<(String, Vec<u8>)>> {
        let registry = self.registry.clone();
        let path = path.to_string();
        bridge_block_on(self.rt().handle(), async move {
            for zone_id in registry.list_zones() {
                let Some(node) = registry.get_node(&zone_id) else {
                    continue;
                };
                let found = node
                    .with_state_machine(|sm: &FullStateMachine| sm.get_metadata(&path))
                    .await;
                match found {
                    Ok(Some(bytes)) => return Ok(Some((zone_id, bytes))),
                    Ok(None) => continue,
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            Ok(None)
        })
    }

    /// Mount target zone at `mount_path` inside parent zone (NFS-style).
    ///
    /// Writes a DT_MOUNT FileMetadata entry at `mount_path` in the
    /// parent zone's raft-replicated metastore, then bumps the target
    /// zone's `__i_links_count__`. Auto-creates a DT_DIR at
    /// `mount_path` if absent. Idempotent when already DT_MOUNT to the
    /// same target.
    pub fn mount(
        &self,
        parent_zone_id: &str,
        mount_path: &str,
        target_zone_id: &str,
        increment_links: bool,
    ) -> Result<()> {
        self.mount_subtree(
            parent_zone_id,
            mount_path,
            target_zone_id,
            contracts::VFS_ROOT,
            increment_links,
        )
    }

    /// Like [`Self::mount`], but exposing only `target_subtree` of the target
    /// zone.
    ///
    /// A separate entry point for the same reason `ZoneMetaStore` has one:
    /// every existing caller mounts a WHOLE zone, and making them all say `"/"`
    /// would be one more place for one of them to say something else. The
    /// subtree is what keeps several mounts of ONE zone from aliasing
    /// (nexi-lab/nexus-vfs#361).
    pub fn mount_subtree(
        &self,
        parent_zone_id: &str,
        mount_path: &str,
        target_zone_id: &str,
        target_subtree: &str,
        increment_links: bool,
    ) -> Result<()> {
        let parent_node = self.registry.get_node(parent_zone_id).ok_or_else(|| {
            RaftError::InvalidState(format!("Parent zone '{}' not found", parent_zone_id))
        })?;
        let target_node = self.registry.get_node(target_zone_id).ok_or_else(|| {
            RaftError::InvalidState(format!("Target zone '{}' not found", target_zone_id))
        })?;
        // R12: a deprovisioned target must not gain a mount. A RESIDENT
        // target bypasses the cold-boot materialize gate (that gate only
        // sees zones materializing from disk), so the deletion check is
        // repeated here — the same epoch-vs-creation comparison the boot
        // and purge paths use. This closes the mount side of the
        // deprovision/mount race to the (replication-lag + interleave)
        // window shared by both checks.
        if self.deleted_newer_than_disk(target_zone_id) {
            return Err(RaftError::InvalidState(format!(
                "Target zone '{}' was deprovisioned; mount refused",
                target_zone_id
            )));
        }

        let handle = self.rt().handle().clone();

        let existing = bridge_block_on(
            &handle,
            parent_node.with_state_machine(|sm: &FullStateMachine| sm.get_metadata(mount_path)),
        )
        .map_err(|e| RaftError::Raft(format!("get_metadata: {}", e)))?
        .map(|bytes| decode_file_metadata(&bytes))
        .transpose()
        .map_err(|e| RaftError::Raft(format!("decode existing: {}", e)))?;

        if let Some(ref meta) = existing {
            if meta.entry_type == DT_MOUNT {
                if meta.target_zone_id == target_zone_id {
                    // The subtree is part of a mount's identity (a whole-zone
                    // mount and a subtree mount of the same zone are
                    // DIFFERENT mounts — write_mount_entry compares both on
                    // the topology path). Answering idempotent-success for a
                    // same-target/different-subtree request would report a
                    // mount that was not made; upgrading in place instead
                    // would double-count the target's i_links (this path
                    // has no ensure_links_count reconciliation), so a
                    // subtree change is a refusal: unmount first.
                    if meta.target_subtree == target_subtree {
                        // Idempotent.
                        return Ok(());
                    }
                    return Err(RaftError::InvalidState(format!(
                        "Mount point '{}' already mounts a different subtree of zone '{}' \
                         ('{}' != '{}'); unmount first",
                        mount_path, target_zone_id, meta.target_subtree, target_subtree
                    )));
                }
                return Err(RaftError::InvalidState(format!(
                    "Mount point '{}' is already a DT_MOUNT in zone '{}'. Unmount first.",
                    mount_path, parent_zone_id
                )));
            }
            if meta.entry_type != DT_DIR {
                return Err(RaftError::InvalidState(format!(
                    "Mount point '{}' is not a directory (type={}) in zone '{}'. \
                     Mount points must be directories.",
                    mount_path, meta.entry_type, parent_zone_id
                )));
            }
        } else {
            // Auto-create DT_DIR (mkdir -p semantics).
            let dir_bytes = encode_file_metadata(mount_path, DT_DIR, parent_zone_id, "");
            propose_set_metadata(&handle, &parent_node, mount_path, dir_bytes)?;
        }

        // Replace DT_DIR with DT_MOUNT (shadows original contents).
        let mount_bytes =
            encode_mount_metadata(mount_path, parent_zone_id, target_zone_id, target_subtree);
        propose_set_metadata(&handle, &parent_node, mount_path, mount_bytes)?;

        if increment_links {
            propose_adjust_counter(&handle, &target_node, I_LINKS_COUNT_KEY, 1)?;
        }

        Ok(())
    }

    /// Remove a mount point, restoring DT_DIR. Returns the former
    /// target zone id so the caller can decrement remote links.
    pub fn unmount(&self, parent_zone_id: &str, mount_path: &str) -> Result<Option<String>> {
        let parent_node = self.registry.get_node(parent_zone_id).ok_or_else(|| {
            RaftError::InvalidState(format!("Parent zone '{}' not found", parent_zone_id))
        })?;
        let handle = self.rt().handle().clone();
        let registry = self.registry.clone();

        let existing = bridge_block_on(
            &handle,
            parent_node.with_state_machine(|sm: &FullStateMachine| sm.get_metadata(mount_path)),
        )
        .map_err(|e| RaftError::Raft(format!("get_metadata: {}", e)))?
        .map(|bytes| decode_file_metadata(&bytes))
        .transpose()
        .map_err(|e| RaftError::Raft(format!("decode existing: {}", e)))?;

        let existing = match existing {
            Some(m) if m.entry_type == DT_MOUNT => m,
            _ => {
                return Err(RaftError::InvalidState(format!(
                    "'{}' is not a mount point in zone '{}'",
                    mount_path, parent_zone_id
                )));
            }
        };

        let target_zone_id_opt: Option<String> = if existing.target_zone_id.is_empty() {
            None
        } else {
            Some(existing.target_zone_id.clone())
        };

        // Restore DT_DIR at the mount point.
        let dir_bytes = encode_file_metadata(mount_path, DT_DIR, parent_zone_id, "");
        propose_set_metadata(&handle, &parent_node, mount_path, dir_bytes)?;

        if let Some(ref target_id) = target_zone_id_opt {
            if let Some(target_node) = registry.get_node(target_id) {
                propose_adjust_counter(&handle, &target_node, I_LINKS_COUNT_KEY, -1)?;
            }
            // Target not locally hosted → remote leader's job.
        }

        Ok(target_zone_id_opt)
    }

    /// Every metadata row under `normalized_prefix` in `parent_zone_id`.
    ///
    /// The ONE scan behind both "what would a share copy" and "how many are there".
    /// Sharing what a separate count promised requires the prefix rule to be the same
    /// rule — two spellings of [`path_matches_prefix`] would let a pre-flight check
    /// green-light a share that copies something else.
    ///
    /// A local, leader-free read: sequential consistency on the parent zone, no
    /// propose, so a caller may ask before the target zone exists.
    fn subtree_entries(
        &self,
        parent_zone_id: &str,
        normalized_prefix: &str,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let parent_node = self.registry.get_node(parent_zone_id).ok_or_else(|| {
            RaftError::InvalidState(format!("Parent zone '{parent_zone_id}' not found"))
        })?;
        let scan_prefix = if normalized_prefix.is_empty() {
            "/".to_string()
        } else {
            normalized_prefix.to_string()
        };
        let handle = self.rt().handle().clone();
        let entries = bridge_block_on(
            &handle,
            parent_node
                .with_state_machine(move |sm: &FullStateMachine| sm.list_metadata(&scan_prefix)),
        )
        .map_err(|e| RaftError::Raft(format!("list_metadata: {e}")))?;
        Ok(entries
            .into_iter()
            .filter(|(path, _)| path_matches_prefix(path, normalized_prefix))
            .collect())
    }

    /// How many metadata entries live under `prefix` in `parent_zone_id`.
    ///
    /// Exposed so a caller can decide whether a share is worth doing BEFORE the
    /// target zone exists: creating the zone first makes "it copied nothing" a
    /// discovery you make too late, with an orphan raft group already mounted behind
    /// a path that was never there.
    ///
    /// Zero means "nothing there", and deliberately does not distinguish an empty
    /// directory from a missing one: the state machine holds metadata rows, not
    /// directory objects, so at this layer those are the same observation. A caller
    /// that cares treats zero as a question for the operator.
    ///
    /// # Errors
    ///
    /// When `prefix` is unusable, `parent_zone_id` is not a zone this node hosts, or
    /// the state-machine read fails.
    pub fn subtree_entry_count(&self, parent_zone_id: &str, prefix: &str) -> Result<usize> {
        let normalized_prefix = normalize_subtree_prefix(prefix)?;
        Ok(self
            .subtree_entries(parent_zone_id, &normalized_prefix)?
            .len())
    }

    /// Copy every FileMetadata entry under `prefix` in `parent_zone_id`
    /// into `new_zone_id` with path rebased; bump `i_links_count` on
    /// every locally-hosted nested DT_MOUNT target. Returns count.
    pub fn share_subtree_core(
        &self,
        parent_zone_id: &str,
        prefix: &str,
        new_zone_id: &str,
    ) -> Result<usize> {
        let new_node = self.registry.get_node(new_zone_id).ok_or_else(|| {
            RaftError::InvalidState(format!(
                "Target zone '{}' not found (was create_zone called?)",
                new_zone_id
            ))
        })?;

        // share_subtree_core writes (`propose_set_metadata`) target
        // ``new_node``, which is leader-required.  ``parent_node`` is
        // only read via ``with_state_machine`` (sequential-consistency
        // local read — no leader needed).  Offline callers (e.g.
        // ``nexusd-cluster share``) hit this immediately after
        // ``create_zone``: the new 1-voter raft tick driver has not
        // yet run its election cycle, so the first propose lands
        // before ``cached_role`` is set to ``LEADER`` and fails with
        // ``NotLeader { leader_hint: Some(self_id) }``.  Wait once,
        // here, so every caller (offline CLI, online RPC, future
        // binding) is safe by construction — single SSOT for this
        // precondition rather than per-caller defensive waits.
        //
        // 10 s covers ~60 election windows; a 1-voter zone that has
        // not elected itself within that timeframe means the raft
        // tick driver did not start, which is a fatal bug worth
        // failing loud about.
        if !new_node.wait_for_leader(std::time::Duration::from_secs(10)) {
            return Err(RaftError::Raft(format!(
                "share_subtree_core: new zone '{}' did not elect self as leader \
                 within 10s (leader hint: {:?}); raft tick driver may not be running",
                new_zone_id,
                new_node.leader_id(),
            )));
        }

        let normalized_prefix = normalize_subtree_prefix(prefix)?;
        let entries = self.subtree_entries(parent_zone_id, &normalized_prefix)?;

        let handle = self.rt().handle().clone();
        let registry = self.registry.clone();

        let mut copied: usize = 0;
        let mut nested_mount_targets: Vec<String> = Vec::new();
        let mut root_written = false;

        for (path, value) in entries {
            let proto = match decode_file_metadata(&value) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        zone = %parent_zone_id,
                        path = %path,
                        error = %e,
                        "share_subtree: skipping entry with undecodable FileMetadata",
                    );
                    continue;
                }
            };

            let (rebased_path, rebased_entry_type) = if path == normalized_prefix {
                root_written = true;
                ("/".to_string(), DT_DIR)
            } else {
                let mut relative = path[normalized_prefix.len()..].to_string();
                if !relative.starts_with('/') {
                    relative.insert(0, '/');
                }
                if proto.entry_type == DT_MOUNT && !proto.target_zone_id.is_empty() {
                    nested_mount_targets.push(proto.target_zone_id.clone());
                }
                (relative, proto.entry_type)
            };

            // Clone every existing field (content_id / size / mime_type / timestamps /
            // permissions) so readers on the new zone can find the CAS blob
            // and serve reads. Only `path`, `zone_id`, and `entry_type` are
            // overridden for the rebased copy. The previous call went through
            // `encode_file_metadata` which took a six-arg subset and dropped
            // every other field — the shared file showed up in sys_stat but
            // had `content_id=None`, so `try_remote_fetch` couldn't look up the
            // CAS hash and cross-node reads failed with "File not found".
            use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
            use prost::Message;
            let rebased_proto = ProtoFileMetadata {
                path: rebased_path.clone(),
                zone_id: new_zone_id.to_string(),
                entry_type: rebased_entry_type,
                ..proto
            };
            let rebased_bytes = rebased_proto.encode_to_vec();
            propose_set_metadata(&handle, &new_node, &rebased_path, rebased_bytes)?;
            copied += 1;
        }

        if !root_written {
            let root_bytes = encode_file_metadata("/", DT_DIR, new_zone_id, "");
            propose_set_metadata(&handle, &new_node, "/", root_bytes)?;
        }

        for target_id in &nested_mount_targets {
            if let Some(target_node) = registry.get_node(target_id) {
                propose_adjust_counter(&handle, &target_node, I_LINKS_COUNT_KEY, 1)?;
            }
        }

        Ok(copied)
    }

    // ── Shared-zone registry (peer discovery) ────────────────────────
    //
    // SSOT for federation share metadata lives in the root zone's raft
    // state machine, keyed under `SHARE_REGISTRY_PREFIX + origin_path`.
    // One `FileMetadata` row per shared subtree carries
    // `target_zone_id = new_zone_id`.  Because the root zone is raft-
    // replicated to every cluster member, a peer that wants to join a
    // shared zone just queries its **local** root-zone state — no
    // separate peer-discovery RPC needed.

    /// Canonical registry key for `origin_path`.
    fn share_registry_key(origin_path: &str) -> String {
        // Concatenate the reserved prefix with the absolute origin path.
        // Origin paths are VFS-global ("/corp/eng/shared-X") → result is
        // "/__shares__/corp/eng/shared-X". Empty / non-absolute inputs
        // fall back to prefix itself (caller should have validated).
        if origin_path.is_empty() || !origin_path.starts_with('/') {
            contracts::SHARE_REGISTRY_PREFIX.to_string()
        } else {
            format!("{}{}", contracts::SHARE_REGISTRY_PREFIX, origin_path)
        }
    }

    /// Register `origin_path → zone_id` in the root zone's share
    /// registry.  Must be called on the raft leader (propose forwards
    /// to leader on follower, so follower-side calls also work but
    /// incur one extra RPC hop).  Idempotent: re-registering the same
    /// pair is a no-op at steady state (raft log gets a duplicate
    /// SetMetadata, state machine settles to the same value).
    pub fn register_share(&self, origin_path: &str, zone_id: &str) -> Result<()> {
        let root = self
            .registry
            .get_node(contracts::ROOT_ZONE_ID)
            .ok_or_else(|| {
                RaftError::InvalidState(
                    "root zone not found — share registry requires a live root raft group"
                        .to_string(),
                )
            })?;
        let key = Self::share_registry_key(origin_path);
        // Encode as a DT_REG FileMetadata; target_zone_id carries the
        // advertised zone. backend_name is a marker that tells readers
        // "this is a share registry row, not a user inode".
        let value = encode_file_metadata(&key, DT_REG, contracts::ROOT_ZONE_ID, zone_id);
        let handle = self.rt().handle().clone();
        propose_set_metadata(&handle, &root, &key, value)
    }

    /// Resolve `origin_path` back to the zone id a peer shared it as.
    /// Returns `None` when no share has been registered for that path
    /// (caller treats as "zone not advertised").
    pub fn lookup_share(&self, origin_path: &str) -> Result<Option<String>> {
        let root = self
            .registry
            .get_node(contracts::ROOT_ZONE_ID)
            .ok_or_else(|| {
                RaftError::InvalidState(
                    "root zone not found — share registry requires a live root raft group"
                        .to_string(),
                )
            })?;
        let key = Self::share_registry_key(origin_path);
        let handle = self.rt().handle().clone();
        let bytes = bridge_block_on(
            &handle,
            root.with_state_machine(move |sm: &FullStateMachine| sm.get_metadata(&key)),
        )
        .map_err(|e| RaftError::Raft(format!("lookup_share: {}", e)))?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let proto = decode_file_metadata(&bytes).map_err(|e| {
            RaftError::InvalidState(format!("share registry row decode failed: {}", e))
        })?;
        if proto.target_zone_id.is_empty() {
            Ok(None)
        } else {
            Ok(Some(proto.target_zone_id))
        }
    }

    /// Gracefully shut down all zones and the gRPC server.
    pub fn shutdown(&self) {
        bridge_block_on(self.rt().handle(), async {
            if let Some(tx) = self.shutdown_tx.lock().await.take() {
                let _ = tx.send(true);
            }
            self.registry.shutdown_all_and_wait().await;
        });
        tracing::info!("ZoneManager local_node_id={} shut down", self.node_id);
    }
}

// ── Async wrappers for `#[tokio::main]` callers ───────────────────
//
// `ZoneManager` exposes the sync façade above for callers that drive
// it from a sync context — the `DistributedCoordinator` trait impl
// reached from `Kernel::setattr_mount` (sync because the kernel is
// sync), and tests / founder paths that build their runtime around
// `main()`.
//
// `nexusd-cluster`'s `run_daemon` / `run_share` / `run_join` are
// `#[tokio::main]` async, so calling the sync methods from them
// needs a `spawn_blocking` hop off the
// async worker — otherwise the inner runtime's `block_on` from
// `bridge_block_on` panics if its `block_in_place` releases a worker
// holding an `Arc<Runtime>` referent (same panic shape PR #4011
// introduced `spawn_blocking` for `bootstrap_or_join_zone`).
//
// Rather than push that `spawn_blocking` pattern onto every async call
// site (DRY violation + repeated leaky abstraction), host one wrapper
// per affected method here.  Sync API, `bridge_block_on`,
// `propose_set_metadata`, runtime ownership, and `Drop` semantics are
// all unchanged — zero raft contract risk; the wrappers only add an
// async-friendly entry point.
//
// Only methods that internally (directly or transitively) use
// `bridge_block_on` get a wrapper.  Pure state-read methods like
// `pending_mounts` (mutex lock only, no nested runtime) are safe to
// call from async contexts unwrapped.
impl ZoneManager {
    /// Async wrapper for [`Self::mount`].
    pub async fn mount_async(
        self: &Arc<Self>,
        parent_zone_id: &str,
        mount_path: &str,
        target_zone_id: &str,
        increment_links: bool,
    ) -> Result<()> {
        let this = Arc::clone(self);
        let parent = parent_zone_id.to_string();
        let path = mount_path.to_string();
        let target = target_zone_id.to_string();
        tokio::task::spawn_blocking(move || this.mount(&parent, &path, &target, increment_links))
            .await
            .map_err(|e| RaftError::InvalidState(format!("mount_async task panicked: {e}")))?
    }

    /// Async wrapper for [`Self::mount_subtree`].
    ///
    /// A joiner needs this, not [`Self::mount_async`]: it mounts what the
    /// founder PUBLISHED, and a joiner that defaulted to the whole zone while
    /// the founder declared a subtree would translate the same path to a
    /// different key and the two would diverge silently.
    pub async fn mount_subtree_async(
        self: &Arc<Self>,
        parent_zone_id: &str,
        mount_path: &str,
        target_zone_id: &str,
        target_subtree: &str,
        increment_links: bool,
    ) -> Result<()> {
        let this = Arc::clone(self);
        let parent = parent_zone_id.to_string();
        let path = mount_path.to_string();
        let target = target_zone_id.to_string();
        let subtree = target_subtree.to_string();
        tokio::task::spawn_blocking(move || {
            this.mount_subtree(&parent, &path, &target, &subtree, increment_links)
        })
        .await
        .map_err(|e| RaftError::InvalidState(format!("mount_subtree_async task panicked: {e}")))?
    }

    /// Async wrapper for [`Self::create_zone`].
    pub async fn create_zone_async(self: &Arc<Self>, zone_id: &str) -> Result<Arc<ZoneHandle>> {
        let this = Arc::clone(self);
        let zone_id = zone_id.to_string();
        tokio::task::spawn_blocking(move || this.create_zone(&zone_id))
            .await
            .map_err(|e| RaftError::InvalidState(format!("create_zone_async task panicked: {e}")))?
    }

    /// Async wrapper for [`Self::share_subtree_core`].
    pub async fn share_subtree_core_async(
        self: &Arc<Self>,
        parent_zone_id: &str,
        prefix: &str,
        new_zone_id: &str,
    ) -> Result<usize> {
        let this = Arc::clone(self);
        let parent = parent_zone_id.to_string();
        let prefix = prefix.to_string();
        let new_zone = new_zone_id.to_string();
        tokio::task::spawn_blocking(move || this.share_subtree_core(&parent, &prefix, &new_zone))
            .await
            .map_err(|e| {
                RaftError::InvalidState(format!("share_subtree_core_async task panicked: {e}"))
            })?
    }

    /// Async wrapper for [`Self::bootstrap_static`].
    pub async fn bootstrap_static_async(
        self: &Arc<Self>,
        zones: Vec<String>,
        mounts: BTreeMap<String, MountDecl>,
    ) -> Result<()> {
        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || this.bootstrap_static(&zones, &mounts))
            .await
            .map_err(|e| {
                RaftError::InvalidState(format!("bootstrap_static_async task panicked: {e}"))
            })?
    }

    /// Async wrapper for [`Self::apply_topology`].
    pub async fn apply_topology_async(self: &Arc<Self>, root_zone_id: &str) -> Result<bool> {
        let this = Arc::clone(self);
        let root = root_zone_id.to_string();
        tokio::task::spawn_blocking(move || this.apply_topology(&root))
            .await
            .map_err(|e| {
                RaftError::InvalidState(format!("apply_topology_async task panicked: {e}"))
            })?
    }
}

impl Drop for ZoneManager {
    fn drop(&mut self) {
        self.registry.shutdown_all();
        // Best-effort shutdown signal.
        if let Ok(mut guard) = self.shutdown_tx.try_lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(true);
            }
        }
        // The inner runtime shuts itself down context-correctly — see the `runtime`
        // field.
    }
}

// ── Join-cluster helper (pre-ZoneManager-exists TLS bootstrap) ────────

/// K3s-style join: generate this node's key, have the leader certify it for
/// the persisted opaque Node ID (token-authorized), verify the CA fingerprint
/// from the join token, and write `ca.pem` / `node.pem` / `node-key.pem` into
/// `<data_dir>/tls`. The key never leaves this node. Called BEFORE ZoneManager
/// exists.
pub fn join_cluster_and_provision_tls(
    peer_address: &str,
    join_token: &str,
    data_dir: &std::path::Path,
) -> Result<()> {
    let token_prefix = "K10";
    let separator = "::server:";
    if !join_token.starts_with(token_prefix) {
        return Err(RaftError::Config(
            "Invalid join token: must start with 'K10'".to_string(),
        ));
    }
    let body = &join_token[token_prefix.len()..];
    let sep_pos = body.find(separator).ok_or_else(|| {
        RaftError::Config("Invalid join token: missing '::server:' separator".to_string())
    })?;
    let password = &body[..sep_pos];
    let expected_fingerprint = &body[sep_pos + separator.len()..];

    if password.is_empty() {
        return Err(RaftError::Config(
            "Invalid join token: empty password".to_string(),
        ));
    }
    if !expected_fingerprint.starts_with("SHA256:") {
        return Err(RaftError::Config(
            "Invalid join token: fingerprint must start with 'SHA256:'".to_string(),
        ));
    }

    let data_path = data_dir
        .to_str()
        .ok_or_else(|| RaftError::Config("data directory must be UTF-8".into()))?;
    let node_id = crate::distributed_coordinator::read_or_mint_node_id(data_path)
        .map_err(RaftError::Config)?;

    let endpoint = if peer_address.starts_with("http") {
        peer_address.to_string()
    } else {
        format!("http://{}", peer_address)
    };

    // Owned (see `OwnedRuntime`) so the `?`s below — a refused RPC, a CA fingerprint
    // that does not match, an unwritable TLS dir — report their reason instead of
    // panicking on this runtime's drop while unwinding.
    //
    // Driven with `Runtime::block_on`, NOT `bridge_block_on`: this runtime is
    // current-thread, so nothing but this call drives its IO driver, and a
    // `Handle::block_on` from elsewhere would poll the future while the connect it is
    // waiting on is never polled at all — boot hangs at "auto-enrolling" until the
    // budget expires. Callers reach this from a blocking context (where
    // `Runtime::block_on` is legal) for exactly that reason.
    let runtime = OwnedRuntime::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| RaftError::Config(format!("Failed to create runtime: {}", e)))?,
    );

    let (csr_pem, key_pem) =
        crate::transport::generate_node_key_request().map_err(RaftError::Config)?;
    let result = runtime
        .block_on(call_join_cluster(
            &endpoint, node_id, "", "root", password, &csr_pem, 30,
        ))
        .map_err(|e| RaftError::Raft(format!("JoinCluster RPC failed: {}", e)))?;

    let ca_fingerprint = crate::transport::certgen::ca_fingerprint_from_pem(&result.ca_pem)
        .map_err(|e| RaftError::Raft(format!("Failed to compute CA fingerprint: {}", e)))?;
    if ca_fingerprint != expected_fingerprint {
        return Err(RaftError::Raft(format!(
            "CA fingerprint mismatch: expected '{}', got '{}'",
            expected_fingerprint, ca_fingerprint
        )));
    }

    let dir = data_dir.join("tls");
    std::fs::create_dir_all(&dir)
        .map_err(|e| RaftError::Config(format!("Failed to create TLS dir: {}", e)))?;

    std::fs::write(dir.join("ca.pem"), &result.ca_pem)
        .map_err(|e| RaftError::Config(format!("Failed to write ca.pem: {}", e)))?;
    crate::transport::persist_node_identity(&dir, &result.node_cert_pem, &key_pem)
        .map_err(RaftError::Config)?;

    // Persist the cluster API-key secret (if the founder served one) to the
    // single SSOT `tls/api-key-secret`, so this joiner authenticates
    // cluster-minted `sk-` keys with NO local `NEXUS_API_KEY_SECRET`. Absent ⇒
    // founder is auth-off, so write nothing and the joiner stays auth-off too.
    if let Some(secret) = &result.api_key_secret {
        lib::transport_primitives::write_secret(&dir.join("api-key-secret"), secret.as_bytes())
            .map_err(|e| RaftError::Config(format!("Failed to write api-key-secret: {}", e)))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn renewal_fixture() -> (TempDir, Arc<ZoneManager>, TlsConfig, TlsConfig) {
        let directory = TempDir::new().unwrap();
        let (ca, ca_key) = crate::transport::generate_zone_ca("root").unwrap();
        let identity = || {
            let (cert_pem, key_pem) =
                crate::transport::generate_node_cert(7, "root", &ca, &ca_key, &[], None).unwrap();
            TlsConfig {
                cert_pem,
                key_pem,
                ca_pem: ca.clone(),
            }
        };
        let initial = identity();
        let files = TlsFiles {
            cert_path: directory.path().join("node.pem"),
            key_path: directory.path().join("node-key.pem"),
            ca_path: directory.path().join("ca.pem"),
            ca_key_path: None,
            join_token_hash: None,
        };
        std::fs::write(&files.cert_path, &initial.cert_pem).unwrap();
        lib::transport_primitives::write_secret(&files.key_path, &initial.key_pem).unwrap();
        std::fs::write(&files.ca_path, &initial.ca_pem).unwrap();
        let manager = ZoneManager::with_node_id(
            "test-host",
            7,
            directory.path().join("data").to_str().unwrap(),
            Vec::new(),
            "127.0.0.1:0",
            Some(files),
            None,
            None,
        )
        .unwrap();
        (directory, manager, initial, identity())
    }

    #[test]
    fn renewal_publishes_one_shared_installation_after_key_validation() {
        let (_directory, manager, initial, next) = renewal_fixture();
        let credentials = manager.registry().shared_tls();
        let original = credentials.snapshot();
        let mut wrong_key = next.clone();
        wrong_key.key_pem = initial.key_pem;
        assert!(manager.install_node_identity(wrong_key).is_err());
        assert!(credentials.is_current(&original));

        manager.install_node_identity(next.clone()).unwrap();
        assert!(!credentials.is_current(&original));
        assert_eq!(manager.node_tls().unwrap(), Some(next.clone()));
        assert_eq!(credentials.snapshot().config().unwrap(), Some(&next));
        credentials.replace(lib::transport_primitives::TlsPolicy::Rejected("revoked"));
        assert_eq!(manager.node_tls(), Err("revoked".into()));
        assert!(manager.install_node_identity(next).is_err());
        assert_eq!(manager.node_tls(), Err("revoked".into()));
    }

    #[test]
    fn renewal_preserves_rejection_or_replacement_during_validation() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_directory, manager, initial, next) = renewal_fixture();
        let notifications = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&notifications);
        manager.on_node_identity(Box::new(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
        }));
        let credentials = manager.registry().shared_tls();
        let original = credentials.snapshot();
        credentials.replace(lib::transport_primitives::TlsPolicy::Configured(
            initial.clone(),
        ));
        let reinstalled = credentials.snapshot();
        assert_eq!(
            manager.install_node_identity_from(&original, next.clone()),
            Err("Node credential installation changed during renewal validation".into())
        );
        assert!(credentials.is_current(&reinstalled));
        assert_eq!(manager.node_tls().unwrap(), Some(initial.clone()));
        credentials.replace(lib::transport_primitives::TlsPolicy::Rejected("revoked"));
        assert_eq!(
            manager.install_node_identity_from(&reinstalled, next.clone()),
            Err("Node credential installation changed during renewal validation".into())
        );
        assert_eq!(manager.node_tls(), Err("revoked".into()));
        assert_eq!(notifications.load(Ordering::SeqCst), 0);

        credentials.replace(lib::transport_primitives::TlsPolicy::Configured(initial));
        manager.install_node_identity(next.clone()).unwrap();
        assert_eq!(manager.node_tls().unwrap(), Some(next));
        assert_eq!(notifications.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mismatched_node_certificate_is_refused_before_opening_zone_storage() {
        let directory = TempDir::new().unwrap();
        let data = directory.path().join("data");
        let (ca, ca_key) = crate::transport::generate_zone_ca("root").unwrap();
        let (cert, key) =
            crate::transport::generate_node_cert(7, "root", &ca, &ca_key, &[], None).unwrap();
        let files = TlsFiles {
            cert_path: directory.path().join("node.pem"),
            key_path: directory.path().join("node-key.pem"),
            ca_path: directory.path().join("ca.pem"),
            ca_key_path: None,
            join_token_hash: None,
        };
        std::fs::write(&files.cert_path, &cert).unwrap();
        lib::transport_primitives::write_secret(&files.key_path, &key).unwrap();
        std::fs::write(&files.ca_path, &ca).unwrap();
        let result = ZoneManager::with_node_id(
            "test-host",
            9,
            data.to_str().unwrap(),
            Vec::new(),
            "127.0.0.1:0",
            Some(files.clone()),
            None,
            None,
        );
        let Err(RaftError::Config(error)) = result else {
            panic!("mismatched certificate must fail before starting the node");
        };
        assert!(error.contains("configured Raft Node ID is 9"), "{error}");
        assert!(
            !data.exists(),
            "refusal must leave existing zone storage alone"
        );
        assert_eq!(std::fs::read(files.cert_path).unwrap(), cert);
    }

    /// Reusable ZoneManager fixture binding to an OS-allocated port so
    /// parallel tests don't collide.  Tests must drop the returned
    /// TempDir last so the on-disk redb is unlinked after the manager
    /// shuts its runtime down.
    fn make_zm(node_id: u64) -> (Arc<ZoneManager>, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let zm = ZoneManager::with_node_id(
            "test-host",
            node_id,
            dir.path().to_str().expect("utf-8"),
            vec![],
            "127.0.0.1:0",
            None,
            None,
            None,
        )
        .expect("ZoneManager");
        (zm, dir)
    }

    #[test]
    fn test_create_zone_repeated_is_noop() {
        // A second create_zone returns the existing handle; it never
        // re-bootstraps or shadows the original raft group.
        let (zm, _dir) = make_zm(1);
        let h1 = zm.create_zone("z1").expect("first create");
        let h2 = zm.create_zone("z1").expect("second create idempotent");
        assert_eq!(h1.zone_id(), h2.zone_id());
        assert_eq!(
            h1.consensus_node().coherence_id(),
            h2.consensus_node().coherence_id()
        );
    }

    #[test]
    fn test_share_subtree_core_after_fresh_create_no_notleader_race() {
        // Regression: ``share_subtree_core`` writes (``propose_set_metadata``)
        // target the freshly-created ``new_zone`` raft group.  Before the
        // SSOT wait moved into the helper, callers had to ``wait_for_leader``
        // themselves between ``create_zone`` and ``share_subtree_core``;
        // forgetting that (or waiting on the wrong zone, like the offline
        // ``nexusd-cluster share`` CLI did against ``parent_zone``) raced the
        // raft election and surfaced as ``NotLeader { leader_hint:
        // Some(self_id) }`` ~400 ms into the call.  This pin keeps the
        // contract: the helper owns its leadership precondition, so
        // back-to-back ``create_zone`` + ``share_subtree_core`` on a
        // single-node cluster must succeed without external waits.
        let (zm, _dir) = make_zm(1);
        // Seed a parent zone with one entry under ``/shared`` so the
        // share copies something non-trivial — the propose path against
        // ``new_zone`` is what we're really exercising.
        let parent = zm
            .create_zone(contracts::ROOT_ZONE_ID)
            .expect("root create");
        assert!(
            parent.wait_for_leader(std::time::Duration::from_secs(5)),
            "root must elect itself as 1-voter leader"
        );
        let meta = encode_file_metadata("/shared", DT_DIR, contracts::ROOT_ZONE_ID, "");
        let handle = zm.rt().handle().clone();
        let root_node = zm
            .registry
            .get_node(contracts::ROOT_ZONE_ID)
            .expect("root node");
        propose_set_metadata(&handle, &root_node, "/shared", meta).expect("seed /shared");

        // Fresh shared zone — created immediately before the share call
        // so the raft tick driver has had no time to elect.  Under the
        // old contract this raced and returned NotLeader.
        zm.create_zone("sharedzone").expect("shared zone create");
        let copied = zm
            .share_subtree_core(contracts::ROOT_ZONE_ID, "/shared", "sharedzone")
            .expect("share_subtree_core must wait for new_zone leader internally");
        assert!(copied >= 1, "at least the /shared root entry copied");
    }

    #[test]
    fn test_create_zone_after_join_with_persisted_conf_state_is_noop() {
        // Cross-process restart: zone "z1" was created in a prior
        // process (1-voter under the opaque-ID contract), redb files
        // persist on disk.  A subsequent process loading from disk
        // must no-op `create_zone` rather than reset the ConfState —
        // restart paths must always preserve persisted membership.
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().to_str().expect("utf-8").to_string();
        {
            let zm =
                ZoneManager::with_node_id("h1", 1, &path, vec![], "127.0.0.1:0", None, None, None)
                    .expect("zm-1");
            zm.create_zone("z1").expect("create");
            // Drop zm — runtime + gRPC server shut down, redb files
            // remain on disk.
        }
        let zm = ZoneManager::with_node_id("h1", 1, &path, vec![], "127.0.0.1:0", None, None, None)
            .expect("zm-2");
        // open_existing_zones_from_disk should have re-loaded "z1"
        // with the persisted ConfState; create_zone with identical
        // (empty) peer list must hit the idempotency branch.
        assert!(zm.get_zone("z1").is_some(), "zone reloaded from disk");
        let _ = zm.create_zone("z1").expect("create idempotent on restart");
    }
}

#[cfg(test)]
mod bind_failure_tests {
    use super::addr_in_use;

    /// A tonic bind failure arrives wrapped, so the check has to walk the chain rather
    /// than look at the top-level error.
    #[derive(Debug)]
    struct Wrapped(std::io::Error);

    impl std::fmt::Display for Wrapped {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "connection error")
        }
    }

    impl std::error::Error for Wrapped {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn a_taken_address_is_recognised_through_the_wrapper() {
        let e = Wrapped(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "address already in use",
        ));
        assert!(addr_in_use(&e));
    }

    #[test]
    fn an_unassigned_address_is_not_a_taken_one() {
        // A Tailscale address while the tunnel is down: the operator's action is
        // different, so the two must not share a message.
        let e = Wrapped(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "cannot assign requested address",
        ));
        assert!(!addr_in_use(&e));
    }

    #[test]
    fn no_io_error_in_the_chain_is_not_a_taken_address() {
        #[derive(Debug)]
        struct Tls;
        impl std::fmt::Display for Tls {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "tls handshake failed")
            }
        }
        impl std::error::Error for Tls {}
        assert!(!addr_in_use(&Tls));
    }
}
