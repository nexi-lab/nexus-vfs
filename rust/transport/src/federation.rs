//! Rust client for federation peer RPCs.
//!
//! Drives ``_discover_mount`` (VFS sys_stat) and
//! ``_request_membership`` (ZoneApiService.JoinZone) flows. Runs every
//! gRPC call through a shared tokio runtime and a per-peer tonic
//! ``Channel`` pool so repeated calls reuse the HTTP/2 connection.
//!
//! mTLS + TOFU: when a [`TlsMaterial`] is attached, each channel
//! negotiates mTLS with the caller-supplied node identity and a CA
//! bundle built from the local CA plus every pinned zone CA in the
//! [`nexus_raft::federation::TofuTrustStore`]. Callers that already
//! have a bundle path can skip the store lookup and pass raw PEM bytes
//! directly.
//!
//! This module lives in the ``rpc`` driver-layer crate where both
//! proto families are reachable: ``vfs.proto`` stubs come through
//! ``kernel::kernel::vfs_proto`` (kernel re-exports the generated
//! module) and ``transport.proto`` ships in the raft rlib that rpc
//! depends on for proto stubs.

// Federation client — wired by the cluster binary's gRPC transport layer.
#![allow(dead_code, private_interfaces)]

#[cfg(test)]
use std::sync::Arc;
use std::time::Duration;

use tonic::transport::Channel;

use crate::peer_channels::{PeerChannels, TlsPolicy};
use kernel::abc::object_store::BackendStat;
use kernel::federation::grpc_ops::{FederationGrpcOps, FederationPeerResult};
use kernel::kernel::vfs_proto;
use lib::transport_primitives::TlsConfig;
use nexus_raft::federation::TofuTrustStore;
use nexus_raft::transport::proto::nexus::raft::{
    zone_api_service_client::ZoneApiServiceClient, JoinZoneRequest,
};

pub mod runtime_directory;

/// Per-peer channel cache + shared runtime.
///
/// Federation and content reads share the credential-bound channel pool.
/// The host owns the executor and each RPC retains its existing timeout.
pub struct FederationClient {
    // The host owns shutdown. Peer pools may outlive a registry/service field
    // during teardown and must never become a runtime's final async owner.
    runtime: tokio::runtime::Handle,
    channels: PeerChannels,
    timeout: Duration,
}

impl FederationClient {
    pub fn new(runtime: tokio::runtime::Handle, tls: Option<TlsConfig>) -> Self {
        Self {
            runtime,
            channels: PeerChannels::new(tls, Duration::from_secs(10)),
            timeout: Duration::from_secs(10),
        }
    }

    /// Install mTLS material so subsequent channel builds use TLS.
    ///
    /// Reconnect subsequent requests with the replacement identity and refuse
    /// publication of connections established under the preceding policy.
    pub fn install_tls(&self, tls: TlsConfig) {
        self.channels.replace_tls(TlsPolicy::Configured(tls));
    }

    /// Discover a peer zone's DT_MOUNT target via VFS ``sys_stat``.
    ///
    /// Returns ``Some(MountInfo)`` on success, ``None`` if the peer
    /// reports the path is not found or the response is an error
    /// (``is_error == true``). Raises on transport failure or malformed
    /// JSON so the caller can distinguish "peer unreachable" from
    /// "path not a mount".
    async fn discover_mount(
        &self,
        peer_addr: &str,
        path: &str,
    ) -> Result<Option<serde_json::Value>, String> {
        let channel = self.channels.channel_for(peer_addr).await?;
        let mut client = vfs_proto::nexus_vfs_service_client::NexusVfsServiceClient::new(channel);

        let req_json = serde_json::json!({ "path": path });
        let payload =
            serde_json::to_vec(&req_json).map_err(|e| format!("encode sys_stat request: {e}"))?;
        let mut request = tonic::Request::new(vfs_proto::CallRequest {
            method: "sys_stat".to_string(),
            payload,
            auth_token: String::new(),
        });
        request.set_timeout(self.timeout);

        let resp = client
            .call(request)
            .await
            .map_err(|e| format!("sys_stat {peer_addr}: {e}"))?
            .into_inner();

        if resp.is_error {
            // Match the Python helper's "warn then return None" behavior
            // — the caller surfaces a clear ValueError downstream.
            let err_body = String::from_utf8_lossy(&resp.payload);
            tracing::warn!(
                peer = %peer_addr,
                path = %path,
                error = %err_body,
                "sys_stat returned error",
            );
            return Ok(None);
        }

        let decoded: serde_json::Value = serde_json::from_slice(&resp.payload)
            .map_err(|e| format!("decode sys_stat response: {e}"))?;
        Ok(Some(decoded))
    }

    /// Request peer membership for a zone (ZoneApiService.JoinZone).
    ///
    /// Follows one level of leader redirect — if the initial peer is a
    /// follower and returns ``leader_address``, the call recurses against
    /// the leader. Deeper redirects are treated as a cluster bug and
    /// surfaced as an error (mirrors Python's single-level retry).
    async fn request_join_zone(
        &self,
        peer_addr: &str,
        zone_id: &str,
        node_id: u64,
        node_address: &str,
        as_learner: bool,
        depth: u8,
    ) -> Result<(), String> {
        if depth > 1 {
            return Err(format!(
                "JoinZone: too many leader redirects (peer={peer_addr}, zone={zone_id})"
            ));
        }
        let channel = self.channels.channel_for(peer_addr).await?;
        let mut client = ZoneApiServiceClient::new(channel);

        let mut request = tonic::Request::new(JoinZoneRequest {
            zone_id: zone_id.to_string(),
            node_id,
            node_address: node_address.to_string(),
            as_learner,
        });
        request.set_timeout(self.timeout);

        let resp = client
            .join_zone(request)
            .await
            .map_err(|e| format!("JoinZone {peer_addr}: {e}"))?
            .into_inner();

        if !resp.success {
            if let Some(leader) = resp.leader_address.filter(|s| !s.is_empty()) {
                tracing::info!(
                    peer = %peer_addr,
                    leader = %leader,
                    zone = %zone_id,
                    "JoinZone redirected to leader",
                );
                // Recurse against the leader. Box the future so the
                // recursive async call compiles (async-fn recursion
                // needs explicit indirection in Rust).
                let fut = Box::pin(self.request_join_zone(
                    &leader,
                    zone_id,
                    node_id,
                    node_address,
                    as_learner,
                    depth + 1,
                ));
                return fut.await;
            }
            return Err(format!(
                "JoinZone failed on {peer_addr}: {}",
                resp.error.unwrap_or_else(|| "unknown error".into())
            ));
        }
        Ok(())
    }

    // ── Typed NexusVFSService RPC wrappers ───────────────────────────
    //
    // Used by `RaftDistributedCoordinator::peer_*` (in the `raft`
    // crate) via the `kernel::federation::grpc_ops::FederationGrpcOps`
    // trait below.  Each wrapper acquires a pooled channel, builds the
    // typed `NexusVFSService` client, fires the RPC, and surfaces the
    // in-band `is_error` flag as an `Err(String)` so callers see the
    // same error shape for transport vs application failures.

    async fn vfs_client(
        &self,
        peer_addr: &str,
    ) -> Result<vfs_proto::nexus_vfs_service_client::NexusVfsServiceClient<Channel>, String> {
        let channel = self.channels.channel_for(peer_addr).await?;
        Ok(
            vfs_proto::nexus_vfs_service_client::NexusVfsServiceClient::new(channel)
                .max_decoding_message_size(contracts::MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(contracts::MAX_GRPC_MESSAGE_BYTES),
        )
    }

    async fn vfs_read(&self, peer_addr: &str, path: &str, offset: u64) -> Result<Vec<u8>, String> {
        let mut client = self.vfs_client(peer_addr).await?;
        let mut request = tonic::Request::new(vfs_proto::ReadRequest {
            path: path.to_string(),
            auth_token: String::new(),
            content_id: String::new(),
            timeout_ms: 0,
            offset,
        });
        request.set_timeout(self.timeout);
        let resp = client
            .read(request)
            .await
            .map_err(|e| format!("federation read {peer_addr} {path}: {e}"))?
            .into_inner();
        if resp.is_error {
            return Err(format!(
                "federation read {peer_addr} {path}: {}",
                String::from_utf8_lossy(&resp.error_payload)
            ));
        }
        Ok(resp.content)
    }

    async fn vfs_stat(&self, peer_addr: &str, path: &str) -> Result<Option<BackendStat>, String> {
        let mut client = self.vfs_client(peer_addr).await?;
        let mut request = tonic::Request::new(vfs_proto::StatRequest {
            path: path.to_string(),
            auth_token: String::new(),
            zone_id: String::new(),
        });
        request.set_timeout(self.timeout);
        let resp = client
            .stat(request)
            .await
            .map_err(|e| format!("federation stat {peer_addr} {path}: {e}"))?
            .into_inner();
        if resp.is_error {
            return Err(format!(
                "federation stat {peer_addr} {path}: {}",
                String::from_utf8_lossy(&resp.error_payload)
            ));
        }
        if !resp.found {
            return Ok(None);
        }
        Ok(Some(BackendStat {
            size: resp.size.max(0) as u64,
            is_dir: resp.is_directory,
        }))
    }

    async fn vfs_readdir(&self, peer_addr: &str, path: &str) -> Result<Vec<(String, u8)>, String> {
        let mut client = self.vfs_client(peer_addr).await?;
        let mut request = tonic::Request::new(vfs_proto::ReaddirRequest {
            path: path.to_string(),
            auth_token: String::new(),
            zone_id: String::new(),
            // Loop-guard: this call IS the fan-out.  Peer's
            // `Readdir` handler routes to
            // `sys_readdir_peer_dispatch` so it runs only its local
            // metastore + backend scan — no re-dispatch.  Keeps
            // 3+ node topologies from ping-ponging when every hop
            // misses locally.
            from_peer: true,
            // Federation fan-out is single-level: the caller
            // (`via_federation_readdir`) merges one directory level per hop
            // and rebases peer paths. Cross-mount recursive descent is a
            // separate axis (see `ReaddirOpts` scope note) — not this probe.
            recursive: false,
            limit: 0,
        });
        request.set_timeout(self.timeout);
        let resp = client
            .readdir(request)
            .await
            .map_err(|e| format!("federation readdir {peer_addr} {path}: {e}"))?
            .into_inner();
        if resp.is_error {
            return Err(format!(
                "federation readdir {peer_addr} {path}: {}",
                String::from_utf8_lossy(&resp.error_payload)
            ));
        }
        Ok(resp
            .entries
            .into_iter()
            .map(|e| (e.name, e.entry_type.min(u8::MAX as u32) as u8))
            .collect())
    }

    async fn vfs_delete(&self, peer_addr: &str, path: &str, recursive: bool) -> Result<(), String> {
        let mut client = self.vfs_client(peer_addr).await?;
        let mut request = tonic::Request::new(vfs_proto::DeleteRequest {
            path: path.to_string(),
            auth_token: String::new(),
            recursive,
        });
        request.set_timeout(self.timeout);
        let resp = client
            .delete(request)
            .await
            .map_err(|e| format!("federation delete {peer_addr} {path}: {e}"))?
            .into_inner();
        if resp.is_error {
            return Err(format!(
                "federation delete {peer_addr} {path}: {}",
                String::from_utf8_lossy(&resp.error_payload)
            ));
        }
        Ok(())
    }

    async fn vfs_mkdir(
        &self,
        peer_addr: &str,
        path: &str,
        parents: bool,
        exist_ok: bool,
    ) -> Result<(), String> {
        let mut client = self.vfs_client(peer_addr).await?;
        let mut request = tonic::Request::new(vfs_proto::MkdirRequest {
            path: path.to_string(),
            auth_token: String::new(),
            parents,
            exist_ok,
        });
        request.set_timeout(self.timeout);
        let resp = client
            .mkdir(request)
            .await
            .map_err(|e| format!("federation mkdir {peer_addr} {path}: {e}"))?
            .into_inner();
        if resp.is_error {
            return Err(format!(
                "federation mkdir {peer_addr} {path}: {}",
                String::from_utf8_lossy(&resp.error_payload)
            ));
        }
        Ok(())
    }

    async fn vfs_rename(
        &self,
        peer_addr: &str,
        old_path: &str,
        new_path: &str,
    ) -> Result<(), String> {
        let mut client = self.vfs_client(peer_addr).await?;
        let mut request = tonic::Request::new(vfs_proto::RenameRequest {
            path: old_path.to_string(),
            new_path: new_path.to_string(),
            auth_token: String::new(),
        });
        request.set_timeout(self.timeout);
        let resp = client
            .rename(request)
            .await
            .map_err(|e| format!("federation rename {peer_addr} {old_path} -> {new_path}: {e}"))?
            .into_inner();
        if resp.is_error {
            return Err(format!(
                "federation rename {peer_addr} {old_path} -> {new_path}: {}",
                String::from_utf8_lossy(&resp.error_payload)
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn vfs_setattr(
        &self,
        peer_addr: &str,
        path: &str,
        mime_type: Option<&str>,
        content_id: Option<&str>,
        modified_at_ms: Option<i64>,
        created_at_ms: Option<i64>,
        size: Option<u64>,
        version: Option<u32>,
    ) -> Result<(), String> {
        let mut client = self.vfs_client(peer_addr).await?;
        // `entry_type = 0` (DT_REG) — cross-node setattr is
        // intentionally limited to regular-file metadata per the
        // HAL trait doc.  DT_MOUNT mount-construction is node-
        // local (driver wiring + per-node backend instance), DT_PIPE
        // / DT_STREAM are IPC.  Zero-defaulting the DT_MOUNT-/DT_PIPE-
        // specific fields keeps the wire payload minimal.
        let mut request = tonic::Request::new(vfs_proto::SetattrRequest {
            path: path.to_string(),
            auth_token: String::new(),
            entry_type: 0,
            zone_id: String::new(),
            // Regular-file metadata only, per the HAL trait doc — a peer does not
            // create links through this path.
            link_target: None,
            mime_type: mime_type.map(|s| s.to_string()),
            content_id: content_id.map(|s| s.to_string()),
            modified_at_ms,
            created_at_ms,
            size,
            version,
            backend_name: String::new(),
            io_profile: String::new(),
            is_external: false,
            capacity: 0,
            backend_type: String::new(),
            backend_params: Default::default(),
        });
        request.set_timeout(self.timeout);
        let resp = client
            .setattr(request)
            .await
            .map_err(|e| format!("federation setattr {peer_addr} {path}: {e}"))?
            .into_inner();
        if resp.is_error {
            return Err(format!(
                "federation setattr {peer_addr} {path}: {}",
                String::from_utf8_lossy(&resp.error_payload)
            ));
        }
        Ok(())
    }
}

// ── FederationGrpcOps trait impl ─────────────────────────────────────
//
// Bridges the async tonic wrappers above to the sync
// `FederationGrpcOps` trait declared at
// `kernel::federation::grpc_ops`.  The cluster-profile binary builds
// a single `Arc<FederationClient>` at boot and passes it into
// `RaftDistributedCoordinator::install_with_kernel` as the grpc_ops
// arc; the coordinator's `peer_*` impls iterate `zone_peers` and
// dispatch each non-self peer through this trait.
//
// Every synchronous entry uses lib::rt's shared ambient-runtime bridge.
// The host retains runtime ownership; this pool only needs its Handle.

impl FederationClient {
    /// Follow the common bridge for sync, multi-thread and current-thread callers.
    #[inline]
    fn block_on_safely<F>(&self, fut: F) -> F::Output
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        lib::rt::block_on_via(&self.runtime, fut)
    }
}

impl FederationGrpcOps for FederationClient {
    fn read(&self, addr: &str, path: &str, offset: u64) -> FederationPeerResult<Vec<u8>> {
        self.block_on_safely(self.vfs_read(addr, path, offset))
    }

    fn stat(&self, addr: &str, path: &str) -> FederationPeerResult<Option<BackendStat>> {
        self.block_on_safely(self.vfs_stat(addr, path))
    }

    fn list_dir(&self, addr: &str, path: &str) -> FederationPeerResult<Vec<(String, u8)>> {
        self.block_on_safely(self.vfs_readdir(addr, path))
    }

    fn delete_file(&self, addr: &str, path: &str) -> FederationPeerResult<()> {
        self.block_on_safely(self.vfs_delete(addr, path, false))
    }

    fn rmdir(&self, addr: &str, path: &str, recursive: bool) -> FederationPeerResult<()> {
        self.block_on_safely(self.vfs_delete(addr, path, recursive))
    }

    fn mkdir(
        &self,
        addr: &str,
        path: &str,
        parents: bool,
        exist_ok: bool,
    ) -> FederationPeerResult<()> {
        self.block_on_safely(self.vfs_mkdir(addr, path, parents, exist_ok))
    }

    fn rename(&self, addr: &str, old_path: &str, new_path: &str) -> FederationPeerResult<()> {
        self.block_on_safely(self.vfs_rename(addr, old_path, new_path))
    }

    fn setattr(
        &self,
        addr: &str,
        path: &str,
        mime_type: Option<&str>,
        content_id: Option<&str>,
        modified_at_ms: Option<i64>,
        created_at_ms: Option<i64>,
        size: Option<u64>,
        version: Option<u32>,
    ) -> FederationPeerResult<()> {
        self.block_on_safely(self.vfs_setattr(
            addr,
            path,
            mime_type,
            content_id,
            modified_at_ms,
            created_at_ms,
            size,
            version,
        ))
    }
}

/// Build the aggregate CA bundle PEM from the local CA file plus every
/// TOFU-pinned zone CA. If ``tofu_store_path`` is ``None`` the bundle
/// collapses to just the local CA. Matches the Python ``_build_channel``
/// CA-bundle behavior exactly so peer certs keep validating.
fn build_ca_bundle_pem(
    local_ca_pem: &[u8],
    tofu_store_path: Option<&str>,
) -> Result<Vec<u8>, String> {
    let mut bundle = Vec::with_capacity(local_ca_pem.len());
    bundle.extend_from_slice(local_ca_pem.trim_ascii());
    if !bundle.is_empty() && !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }

    if let Some(path) = tofu_store_path {
        let store = TofuTrustStore::open(path).map_err(|e| format!("open TOFU store: {e}"))?;
        for entry in store.list_trusted() {
            let pem = entry.ca_pem;
            bundle.extend_from_slice(pem.trim().as_bytes());
            if !bundle.ends_with(b"\n") {
                bundle.push(b'\n');
            }
        }
    }
    Ok(bundle)
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ca_pem(cn: &str) -> String {
        use rcgen::{CertificateParams, KeyPair};
        let mut params = CertificateParams::new(vec![]).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let key = KeyPair::generate().expect("key");
        params.self_signed(&key).expect("sign").pem()
    }

    /// Walks every `build_ca_bundle_pem` branch in one go: no-store,
    /// empty-store, populated-store. Coverage matches three prior
    /// unit tests; consolidating them keeps the test count sane for a
    /// trivial helper.
    #[test]
    fn build_ca_bundle_pem_covers_all_store_states() {
        let local = b"-----BEGIN CERTIFICATE-----\nLOCAL\n-----END CERTIFICATE-----";
        let count_certs = |b: &[u8]| -> usize {
            std::str::from_utf8(b)
                .unwrap()
                .matches("BEGIN CERTIFICATE")
                .count()
        };

        // No store attached → bundle is just the local CA.
        let bundle = build_ca_bundle_pem(local, None).unwrap();
        assert!(std::str::from_utf8(&bundle).unwrap().contains("LOCAL"));
        assert_eq!(count_certs(&bundle), 1);

        // Empty store file (exists, no entries) → still just local CA.
        let dir = tempfile::tempdir().unwrap();
        let empty_store = dir.path().join("empty");
        std::fs::write(&empty_store, "").unwrap();
        let bundle = build_ca_bundle_pem(local, Some(empty_store.to_str().unwrap())).unwrap();
        assert_eq!(count_certs(&bundle), 1);

        // Populated store → every pinned zone CA appended after local.
        let populated = dir.path().join("populated");
        let mut store = TofuTrustStore::open(&populated).unwrap();
        store
            .verify_or_trust("zone-a", make_ca_pem("zone-a-ca").as_bytes(), "a:2126")
            .unwrap();
        store
            .verify_or_trust("zone-b", make_ca_pem("zone-b-ca").as_bytes(), "b:2126")
            .unwrap();
        let bundle = build_ca_bundle_pem(local, Some(populated.to_str().unwrap())).unwrap();
        let text = std::str::from_utf8(&bundle).unwrap();
        assert!(text.contains("LOCAL"));
        assert_eq!(count_certs(&bundle), 3);
    }

    /// Smoke-construct the client so the plumbing (runtime build, TLS
    /// material parse, channel pool init) doesn't regress. End-to-end
    /// discover / join flows are exercised by the federation E2E
    /// suite — they need a running peer.
    #[test]
    fn client_constructs_with_and_without_tls() {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap(),
        );
        // Plaintext variant.
        let plain = FederationClient::new(rt.handle().clone(), None);
        assert!(!plain.channels.uses_tls());

        // TLS variant — the material isn't parsed until the first
        // `channel_for` call, so we just check it was stored.  Uses
        // the shared `lib::transport_primitives::TlsConfig` so the
        // sibling `PeerBlobClient` and `FederationClient` share a
        // single TLS material type.
        let tls = FederationClient::new(
            rt.handle().clone(),
            Some(TlsConfig {
                ca_pem: make_ca_pem("ca").into_bytes(),
                cert_pem: make_ca_pem("node").into_bytes(),
                key_pem: b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----".to_vec(),
            }),
        );
        assert!(tls.channels.uses_tls());
    }
}

#[cfg(test)]
mod tls_tests;
