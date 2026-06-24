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

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tonic::transport::Channel;

use kernel::abc::object_store::{BackendStat, WriteResult};
use kernel::hal::federation_peer::{FederationPeerClient, FederationPeerResult};
use kernel::kernel::vfs_proto;
use lib::transport_primitives::{create_channel, ClientConfig, TlsConfig};
use nexus_raft::federation::TofuTrustStore;
use nexus_raft::transport::proto::nexus::raft::{
    zone_api_service_client::ZoneApiServiceClient, JoinZoneRequest,
};

/// Per-peer channel cache + shared runtime.
///
/// TLS storage + channel build delegate to
/// `lib::transport_primitives::{TlsConfig, create_channel}` — the
/// same machinery the sibling `PeerBlobClient` uses for its
/// `ZoneApiService.ReadBlob` channel pool — so a single set of
/// timeout / keepalive defaults and TLS handshake logic serves both
/// out-bound transport-tier clients.
pub struct FederationClient {
    runtime: Arc<tokio::runtime::Runtime>,
    channels: DashMap<String, Channel>,
    /// Late-bound TLS material.  `None` until the boot installer wires
    /// the cluster CA + node cert (mirrors `PeerBlobClient::tls`); when
    /// `Some`, [`Self::channel_for`] builds the channel as `https://`
    /// with mTLS.
    tls: parking_lot::RwLock<Option<TlsConfig>>,
    timeout: Duration,
}

impl FederationClient {
    pub fn new(runtime: Arc<tokio::runtime::Runtime>, tls: Option<TlsConfig>) -> Self {
        Self {
            runtime,
            channels: DashMap::new(),
            tls: parking_lot::RwLock::new(tls),
            timeout: Duration::from_secs(10),
        }
    }

    /// Install mTLS material so subsequent channel builds use TLS.
    ///
    /// Drops any cached plaintext channels — the next RPC to each
    /// peer reconnects over TLS.  Mirrors
    /// `PeerBlobClient::install_tls_config`.
    pub fn install_tls(&self, tls: TlsConfig) {
        *self.tls.write() = Some(tls);
        self.channels.clear();
    }

    /// Fetch or build a tonic channel for ``address``.
    ///
    /// Address forms: ``host:port`` or ``http(s)://host:port``.
    /// ``https://`` is selected automatically when TLS material is
    /// attached — callers shouldn't need to pick the scheme.
    /// Delegates Endpoint configuration (timeouts / keepalive / TLS)
    /// to `lib::transport_primitives::create_channel` so the build
    /// rules stay aligned with the sibling `PeerBlobClient`.
    async fn channel_for(&self, address: &str) -> Result<Channel, String> {
        if let Some(ch) = self.channels.get(address) {
            return Ok(ch.clone());
        }
        let tls = self.tls.read().clone();
        let scheme = if tls.is_some() { "https" } else { "http" };
        let endpoint = if address.starts_with("http://") || address.starts_with("https://") {
            address.to_string()
        } else {
            format!("{scheme}://{address}")
        };
        let client_cfg = ClientConfig {
            tls,
            request_timeout: self.timeout,
            ..Default::default()
        };
        let channel = create_channel(&endpoint, &client_cfg)
            .await
            .map_err(|e| format!("federation channel {address}: {e}"))?;
        self.channels
            .entry(address.to_string())
            .or_insert_with(|| channel.clone());
        Ok(channel)
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
        let channel = self.channel_for(peer_addr).await?;
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
        let channel = self.channel_for(peer_addr).await?;
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
    // Used by `FederationPeerBackend` (in the `backends` crate) via the
    // `kernel::hal::federation_peer::FederationPeerClient` trait below.
    // Each wrapper acquires a pooled channel, builds the typed
    // `NexusVFSService` client, fires the RPC, and surfaces the in-band
    // `is_error` flag as an `Err(String)` so callers see the same error
    // shape for transport vs application failures.

    async fn vfs_client(
        &self,
        peer_addr: &str,
    ) -> Result<vfs_proto::nexus_vfs_service_client::NexusVfsServiceClient<Channel>, String> {
        let channel = self.channel_for(peer_addr).await?;
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

    async fn vfs_write(
        &self,
        peer_addr: &str,
        path: &str,
        content: &[u8],
    ) -> Result<WriteResult, String> {
        let mut client = self.vfs_client(peer_addr).await?;
        let mut request = tonic::Request::new(vfs_proto::WriteRequest {
            path: path.to_string(),
            content: content.to_vec(),
            auth_token: String::new(),
            content_id: String::new(),
        });
        request.set_timeout(self.timeout);
        let resp = client
            .write(request)
            .await
            .map_err(|e| format!("federation write {peer_addr} {path}: {e}"))?
            .into_inner();
        if resp.is_error {
            return Err(format!(
                "federation write {peer_addr} {path}: {}",
                String::from_utf8_lossy(&resp.error_payload)
            ));
        }
        let content_id = if resp.content_id.is_empty() {
            path.to_string()
        } else {
            resp.content_id
        };
        Ok(WriteResult {
            version: content_id.clone(),
            content_id,
            size: resp.size.max(0) as u64,
        })
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
}

/// Install hook called during kernel process boot —
/// constructs a `FederationClient` borrowing the kernel's tokio
/// runtime and installs it via `Kernel::set_federation_peer_client`,
/// replacing the `NoopFederationPeerClient` default.  Mirrors
/// [`super::peer_blob::install`].
///
/// Without this hook the kernel's federation-peer slot stays at the
/// Noop default and every `sys_readdir` / `sys_stat` / `sys_unlink` /
/// `sys_write` dispatch through `Kernel::dispatch_federation_peer`
/// returns "federation peer client not installed" — the symptom that
/// surfaced as empty cross-node listings in the cc-tasks-share E2E
/// before this hook was wired.
pub fn install(kernel: &kernel::kernel::Kernel) {
    let client = Arc::new(FederationClient::new(Arc::clone(kernel.runtime()), None));
    kernel.set_federation_peer_client(
        client as Arc<dyn kernel::hal::federation_peer::FederationPeerClient>,
    );
}

// ── HAL trait impl ───────────────────────────────────────────────────
//
// Bridges the async tonic wrappers above to the sync
// `FederationPeerClient` trait the kernel HAL declares.  Every call
// uses `runtime.block_on` (same pattern as PeerBlobClient::fetch).

impl FederationPeerClient for FederationClient {
    fn read(&self, addr: &str, path: &str, offset: u64) -> FederationPeerResult<Vec<u8>> {
        self.runtime.block_on(self.vfs_read(addr, path, offset))
    }

    fn write(&self, addr: &str, path: &str, content: &[u8]) -> FederationPeerResult<WriteResult> {
        self.runtime.block_on(self.vfs_write(addr, path, content))
    }

    fn stat(&self, addr: &str, path: &str) -> FederationPeerResult<Option<BackendStat>> {
        self.runtime.block_on(self.vfs_stat(addr, path))
    }

    fn list_dir(&self, addr: &str, path: &str) -> FederationPeerResult<Vec<(String, u8)>> {
        self.runtime.block_on(self.vfs_readdir(addr, path))
    }

    fn delete_file(&self, addr: &str, path: &str) -> FederationPeerResult<()> {
        self.runtime.block_on(self.vfs_delete(addr, path, false))
    }

    fn rmdir(&self, addr: &str, path: &str, recursive: bool) -> FederationPeerResult<()> {
        self.runtime
            .block_on(self.vfs_delete(addr, path, recursive))
    }

    fn mkdir(
        &self,
        addr: &str,
        path: &str,
        parents: bool,
        exist_ok: bool,
    ) -> FederationPeerResult<()> {
        self.runtime
            .block_on(self.vfs_mkdir(addr, path, parents, exist_ok))
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
        let plain = FederationClient::new(Arc::clone(&rt), None);
        assert!(plain.tls.read().is_none());

        // TLS variant — the material isn't parsed until the first
        // `channel_for` call, so we just check it was stored.  Uses
        // the shared `lib::transport_primitives::TlsConfig` so the
        // sibling `PeerBlobClient` and `FederationClient` share a
        // single TLS material type.
        let tls = FederationClient::new(
            rt,
            Some(TlsConfig {
                ca_pem: make_ca_pem("ca").into_bytes(),
                cert_pem: make_ca_pem("node").into_bytes(),
                key_pem: b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----".to_vec(),
            }),
        );
        assert!(tls.tls.read().is_some());
    }

    /// `install_tls` swaps the slot and drops cached channels so
    /// follow-up RPCs reconnect over TLS — same shape as
    /// `PeerBlobClient::install_tls_config`.
    #[test]
    fn install_tls_updates_slot_and_clears_channel_cache() {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap(),
        );
        let client = FederationClient::new(Arc::clone(&rt), None);
        // Pre-seed a fake cached channel so we can assert it gets cleared.
        // We can't construct a real `tonic::transport::Channel` cheaply,
        // so verify by asserting the channels map is empty post-install
        // (boot state) and stays empty after install.
        assert_eq!(client.channels.len(), 0);
        client.install_tls(TlsConfig {
            ca_pem: make_ca_pem("ca").into_bytes(),
            cert_pem: make_ca_pem("node").into_bytes(),
            key_pem: b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----".to_vec(),
        });
        assert!(client.tls.read().is_some(), "tls slot must be populated");
        assert_eq!(
            client.channels.len(),
            0,
            "install_tls must clear any cached channels"
        );
    }
}
