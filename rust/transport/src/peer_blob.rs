//! PeerBlobClient — shared gRPC infrastructure for CAS-level peer fetch.
//!
//! Holds a `tokio::runtime::Handle` (not an `Arc<Runtime>`) plus a
//! tonic `Channel` pool (one per peer address) so every peer RPC
//! reuses its channel instead of building an HTTP/2 connection per
//! call.
//!
//! Runtime ownership lives with `Kernel` — `PeerBlobClient` only
//! borrows the executor via the `Handle`.  Dropping this client never
//! triggers a runtime shutdown, so the client can safely outlive the
//! kernel and drop in any context (including from an async worker
//! during process shutdown).  When the kernel drops its
//! `Arc<Runtime>` the `Handle` here invalidates on next use; that's
//! the correct ownership shape — peer fetches must not survive their
//! runtime.
//!
//! Thread-safety: `DashMap` guards the channel pool; per-peer + global
//! semaphores cap concurrent RPCs.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::Semaphore;

use nexus_raft::transport::proto::nexus::raft::{
    zone_api_service_client::ZoneApiServiceClient, ReadBlobRequest, ReadZoneBlobRequest,
};

/// Default per-peer permit count — caps outstanding RPCs per peer so one
/// slow origin cannot monopolise the client. 8 matches Python
/// `CASRemoteContentFetcher`'s default worker count.
const DEFAULT_PER_PEER_PERMITS: usize = 8;
/// Default global permit count — caps total concurrent blob fetches to keep
/// aggregate outbound bandwidth bounded on small nodes.
const DEFAULT_GLOBAL_PERMITS: usize = 16;
/// Default per-RPC timeout. Matches Python `PeerBlobClient.timeout` default.
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(30);

use crate::peer_channels::{PeerChannels, TlsPolicy};

/// Shared peer-RPC client. Construct once per kernel, clone the `Arc` into
/// any caller that needs to fetch blobs from peers.
#[allow(dead_code)]
pub struct PeerBlobClient {
    runtime: tokio::runtime::Handle,
    channels: PeerChannels,
    per_peer_semaphores: DashMap<String, Arc<Semaphore>>,
    global_semaphore: Arc<Semaphore>,
    timeout: Duration,
    per_peer_permits: usize,
}

#[allow(dead_code)]
impl PeerBlobClient {
    /// Build a peer-blob client borrowing the executor via `Handle`.
    ///
    /// The kernel owns the runtime; this client only needs spawn /
    /// block_on access.  Holding a `Handle` rather than `Arc<Runtime>`
    /// keeps runtime shutdown a kernel-side responsibility and makes
    /// drops here side-effect-free.
    pub fn new(runtime: tokio::runtime::Handle) -> Self {
        Self {
            runtime,
            channels: PeerChannels::new(
                None,
                lib::transport_primitives::ClientConfig::default().request_timeout,
            ),
            per_peer_semaphores: DashMap::new(),
            global_semaphore: Arc::new(Semaphore::new(DEFAULT_GLOBAL_PERMITS)),
            timeout: DEFAULT_RPC_TIMEOUT,
            per_peer_permits: DEFAULT_PER_PEER_PERMITS,
        }
    }

    /// Install mTLS material so subsequent channel builds use TLS.
    ///
    /// Drops any cached plaintext channels — the next RPC to each peer
    /// reconnects over TLS. Called by the boot installer once the
    /// leader / joiner has resolved the cluster CA + node cert.
    pub fn install_tls_config(&self, tls: lib::transport_primitives::TlsConfig) {
        self.channels.replace_tls(TlsPolicy::Configured(tls));
    }

    /// Resolve (or create) the per-peer semaphore gating outstanding RPCs.
    fn per_peer_semaphore(&self, address: &str) -> Arc<Semaphore> {
        if let Some(s) = self.per_peer_semaphores.get(address) {
            return Arc::clone(&s);
        }
        let entry = self
            .per_peer_semaphores
            .entry(address.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.per_peer_permits)));
        Arc::clone(&entry)
    }

    /// Fetch content from ``address`` asynchronously, using the
    /// store-and-forward ``ReadBlob`` RPC: send opaque ``content_id``,
    /// receive bytes. The peer's data plane decides locally whether
    /// ``content_id`` is a VFS path (federation read) or a CAS hash
    /// (chunk dedup) — caller doesn't care.
    ///
    /// Returns ``Err(..)`` on transport errors OR when the peer reports
    /// ``error`` (content not found / not routable on that peer).
    pub(crate) async fn fetch_async(
        &self,
        address: &str,
        content_id: &str,
    ) -> Result<Vec<u8>, String> {
        self.fetch_scoped_async(address, None, content_id).await
    }

    /// Fetch only from the named data zone. Servers without this RPC refuse
    /// the request; scoped reads retain their scope across version differences.
    pub async fn fetch_in_zone_async(
        &self,
        address: &str,
        zone_id: &str,
        content_id: &str,
    ) -> Result<Vec<u8>, String> {
        self.fetch_scoped_async(address, Some(zone_id), content_id)
            .await
    }

    async fn fetch_scoped_async(
        &self,
        address: &str,
        zone_id: Option<&str>,
        content_id: &str,
    ) -> Result<Vec<u8>, String> {
        if let Some(zone_id) = zone_id {
            contracts::validate_zone_id_for(contracts::ZoneIdUse::TenantCreate, zone_id)
                .map_err(|error| error.to_string())?;
        }
        // Global cap: total concurrent fetches across all peers.
        let _global_permit = self
            .global_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| format!("global semaphore closed: {e}"))?;
        // Per-peer cap: one peer cannot monopolise the pool.
        let per_peer = self.per_peer_semaphore(address);
        let _peer_permit = per_peer
            .acquire_owned()
            .await
            .map_err(|e| format!("per-peer semaphore closed: {e}"))?;

        let channel = self.channels.channel_for(address).await?;
        // ReadBlob lives on the raft ``ZoneApiService`` (co-located
        // with consensus on the advertised raft port — inherits
        // cluster mTLS). Message caps match the server: tonic's
        // default 4 MiB decode cap would reject any CAS chunk above
        // that threshold (16 MiB CDC boundary).
        // SSOT: ``contracts::MAX_GRPC_MESSAGE_BYTES``.
        let mut client = ZoneApiServiceClient::new(channel)
            .max_decoding_message_size(contracts::MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(contracts::MAX_GRPC_MESSAGE_BYTES);
        let method = if zone_id.is_some() {
            "ReadZoneBlob"
        } else {
            "ReadBlob"
        };
        let resp = match zone_id {
            Some(zone_id) => {
                let mut request = tonic::Request::new(ReadZoneBlobRequest {
                    zone_id: zone_id.to_string(),
                    content_id: content_id.to_string(),
                });
                request.set_timeout(self.timeout);
                client.read_zone_blob(request).await
            }
            None => {
                let mut request = tonic::Request::new(ReadBlobRequest {
                    content_id: content_id.to_string(),
                });
                request.set_timeout(self.timeout);
                client.read_blob(request).await
            }
        }
        .map_err(|error| format!("{method} {address}: {error}"))?
        .into_inner();
        if !resp.error.is_empty() {
            return Err(format!("{method} {address} error: {}", resp.error));
        }
        Ok(resp.content)
    }

    /// Blocking fetch on the shared runtime, including from a worker already
    /// executing on that runtime.
    pub(crate) fn fetch(&self, address: &str, content_id: &str) -> Result<Vec<u8>, String> {
        self.fetch_scoped(address, None, content_id)
    }

    /// Blocking scoped fetch on the same shared runtime and connection policy.
    pub fn fetch_in_zone(
        &self,
        address: &str,
        zone_id: &str,
        content_id: &str,
    ) -> Result<Vec<u8>, String> {
        self.fetch_scoped(address, Some(zone_id), content_id)
    }

    /// Drive both blocking entry points through the shared runtime bridge,
    /// including callers on a current-thread Agent runtime.
    fn fetch_scoped(
        &self,
        address: &str,
        zone_id: Option<&str>,
        content_id: &str,
    ) -> Result<Vec<u8>, String> {
        lib::rt::block_on_via(
            &self.runtime,
            self.fetch_scoped_async(address, zone_id, content_id),
        )
    }
}

/// Build the kernel-owned multi-threaded runtime. Two workers is plenty for
/// IO-bound peer RPCs; increase only if a workload saturates both.
#[allow(dead_code)]
pub fn build_kernel_runtime() -> Arc<tokio::runtime::Runtime> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("nexus-kernel-peer")
        .enable_all()
        .build()
        .expect("failed to build kernel tokio runtime");
    Arc::new(rt)
}

// ── HAL trait wiring ─────────────────────────────────────────────────
//
// Kernel holds an `Arc<dyn kernel::hal::peer::PeerBlobClient>`. The
// This adapter preserves the selected read scope and shared TLS configuration.

impl kernel::hal::peer::PeerBlobClient for PeerBlobClient {
    fn fetch(&self, addr: &str, content_id: &str) -> kernel::hal::peer::PeerBlobResult<Vec<u8>> {
        // Inherent method shadows the trait method — fully-qualify.
        PeerBlobClient::fetch(self, addr, content_id)
    }

    fn fetch_in_zone(
        &self,
        addr: &str,
        zone_id: &str,
        content_id: &str,
    ) -> kernel::hal::peer::PeerBlobResult<Vec<u8>> {
        PeerBlobClient::fetch_in_zone(self, addr, zone_id, content_id)
    }

    fn install_tls(&self, ca_pem: &[u8], cert_pem: Option<&[u8]>, key_pem: Option<&[u8]>) {
        let (Some(cert), Some(key)) = (cert_pem, key_pem) else {
            self.channels.replace_tls(TlsPolicy::Rejected(
                "peer mTLS requires both client certificate and private key",
            ));
            return;
        };
        PeerBlobClient::install_tls_config(
            self,
            lib::transport_primitives::TlsConfig {
                ca_pem: ca_pem.to_vec(),
                cert_pem: cert.to_vec(),
                key_pem: key.to_vec(),
            },
        );
    }
}

/// Install hook called during kernel process boot —
/// constructs a `PeerBlobClient` that borrows the kernel's tokio
/// runtime via `Handle` and installs it via `Kernel::set_peer_client`,
/// replacing the `NoopPeerBlobClient` default.
pub fn install(kernel: &kernel::kernel::Kernel) {
    let client = Arc::new(PeerBlobClient::new(kernel.runtime().handle().clone()));
    kernel.set_peer_client(client as Arc<dyn kernel::hal::peer::PeerBlobClient>);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_runtime_succeeds() {
        let rt = build_kernel_runtime();
        // Can drive a simple future.
        rt.block_on(async { 1 + 1 });
        assert!(Arc::strong_count(&rt) >= 1);
    }

    #[test]
    fn test_client_constructs_with_handle() {
        let rt = build_kernel_runtime();
        let client = PeerBlobClient::new(rt.handle().clone());
        // Smoke: drives a trivial future through the borrowed Handle.
        let _ = client.runtime.block_on(async { 1 + 1 });
    }

    #[test]
    fn test_fetch_unreachable_peer_errors() {
        // Use a port we know is unbound so we test the error path without
        // needing a live peer. Short timeout = fast test.
        let rt = build_kernel_runtime();
        let mut client = PeerBlobClient::new(rt.handle().clone());
        client.timeout = Duration::from_millis(200);
        let result = client.fetch(
            "127.0.0.1:1",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());
    }

    /// Re-entrancy regression pin: invoking `fetch` from inside a tokio
    /// worker on the SAME runtime must not panic with "Cannot start a
    /// runtime from within a runtime". This mirrors PR #74's reentrancy
    /// guard for `FederationClient::block_on_safely`; without the guard
    /// here, `PeerBlobClient::fetch` panics any time a kernel hot path
    /// (gRPC handler, FUSE callback, raft apply) reaches it.
    #[test]
    fn test_fetch_from_within_runtime_does_not_panic() {
        let rt = build_kernel_runtime();
        let mut client = PeerBlobClient::new(rt.handle().clone());
        client.timeout = Duration::from_millis(200);
        let client = Arc::new(client);
        let client_for_task = Arc::clone(&client);
        let result = rt.block_on(async move {
            tokio::spawn(async move {
                client_for_task.fetch(
                    "127.0.0.1:1",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
            })
            .await
            .expect("spawn join")
        });
        assert!(result.is_err(), "expected connection error, got Ok");
    }
}

#[cfg(test)]
mod tls_tests;
