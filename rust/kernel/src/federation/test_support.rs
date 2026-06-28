//! Federation-domain test scaffolding — `#[cfg(test)]` only.
//!
//! `dispatch_federation_peer` and the seven per-syscall thin wrappers
//! that go through it depend on three HAL surfaces:
//!
//!   * [`FederationPeerClient`](crate::hal::federation_peer::FederationPeerClient)
//!     — the typed gRPC-side per-syscall trait.
//!   * [`DistributedCoordinator`](crate::hal::distributed_coordinator::DistributedCoordinator)
//!     — supplies `zone_peers` (the list dispatch iterates).
//!   * `self_address` — the loop-back guard's input.
//!
//! Each of those has a Noop / always-errors default at `Kernel::new`,
//! so behavioral unit tests need controllable replacements.  This
//! module provides:
//!
//!   * [`FakeFederationPeerClient`] — a no-op `FederationPeerClient`
//!     impl (every trait method errors).  The trait methods themselves
//!     are NOT called by `dispatch_federation_peer` — the `op` closure
//!     argument controls behavior — so the trait impl only needs to
//!     exist to satisfy the slot's `Arc<dyn …>` shape.
//!   * [`FakePeers`] — a `DistributedCoordinator` whose `zone_peers`
//!     returns a caller-injected `Vec<String>`.  All other methods
//!     mirror `NoopDistributedCoordinator`'s "not installed" errors.
//!   * [`build_kernel_with_peers`] — convenience constructor returning
//!     a `Kernel` with both fakes installed and a chosen `self_address`.
//!
//! Designed to be reusable across other federation-domain unit tests
//! (coordinator_wiring, peer_dispatch siblings) — keep additions here
//! generic, not tied to one syscall's shape.

use std::sync::Arc;

use crate::abc::object_store::{BackendStat, WriteResult};
use crate::hal::distributed_coordinator::{
    ClusterInfo, CoordinatorResult, DistributedCoordinator, ShareInfo,
};
use crate::hal::federation_peer::{FederationPeerClient, FederationPeerResult};
use crate::kernel::Kernel;

/// `FederationPeerClient` shim — every trait method errors.  Present
/// only to satisfy the slot's `Arc<dyn FederationPeerClient>` type;
/// `dispatch_federation_peer` test bodies inject behavior via the `op`
/// closure parameter, not via this client's methods.
pub(crate) struct FakeFederationPeerClient;

impl FederationPeerClient for FakeFederationPeerClient {
    fn read(&self, _addr: &str, _path: &str, _offset: u64) -> FederationPeerResult<Vec<u8>> {
        Err("FakeFederationPeerClient: read not used in test".into())
    }
    fn write(
        &self,
        _addr: &str,
        _path: &str,
        _content: &[u8],
    ) -> FederationPeerResult<WriteResult> {
        Err("FakeFederationPeerClient: write not used in test".into())
    }
    fn stat(&self, _addr: &str, _path: &str) -> FederationPeerResult<Option<BackendStat>> {
        Err("FakeFederationPeerClient: stat not used in test".into())
    }
    fn list_dir(&self, _addr: &str, _path: &str) -> FederationPeerResult<Vec<(String, u8)>> {
        Err("FakeFederationPeerClient: list_dir not used in test".into())
    }
    fn delete_file(&self, _addr: &str, _path: &str) -> FederationPeerResult<()> {
        Err("FakeFederationPeerClient: delete_file not used in test".into())
    }
    fn rmdir(&self, _addr: &str, _path: &str, _recursive: bool) -> FederationPeerResult<()> {
        Err("FakeFederationPeerClient: rmdir not used in test".into())
    }
    fn mkdir(
        &self,
        _addr: &str,
        _path: &str,
        _parents: bool,
        _exist_ok: bool,
    ) -> FederationPeerResult<()> {
        Err("FakeFederationPeerClient: mkdir not used in test".into())
    }
    fn rename(&self, _addr: &str, _old_path: &str, _new_path: &str) -> FederationPeerResult<()> {
        Err("FakeFederationPeerClient: rename not used in test".into())
    }
    fn setattr(
        &self,
        _addr: &str,
        _path: &str,
        _mime_type: Option<&str>,
        _content_id: Option<&str>,
        _modified_at_ms: Option<i64>,
        _created_at_ms: Option<i64>,
        _size: Option<u64>,
        _version: Option<u32>,
    ) -> FederationPeerResult<()> {
        Err("FakeFederationPeerClient: setattr not used in test".into())
    }
}

/// `DistributedCoordinator` whose `zone_peers` returns a caller-
/// injected list.  All other methods mirror the Noop shim's "not
/// installed" errors — federation-domain unit tests should NOT
/// exercise zone lifecycle or share-registry paths through this fake.
pub(crate) struct FakePeers {
    pub(crate) peers: Vec<String>,
}

impl FakePeers {
    pub(crate) fn new<I, S>(peers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            peers: peers.into_iter().map(Into::into).collect(),
        }
    }
}

impl DistributedCoordinator for FakePeers {
    fn list_zones(&self, _kernel: &Kernel) -> Vec<String> {
        Vec::new()
    }

    fn cluster_info(&self, _kernel: &Kernel, _zone_id: &str) -> CoordinatorResult<ClusterInfo> {
        Err("FakePeers: cluster_info not used in test".into())
    }

    fn zone_peers(&self, _kernel: &Kernel, _zone_id: &str) -> Vec<String> {
        self.peers.clone()
    }

    fn create_zone(&self, _kernel: &Kernel, _zone_id: &str) -> CoordinatorResult<()> {
        Err("FakePeers: create_zone not used in test".into())
    }

    fn remove_zone(&self, _kernel: &Kernel, _zone_id: &str, _force: bool) -> CoordinatorResult<()> {
        Err("FakePeers: remove_zone not used in test".into())
    }

    fn join_zone(
        &self,
        _kernel: &Kernel,
        _zone_id: &str,
        _as_learner: bool,
    ) -> CoordinatorResult<()> {
        Err("FakePeers: join_zone not used in test".into())
    }

    fn wire_mount(
        &self,
        _kernel: &Kernel,
        _parent_zone: &str,
        _mount_path: &str,
        _target_zone: &str,
    ) -> CoordinatorResult<()> {
        Err("FakePeers: wire_mount not used in test".into())
    }

    fn unwire_mount(
        &self,
        _kernel: &Kernel,
        _parent_zone: &str,
        _mount_path: &str,
    ) -> CoordinatorResult<()> {
        Err("FakePeers: unwire_mount not used in test".into())
    }

    fn share_zone(
        &self,
        _kernel: &Kernel,
        _local_path: &str,
        _new_zone_id: &str,
    ) -> CoordinatorResult<ShareInfo> {
        Err("FakePeers: share_zone not used in test".into())
    }

    fn lookup_share(
        &self,
        _kernel: &Kernel,
        _remote_path: &str,
    ) -> CoordinatorResult<Option<ShareInfo>> {
        Ok(None)
    }

    fn metastore_for_zone(
        &self,
        _kernel: &Kernel,
        _zone_id: &str,
    ) -> CoordinatorResult<Arc<dyn crate::abc::meta_store::MetaStore>> {
        Err("FakePeers: metastore_for_zone not used in test".into())
    }

    fn locks_for_zone(
        &self,
        _kernel: &Kernel,
        _zone_id: &str,
    ) -> CoordinatorResult<Arc<dyn contracts::lock_state::Locks>> {
        Err("FakePeers: locks_for_zone not used in test".into())
    }
}

/// Build a `Kernel` with [`FakePeers`] and [`FakeFederationPeerClient`]
/// installed plus a chosen `self_address`.
///
/// `peers` is the list `DistributedCoordinator::zone_peers` will
/// return for every queried zone.  `self_addr` is what
/// `dispatch_federation_peer` reads via `self.self_address.read()` —
/// matching entries in `peers` are loop-back-skipped.
pub(crate) fn build_kernel_with_peers<I, S>(self_addr: Option<&str>, peers: I) -> Kernel
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let k = Kernel::new();
    k.set_distributed_coordinator(Arc::new(FakePeers::new(peers)));
    k.set_federation_peer_client(Arc::new(FakeFederationPeerClient));
    if let Some(addr) = self_addr {
        *k.self_address.write() = Some(addr.to_string());
    }
    k
}
