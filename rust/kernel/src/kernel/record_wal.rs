//! Scoped WAL construction for the trusted owning service.
//!
//! These handles retain the captured store and owner revision. They are not
//! installed in the generic StreamManager and grant no Session/RPC capability.

use std::sync::Arc;

use crate::core::stream::wal::{wal_stream_prefix, WalStreamCore};
use crate::meta_store::{ConditionalMetadataResult, MetaStore, MetaStoreError, DT_STREAM};
use crate::vfs_router::RouteResult;
use crate::Permission;

use super::conditional_content::ConditionalContentError;
use super::record_control::RecordContentOwner;
use super::{Kernel, KernelError, OperationContext};

mod recovery;
pub use recovery::{RecordWalCreateError, RecordWalRecovery};

/// An admitted WAL and lifecycle authority captured from the same store.
/// Keep this pair for the complete Session consumer lifetime. A fresh lookup
/// after a mount change cannot replace its original control capability.
pub struct RecordWalHandle {
    wal: WalStreamCore,
    owner: RecordContentOwner,
}

impl RecordWalHandle {
    /// Use the data handle admitted with this pair's original storage owner.
    pub fn wal(&self) -> &WalStreamCore {
        &self.wal
    }

    /// Retain this authority for readback, retirement and actual-I/O drain.
    pub fn owner(&self) -> &RecordContentOwner {
        &self.owner
    }
}

fn refused(message: &str) -> ConditionalContentError {
    KernelError::IOError(message.into()).into()
}

fn storage_error(error: MetaStoreError) -> ConditionalContentError {
    match error {
        MetaStoreError::OutcomeUnknown(message) => ConditionalContentError::Unknown(message),
        error => KernelError::IOError(error.to_string()).into(),
    }
}

impl Kernel {
    /// Create an absent, unpublished, zero-retention WAL for an enrolled owner.
    /// Binding precedes inode creation, so ordinary writers cannot race a new
    /// inode into service. A second check after binding refuses retained WAL
    /// state, including entries appended before the binding committed.
    ///
    /// Occupied paths are never upgraded. The service keeps the new name
    /// unpublished until its own durable initialization record is committed.
    /// Unknown outcomes retain the original operation for authoritative readback;
    /// no handle is returned and no automatic rollback deletes prior data.
    /// A create refusal may leave its permanent owner reservation. Once inode
    /// creation commits, a later handle-admission failure reports Unknown.
    pub fn create_record_wal(
        &self,
        path: &str,
        owner_path: &str,
        ctx: &OperationContext,
        owner_version: &[u8],
    ) -> Result<WalStreamCore, ConditionalContentError> {
        let (path, owner_path, route) = self.record_wal_owner_route(path, owner_path, ctx)?;
        let store = route
            .metastore
            .as_ref()
            .cloned()
            .ok_or(ConditionalContentError::Unsupported)?;
        self.create_record_wal_at(
            &path,
            &owner_path,
            &route,
            Arc::clone(&store),
            owner_version,
            || self.record_wal_core(&path, &route, store, owner_version),
        )
    }

    /// Create a WAL and retain its exact original lifecycle-control authority.
    /// The owning service verifies its initialization record before publication.
    /// Neither result is constructed through a second mount lookup.
    pub fn create_record_wal_with_control(
        &self,
        path: &str,
        owner_path: &str,
        ctx: &OperationContext,
        owner_version: &[u8],
    ) -> Result<RecordWalHandle, RecordWalCreateError> {
        let (path, owner_path, route) = self.record_wal_owner_route(path, owner_path, ctx)?;
        let store = route
            .metastore
            .as_ref()
            .cloned()
            .ok_or(ConditionalContentError::Unsupported)?;
        let recovery = self.record_wal_recovery(
            &path,
            &owner_path,
            &route,
            Arc::clone(&store),
            owner_version,
        )?;
        match self.create_record_wal_at(&path, &owner_path, &route, store, owner_version, || {
            recovery.open().map(|handle| handle.wal)
        }) {
            Ok(wal) => Ok(RecordWalHandle {
                wal,
                owner: recovery.owner().clone(),
            }),
            Err(error) => Err(RecordWalCreateError::captured(error, recovery)),
        }
    }

    fn record_wal_owner_route(
        &self,
        path: &str,
        owner_path: &str,
        ctx: &OperationContext,
    ) -> Result<(String, String, RouteResult), ConditionalContentError> {
        self.check_metadata_permission(path, Permission::Read, ctx)?;
        let result = self.record_control_pair(path, owner_path, ctx)?;
        self.check_metadata_permission(&result.0, Permission::Read, ctx)?;
        Ok(result)
    }

    fn create_record_wal_at(
        &self,
        path: &str,
        owner_path: &str,
        route: &RouteResult,
        store: Arc<dyn MetaStore>,
        owner_version: &[u8],
        admit: impl FnOnce() -> Result<WalStreamCore, ConditionalContentError>,
    ) -> Result<WalStreamCore, ConditionalContentError> {
        let records = store
            .as_guarded_records()
            .ok_or(ConditionalContentError::Unsupported)?;
        let _io = records.begin_record_io(owner_path, owner_version)?;
        if store.get(path).map_err(storage_error)?.is_some() {
            return Err(refused("new owned WAL path already exists"));
        }
        records.bind_record_guard(path, None, owner_path, owner_version)?;
        let prefix = wal_stream_prefix(&records.record_storage_key(path));
        if store.stream_tail(&prefix).map_err(storage_error)? != 0
            || store.stream_floor(&prefix).map_err(storage_error)? != 0
            || store.stream_earliest(&prefix).map_err(storage_error)? != 0
            || !store
                .list_stream_segments(&prefix)
                .map_err(storage_error)?
                .is_empty()
        {
            return Err(refused("new owned WAL path retains previous log data"));
        }
        let metadata = self.build_metadata(
            path,
            &route.zone_id,
            DT_STREAM,
            0,
            None,
            0,
            1,
            None,
            None,
            None,
        );
        match records.replace_guarded_record(path, metadata, None, owner_version)? {
            ConditionalMetadataResult::Committed { .. } => admit().map_err(|error| {
                ConditionalContentError::Unknown(format!(
                    "owned WAL inode committed but handle admission failed: {error}"
                ))
            }),
            ConditionalMetadataResult::Conflict { .. } => {
                Err(refused("new owned WAL inode changed during creation"))
            }
        }
    }

    /// Reopen a WAL already bound to the captured owner revision.
    /// The owning service must verify its original initialization record before
    /// publishing this handle. DT_STREAM alone does not prove a Session format.
    /// This method neither enrolls old consumers nor changes their owner.
    pub fn open_record_wal(
        &self,
        path: &str,
        ctx: &OperationContext,
        owner_version: &[u8],
    ) -> Result<WalStreamCore, ConditionalContentError> {
        self.check_metadata_permission(path, Permission::Read, ctx)?;
        let (path, route) = self.record_control_route(path, ctx)?;
        self.check_metadata_permission(&path, Permission::Read, ctx)?;
        let store = route
            .metastore
            .as_ref()
            .cloned()
            .ok_or(ConditionalContentError::Unsupported)?;
        self.record_wal_core(&path, &route, store, owner_version)
    }

    /// Reopen through one captured storage pair and retain its owner control.
    /// The service supplies the original owner binding and checks its durable
    /// Session initialization before exposing this handle to consumers.
    pub fn open_record_wal_with_control(
        &self,
        path: &str,
        owner_path: &str,
        ctx: &OperationContext,
        owner_version: &[u8],
    ) -> Result<RecordWalHandle, ConditionalContentError> {
        let (path, owner_path, route) = self.record_wal_owner_route(path, owner_path, ctx)?;
        let store = route
            .metastore
            .as_ref()
            .cloned()
            .ok_or(ConditionalContentError::Unsupported)?;
        self.record_wal_recovery(&path, &owner_path, &route, store, owner_version)?
            .open()
    }

    fn record_wal_recovery(
        &self,
        path: &str,
        owner_path: &str,
        route: &RouteResult,
        store: Arc<dyn MetaStore>,
        owner_version: &[u8],
    ) -> Result<RecordWalRecovery, ConditionalContentError> {
        let owner = RecordContentOwner::from_route(route, owner_path)?;
        let canonical = store
            .as_guarded_records()
            .ok_or(ConditionalContentError::Unsupported)?
            .record_storage_key(path);
        let backend = route
            .backend
            .as_ref()
            .cloned()
            .ok_or(ConditionalContentError::Unsupported)?;
        let cold = self.cold_segment_store_for_backend(&route.zone_id, &canonical, backend);
        Ok(RecordWalRecovery::new(
            path,
            owner_path,
            owner_version,
            store,
            cold,
            self.seal_policy(),
            owner,
        ))
    }

    fn record_wal_core(
        &self,
        path: &str,
        route: &RouteResult,
        store: Arc<dyn MetaStore>,
        owner_version: &[u8],
    ) -> Result<WalStreamCore, ConditionalContentError> {
        let records = store
            .as_guarded_records()
            .ok_or(ConditionalContentError::Unsupported)?;
        let canonical = records.record_storage_key(path);
        let backend = route
            .backend
            .as_ref()
            .cloned()
            .ok_or(ConditionalContentError::Unsupported)?;
        let cold = self.cold_segment_store_for_backend(&route.zone_id, &canonical, backend);
        recovery::open_core(path, store, owner_version, cold, self.seal_policy())
    }
}
