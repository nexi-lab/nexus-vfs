//! Qualified regular-file ownership controls for the trusted runtime service.
//!
//! These methods retain the service's original identity and mount authority.
//! They neither expose native handles over RPC nor start physical reclamation.

use std::sync::Arc;

use crate::extensions::guarded_records::{RecordIoGuard, RecordOwnerState};
use crate::meta_store::{ConditionalMetadataError, ConditionalMetadataResult, MetaStoreError};
use crate::vfs_router::RouteResult;

use super::conditional_content::{ConditionalContentError, ConditionalContentResult};
use super::{Kernel, KernelError, OperationContext};

fn storage_error(error: MetaStoreError) -> ConditionalContentError {
    ConditionalMetadataError::Failed(error).into()
}

impl Kernel {
    /// Inspect the original owner decision through the trusted control plane.
    /// This supports unknown-outcome/restart readback while generic content
    /// reads stay refused. A retired result requires separate I/O exclusion
    /// before reclamation; it grants no permission to delete shared content.
    pub fn record_content_owner_state(
        &self,
        path: &str,
        ctx: &OperationContext,
    ) -> Result<RecordOwnerState, ConditionalContentError> {
        let (path, route) = self.record_control_route(path, ctx)?;
        self.with_metastore_route(&route, |store| {
            let records = store
                .as_guarded_records()
                .ok_or(ConditionalContentError::Unsupported)?;
            records
                .record_owner_state(&records.record_storage_key(&path))
                .map_err(ConditionalContentError::from)
        })
        .ok_or(ConditionalContentError::Unsupported)?
    }

    /// Ordinary reads cannot materialize content owned by an enrolled service.
    /// Resolve the canonical key through the same captured route/store as I/O.
    pub(super) fn check_unscoped_content_io(
        &self,
        path: &str,
        route: &RouteResult,
    ) -> Result<(), KernelError> {
        Self::with_captured_metastore_route(route, |store| {
            if let Some(records) = store.as_guarded_records() {
                records
                    .check_unscoped_io(&records.record_storage_key(path))
                    .map_err(|error| KernelError::IOError(error.to_string()))?;
            }
            Ok(())
        })
        .unwrap_or(Ok(()))
    }

    /// Enroll a fresh or quiescent protected owner for actual content I/O.
    /// The service must retire pre-enrollment consumers before calling this.
    /// Protect its immutable image with `protect_record_content` first. This
    /// metadata-only enrollment preserves that image and its exact revision.
    pub fn admit_record_content_io(
        &self,
        path: &str,
        ctx: &OperationContext,
        expected_version: &[u8],
    ) -> Result<(), ConditionalContentError> {
        let (path, route) = self.record_control_route(path, ctx)?;
        self.with_metastore_route(&route, |store| {
            store
                .as_guarded_records()
                .ok_or(ConditionalContentError::Unsupported)?
                .admit_record_io_owner(&path, expected_version)
                .map_err(ConditionalContentError::from)
        })
        .ok_or(ConditionalContentError::Unsupported)?
    }

    /// Bind an absent or qualified immutable regular file to one live owner.
    /// Both names must resolve through the same captured mount and metastore;
    /// use one spelling of an alias for both paths. The final apply compares
    /// the exact qualified image before publishing its permanent binding.
    pub fn bind_record_content_owner(
        &self,
        path: &str,
        owner_path: &str,
        ctx: &OperationContext,
        owner_version: &[u8],
    ) -> Result<(), ConditionalContentError> {
        let (path, owner_path, route) = self.record_control_pair(path, owner_path, ctx)?;
        self.with_metastore_route(&route, |store| {
            let records = store
                .as_guarded_records()
                .ok_or(ConditionalContentError::Unsupported)?;
            let _io = records.begin_record_io(&owner_path, owner_version)?;
            let metadata = store.get(&path).map_err(storage_error)?;
            if let Some(metadata) = &metadata {
                self.qualify_record_content(&route, metadata)
                    .map_err(storage_error)?;
            }
            records
                .bind_record_guard(&path, metadata.as_ref(), &owner_path, owner_version)
                .map_err(ConditionalContentError::from)
        })
        .ok_or(ConditionalContentError::Unsupported)?
    }

    pub(super) fn record_control_pair(
        &self,
        path: &str,
        owner_path: &str,
        ctx: &OperationContext,
    ) -> Result<(String, String, RouteResult), ConditionalContentError> {
        let (path, route) = self.record_control_route(path, ctx)?;
        let (owner_path, owner_route) = self.record_control_route(owner_path, ctx)?;
        let same_store = match (&route.metastore, &owner_route.metastore) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            (None, None) => true,
            _ => false,
        };
        if route.mount_point != owner_route.mount_point
            || route.zone_id != owner_route.zone_id
            || !same_store
            || !matches!((&route.backend, &owner_route.backend), (Some(left), Some(right)) if Arc::ptr_eq(left, right))
        {
            return Err(ConditionalContentError::Unsupported);
        }
        Ok((path, owner_path, route))
    }

    /// Permanently retire an owner without changing its immutable bytes.
    /// The terminal storage marker and new revision are the deletion authority;
    /// the file's application payload is not a second retirement decision.
    /// An unknown outcome requires authoritative retirement readback.
    pub fn retire_record_content_owner(
        &self,
        path: &str,
        ctx: &OperationContext,
        expected_version: &[u8],
    ) -> Result<ConditionalContentResult, ConditionalContentError> {
        let (path, route) = self.record_control_route(path, ctx)?;
        self.with_metastore_route(&route, |store| -> Result<_, ConditionalContentError> {
            let snapshot = store
                .as_conditional_metadata()
                .ok_or(ConditionalContentError::Unsupported)?
                .read_versioned(&path)?
                .ok_or_else(|| {
                    storage_error(MetaStoreError::IOError("record owner is absent".into()))
                })?;
            let result = store
                .as_guarded_records()
                .ok_or(ConditionalContentError::Unsupported)?
                .retire_record_guard(&path, snapshot.metadata, expected_version)?;
            Ok(match result {
                ConditionalMetadataResult::Committed { version } => {
                    ConditionalContentResult::Committed { version }
                }
                ConditionalMetadataResult::Conflict { current_version } => {
                    ConditionalContentResult::Conflict { current_version }
                }
            })
        })
        .ok_or(ConditionalContentError::Unsupported)?
    }

    /// Validate the terminal revision and try to exclude real storage I/O.
    /// A successful `None` confirms retirement but means actual I/O remains.
    /// Retain the returned native handle through any future reclamation work.
    /// This does not qualify shared CAS references or delete any content.
    pub fn try_exclude_retired_content_io(
        &self,
        path: &str,
        ctx: &OperationContext,
        terminal_version: &[u8],
    ) -> Result<Option<Box<dyn RecordIoGuard>>, ConditionalContentError> {
        let (path, route) = self.record_control_route(path, ctx)?;
        self.with_metastore_route(&route, |store| {
            store
                .as_guarded_records()
                .ok_or(ConditionalContentError::Unsupported)?
                .try_exclude_retired_record_io(&path, terminal_version)
                .map_err(ConditionalContentError::from)
        })
        .ok_or(ConditionalContentError::Unsupported)?
    }
}
