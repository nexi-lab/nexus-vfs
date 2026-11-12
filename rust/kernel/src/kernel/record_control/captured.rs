//! Native control handles keep an admitted owner's original storage identity.

use std::sync::Arc;

use crate::abc::object_store::ObjectStore;
use crate::extensions::guarded_records::{GuardedRecords, RecordIoGuard, RecordOwnerState};
use crate::meta_store::MetaStore;
use crate::vfs_router::RouteResult;

use super::super::conditional_content::{ConditionalContentError, ConditionalContentResult};
use super::super::KernelError;

/// The trusted service's original owner, independent of later mount changes.
/// This is a native capability, not a serialized path/revision or a child grant.
/// Obtain a WAL and its control together before publishing either to consumers.
#[derive(Clone)]
pub struct RecordContentOwner {
    store: Arc<dyn MetaStore>,
    backend: Arc<dyn ObjectStore>,
    path: String,
    storage_key: String,
}

/// Exclusive actual-I/O coverage for exactly one captured storage owner.
/// Keep this handle through storage-local reclamation. It grants no permission
/// to delete through a freshly routed path or remove independently retained CAS.
pub struct RecordContentExclusion {
    owner: RecordContentOwner,
    _io: Box<dyn RecordIoGuard>,
}

impl RecordContentOwner {
    pub(crate) fn from_route(
        route: &RouteResult,
        path: &str,
    ) -> Result<Self, ConditionalContentError> {
        let store = route
            .metastore
            .as_ref()
            .cloned()
            .ok_or(ConditionalContentError::Unsupported)?;
        let backend = route
            .backend
            .as_ref()
            .cloned()
            .ok_or(ConditionalContentError::Unsupported)?;
        let storage_key = store
            .as_guarded_records()
            .ok_or(ConditionalContentError::Unsupported)?
            .record_storage_key(path);
        let owner = Self {
            store,
            backend,
            path: path.to_owned(),
            storage_key,
        };
        // Bound children and protected-but-unenrolled records cannot mint an
        // owner's lifecycle capability. Retired owners remain readable.
        owner.state()?;
        Ok(owner)
    }

    fn records(&self) -> Result<&dyn GuardedRecords, ConditionalContentError> {
        let records = self
            .store
            .as_guarded_records()
            .ok_or(ConditionalContentError::Unsupported)?;
        if records.record_storage_key(&self.path) != self.storage_key {
            return Err(KernelError::IOError("captured owner storage key changed".into()).into());
        }
        Ok(records)
    }

    /// Read the original storage decision, including after Unknown or retirement.
    /// A terminal result alone does not establish actual I/O completion.
    pub fn state(&self) -> Result<RecordOwnerState, ConditionalContentError> {
        self.records()?
            .record_owner_state(&self.storage_key)
            .map_err(ConditionalContentError::from)
    }

    /// Irrevocably retire this original owner. Unknown must be resolved through
    /// this same handle's state, never a fresh lookup of the visible path.
    pub fn retire(
        &self,
        expected_version: &[u8],
    ) -> Result<ConditionalContentResult, ConditionalContentError> {
        self.records()?;
        super::retire_in_store(self.store.as_ref(), &self.path, expected_version)
    }

    /// None means original actual I/O still holds the shared lifetime lock.
    /// A replacement store's guard cannot establish this owner's exclusion.
    pub fn try_exclude_retired_io(
        &self,
        terminal_version: &[u8],
    ) -> Result<Option<RecordContentExclusion>, ConditionalContentError> {
        Ok(self
            .records()?
            .try_exclude_retired_record_io(&self.path, terminal_version)?
            .map(|io| RecordContentExclusion {
                owner: self.clone(),
                _io: io,
            }))
    }

    /// Compare the original storage object and canonical key, not opaque
    /// revisions or path spelling. Consumers retain this proof through cleanup.
    pub fn owns_exclusion(&self, exclusion: &RecordContentExclusion) -> bool {
        Arc::ptr_eq(&self.store, &exclusion.owner.store)
            && Arc::ptr_eq(&self.backend, &exclusion.owner.backend)
            && self.storage_key == exclusion.owner.storage_key
    }
}
