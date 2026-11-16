//! Original-store readback survives an uncertain paired WAL construction.

use std::sync::Arc;

use crate::core::stream::wal::{ColdSegmentStore, SealPolicy, WalStreamCore};
use crate::meta_store::{MetaStore, DT_STREAM};

use super::{refused, storage_error, ConditionalContentError, RecordContentOwner, RecordWalHandle};

/// The original storage and admission used by one WAL construction.
/// Reopening through this capability never consults the current mount table.
/// The service still verifies the original Session initialization before use.
#[derive(Clone)]
pub struct RecordWalRecovery {
    storage: Arc<RecoveryStorage>,
}

struct RecoveryStorage {
    path: String,
    owner_path: String,
    owner_version: Vec<u8>,
    store: Arc<dyn MetaStore>,
    cold: Option<Arc<dyn ColdSegmentStore>>,
    policy: SealPolicy,
    owner: RecordContentOwner,
}

/// A paired construction failure retains authoritative readback after capture.
/// Pre-capture refusals have no recovery capability. Unknown remains Unknown;
/// this value never claims an inode or initialization record committed.
#[derive(Debug)]
pub struct RecordWalCreateError {
    outcome: Box<ConditionalContentError>,
    recovery: Option<RecordWalRecovery>,
}

impl std::fmt::Debug for RecordWalRecovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordWalRecovery")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RecordWalCreateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.outcome.as_ref(), formatter)
    }
}

impl std::error::Error for RecordWalCreateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.outcome.as_ref())
    }
}

impl From<ConditionalContentError> for RecordWalCreateError {
    fn from(outcome: ConditionalContentError) -> Self {
        Self {
            outcome: Box::new(outcome),
            recovery: None,
        }
    }
}

impl RecordWalCreateError {
    pub(super) fn captured(outcome: ConditionalContentError, recovery: RecordWalRecovery) -> Self {
        Self {
            outcome: Box::new(outcome),
            recovery: Some(recovery),
        }
    }

    /// Preserve the original failure classification and message.
    pub fn outcome(&self) -> &ConditionalContentError {
        &self.outcome
    }

    /// Retain this capability for readback, even if the visible path remounts.
    /// Absence does not establish whether an operation committed.
    pub fn recovery(&self) -> Option<&RecordWalRecovery> {
        self.recovery.as_ref()
    }
}

impl RecordWalRecovery {
    pub(super) fn new(
        path: &str,
        owner_path: &str,
        owner_version: &[u8],
        store: Arc<dyn MetaStore>,
        cold: Option<Arc<dyn ColdSegmentStore>>,
        policy: SealPolicy,
        owner: RecordContentOwner,
    ) -> Self {
        Self {
            storage: Arc::new(RecoveryStorage {
                path: path.into(),
                owner_path: owner_path.into(),
                owner_version: owner_version.into(),
                store,
                cold,
                policy,
                owner,
            }),
        }
    }

    /// Read or retire the original owner independently of WAL admission.
    pub fn owner(&self) -> &RecordContentOwner {
        &self.storage.owner
    }

    /// Reopen only the original bound inode. This neither creates a name nor
    /// refreshes a retired revision, and it never publishes a Session binding.
    pub fn open(&self) -> Result<RecordWalHandle, ConditionalContentError> {
        let storage = &self.storage;
        storage
            .store
            .as_guarded_records()
            .ok_or(ConditionalContentError::Unsupported)?
            .check_record_owner_binding(
                &storage.path,
                &storage.owner_path,
                &storage.owner_version,
            )?;
        let wal = open_core(
            &storage.path,
            Arc::clone(&storage.store),
            &storage.owner_version,
            storage.cold.as_ref().map(Arc::clone),
            storage.policy,
        )?;
        Ok(RecordWalHandle {
            wal,
            owner: storage.owner.clone(),
        })
    }
}

pub(super) fn open_core(
    path: &str,
    store: Arc<dyn MetaStore>,
    owner_version: &[u8],
    cold: Option<Arc<dyn ColdSegmentStore>>,
    policy: SealPolicy,
) -> Result<WalStreamCore, ConditionalContentError> {
    let records = store
        .as_guarded_records()
        .ok_or(ConditionalContentError::Unsupported)?;
    let _io = records.begin_record_io(path, owner_version)?;
    let metadata = store
        .get(path)
        .map_err(storage_error)?
        .ok_or_else(|| refused("owned WAL inode is absent"))?;
    if metadata.entry_type != DT_STREAM || metadata.size != 0 {
        return Err(ConditionalContentError::Unsupported);
    }
    let canonical = records.record_storage_key(path);
    let core = match cold {
        Some(cold) => WalStreamCore::with_cold_tier(Arc::clone(&store), canonical, cold, policy, 0),
        None => WalStreamCore::new(Arc::clone(&store), canonical),
    };
    core.with_record_owner(path, owner_version.to_vec())
        .map_err(ConditionalContentError::from)
}
