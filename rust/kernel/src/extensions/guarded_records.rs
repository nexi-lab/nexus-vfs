//! Optional storage authority for record ownership and final commit fences.

use crate::abc::meta_store::{FileMetadata, StreamSegment};
use crate::extensions::conditional_metadata::{
    ConditionalMetadataError, ConditionalMetadataResult,
};

/// Retain this storage-owned handle until the actual I/O has finished, including
/// work that continues after its request future has been cancelled.
pub trait RecordIoGuard: Send + Sync {}

/// The committed lifetime decision, read independently of data-plane I/O.
/// A terminal revision revokes operations but does not prove that I/O drained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordOwnerState {
    pub version: Vec<u8>,
    pub is_retired: bool,
}

/// The caller qualifies immutable content or a durable WAL before binding it.
/// I/O enrollment is explicit; physical reclamation remains a separate control.
/// All paths resolve in one owning store; versions are opaque storage tokens.
pub trait GuardedRecords: Send + Sync {
    /// Map this store view's caller path to its canonical storage key.
    /// This uses the owning store's existing path mapping, not a new authority.
    fn record_storage_key(&self, path: &str) -> String;

    /// Refuse generic I/O on an explicitly I/O-enrolled owner or its child.
    /// The input is already this store's canonical key, as used by the WAL.
    /// Check existing ownership state on every operation, including retained
    /// unowned handles; an earlier unprotected result cannot be cached.
    fn check_unscoped_io(&self, storage_key: &str) -> Result<(), ConditionalMetadataError>;

    /// Read one actual owner's revision and retirement marker in one snapshot.
    /// Bound children cannot impersonate their owner. The canonical key is
    /// resolved by the owning service; this grants no content read or cleanup.
    fn record_owner_state(
        &self,
        storage_key: &str,
    ) -> Result<RecordOwnerState, ConditionalMetadataError>;

    /// Enroll a fresh/quiescent owner before admitting content I/O. This upgrades
    /// the reader requirement and preserves its revision. The owning service
    /// retires previous consumers before enrollment.
    fn admit_record_io_owner(
        &self,
        path: &str,
        expected_version: &[u8],
    ) -> Result<(), ConditionalMetadataError>;

    /// Retain actual storage I/O. The owner is checked after acquiring the
    /// lifetime guard too; the caller holds this guard through all work.
    /// The path may be an explicitly enrolled owner or its bound child. Owner
    /// I/O covers qualification of a new child before binding can commit.
    fn begin_record_io(
        &self,
        path: &str,
        guard_version: &[u8],
    ) -> Result<Box<dyn RecordIoGuard>, ConditionalMetadataError>;

    /// Verify an existing child's permanent binding to this exact live owner.
    /// Matching opaque revisions alone cannot pair a data handle with control.
    /// This reads existing authority; it never enrolls or reassigns a record.
    fn check_record_owner_binding(
        &self,
        _path: &str,
        _owner_path: &str,
        _owner_version: &[u8],
    ) -> Result<(), ConditionalMetadataError> {
        Err(ConditionalMetadataError::Unsupported)
    }

    /// Return exclusive retirement coverage after every admitted I/O has ended.
    /// None means an actual operation still holds its lifetime guard.
    fn try_exclude_retired_record_io(
        &self,
        owner_path: &str,
        terminal_version: &[u8],
    ) -> Result<Option<Box<dyn RecordIoGuard>>, ConditionalMetadataError>;

    /// Compare the exact qualified image and permanently bind its owner.
    fn bind_record_guard(
        &self,
        path: &str,
        expected_image: Option<&FileMetadata>,
        guard_path: &str,
        guard_version: &[u8],
    ) -> Result<(), ConditionalMetadataError>;

    /// Compare the record and its owner at the final metadata publication.
    fn replace_guarded_record(
        &self,
        path: &str,
        metadata: FileMetadata,
        expected_version: Option<&[u8]>,
        guard_version: &[u8],
    ) -> Result<ConditionalMetadataResult, ConditionalMetadataError>;

    /// Check the owner and assign the WAL offset at one serialization point.
    fn append_guarded_record(
        &self,
        path: &str,
        data: &[u8],
        guard_version: &[u8],
    ) -> Result<u64, ConditionalMetadataError>;

    /// Publish a cold segment under the same final owner comparison as append.
    /// The caller retains its actual I/O guard through staging and publication.
    fn seal_guarded_record(
        &self,
        path: &str,
        segment: &StreamSegment,
        guard_version: &[u8],
    ) -> Result<(), ConditionalMetadataError>;

    /// Retire segment references only while the captured owner is still live.
    /// Physical content deletion remains the reference authority's responsibility.
    fn trim_guarded_record(
        &self,
        path: &str,
        up_to_seq: u64,
        trimmed: Vec<(String, String)>,
        guard_version: &[u8],
    ) -> Result<(), ConditionalMetadataError>;

    /// Publish the terminal owner image and irrevocably revoke its handles.
    fn retire_record_guard(
        &self,
        path: &str,
        terminal_image: FileMetadata,
        expected_version: &[u8],
    ) -> Result<ConditionalMetadataResult, ConditionalMetadataError>;
}

/// Generic WAL handles already carry a canonical storage key. Stores without
/// this optional capability cannot enroll an owner and retain ordinary I/O.
pub(crate) fn check_unscoped_record_io(
    store: &dyn crate::abc::meta_store::MetaStore,
    storage_key: &str,
) -> Result<(), ConditionalMetadataError> {
    if let Some(records) = store.as_guarded_records() {
        records.check_unscoped_io(storage_key)?;
    }
    Ok(())
}
