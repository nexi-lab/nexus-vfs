//! Optional storage authority for record ownership and final commit fences.

use crate::abc::meta_store::FileMetadata;
use crate::extensions::conditional_metadata::{
    ConditionalMetadataError, ConditionalMetadataResult,
};

/// These metadata controls require qualified immutable content at their caller.
/// They do not provide OS locks, storage I/O drain or physical reclamation.
/// All paths resolve in one owning store; versions are opaque storage tokens.
pub trait GuardedRecords: Send + Sync {
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

    /// Publish the terminal owner image and irrevocably revoke its handles.
    fn retire_record_guard(
        &self,
        path: &str,
        terminal_image: FileMetadata,
        expected_version: &[u8],
    ) -> Result<ConditionalMetadataResult, ConditionalMetadataError>;
}
