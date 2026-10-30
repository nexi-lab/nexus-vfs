//! Storage-owned admission of an existing record to conditional-only writes.

use crate::abc::meta_store::{FileMetadata, MetaStoreError};
use crate::extensions::conditional_metadata::ConditionalMetadataError;

/// The policy is committed, or an ordinary writer changed the qualified image.
#[derive(Debug, PartialEq, Eq)]
pub enum RecordProtectionResult {
    Protected,
    Conflict,
}

/// Optional control operation for a record's owning runtime service.
///
/// The store reads one authoritative image, invokes `qualify` on that image's
/// regular-file metadata, then compares that exact image and commits its write
/// policy and revision atomically. Qualification runs outside consensus and
/// database transactions. An absent record needs no content qualification.
/// Repeating admission of a protected record preserves its current revision.
pub trait RecordProtection: Send + Sync {
    fn protect_record(
        &self,
        path: &str,
        qualify: &dyn Fn(&FileMetadata) -> Result<(), MetaStoreError>,
    ) -> Result<RecordProtectionResult, ConditionalMetadataError>;
}
