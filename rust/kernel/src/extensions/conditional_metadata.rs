//! Atomic metadata images and their committed opaque revisions.

use crate::abc::meta_store::{FileMetadata, MetaStoreError};

/// One authoritative metadata image and its opaque committed content revision.
#[derive(Clone, Debug)]
pub struct MetadataSnapshot {
    pub metadata: FileMetadata,
    pub version: Vec<u8>,
}

/// Result of conditionally replacing an authoritative metadata image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConditionalMetadataResult {
    Committed { version: Vec<u8> },
    Conflict { current_version: Option<Vec<u8>> },
}

/// Conditional metadata distinguishes unsupported storage and ambiguous writes.
#[derive(Debug)]
pub enum ConditionalMetadataError {
    Unsupported,
    /// A read failed, or a write was definitely refused before submission.
    Failed(MetaStoreError),
    /// A submitted write may have committed and requires authoritative readback.
    Unknown(String),
}

impl std::fmt::Display for ConditionalMetadataError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => formatter.write_str("conditional metadata is unsupported"),
            Self::Failed(error) => write!(formatter, "conditional metadata failed: {error}"),
            Self::Unknown(error) => {
                write!(formatter, "conditional metadata outcome unknown: {error}")
            }
        }
    }
}

impl std::error::Error for ConditionalMetadataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(error) => Some(error),
            _ => None,
        }
    }
}

/// Optional atomic metadata capability used with a qualified immutable store.
/// Missing metadata is `None`; each present snapshot carries its own revision.
/// Replacements compare and publish in one transaction. A missing expected
/// version requires absence; conflict leaves the authoritative image unchanged.
pub trait ConditionalMetadata: Send + Sync {
    fn read_versioned(
        &self,
        path: &str,
    ) -> Result<Option<MetadataSnapshot>, ConditionalMetadataError>;

    fn replace_if_version(
        &self,
        path: &str,
        metadata: FileMetadata,
        expected_version: Option<&[u8]>,
    ) -> Result<ConditionalMetadataResult, ConditionalMetadataError>;
}
