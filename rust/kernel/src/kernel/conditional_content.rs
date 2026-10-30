//! Coherent immutable content snapshots and atomic full-file replacement.

use crate::abc::object_store::WriteResult;
use crate::cas_engine::CASError;
use crate::meta_store::{
    ConditionalMetadataError, ConditionalMetadataResult, FileMetadata, MetadataSnapshot, DT_REG,
};
use crate::vfs_router::RouteResult;

use super::{validate_path_fast, Kernel, KernelError, OperationContext};

/// Bytes selected by one authoritative metadata image and its committed revision.
#[derive(Debug)]
pub struct VersionedContent {
    pub content: Vec<u8>,
    pub version: Vec<u8>,
}

/// A conditional replacement either commits a new revision or leaves the file intact.
#[derive(Debug, PartialEq, Eq)]
pub enum ConditionalContentResult {
    Committed { version: Vec<u8> },
    Conflict { current_version: Option<Vec<u8>> },
}

/// Unsupported storage, definite failures and possibly committed replacements.
#[derive(Debug)]
pub enum ConditionalContentError {
    Unsupported,
    Failed(KernelError),
    Unknown(String),
}

impl std::fmt::Display for ConditionalContentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => formatter.write_str("conditional content is unsupported"),
            Self::Failed(error) => write!(formatter, "conditional content failed: {error}"),
            Self::Unknown(error) => {
                write!(formatter, "conditional content outcome unknown: {error}")
            }
        }
    }
}

impl std::error::Error for ConditionalContentError {}

impl From<KernelError> for ConditionalContentError {
    fn from(error: KernelError) -> Self {
        Self::Failed(error)
    }
}

impl From<ConditionalMetadataError> for ConditionalContentError {
    fn from(error: ConditionalMetadataError) -> Self {
        match error {
            ConditionalMetadataError::Unsupported => Self::Unsupported,
            ConditionalMetadataError::Failed(error) => {
                Self::Failed(KernelError::IOError(error.to_string()))
            }
            ConditionalMetadataError::Unknown(error) => Self::Unknown(error),
        }
    }
}

fn storage_error(error: CASError) -> ConditionalContentError {
    ConditionalContentError::Failed(KernelError::BackendError(format!("{error:?}")))
}

impl Kernel {
    /// Read the exact immutable object selected by one committed metadata snapshot.
    /// Missing metadata is absence; missing or corrupt bytes are storage failures.
    pub fn read_versioned_content(
        &self,
        path: &str,
        ctx: &OperationContext,
    ) -> Result<Option<VersionedContent>, ConditionalContentError> {
        self.read_versioned_content_at(path, ctx, 1)
    }

    fn read_versioned_content_at(
        &self,
        path: &str,
        ctx: &OperationContext,
        link_hops: u8,
    ) -> Result<Option<VersionedContent>, ConditionalContentError> {
        validate_path_fast(path)?;
        self.apply_read_hooks(path, ctx)?;
        if let Some(target) = self.directory_link_target(path, &ctx.zone_id)? {
            require_link_hop(path, link_hops)?;
            return self.read_versioned_content_at(&target, ctx, link_hops - 1);
        }
        let route = self.conditional_content_route(path, ctx)?;
        let Some(snapshot) = self.conditional_content_snapshot(path, &route)? else {
            return Ok(None);
        };
        let content = self.read_immutable_content(&route, &snapshot.metadata)?;
        Ok(Some(VersionedContent {
            content,
            version: snapshot.version,
        }))
    }

    pub(super) fn read_immutable_content(
        &self,
        route: &RouteResult,
        metadata: &FileMetadata,
    ) -> Result<Vec<u8>, ConditionalContentError> {
        require_regular(metadata)?;
        let content_id = metadata.content_id.as_deref().ok_or_else(|| {
            ConditionalContentError::Failed(KernelError::BackendError(
                "versioned regular file has no immutable content identifier".into(),
            ))
        })?;
        let engine = route
            .backend
            .as_ref()
            .and_then(|backend| backend.as_cas())
            .ok_or(ConditionalContentError::Unsupported)?;
        let content = engine.read_content(content_id).map_err(storage_error)?;
        if content.len() as u64 != metadata.size {
            return Err(ConditionalContentError::Failed(KernelError::BackendError(
                "versioned content size differs from its metadata image".into(),
            )));
        }
        Ok(content)
    }

    /// Stage durable immutable bytes, then compare and publish their pointer atomically.
    /// An absent expected revision requires an absent file. Stale revisions cannot
    /// change its visible bytes. Unknown outcomes require authoritative readback.
    pub fn replace_content_if_version(
        &self,
        path: &str,
        ctx: &OperationContext,
        content: &[u8],
        expected_version: Option<&[u8]>,
    ) -> Result<ConditionalContentResult, ConditionalContentError> {
        self.replace_content_if_version_at(path, ctx, content, expected_version, 1)
    }

    fn replace_content_if_version_at(
        &self,
        path: &str,
        ctx: &OperationContext,
        content: &[u8],
        expected_version: Option<&[u8]>,
        link_hops: u8,
    ) -> Result<ConditionalContentResult, ConditionalContentError> {
        validate_path_fast(path)?;
        let replacement = self.apply_mutating_write_hooks(path, ctx, content)?;
        let content = replacement.as_deref().unwrap_or(content);
        if let Some(target) = self.directory_link_target(path, &ctx.zone_id)? {
            require_link_hop(path, link_hops)?;
            return self.replace_content_if_version_at(
                &target,
                ctx,
                content,
                expected_version,
                link_hops - 1,
            );
        }
        let route = self.conditional_content_route(path, ctx)?;
        let old = self.conditional_content_snapshot(path, &route)?;
        if let Some(snapshot) = &old {
            require_regular(&snapshot.metadata)?;
        }
        let engine = route
            .backend
            .as_ref()
            .and_then(|backend| backend.as_cas())
            .ok_or(ConditionalContentError::Unsupported)?;
        let content_id = engine.write_content(content).map_err(storage_error)?;
        let written = WriteResult {
            version: content_id.clone(),
            content_id,
            size: content.len() as u64,
        };
        let metadata = self.replacement_file_metadata(
            path,
            &route.zone_id,
            &written,
            old.as_ref().map(|snapshot| &snapshot.metadata),
        );
        let write_result = self.file_write_result(
            &metadata,
            written,
            old.as_ref().map(|snapshot| &snapshot.metadata),
        );
        let result = self
            .with_metastore_route(&route, |store| {
                let operation = store
                    .as_conditional_metadata()
                    .ok_or(ConditionalContentError::Unsupported)?;
                operation
                    .replace_if_version(path, metadata, expected_version)
                    .map_err(ConditionalContentError::from)
            })
            .ok_or(ConditionalContentError::Unsupported)??;
        Ok(match result {
            ConditionalMetadataResult::Committed { version } => {
                self.notify_file_write(path, ctx, &write_result);
                ConditionalContentResult::Committed { version }
            }
            ConditionalMetadataResult::Conflict { current_version } => {
                ConditionalContentResult::Conflict { current_version }
            }
        })
    }

    pub(super) fn conditional_content_route(
        &self,
        path: &str,
        ctx: &OperationContext,
    ) -> Result<RouteResult, ConditionalContentError> {
        if self.trie.lookup(path).is_some() {
            return Err(ConditionalContentError::Unsupported);
        }
        let route = self
            .vfs_router
            .route(path, &ctx.zone_id)
            .ok_or(ConditionalContentError::Unsupported)?;
        let durable = route
            .backend
            .as_ref()
            .and_then(|backend| backend.as_cas())
            .is_some_and(|engine| engine.transport().has_durable_publication());
        if !durable {
            return Err(ConditionalContentError::Unsupported);
        }
        Ok(route)
    }

    fn conditional_content_snapshot(
        &self,
        path: &str,
        route: &RouteResult,
    ) -> Result<Option<MetadataSnapshot>, ConditionalContentError> {
        self.with_metastore_route(route, |store| {
            store
                .as_conditional_metadata()
                .ok_or(ConditionalContentError::Unsupported)?
                .read_versioned(path)
                .map_err(ConditionalContentError::from)
        })
        .ok_or(ConditionalContentError::Unsupported)?
    }
}

fn require_regular(metadata: &FileMetadata) -> Result<(), ConditionalContentError> {
    if metadata.entry_type == DT_REG {
        Ok(())
    } else {
        Err(ConditionalContentError::Unsupported)
    }
}

pub(super) fn require_link_hop(path: &str, remaining: u8) -> Result<(), ConditionalContentError> {
    if remaining == 0 {
        Err(
            KernelError::PermissionDenied(format!("DT_LINK chain rejected (ELOOP) at {path}"))
                .into(),
        )
    } else {
        Ok(())
    }
}
