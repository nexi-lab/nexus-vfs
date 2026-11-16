//! Content operations retain storage I/O and compare the admitted owner.
//!
//! Admission and retirement belong to the owning runtime service. These
//! operations retain the caller's permissions, hooks and owning-zone routing.

use super::conditional_content::{
    ConditionalContentError, ConditionalContentResult, VersionedContent,
};
use super::{Kernel, OperationContext};

impl Kernel {
    /// Read an immutable record while its admitted storage owner is live.
    /// The native I/O handle remains with this synchronous operation through
    /// the actual read, including execution in a cancelled request's worker.
    pub fn read_guarded_content(
        &self,
        path: &str,
        ctx: &OperationContext,
        owner_version: &[u8],
    ) -> Result<Option<VersionedContent>, ConditionalContentError> {
        self.read_versioned_content_at(path, ctx, Some(owner_version), 1)
    }

    /// Publish immutable bytes only while the admitted owner remains live.
    /// Storage checks the owner again in the final metadata transaction;
    /// retirement may invalidate a write whose content I/O has already begun.
    pub fn replace_guarded_content(
        &self,
        path: &str,
        ctx: &OperationContext,
        content: &[u8],
        expected_version: Option<&[u8]>,
        owner_version: &[u8],
    ) -> Result<ConditionalContentResult, ConditionalContentError> {
        self.replace_content_if_version_at(
            path,
            ctx,
            content,
            expected_version,
            Some(owner_version),
            1,
        )
    }
}
