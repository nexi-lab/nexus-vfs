//! The runtime service admits a record using its exact immutable content image.

use crate::dispatch::Permission;
use crate::meta_store::{MetaStoreError, RecordProtectionResult};

use super::conditional_content::{require_link_hop, ConditionalContentError};
use super::{Kernel, KernelError, OperationContext};

impl Kernel {
    /// Protect an existing record at its current path, or reserve an absent path.
    /// The owning runtime service retires previous consumers before admission.
    /// Content qualification and the comparison use the same metadata image.
    pub fn protect_record_content(
        &self,
        path: &str,
        ctx: &OperationContext,
    ) -> Result<RecordProtectionResult, ConditionalContentError> {
        self.protect_record_content_at(path, ctx, 1)
    }

    fn protect_record_content_at(
        &self,
        path: &str,
        ctx: &OperationContext,
        link_hops: u8,
    ) -> Result<RecordProtectionResult, ConditionalContentError> {
        self.check_metadata_permission(path, Permission::Write, ctx)?;
        if !ctx.is_admin && !ctx.is_system {
            return Err(KernelError::PermissionDenied(
                "record protection requires the owning runtime service".into(),
            )
            .into());
        }
        self.apply_read_hooks(path, ctx)?;
        if let Some(target) = self.directory_link_target(path, &ctx.zone_id)? {
            require_link_hop(path, link_hops)?;
            return self.protect_record_content_at(&target, ctx, link_hops - 1);
        }
        let route = self.conditional_content_route(path, ctx)?;
        self.with_metastore_route(&route, |store| {
            let operation = store
                .as_record_protection()
                .ok_or(ConditionalContentError::Unsupported)?;
            operation
                .protect_record(path, &|metadata| {
                    let content = self
                        .read_immutable_content(&route, metadata)
                        .map_err(|error| MetaStoreError::IOError(error.to_string()))?;
                    let engine = route
                        .backend
                        .as_ref()
                        .and_then(|backend| backend.as_cas())
                        .ok_or_else(|| {
                            MetaStoreError::IOError("record storage is unavailable".into())
                        })?;
                    // The existing publisher verifies and synchronizes dedup
                    // hits too. Admission preserves the qualified legacy pointer.
                    let published = engine.write_content(&content).map_err(|error| {
                        MetaStoreError::IOError(format!(
                            "record content publication failed: {error:?}"
                        ))
                    })?;
                    if metadata.content_id.as_deref() != Some(published.as_str()) {
                        return Err(MetaStoreError::IOError(
                            "record content requires a qualified canonical image".into(),
                        ));
                    }
                    Ok(())
                })
                .map_err(ConditionalContentError::from)
        })
        .ok_or(ConditionalContentError::Unsupported)?
    }
}
