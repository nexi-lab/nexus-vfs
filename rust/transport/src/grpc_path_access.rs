//! Authorization for VFS RPCs whose kernel primitives do not carry identity.

use kernel::kernel::{KernelError, OperationContext};
use kernel::Permission;
use tonic::Status;

use crate::grpc::VfsServiceImpl;

impl VfsServiceImpl {
    /// A glob watches its fixed parent namespace. Individual events are checked
    /// again before returning because permission can change during the wait.
    pub(crate) fn watch_scope(pattern: &str) -> &str {
        match pattern.find(['*', '?', '[', '{', '\\']) {
            None => pattern,
            Some(index) => pattern[..index]
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .unwrap_or("/"),
        }
    }

    pub(crate) fn authorize_path(
        &self,
        path: &str,
        permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), Status> {
        self.kernel
            .check_metadata_permission(path, permission, ctx)
            .map_err(|error| match error {
                KernelError::InvalidPath(_) => Status::invalid_argument(error.to_string()),
                KernelError::PermissionDenied(_) => Status::permission_denied(error.to_string()),
                _ => Status::internal(error.to_string()),
            })
    }
}
