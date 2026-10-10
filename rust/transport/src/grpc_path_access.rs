//! Authorization for VFS RPCs whose kernel primitives do not carry identity.

use kernel::kernel::{validate_path_fast, KernelError, OperationContext};
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
        validate_path_fast(path).map_err(|error| Status::invalid_argument(error.to_string()))?;
        // Synthetic metadata primitives do not receive an authenticated context.
        if !ctx.is_admin && !ctx.is_system && (path == "/__sys__" || path.starts_with("/__sys__/"))
        {
            return Err(Status::permission_denied(
                "system metadata requires an administrator",
            ));
        }
        let route = if ctx.is_admin || ctx.is_system {
            None
        } else {
            self.kernel.vfs_router_arc().route(path, &ctx.zone_id)
        };
        self.kernel
            .check_permission_with_route(path, route.as_ref(), permission, ctx)
            .map_err(|error| match error {
                KernelError::PermissionDenied(_) => Status::permission_denied(error.to_string()),
                _ => Status::internal(error.to_string()),
            })
    }
}
