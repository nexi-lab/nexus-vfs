//! Typed zone operations use the shared authenticated request path.
//!
//! The operator surface controls cluster lifecycle. The owner surface uses a
//! private-root backend for admitted learner joins, local mounts and removal.
//! Its original caller and receiver installation are checked around execution.

mod authorization;

use std::sync::Arc;

use kernel::kernel::vfs_proto::zone_runtime_service_server::ZoneRuntimeServiceServer;
use kernel::kernel::vfs_proto::{
    GetRuntimeCapabilitiesRequest, GetRuntimeCapabilitiesResponse, GetZoneOperationRequest,
    ZoneCreateRequest, ZoneDeprovisionRequest, ZoneJoinRequest, ZoneMountRequest,
    ZoneOperationRecord, ZoneReceipt, ZoneRemoveReplicaRequest, ZoneStatusRequest,
    ZoneStatusResponse, ZoneUnmountRequest,
};
use kernel::kernel::{Kernel, OperationContext};
use nexus_raft::{ZoneRuntimeBackend, ZoneRuntimeError};
use tonic::{Request, Response, Status};

use crate::auth::AuthProvider;
use crate::grpc::{authenticate_with, AuthedRequest, DataPlaneReady, ForeignCaVerifierSlot};
use crate::runtime_scope::RuntimeScope;
use authorization::OwnerRequest;

/// The backend seam. Implemented by the raft-side `ZoneRuntimeBackend`
/// (below — a local-trait-for-foreign-type impl: this crate owns the
/// trait, raft owns the struct, keeping transport free of raft internals).
pub trait ZoneRuntimeOps: Send + Sync {
    /// Confined routes accept only a backend whose private-root scope is enforced.
    fn is_local_root(&self) -> bool {
        false
    }
    fn zone_create(&self, req: &ZoneCreateRequest) -> Result<ZoneReceipt, ZoneRuntimeError>;
    fn zone_join(&self, req: &ZoneJoinRequest) -> Result<ZoneReceipt, ZoneRuntimeError>;
    fn zone_status(&self, req: &ZoneStatusRequest) -> Result<ZoneStatusResponse, ZoneRuntimeError>;
    fn zone_mount(&self, req: &ZoneMountRequest) -> Result<ZoneReceipt, ZoneRuntimeError>;
    fn zone_unmount(&self, req: &ZoneUnmountRequest) -> Result<ZoneReceipt, ZoneRuntimeError>;
    fn zone_remove_replica(
        &self,
        req: &ZoneRemoveReplicaRequest,
    ) -> Result<ZoneReceipt, ZoneRuntimeError>;
    fn zone_deprovision(
        &self,
        req: &ZoneDeprovisionRequest,
    ) -> Result<ZoneReceipt, ZoneRuntimeError>;
    fn get_zone_operation(
        &self,
        req: &GetZoneOperationRequest,
    ) -> Result<ZoneOperationRecord, ZoneRuntimeError>;
}

impl ZoneRuntimeOps for ZoneRuntimeBackend {
    fn is_local_root(&self) -> bool {
        ZoneRuntimeBackend::is_local_root(self)
    }
    fn zone_create(&self, req: &ZoneCreateRequest) -> Result<ZoneReceipt, ZoneRuntimeError> {
        ZoneRuntimeBackend::zone_create(self, req)
    }
    fn zone_join(&self, req: &ZoneJoinRequest) -> Result<ZoneReceipt, ZoneRuntimeError> {
        ZoneRuntimeBackend::zone_join(self, req)
    }
    fn zone_status(&self, req: &ZoneStatusRequest) -> Result<ZoneStatusResponse, ZoneRuntimeError> {
        ZoneRuntimeBackend::zone_status(self, req)
    }
    fn zone_mount(&self, req: &ZoneMountRequest) -> Result<ZoneReceipt, ZoneRuntimeError> {
        ZoneRuntimeBackend::zone_mount(self, req)
    }
    fn zone_unmount(&self, req: &ZoneUnmountRequest) -> Result<ZoneReceipt, ZoneRuntimeError> {
        ZoneRuntimeBackend::zone_unmount(self, req)
    }
    fn zone_remove_replica(
        &self,
        req: &ZoneRemoveReplicaRequest,
    ) -> Result<ZoneReceipt, ZoneRuntimeError> {
        ZoneRuntimeBackend::zone_remove_replica(self, req)
    }
    fn zone_deprovision(
        &self,
        req: &ZoneDeprovisionRequest,
    ) -> Result<ZoneReceipt, ZoneRuntimeError> {
        ZoneRuntimeBackend::zone_deprovision(self, req)
    }
    fn get_zone_operation(
        &self,
        req: &GetZoneOperationRequest,
    ) -> Result<ZoneOperationRecord, ZoneRuntimeError> {
        ZoneRuntimeBackend::get_zone_operation(self, req)
    }
}

/// Late-bound backend slot — same lifecycle as [`ForeignCaVerifierSlot`]:
/// routes are built BEFORE the `ZoneManager` (they are handed into
/// `open_zone_manager`), boot fills this the instant the backend exists.
pub type ZoneRuntimeOpsSlot = Arc<std::sync::OnceLock<Arc<dyn ZoneRuntimeOps>>>;

/// Boot-declared capability snapshot answered by `GetRuntimeCapabilities`
/// (R13). Filled once during boot; the handler is a pure read of it.
pub struct ZoneRuntimeCapabilities {
    pub node_id: String,
    pub auth_armed: bool,
    pub auth_mode: String,
    pub permission_provider_armed: bool,
    pub journal_zone: String,
    pub deletion_protection: bool,
    pub capabilities: Vec<String>,
}

pub type ZoneRuntimeCapabilitiesSlot = Arc<std::sync::OnceLock<Arc<ZoneRuntimeCapabilities>>>;

pub(crate) struct ZoneRuntimeServiceImpl {
    owner_scope: Option<Arc<RuntimeScope>>,
    auth: Arc<dyn AuthProvider>,
    ops: ZoneRuntimeOpsSlot,
    ready: Arc<DataPlaneReady>,
    kernel: Arc<Kernel>,
    capabilities: ZoneRuntimeCapabilitiesSlot,
    foreign_ca_verifier: ForeignCaVerifierSlot,
}

impl AuthedRequest for ZoneCreateRequest {
    fn auth_token(&self) -> &str {
        &self.auth_token
    }
}
impl AuthedRequest for ZoneJoinRequest {
    fn auth_token(&self) -> &str {
        &self.auth_token
    }
}
impl AuthedRequest for ZoneStatusRequest {
    fn auth_token(&self) -> &str {
        &self.auth_token
    }
}
impl AuthedRequest for ZoneMountRequest {
    fn auth_token(&self) -> &str {
        &self.auth_token
    }
}
impl AuthedRequest for ZoneUnmountRequest {
    fn auth_token(&self) -> &str {
        &self.auth_token
    }
}
impl AuthedRequest for ZoneRemoveReplicaRequest {
    fn auth_token(&self) -> &str {
        &self.auth_token
    }
}
impl AuthedRequest for ZoneDeprovisionRequest {
    fn auth_token(&self) -> &str {
        &self.auth_token
    }
}
impl AuthedRequest for GetZoneOperationRequest {
    fn auth_token(&self) -> &str {
        &self.auth_token
    }
}
impl AuthedRequest for GetRuntimeCapabilitiesRequest {
    fn auth_token(&self) -> &str {
        &self.auth_token
    }
}

struct ZoneRequest {
    context: OperationContext,
    owner: Option<Arc<OwnerRequest>>,
}

impl ZoneRequest {
    fn check(&self) -> Result<OperationContext, Status> {
        self.owner
            .as_ref()
            .map_or_else(|| Ok(self.context.clone()), |owner| owner.check())
    }

    fn finish<T>(&self, result: Result<T, Status>, mutation: bool) -> Result<T, Status> {
        let checked = self.check().map(|_| ());
        let result = match (checked, &self.owner) {
            (Ok(()), Some(owner)) => owner.publish(result),
            (Ok(()), None) => Ok(result),
            (Err(error), _) => Err(error),
        };
        match result {
            Ok(outcome) => outcome,
            Err(_) if mutation => Err(Status::unknown(
                "zone operation may have executed; query its original operation ID",
            )),
            Err(error) => Err(error),
        }
    }
}

impl ZoneRuntimeServiceImpl {
    async fn authenticate<T: AuthedRequest>(
        &self,
        req: Request<T>,
    ) -> Result<(Arc<ZoneRequest>, T), Status> {
        if let Some(scope) = &self.owner_scope {
            crate::grpc::wait_for_data_plane(&self.ready).await?;
            let owner = Arc::new(OwnerRequest::capture(
                Arc::clone(&self.auth),
                Arc::clone(&self.foreign_ca_verifier),
                Arc::clone(scope),
                &req,
            )?);
            let context = owner.context().clone();
            return Ok((
                Arc::new(ZoneRequest {
                    context,
                    owner: Some(owner),
                }),
                req.into_inner(),
            ));
        }
        let (context, inner) = authenticate_with(
            &self.auth,
            &self.ready,
            &self.foreign_ca_verifier,
            None,
            req,
        )
        .await?;
        Ok((
            Arc::new(ZoneRequest {
                context,
                owner: None,
            }),
            inner,
        ))
    }

    fn require_mutation(&self, request: &ZoneRequest, mutation: &str) -> Result<(), Status> {
        if self.owner_scope.is_some() {
            return if matches!(mutation, "create" | "deprovision") {
                Err(Status::permission_denied(
                    "global zone lifecycle requires the control plane",
                ))
            } else {
                Ok(())
            };
        }
        if request.context.is_admin || request.context.is_system {
            return Ok(());
        }
        Err(Status::permission_denied(format!(
            "zone {mutation} requires an admin/system context"
        )))
    }

    async fn execute<T: Send + 'static>(
        &self,
        request: Arc<ZoneRequest>,
        mutation: bool,
        mount: Option<(String, String)>,
        operation: impl FnOnce(&dyn ZoneRuntimeOps, &OperationContext) -> Result<T, Status>
            + Send
            + 'static,
    ) -> Result<T, Status> {
        let ops = self.ops()?;
        let worker = Arc::clone(&request);
        let kernel = Arc::clone(&self.kernel);
        // A queued worker revalidates before it can reach the journal. Once
        // started, cancellation retains the worker and its original receipt.
        let result = tokio::task::spawn_blocking(move || {
            let mut context = worker.check()?;
            if let Some((parent, path)) = mount {
                Self::check_mount_path(&kernel, &context, &parent, &path)?;
                context = worker.check()?;
            }
            Ok::<_, Status>(operation(ops.as_ref(), &context))
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "zone runtime worker failed");
            if mutation && request.owner.is_some() {
                Status::unknown("zone worker ended; query the original operation ID")
            } else {
                Status::internal("zone runtime worker failed")
            }
        })??;
        request.finish(result, mutation)
    }

    /// Recheck the canonical mount path using the current caller in the worker.
    fn check_mount_path(
        kernel: &Kernel,
        ctx: &OperationContext,
        parent_zone_id: &str,
        mount_path: &str,
    ) -> Result<(), Status> {
        let canonical =
            kernel::core::vfs_router::canonicalize_mount_path(mount_path, parent_zone_id);
        if let Err(e) = kernel.check_permission(&canonical, kernel::Permission::Write, ctx) {
            return Err(Status::permission_denied(format!(
                "mount path '{canonical}' not writable for this caller: {e:?}"
            )));
        }
        Ok(())
    }

    fn ops(&self) -> Result<Arc<dyn ZoneRuntimeOps>, Status> {
        let ops = self.ops.get().cloned().ok_or_else(|| {
            Status::unavailable("zone runtime backend is not wired on this process")
        })?;
        if self.owner_scope.is_some() && !ops.is_local_root() {
            return Err(Status::unavailable(
                "owner zone service requires a private-root backend",
            ));
        }
        Ok(ops)
    }
}

/// Map a backend refusal onto the wire. (A free function, not `From` —
/// `Status` and `ZoneRuntimeError` are both foreign types here.)
fn status_from(e: ZoneRuntimeError) -> Status {
    match e {
        ZoneRuntimeError::PermissionDenied(m) => Status::permission_denied(m),
        ZoneRuntimeError::Invalid(m) => Status::invalid_argument(m),
        ZoneRuntimeError::Conflict(m) => Status::failed_precondition(m),
        ZoneRuntimeError::NotFound(m) => Status::not_found(m),
        ZoneRuntimeError::Unavailable(m) => Status::unavailable(m),
        ZoneRuntimeError::Internal(m) => {
            // Same discipline as `map_kernel_err` on the VFS face: the
            // detail (store errors, RaftError Debug text) is for the
            // operator's log, not the wire.
            tracing::error!("zone runtime internal error: {m}");
            Status::internal("internal error")
        }
    }
}

#[tonic::async_trait]
impl kernel::kernel::vfs_proto::zone_runtime_service_server::ZoneRuntimeService
    for ZoneRuntimeServiceImpl
{
    async fn zone_create(
        &self,
        req: Request<ZoneCreateRequest>,
    ) -> Result<Response<ZoneReceipt>, Status> {
        let (request, inner) = self.authenticate(req).await?;
        self.require_mutation(&request, "create")?;
        let out = self
            .execute(request, true, None, move |ops, _context| {
                ops.zone_create(&inner).map_err(status_from)
            })
            .await?;
        Ok(Response::new(out))
    }

    async fn zone_join(
        &self,
        req: Request<ZoneJoinRequest>,
    ) -> Result<Response<ZoneReceipt>, Status> {
        let (request, inner) = self.authenticate(req).await?;
        self.require_mutation(&request, "join")?;
        let out = self
            .execute(request, true, None, move |ops, _context| {
                ops.zone_join(&inner).map_err(status_from)
            })
            .await?;
        Ok(Response::new(out))
    }

    async fn zone_mount(
        &self,
        req: Request<ZoneMountRequest>,
    ) -> Result<Response<ZoneReceipt>, Status> {
        let (request, inner) = self.authenticate(req).await?;
        self.require_mutation(&request, "mount")?;
        let mount = Some((inner.parent_zone_id.clone(), inner.mount_path.clone()));
        let out = self
            .execute(request, true, mount, move |ops, _context| {
                ops.zone_mount(&inner).map_err(status_from)
            })
            .await?;
        Ok(Response::new(out))
    }

    async fn zone_unmount(
        &self,
        req: Request<ZoneUnmountRequest>,
    ) -> Result<Response<ZoneReceipt>, Status> {
        let (request, inner) = self.authenticate(req).await?;
        self.require_mutation(&request, "unmount")?;
        let mount = Some((inner.parent_zone_id.clone(), inner.mount_path.clone()));
        let out = self
            .execute(request, true, mount, move |ops, _context| {
                ops.zone_unmount(&inner).map_err(status_from)
            })
            .await?;
        Ok(Response::new(out))
    }

    async fn zone_remove_replica(
        &self,
        req: Request<ZoneRemoveReplicaRequest>,
    ) -> Result<Response<ZoneReceipt>, Status> {
        let (request, inner) = self.authenticate(req).await?;
        self.require_mutation(&request, "remove_replica")?;
        let out = self
            .execute(request, true, None, move |ops, _context| {
                ops.zone_remove_replica(&inner).map_err(status_from)
            })
            .await?;
        Ok(Response::new(out))
    }

    async fn zone_deprovision(
        &self,
        req: Request<ZoneDeprovisionRequest>,
    ) -> Result<Response<ZoneReceipt>, Status> {
        let (request, inner) = self.authenticate(req).await?;
        self.require_mutation(&request, "deprovision")?;
        let out = self
            .execute(request, true, None, move |ops, _context| {
                ops.zone_deprovision(&inner).map_err(status_from)
            })
            .await?;
        Ok(Response::new(out))
    }

    async fn zone_status(
        &self,
        req: Request<ZoneStatusRequest>,
    ) -> Result<Response<ZoneStatusResponse>, Status> {
        let (request, inner) = self.authenticate(req).await?;
        let operator = request.context.is_admin || request.context.is_system;
        let mut out = self
            .execute(request, false, None, move |ops, _| {
                ops.zone_status(&inner).map_err(status_from)
            })
            .await?;
        if !operator {
            out.cluster = None;
        }
        Ok(Response::new(out))
    }

    async fn get_zone_operation(
        &self,
        req: Request<GetZoneOperationRequest>,
    ) -> Result<Response<ZoneOperationRecord>, Status> {
        let (request, inner) = self.authenticate(req).await?;
        let operator = request.context.is_admin || request.context.is_system;
        let mut out = self
            .execute(request, false, None, move |ops, _| {
                ops.get_zone_operation(&inner).map_err(status_from)
            })
            .await?;
        if !operator {
            if let Some(receipt) = out.receipt.as_mut() {
                receipt.cluster = None;
            }
            if !out.error.is_empty() {
                tracing::warn!(operation_id = %out.operation_id, "zone operation error redacted: {}", out.error);
                out.error = "operation was rejected".to_owned();
            }
        }
        Ok(Response::new(out))
    }

    async fn get_runtime_capabilities(
        &self,
        req: Request<GetRuntimeCapabilitiesRequest>,
    ) -> Result<Response<GetRuntimeCapabilitiesResponse>, Status> {
        let (request, _) = self.authenticate(req).await?;
        if self.owner_scope.is_some() {
            self.ops()?;
        }
        let caps = self.capabilities.get().ok_or_else(|| {
            Status::unavailable("zone runtime capabilities are not wired on this process")
        })?;
        request.finish(
            Ok(Response::new(GetRuntimeCapabilitiesResponse {
                node_id: caps.node_id.clone(),
                data_plane_ready: true,
                auth: Some(caps.auth_proto()),
                permission: Some(caps.permission_proto()),
                zone_runtime: Some(caps.zone_runtime_proto()),
                capabilities: caps.capabilities.clone(),
            })),
            false,
        )
    }
}

impl ZoneRuntimeCapabilities {
    fn auth_proto(&self) -> kernel::kernel::vfs_proto::RuntimeAuthCapability {
        kernel::kernel::vfs_proto::RuntimeAuthCapability {
            armed: self.auth_armed,
            mode: self.auth_mode.clone(),
        }
    }
    fn permission_proto(&self) -> kernel::kernel::vfs_proto::RuntimePermissionCapability {
        kernel::kernel::vfs_proto::RuntimePermissionCapability {
            provider_armed: self.permission_provider_armed,
        }
    }
    fn zone_runtime_proto(&self) -> kernel::kernel::vfs_proto::RuntimeZoneCapability {
        kernel::kernel::vfs_proto::RuntimeZoneCapability {
            journal_zone: self.journal_zone.clone(),
            deletion_protection: self.deletion_protection,
        }
    }
}

/// Build the ZoneRuntime service as a FALLBACK-FREE axum router, routed at
/// its `/nexus.grpc.vfs.ZoneRuntimeService/{*method}` prefix.
///
/// Why not `tonic::service::Routes` like [`crate::grpc::build_vfs_routes`]:
/// `Routes::new` installs the service as the router's FALLBACK, and axum
/// refuses to merge two routers that both have one — co-hosting this
/// service on the VFS port would panic at boot. An explicitly-routed
/// addon (no fallback of its own) merges cleanly under the VFS face's
/// fallback; the paths are disjoint by construction (different service
/// names in the same package).
#[allow(clippy::too_many_arguments)]
pub fn build_zone_runtime_routes(
    auth: Arc<dyn AuthProvider>,
    ops: ZoneRuntimeOpsSlot,
    ready: Arc<DataPlaneReady>,
    kernel: Arc<Kernel>,
    capabilities: ZoneRuntimeCapabilitiesSlot,
    foreign_ca_verifier: ForeignCaVerifierSlot,
    max_message_bytes: usize,
) -> axum::Router {
    let svc = ZoneRuntimeServiceImpl {
        owner_scope: None,
        auth,
        ops,
        ready,
        kernel,
        capabilities,
        foreign_ca_verifier,
    };
    routes(svc, max_message_bytes)
}

/// The owner surface shares the VFS scope and requires a confined backend.
#[allow(clippy::too_many_arguments)]
pub fn build_user_zone_runtime_routes(
    auth: Arc<dyn AuthProvider>,
    ops: ZoneRuntimeOpsSlot,
    ready: Arc<DataPlaneReady>,
    kernel: Arc<Kernel>,
    capabilities: ZoneRuntimeCapabilitiesSlot,
    foreign_ca_verifier: ForeignCaVerifierSlot,
    scope: RuntimeScope,
    max_message_bytes: usize,
) -> axum::Router {
    routes(
        ZoneRuntimeServiceImpl {
            owner_scope: Some(Arc::new(scope)),
            auth,
            ops,
            ready,
            kernel,
            capabilities,
            foreign_ca_verifier,
        },
        max_message_bytes,
    )
}

fn routes(svc: ZoneRuntimeServiceImpl, max_message_bytes: usize) -> axum::Router {
    let server = ZoneRuntimeServiceServer::new(svc)
        .max_decoding_message_size(max_message_bytes)
        .max_encoding_message_size(max_message_bytes);
    axum::Router::new().route_service("/nexus.grpc.vfs.ZoneRuntimeService/{*method}", server)
}
