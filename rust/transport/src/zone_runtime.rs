//! Typed Zone runtime gRPC surface (R7–R13) — `ZoneRuntimeService`.
//!
//! The same door as the VFS face (`authenticate_with`: boot-gate wait →
//! peer identity → `AuthProvider::resolve`), then zone-level authz, then
//! a late-bound [`ZoneRuntimeOps`] backend (the raft `ZoneRuntimeBackend`,
//! filled by boot after the `ZoneManager` exists — the `ForeignCaVerifierSlot`
//! pattern: routes are built before the thing they serve).
//!
//! Authz (deliberately NOT `kernel.check_permission` for the admin gate —
//! the TLS-on cluster profile installs a containment provider that admits
//! every domestic caller, so it can never be the authorization basis
//! here; it IS the additional mount-path defense-in-depth below the admin
//! gate for shapes that arm a real permission provider):
//!
//! - every mutation (create/join/mount/unmount/remove-replica/deprovision)
//!   requires `is_admin || is_system` — the `setattr_mount` gRPC-layer
//!   admin-gate precedent, now uniform across the zone lifecycle;
//! - mount/unmount additionally pass
//!   `kernel.check_permission(canonical_mount_path, Write, ctx)` — the
//!   zone-level layer of the two-layer mount decision (D3);
//! - status / GetZoneOperation / GetRuntimeCapabilities are reads: any
//!   authenticated caller.

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

/// The backend seam. Implemented by the raft-side `ZoneRuntimeBackend`
/// (below — a local-trait-for-foreign-type impl: this crate owns the
/// trait, raft owns the struct, keeping transport free of raft internals).
pub trait ZoneRuntimeOps: Send + Sync {
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

impl ZoneRuntimeServiceImpl {
    async fn authenticate<T: AuthedRequest>(
        &self,
        req: Request<T>,
    ) -> Result<(OperationContext, T), Status> {
        authenticate_with(&self.auth, &self.ready, &self.foreign_ca_verifier, req).await
    }

    fn require_admin(ctx: &OperationContext, mutation: &str) -> Result<(), Status> {
        if ctx.is_admin || ctx.is_system {
            return Ok(());
        }
        Err(Status::permission_denied(format!(
            "zone {mutation} requires an admin/system context"
        )))
    }

    /// Zone-level mount-path gate (D3's second layer): the canonical path
    /// `/{parent_zone}{mount_path}` must be writable for this caller under
    /// whatever permission provider this deployment armed. With no
    /// provider armed (NoAuth loopback) the gate is a no-op — the admin
    /// gate above is the authorization basis.
    fn check_mount_path(
        &self,
        ctx: &OperationContext,
        parent_zone_id: &str,
        mount_path: &str,
    ) -> Result<(), Status> {
        let canonical = format!("/{parent_zone_id}{mount_path}");
        if let Err(e) = self
            .kernel
            .check_permission(&canonical, kernel::Permission::Write, ctx)
        {
            return Err(Status::permission_denied(format!(
                "mount path '{canonical}' not writable for this caller: {e:?}"
            )));
        }
        Ok(())
    }

    fn ops(&self) -> Result<Arc<dyn ZoneRuntimeOps>, Status> {
        self.ops
            .get()
            .cloned()
            .ok_or_else(|| Status::unavailable("zone runtime backend is not wired on this process"))
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
        ZoneRuntimeError::Internal(m) => Status::internal(m),
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
        let (ctx, inner) = self.authenticate(req).await?;
        Self::require_admin(&ctx, "create")?;
        let ops = self.ops()?;
        let out = tokio::task::spawn_blocking(move || ops.zone_create(&inner))
            .await
            .map_err(|e| Status::internal(format!("zone runtime worker panicked: {e}")))?
            .map_err(status_from)?;
        Ok(Response::new(out))
    }

    async fn zone_join(
        &self,
        req: Request<ZoneJoinRequest>,
    ) -> Result<Response<ZoneReceipt>, Status> {
        let (ctx, inner) = self.authenticate(req).await?;
        Self::require_admin(&ctx, "join")?;
        let ops = self.ops()?;
        let out = tokio::task::spawn_blocking(move || ops.zone_join(&inner))
            .await
            .map_err(|e| Status::internal(format!("zone runtime worker panicked: {e}")))?
            .map_err(status_from)?;
        Ok(Response::new(out))
    }

    async fn zone_status(
        &self,
        req: Request<ZoneStatusRequest>,
    ) -> Result<Response<ZoneStatusResponse>, Status> {
        let (_ctx, inner) = self.authenticate(req).await?;
        let ops = self.ops()?;
        let out = tokio::task::spawn_blocking(move || ops.zone_status(&inner))
            .await
            .map_err(|e| Status::internal(format!("zone runtime worker panicked: {e}")))?
            .map_err(status_from)?;
        Ok(Response::new(out))
    }

    async fn zone_mount(
        &self,
        req: Request<ZoneMountRequest>,
    ) -> Result<Response<ZoneReceipt>, Status> {
        let (ctx, inner) = self.authenticate(req).await?;
        Self::require_admin(&ctx, "mount")?;
        self.check_mount_path(&ctx, &inner.parent_zone_id, &inner.mount_path)?;
        let ops = self.ops()?;
        let out = tokio::task::spawn_blocking(move || ops.zone_mount(&inner))
            .await
            .map_err(|e| Status::internal(format!("zone runtime worker panicked: {e}")))?
            .map_err(status_from)?;
        Ok(Response::new(out))
    }

    async fn zone_unmount(
        &self,
        req: Request<ZoneUnmountRequest>,
    ) -> Result<Response<ZoneReceipt>, Status> {
        let (ctx, inner) = self.authenticate(req).await?;
        Self::require_admin(&ctx, "unmount")?;
        self.check_mount_path(&ctx, &inner.parent_zone_id, &inner.mount_path)?;
        let ops = self.ops()?;
        let out = tokio::task::spawn_blocking(move || ops.zone_unmount(&inner))
            .await
            .map_err(|e| Status::internal(format!("zone runtime worker panicked: {e}")))?
            .map_err(status_from)?;
        Ok(Response::new(out))
    }

    async fn zone_remove_replica(
        &self,
        req: Request<ZoneRemoveReplicaRequest>,
    ) -> Result<Response<ZoneReceipt>, Status> {
        let (ctx, inner) = self.authenticate(req).await?;
        Self::require_admin(&ctx, "remove_replica")?;
        let ops = self.ops()?;
        let out = tokio::task::spawn_blocking(move || ops.zone_remove_replica(&inner))
            .await
            .map_err(|e| Status::internal(format!("zone runtime worker panicked: {e}")))?
            .map_err(status_from)?;
        Ok(Response::new(out))
    }

    async fn zone_deprovision(
        &self,
        req: Request<ZoneDeprovisionRequest>,
    ) -> Result<Response<ZoneReceipt>, Status> {
        let (ctx, inner) = self.authenticate(req).await?;
        Self::require_admin(&ctx, "deprovision")?;
        let ops = self.ops()?;
        let out = tokio::task::spawn_blocking(move || ops.zone_deprovision(&inner))
            .await
            .map_err(|e| Status::internal(format!("zone runtime worker panicked: {e}")))?
            .map_err(status_from)?;
        Ok(Response::new(out))
    }

    async fn get_zone_operation(
        &self,
        req: Request<GetZoneOperationRequest>,
    ) -> Result<Response<ZoneOperationRecord>, Status> {
        let (_ctx, inner) = self.authenticate(req).await?;
        let ops = self.ops()?;
        let out = tokio::task::spawn_blocking(move || ops.get_zone_operation(&inner))
            .await
            .map_err(|e| Status::internal(format!("zone runtime worker panicked: {e}")))?
            .map_err(status_from)?;
        Ok(Response::new(out))
    }

    async fn get_runtime_capabilities(
        &self,
        req: Request<GetRuntimeCapabilitiesRequest>,
    ) -> Result<Response<GetRuntimeCapabilitiesResponse>, Status> {
        // The ready gate in `authenticate` IS the readiness semantics: a
        // caller that gets this far is answered, one that doesn't gets
        // `Unavailable` (retryable — the probe convention).
        let _ = self.authenticate(req).await?;
        let caps = self.capabilities.get().ok_or_else(|| {
            Status::unavailable("zone runtime capabilities are not wired on this process")
        })?;
        Ok(Response::new(GetRuntimeCapabilitiesResponse {
            node_id: caps.node_id.clone(),
            // `authenticate` waited out the boot window: true here.
            data_plane_ready: true,
            auth: Some(caps.auth_proto()),
            permission: Some(caps.permission_proto()),
            zone_runtime: Some(caps.zone_runtime_proto()),
            capabilities: caps.capabilities.clone(),
        }))
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
        auth,
        ops,
        ready,
        kernel,
        capabilities,
        foreign_ca_verifier,
    };
    let server = ZoneRuntimeServiceServer::new(svc)
        .max_decoding_message_size(max_message_bytes)
        .max_encoding_message_size(max_message_bytes);
    axum::Router::new().route_service("/nexus.grpc.vfs.ZoneRuntimeService/{*method}", server)
}
