//! Request-local identity and receiver installation for owner zone operations.

use std::sync::Arc;

use kernel::kernel::OperationContext;
use lib::transport_primitives::{SharedTlsConfig, TlsSnapshot};
use tonic::{Request, Status};

use crate::auth::AuthProvider;
use crate::grpc::{resolve_request_identity, AuthedRequest, ForeignCaVerifierSlot};
use crate::runtime_scope::RuntimeScope;

pub(super) struct OwnerRequest {
    auth: Arc<dyn AuthProvider>,
    verifier: ForeignCaVerifierSlot,
    scope: Arc<RuntimeScope>,
    token: String,
    extensions: tonic::Extensions,
    metadata: tonic::metadata::MetadataMap,
    source: SharedTlsConfig,
    installation: TlsSnapshot,
    original: OperationContext,
}

impl OwnerRequest {
    pub(super) fn capture<T: AuthedRequest>(
        auth: Arc<dyn AuthProvider>,
        verifier: ForeignCaVerifierSlot,
        scope: Arc<RuntimeScope>,
        request: &Request<T>,
    ) -> Result<Self, Status> {
        let source = scope.server_identity().cloned().ok_or_else(|| {
            Status::unavailable("owner zone operations require a live receiver credential")
        })?;
        let installation = source.snapshot();
        if !matches!(installation.config(), Ok(Some(_))) {
            return Err(Status::unavailable(
                "owner zone receiver credential is unavailable",
            ));
        }
        // The shared resolver consumes the actual envelope, including current
        // certificate validity and revocation; cached in-process contexts are
        // intentionally handled only by the ordinary VFS resolver.
        let original = resolve_request_identity(
            &auth,
            &verifier,
            Some(&scope),
            request.get_ref().auth_token(),
            request.extensions(),
            request.metadata(),
        )?;
        let captured = Self {
            auth,
            verifier,
            scope,
            token: request.get_ref().auth_token().to_owned(),
            extensions: request.extensions().clone(),
            metadata: request.metadata().clone(),
            source,
            installation,
            original,
        };
        if !captured.source.is_current(&captured.installation) {
            return Err(Status::unavailable(
                "owner zone receiver credential changed",
            ));
        }
        Ok(captured)
    }

    pub(super) fn context(&self) -> &OperationContext {
        &self.original
    }

    pub(super) fn check(&self) -> Result<OperationContext, Status> {
        if !self.source.is_current(&self.installation) {
            return Err(Status::unavailable(
                "owner zone receiver credential changed",
            ));
        }
        let current = resolve_request_identity(
            &self.auth,
            &self.verifier,
            Some(&self.scope),
            &self.token,
            &self.extensions,
            &self.metadata,
        )?;
        // Authentication may wait on its own provider locks. Recheck the
        // original receiver installation after that wait as well.
        if !self.source.is_current(&self.installation) {
            return Err(Status::unavailable(
                "owner zone receiver credential changed",
            ));
        }
        if current.user_id != self.original.user_id
            || current.agent_id != self.original.agent_id
            || current.subject_type != self.original.subject_type
            || current.subject_id != self.original.subject_id
            || current.trust_domain != self.original.trust_domain
            || current.is_admin != self.original.is_admin
            || current.is_system != self.original.is_system
        {
            return Err(Status::permission_denied(
                "owner zone caller identity changed",
            ));
        }
        Ok(current)
    }

    pub(super) fn publish<T>(&self, value: T) -> Result<T, Status> {
        self.source
            .with_current(&self.installation, || {
                // RuntimeScope reads the same source, so do not call check while
                // holding its lock. The caller revalidates immediately beforehand.
                value
            })
            .ok_or_else(|| Status::unavailable("owner zone receiver credential changed"))
    }
}
