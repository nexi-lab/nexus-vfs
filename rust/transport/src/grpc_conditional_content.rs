//! Authenticated transport projection of the kernel's conditional file operations.

use std::sync::Arc;

use kernel::kernel::conditional_content::{ConditionalContentError, ConditionalContentResult};
use kernel::kernel::vfs_proto::{
    conditional_content_failure::Kind, read_versioned_response, write_if_version_response,
    AbsentContent, ConditionalContentConflict, ConditionalContentFailure, ReadGuardedRequest,
    ReadVersionedRequest, ReadVersionedResponse, VersionedContent, WriteGuardedRequest,
    WriteIfVersionRequest, WriteIfVersionResponse,
};
use kernel::kernel::{Kernel, OperationContext};
use tonic::{Request, Response, Status};

use crate::grpc::{run_blocking, VfsServiceImpl};

impl VfsServiceImpl {
    pub(crate) async fn read_guarded_content(
        &self,
        req: Request<ReadGuardedRequest>,
    ) -> Result<Response<ReadVersionedResponse>, Status> {
        let (ctx, req) = self.authenticate(req).await?;
        read_content(self.kernel.clone(), ctx, req.path, Some(req.owner_version)).await
    }

    pub(crate) async fn write_guarded_content(
        &self,
        req: Request<WriteGuardedRequest>,
    ) -> Result<Response<WriteIfVersionResponse>, Status> {
        let (ctx, req) = self.authenticate(req).await?;
        write_content(
            self.kernel.clone(),
            ctx,
            req.path,
            req.content,
            req.expected_version,
            Some(req.owner_version),
        )
        .await
    }

    pub(crate) async fn read_versioned_content(
        &self,
        req: Request<ReadVersionedRequest>,
    ) -> Result<Response<ReadVersionedResponse>, Status> {
        let (ctx, req) = self.authenticate(req).await?;
        read_content(self.kernel.clone(), ctx, req.path, None).await
    }

    pub(crate) async fn write_content_if_version(
        &self,
        req: Request<WriteIfVersionRequest>,
    ) -> Result<Response<WriteIfVersionResponse>, Status> {
        let (ctx, req) = self.authenticate(req).await?;
        write_content(
            self.kernel.clone(),
            ctx,
            req.path,
            req.content,
            req.expected_version,
            None,
        )
        .await
    }
}

// Each operation shares one blocking task and response encoder across its two
// admission modes. The typed guarded endpoints always supply an owner token.
async fn read_content(
    kernel: Arc<Kernel>,
    ctx: OperationContext,
    path: String,
    owner: Option<Vec<u8>>,
) -> Result<Response<ReadVersionedResponse>, Status> {
    let result = run_blocking(move || match owner {
        Some(owner) => kernel.read_guarded_content(&path, &ctx, &owner),
        None => kernel.read_versioned_content(&path, &ctx),
    })
    .await?;
    Ok(Response::new(read_response(result)))
}

async fn write_content(
    kernel: Arc<Kernel>,
    ctx: OperationContext,
    path: String,
    content: Vec<u8>,
    expected: Option<Vec<u8>>,
    owner: Option<Vec<u8>>,
) -> Result<Response<WriteIfVersionResponse>, Status> {
    let result = run_blocking(move || match owner {
        Some(owner) => {
            kernel.replace_guarded_content(&path, &ctx, &content, expected.as_deref(), &owner)
        }
        None => kernel.replace_content_if_version(&path, &ctx, &content, expected.as_deref()),
    })
    .await?;
    Ok(Response::new(write_response(result)))
}

fn read_response(
    result: Result<
        Option<kernel::kernel::conditional_content::VersionedContent>,
        ConditionalContentError,
    >,
) -> ReadVersionedResponse {
    let outcome = match result {
        Ok(Some(snapshot)) => read_versioned_response::Outcome::Snapshot(VersionedContent {
            content: snapshot.content,
            version: snapshot.version,
        }),
        Ok(None) => read_versioned_response::Outcome::Absent(AbsentContent {}),
        Err(error) => read_versioned_response::Outcome::Failure(failure(error)),
    };
    ReadVersionedResponse {
        outcome: Some(outcome),
    }
}

fn write_response(
    result: Result<ConditionalContentResult, ConditionalContentError>,
) -> WriteIfVersionResponse {
    let outcome = match result {
        Ok(ConditionalContentResult::Committed { version }) => {
            write_if_version_response::Outcome::CommittedVersion(version)
        }
        Ok(ConditionalContentResult::Conflict { current_version }) => {
            write_if_version_response::Outcome::Conflict(ConditionalContentConflict {
                current_version,
            })
        }
        Err(error) => write_if_version_response::Outcome::Failure(failure(error)),
    };
    WriteIfVersionResponse {
        outcome: Some(outcome),
    }
}

fn failure(error: ConditionalContentError) -> ConditionalContentFailure {
    let kind = match &error {
        ConditionalContentError::Unsupported => Kind::Unsupported,
        ConditionalContentError::Failed(_) => Kind::Failed,
        ConditionalContentError::Unknown(_) => Kind::Unknown,
    };
    ConditionalContentFailure {
        kind: kind as i32,
        message: error.to_string(),
    }
}
