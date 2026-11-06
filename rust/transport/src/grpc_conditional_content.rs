//! Authenticated transport projection of the kernel's conditional file operations.

use kernel::kernel::conditional_content::{ConditionalContentError, ConditionalContentResult};
use kernel::kernel::vfs_proto::{
    conditional_content_failure::Kind, read_versioned_response, write_if_version_response,
    AbsentContent, ConditionalContentConflict, ConditionalContentFailure, ReadGuardedRequest,
    ReadVersionedRequest, ReadVersionedResponse, VersionedContent, WriteGuardedRequest,
    WriteIfVersionRequest, WriteIfVersionResponse,
};
use tonic::{Request, Response, Status};

use crate::grpc::{run_blocking, VfsServiceImpl};

impl VfsServiceImpl {
    pub(crate) async fn read_guarded_content(
        &self,
        req: Request<ReadGuardedRequest>,
    ) -> Result<Response<ReadVersionedResponse>, Status> {
        let (ctx, req) = self.authenticate(req).await?;
        let kernel = self.kernel.clone();
        let result =
            run_blocking(move || kernel.read_guarded_content(&req.path, &ctx, &req.owner_version))
                .await?;
        Ok(Response::new(read_response(result)))
    }

    pub(crate) async fn write_guarded_content(
        &self,
        req: Request<WriteGuardedRequest>,
    ) -> Result<Response<WriteIfVersionResponse>, Status> {
        let (ctx, req) = self.authenticate(req).await?;
        let kernel = self.kernel.clone();
        let result = run_blocking(move || {
            kernel.replace_guarded_content(
                &req.path,
                &ctx,
                &req.content,
                req.expected_version.as_deref(),
                &req.owner_version,
            )
        })
        .await?;
        Ok(Response::new(write_response(result)))
    }

    pub(crate) async fn read_versioned_content(
        &self,
        req: Request<ReadVersionedRequest>,
    ) -> Result<Response<ReadVersionedResponse>, Status> {
        let (ctx, req) = self.authenticate(req).await?;
        let kernel = self.kernel.clone();
        let result = run_blocking(move || kernel.read_versioned_content(&req.path, &ctx)).await?;
        Ok(Response::new(read_response(result)))
    }

    pub(crate) async fn write_content_if_version(
        &self,
        req: Request<WriteIfVersionRequest>,
    ) -> Result<Response<WriteIfVersionResponse>, Status> {
        let (ctx, req) = self.authenticate(req).await?;
        let kernel = self.kernel.clone();
        let result = run_blocking(move || {
            kernel.replace_content_if_version(
                &req.path,
                &ctx,
                &req.content,
                req.expected_version.as_deref(),
            )
        })
        .await?;
        Ok(Response::new(write_response(result)))
    }
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
