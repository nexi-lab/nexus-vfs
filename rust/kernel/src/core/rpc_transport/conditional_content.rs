//! Conditional file calls shared by blocking and asynchronous clients.

use crate::kernel::conditional_content::{
    ConditionalContentError, ConditionalContentResult, VersionedContent,
};
use crate::kernel::{vfs_proto, KernelError};
use tonic::transport::Channel;
use tonic::Request;
use vfs_proto::{
    conditional_content_failure::Kind, nexus_vfs_service_client::NexusVfsServiceClient,
    read_versioned_response, write_if_version_response,
};

use super::RpcTransport;

/// Read a coherent image using the caller's configured channel and request envelope.
/// Authentication metadata, deadlines and message limits remain caller-owned.
pub async fn read_versioned(
    client: &mut NexusVfsServiceClient<Channel>,
    request: Request<vfs_proto::ReadVersionedRequest>,
) -> Result<Option<VersionedContent>, ConditionalContentError> {
    let response = client
        .read_versioned(request)
        .await
        .map_err(|status| {
            if status.code() == tonic::Code::Unimplemented {
                ConditionalContentError::Unsupported
            } else {
                failed(status.to_string())
            }
        })?
        .into_inner();
    match response.outcome {
        Some(read_versioned_response::Outcome::Snapshot(snapshot))
            if !snapshot.version.is_empty() =>
        {
            Ok(Some(VersionedContent {
                content: snapshot.content,
                version: snapshot.version,
            }))
        }
        Some(read_versioned_response::Outcome::Absent(_)) => Ok(None),
        Some(read_versioned_response::Outcome::Failure(error)) => Err(decode_failure(error)),
        _ => Err(failed("invalid versioned-content response".into())),
    }
}

/// Submit one complete replacement using the caller's authenticated request.
/// Lost or malformed replies remain Unknown; consumers resolve them by readback.
pub async fn write_if_version(
    client: &mut NexusVfsServiceClient<Channel>,
    request: Request<vfs_proto::WriteIfVersionRequest>,
) -> Result<ConditionalContentResult, ConditionalContentError> {
    if request
        .get_ref()
        .expected_version
        .as_deref()
        .is_some_and(<[u8]>::is_empty)
    {
        return Err(failed(
            "expected version must be a nonempty token or absent".into(),
        ));
    }
    let response = client
        .write_if_version(request)
        .await
        .map_err(|status| {
            if status.code() == tonic::Code::Unimplemented {
                ConditionalContentError::Unsupported
            } else {
                ConditionalContentError::Unknown(status.to_string())
            }
        })?
        .into_inner();
    match response.outcome {
        Some(write_if_version_response::Outcome::CommittedVersion(version))
            if !version.is_empty() =>
        {
            Ok(ConditionalContentResult::Committed { version })
        }
        Some(write_if_version_response::Outcome::Conflict(conflict))
            if conflict
                .current_version
                .as_ref()
                .is_none_or(|version| !version.is_empty()) =>
        {
            Ok(ConditionalContentResult::Conflict {
                current_version: conflict.current_version,
            })
        }
        Some(write_if_version_response::Outcome::Failure(error)) => Err(decode_failure(error)),
        _ => Err(ConditionalContentError::Unknown(
            "invalid conditional-write response".into(),
        )),
    }
}

impl RpcTransport {
    /// Read one coherent file image and its opaque committed revision.
    pub fn read_versioned(
        &self,
        path: &str,
    ) -> Result<Option<VersionedContent>, ConditionalContentError> {
        self.block_on(read_versioned(
            &mut self.client(),
            Request::new(vfs_proto::ReadVersionedRequest {
                path: path.into(),
                auth_token: self.auth_token.clone(),
            }),
        ))
    }

    /// Replace the complete file once. Resolve uncertain outcomes through readback.
    pub fn write_if_version(
        &self,
        path: &str,
        content: &[u8],
        expected_version: Option<&[u8]>,
    ) -> Result<ConditionalContentResult, ConditionalContentError> {
        self.block_on(write_if_version(
            &mut self.client(),
            Request::new(vfs_proto::WriteIfVersionRequest {
                path: path.into(),
                content: content.to_vec(),
                auth_token: self.auth_token.clone(),
                expected_version: expected_version.map(<[u8]>::to_vec),
            }),
        ))
    }
}

fn decode_failure(error: vfs_proto::ConditionalContentFailure) -> ConditionalContentError {
    match Kind::try_from(error.kind) {
        Ok(Kind::Unsupported) => ConditionalContentError::Unsupported,
        Ok(Kind::Failed) => failed(error.message),
        _ => ConditionalContentError::Unknown(error.message),
    }
}

fn failed(message: String) -> ConditionalContentError {
    ConditionalContentError::Failed(KernelError::BackendError(message))
}
