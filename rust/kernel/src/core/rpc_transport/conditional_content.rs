//! Typed conditional content calls with explicit uncertain-write outcomes.

use crate::kernel::conditional_content::{
    ConditionalContentError, ConditionalContentResult, VersionedContent,
};
use crate::kernel::{vfs_proto, KernelError};
use vfs_proto::{
    conditional_content_failure::Kind, read_versioned_response, write_if_version_response,
};

use super::RpcTransport;

impl RpcTransport {
    /// Read one coherent file image and its opaque committed revision.
    pub fn read_versioned(
        &self,
        path: &str,
    ) -> Result<Option<VersionedContent>, ConditionalContentError> {
        self.block_on(async {
            let response = self
                .client()
                .read_versioned(vfs_proto::ReadVersionedRequest {
                    path: path.into(),
                    auth_token: self.auth_token.clone(),
                })
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
                Some(read_versioned_response::Outcome::Failure(error)) => {
                    Err(decode_failure(error))
                }
                _ => Err(failed("invalid versioned-content response".into())),
            }
        })
    }

    /// Replace the complete file once. Resolve uncertain outcomes through readback.
    pub fn write_if_version(
        &self,
        path: &str,
        content: &[u8],
        expected_version: Option<&[u8]>,
    ) -> Result<ConditionalContentResult, ConditionalContentError> {
        if expected_version.is_some_and(<[u8]>::is_empty) {
            return Err(failed(
                "expected version must be a nonempty token or absent".into(),
            ));
        }
        self.block_on(async {
            let response = self
                .client()
                .write_if_version(vfs_proto::WriteIfVersionRequest {
                    path: path.into(),
                    content: content.to_vec(),
                    auth_token: self.auth_token.clone(),
                    expected_version: expected_version.map(<[u8]>::to_vec),
                })
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
                Some(write_if_version_response::Outcome::Failure(error)) => {
                    Err(decode_failure(error))
                }
                _ => Err(ConditionalContentError::Unknown(
                    "invalid conditional-write response".into(),
                )),
            }
        })
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
