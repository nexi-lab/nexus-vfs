//! Guarded file calls require an explicit storage-owned handle on the wire.

use super::conditional_content::{
    decode_read, decode_write, failed, read_error, validate_expected_version, write_error,
};
use super::RpcTransport;
use crate::kernel::conditional_content::{
    ConditionalContentError, ConditionalContentResult, VersionedContent,
};
use crate::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient, ReadGuardedRequest, WriteGuardedRequest,
};
use tonic::transport::Channel;
use tonic::Request;

fn require_owner(version: &[u8]) -> Result<(), ConditionalContentError> {
    if version.is_empty() {
        Err(failed(
            "owner version must be a nonempty storage token".into(),
        ))
    } else {
        Ok(())
    }
}

/// Use the caller's authenticated envelope, deadline and channel limits.
/// An older server returns Unsupported; no unguarded fallback is permitted.
pub async fn read_guarded(
    client: &mut NexusVfsServiceClient<Channel>,
    request: Request<ReadGuardedRequest>,
) -> Result<Option<VersionedContent>, ConditionalContentError> {
    require_owner(&request.get_ref().owner_version)?;
    decode_read(
        client
            .read_guarded(request)
            .await
            .map_err(read_error)?
            .into_inner(),
    )
}

/// Lost replies remain Unknown and require authoritative readback.
pub async fn write_guarded(
    client: &mut NexusVfsServiceClient<Channel>,
    request: Request<WriteGuardedRequest>,
) -> Result<ConditionalContentResult, ConditionalContentError> {
    require_owner(&request.get_ref().owner_version)?;
    validate_expected_version(request.get_ref().expected_version.as_deref())?;
    decode_write(
        client
            .write_guarded(request)
            .await
            .map_err(write_error)?
            .into_inner(),
    )
}

impl RpcTransport {
    /// Read the bytes and revision selected by a live admitted owner.
    pub fn read_guarded(
        &self,
        path: &str,
        owner_version: &[u8],
    ) -> Result<Option<VersionedContent>, ConditionalContentError> {
        self.block_on(read_guarded(
            &mut self.client(),
            Request::new(ReadGuardedRequest {
                path: path.into(),
                auth_token: self.auth_token.clone(),
                owner_version: owner_version.to_vec(),
            }),
        ))
    }

    /// Retain I/O in the server worker and compare its owner at final commit.
    pub fn write_guarded(
        &self,
        path: &str,
        content: &[u8],
        expected_version: Option<&[u8]>,
        owner_version: &[u8],
    ) -> Result<ConditionalContentResult, ConditionalContentError> {
        self.block_on(write_guarded(
            &mut self.client(),
            Request::new(WriteGuardedRequest {
                path: path.into(),
                content: content.to_vec(),
                auth_token: self.auth_token.clone(),
                expected_version: expected_version.map(<[u8]>::to_vec),
                owner_version: owner_version.to_vec(),
            }),
        ))
    }
}
