//! Forward the complete typed VFS surface using the authenticated runtime owner.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient, nexus_vfs_service_server::NexusVfsService, *,
};
use tonic::transport::Channel;
use tonic::{Request, Response, Status};

use crate::grpc::{AuthenticatedRequestContext, VfsServiceImpl};
use crate::runtime_scope::RuntimeDelegation;

/// Deployment-owned placement lookup. Channels must come from trusted placement
/// and use credentials confined to the selected user runtime.
#[tonic::async_trait]
pub trait UserRuntimeResolver: Send + Sync {
    async fn resolve(&self, user_id: &str) -> Result<Channel, Status>;
}

pub(crate) struct UserRuntimeGateway {
    pub(crate) local: VfsServiceImpl,
    pub(crate) resolver: Arc<dyn UserRuntimeResolver>,
    pub(crate) max_message_bytes: usize,
}

macro_rules! gateway_methods {
    ($($method:ident: $request:ty => $response:ty),+ $(,)?) => {
        #[tonic::async_trait]
        impl NexusVfsService for UserRuntimeGateway {
            $(async fn $method(&self, mut req: Request<$request>) -> Result<Response<$response>, Status> {
                let started = Instant::now();
                let ctx = self.local.request_context(&req).await?;
                let is_session_agent = ctx.subject_type == "agent"
                    && ctx.agent_id.as_ref().is_some_and(|agent| agent != &ctx.user_id);
                if !is_session_agent {
                    req.extensions_mut().insert(AuthenticatedRequestContext(ctx));
                    return self.local.$method(req).await;
                }
                let timeout = request_timeout(req.metadata())?;
                let channel = self.resolver.resolve(&ctx.user_id).await?;
                let delegation = RuntimeDelegation::from_context(&ctx)?;
                req.get_mut().auth_token.clear();
                delegation.apply(req.metadata_mut())?;
                if let Some(budget) = timeout {
                    req.set_timeout(remaining_timeout(budget, started.elapsed())?);
                }
                NexusVfsServiceClient::new(channel)
                    .max_decoding_message_size(self.max_message_bytes)
                    .max_encoding_message_size(self.max_message_bytes)
                    .$method(req)
                    .await
            })+
        }
    };
}

fn request_timeout(metadata: &tonic::metadata::MetadataMap) -> Result<Option<Duration>, Status> {
    let Some(value) = metadata.get("grpc-timeout") else {
        return Ok(None);
    };
    let invalid = || Status::invalid_argument("invalid gRPC request timeout");
    let text = value.to_str().map_err(|_| invalid())?;
    let Some((&unit, digits)) = text.as_bytes().split_last() else {
        return Err(invalid());
    };
    if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(invalid());
    }
    let value: u64 = text[..digits.len()].parse().map_err(|_| invalid())?;
    let duration = match unit {
        b'H' => Duration::from_secs(value * 3600),
        b'M' => Duration::from_secs(value * 60),
        b'S' => Duration::from_secs(value),
        b'm' => Duration::from_millis(value),
        b'u' => Duration::from_micros(value),
        b'n' => Duration::from_nanos(value),
        _ => return Err(invalid()),
    };
    Ok(Some(duration))
}

fn remaining_timeout(budget: Duration, elapsed: Duration) -> Result<Duration, Status> {
    budget
        .checked_sub(elapsed)
        .filter(|value| !value.is_zero())
        .ok_or_else(|| Status::deadline_exceeded("request timed out before runtime forwarding"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_timeout_uses_the_remaining_grpc_budget() {
        for (wire, duration) in [
            ("1H", Duration::from_secs(3600)),
            ("1M", Duration::from_secs(60)),
            ("1S", Duration::from_secs(1)),
            ("1m", Duration::from_millis(1)),
            ("1u", Duration::from_micros(1)),
            ("1n", Duration::from_nanos(1)),
        ] {
            let mut metadata = tonic::metadata::MetadataMap::new();
            metadata.insert("grpc-timeout", wire.parse().unwrap());
            assert_eq!(request_timeout(&metadata).unwrap(), Some(duration));
        }
        assert_eq!(
            remaining_timeout(Duration::from_secs(5), Duration::from_secs(3)).unwrap(),
            Duration::from_secs(2)
        );
        assert_eq!(
            remaining_timeout(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap_err()
                .code(),
            tonic::Code::DeadlineExceeded
        );
        assert_eq!(
            remaining_timeout(Duration::from_secs(5), Duration::from_secs(6))
                .unwrap_err()
                .code(),
            tonic::Code::DeadlineExceeded
        );
        for wire in ["", "123456789S", "-1S", "1.0S", "S", "1s"] {
            let mut metadata = tonic::metadata::MetadataMap::new();
            metadata.insert("grpc-timeout", wire.parse().unwrap());
            assert_eq!(
                request_timeout(&metadata).unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
        }
    }
}

gateway_methods! {
    read: ReadRequest => ReadResponse,
    write: WriteRequest => WriteResponse,
    delete: DeleteRequest => DeleteResponse,
    mkdir: MkdirRequest => MkdirResponse,
    stat: StatRequest => StatResponse,
    readdir: ReaddirRequest => ReaddirResponse,
    setattr: SetattrRequest => SetattrResponse,
    rename: RenameRequest => RenameResponse,
    copy: CopyRequest => CopyResponse,
    lock: LockRequest => LockResponse,
    unlock: UnlockRequest => UnlockResponse,
    watch: WatchRequest => WatchResponse,
    get_xattr: GetXattrRequest => GetXattrResponse,
    set_xattr: SetXattrRequest => SetXattrResponse,
    get_xattr_bulk: GetXattrBulkRequest => GetXattrBulkResponse,
    close_pipe: IpcPathRequest => IpcAck,
    has_pipe: IpcPathRequest => IpcHasResponse,
    close_all_pipes: IpcEmpty => IpcAck,
    close_stream: IpcPathRequest => IpcAck,
    has_stream: IpcPathRequest => IpcHasResponse,
    stream_write_nowait: StreamWriteRequest => StreamWriteResponse,
    stream_read_at: StreamReadAtRequest => StreamReadAtResponse,
    stream_collect_all: IpcPathRequest => StreamCollectAllResponse,
    ping: PingRequest => PingResponse,
    batch_read: BatchReadRequest => BatchReadResponse,
    batch_stat: BatchStatRequest => BatchStatResponse,
    batch_write: BatchWriteRequest => BatchWriteResponse,
    call: CallRequest => CallResponse,
}
