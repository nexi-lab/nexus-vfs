//! Rust-native gRPC server for `NexusVFSService`.
//!
//! Owns the :2028 socket via tonic. Auth is handled by
//! `transport::auth::AuthProvider` (pure Rust).
//!
//! Per-RPC architecture:
//!
//! | RPC                              | Path                                     |
//! | -------------------------------- | ---------------------------------------- |
//! | `Read`/`Write`/`Delete`/`Ping`   | Pure Rust → `Kernel::sys_*`              |
//! | `BatchRead`                      | Pure Rust → `Kernel::sys_read` (batch)   |
//! | `Call`                           | Stubbed (`Unimplemented`)                |

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::auth::{AuthCredentials, AuthProvider};
use crate::peer_identity;
use tokio::sync::oneshot;
use tonic::{transport::Server, Request, Response, Status};

use crate::TlsConfig;
use kernel::abi::KernelAbi;
use kernel::hal::object_store_provider::{get_provider, ObjectStoreProviderArgs};
use kernel::kernel::convenience::KernelConvenience;
use kernel::kernel::vfs_proto::{
    nexus_vfs_service_server::{NexusVfsService, NexusVfsServiceServer},
    BatchReadItemResponse, BatchReadRequest, BatchReadResponse, BatchStatItem, BatchStatRequest,
    BatchStatResponse, BatchWriteItemResponse, BatchWriteRequest, BatchWriteResponse, CallRequest,
    CallResponse, CopyRequest, CopyResponse, DeleteRequest, DeleteResponse, GetXattrBulkItem,
    GetXattrBulkRequest, GetXattrBulkResponse, GetXattrRequest, GetXattrResponse, IpcAck, IpcEmpty,
    IpcHasResponse, IpcPathRequest, LockRequest, LockResponse, MkdirRequest, MkdirResponse,
    PingRequest, PingResponse, ReadRequest, ReadResponse, ReaddirEntry, ReaddirRequest,
    ReaddirResponse, RenameRequest, RenameResponse, SetXattrRequest, SetXattrResponse,
    SetattrRequest, SetattrResponse, StatRequest, StatResponse, StreamCollectAllResponse,
    StreamReadAtRequest, StreamReadAtResponse, StreamWriteRequest, StreamWriteResponse,
    UnlockRequest, UnlockResponse, WatchRequest, WatchResponse, WriteRequest, WriteResponse,
};
use kernel::kernel::{Kernel, KernelError, OperationContext};

/// Configuration for the VFS gRPC server.
#[derive(Clone)]
pub struct VfsGrpcConfig {
    pub bind_addr: SocketAddr,
    /// Optional mTLS config (PEM bytes). `None` = plaintext HTTP/2.
    pub tls: Option<TlsConfig>,
    /// Max gRPC message size in bytes (default 64 MiB to match
    /// `contracts::constants::MAX_GRPC_MESSAGE_BYTES`).
    pub max_message_bytes: usize,
    /// Server `version` advertised in `Ping` responses.
    pub server_version: String,
}

/// Handle returned at startup. Dropping it (or calling `shutdown()`)
/// triggers graceful shutdown of the tonic server. The dedicated tokio
/// runtime is dropped with the handle, so the server task is
/// guaranteed to stop.
pub struct VfsGrpcHandle {
    pub(crate) shutdown_tx: Option<oneshot::Sender<()>>,
    pub(crate) runtime: Option<tokio::runtime::Runtime>,
}

impl VfsGrpcHandle {
    pub fn shutdown_blocking(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_timeout(std::time::Duration::from_secs(5));
        }
    }
}

impl Drop for VfsGrpcHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_timeout(std::time::Duration::from_secs(5));
        }
    }
}

/// Core VFS service implementation — pure Rust.
///
/// Auth is delegated to `Arc<dyn AuthProvider>`.  `Call` RPC returns
/// `Unimplemented`.
#[derive(Clone)]
pub(crate) struct VfsServiceImpl {
    pub(crate) kernel: Arc<Kernel>,
    pub(crate) auth: Arc<dyn AuthProvider>,
    pub(crate) server_started_at: Instant,
    pub(crate) server_version: Arc<str>,
    pub(crate) started_secs: Arc<AtomicU64>,
}

/// Every VFS request message carries its bearer token in an `auth_token`
/// field. Naming that shape as a trait is what lets [`VfsServiceImpl::authenticate`]
/// be written once instead of 28 times.
pub(crate) trait AuthedRequest {
    fn auth_token(&self) -> &str;
}

macro_rules! impl_authed_request {
    ($($t:ty),+ $(,)?) => {
        $(impl AuthedRequest for $t {
            #[inline]
            fn auth_token(&self) -> &str {
                &self.auth_token
            }
        })+
    };
}

impl_authed_request!(
    BatchReadRequest,
    BatchStatRequest,
    BatchWriteRequest,
    CallRequest,
    CopyRequest,
    DeleteRequest,
    GetXattrBulkRequest,
    GetXattrRequest,
    IpcEmpty,
    IpcPathRequest,
    LockRequest,
    MkdirRequest,
    PingRequest,
    ReadRequest,
    ReaddirRequest,
    RenameRequest,
    SetXattrRequest,
    SetattrRequest,
    StatRequest,
    StreamReadAtRequest,
    StreamWriteRequest,
    UnlockRequest,
    WatchRequest,
    WriteRequest,
);

impl VfsServiceImpl {
    /// Authenticate a request and unwrap it.
    ///
    /// The peer certificate must be read off the `Request` envelope
    /// *before* `into_inner()` drops it — that ordering is the whole
    /// reason this helper exists rather than each handler unwrapping
    /// first and resolving a bare token. A caller reaching a handler
    /// over mTLS has already had its chain verified against the cluster
    /// CA by rustls, and [`AuthCredentials::peer`] is how a provider
    /// gets to use that fact.
    pub(crate) fn authenticate<T: AuthedRequest>(
        &self,
        req: Request<T>,
    ) -> Result<(OperationContext, T), Status> {
        let peer = peer_identity::from_request(&req);
        let inner = req.into_inner();
        let ctx = self.auth.resolve(&AuthCredentials {
            token: inner.auth_token(),
            peer: peer.as_ref(),
        })?;
        Ok((ctx, inner))
    }

    pub(crate) fn map_kernel_err(&self, err: KernelError) -> (RpcErrorCode, String) {
        match err {
            KernelError::FileNotFound(p) => (RpcErrorCode::FileNotFound, p),
            KernelError::PermissionDenied(m) => (RpcErrorCode::PermissionError, m),
            KernelError::InvalidPath(m) => (RpcErrorCode::InvalidPath, m),
            KernelError::BackendError(m) => {
                let lower = m.to_ascii_lowercase();
                if lower.contains("permission")
                    || lower.contains("denied")
                    || lower.contains("read-only")
                {
                    (RpcErrorCode::PermissionError, m)
                } else {
                    (RpcErrorCode::InternalError, m)
                }
            }
            KernelError::PipeClosed(m) | KernelError::StreamClosed(m) => {
                (RpcErrorCode::InternalError, m)
            }
            other => (RpcErrorCode::InternalError, format!("{:?}", other)),
        }
    }

    /// DT_MOUNT (`entry_type == 2`) handler — bridge-2 (#4262).
    ///
    /// Builds a live `ObjectStore` from the wire-carried backend params via
    /// the registered [`ObjectStoreProvider`] and mounts it through
    /// `Kernel::sys_setattr`, replacing the old blanket synthetic ack — but
    /// only for the *networked* object-store drivers the provider
    /// constructs from those params: `s3` (the epic's focus, and the path
    /// S3-compatible Cloudflare R2 / MinIO ride via `s3_endpoint` +
    /// `aws_region = "auto"`) plus the forward-compat `gcs` / `remote` arms.
    ///
    /// Three-way on the `backend_type`, fail-closed:
    ///   * `{s3, gcs, remote}` → build via the provider and mount.
    ///   * **synthetic ack** (no provider build, as before): the empty
    ///     `backend_type` (metadata-only / federation), and the local-host
    ///     backends (`path_local` / `cas-local` / `local_connector`) at ANY
    ///     path — they carry no `local_root` on the wire, but the host binary
    ///     serves every local path through its root `/` mount (host-fs), so a
    ///     write to e.g. `/files/…` falls through and lands on disk. (The boot
    ///     `sys_setattr(DT_MOUNT, "/")` remount is the same case.)
    ///   * anything else (a connector / LLM type this server can't build, a
    ///     typo, a legacy name like `path_s3`, a version-skewed client, a
    ///     future driver) → **error, never a silent ack**: those have no
    ///     host-fs fall-through, so a bare `created=false` ack would let the
    ///     caller write into a phantom mount — a silent data-placement failure.
    ///
    /// Requires an admin or system context, mirroring the Python
    /// `sys_setattr(DT_MOUNT)` gate: this path is now stateful (creates /
    /// overwrites mounts), so a non-privileged token must not reach
    /// `provider.build` / `Kernel::sys_setattr`.
    fn setattr_mount(&self, req: SetattrRequest, ctx: &OperationContext) -> SetattrResponse {
        // DT_MOUNT mutates mount/zone state — gate it admin-only like the
        // Python primitive. The cluster's NoAuth resolves to an admin+system
        // context so this is transparent there; a real AuthProvider issuing a
        // non-privileged context is rejected before any state change.
        if !(ctx.is_admin || ctx.is_system) {
            return error_setattr(Status::permission_denied(
                "DT_MOUNT requires an admin or system context",
            ));
        }

        // Networked object-store drivers the provider builds from the wire
        // params, and the local-host drivers the host binary owns.
        const PROVIDER_BUILT: [&str; 3] = ["s3", "gcs", "remote"];
        const LOCAL_HOST: [&str; 3] = ["path_local", "cas-local", "local_connector"];

        // Local-host backends (path_local / cas-local / local_connector) keep
        // the pre-#4262 synthetic ack at ANY path. They carry no `local_root`
        // on the wire so they can't be built here, but the host binary serves
        // every local path through its root `/` mount (host-fs): acking lets a
        // write to e.g. `/files/…` fall through to that root mount and land on
        // disk — the established behavior the self-contained e2e suite relies
        // on (it mounts `cas-local` at `/files` over gRPC). The boot-time
        // DT_MOUNT("/") remount is the same case. (Connector / LLM / unknown
        // types below have NO such fall-through, so they fail closed instead.)
        if LOCAL_HOST.contains(&req.backend_type.as_str()) {
            return synthetic_setattr_ack(&req);
        }
        // Empty backend_type — federation / metadata-only DT_MOUNT. This is a
        // no-op ack over gRPC (the pre-#4262 behavior, deliberately retained).
        // Federation zone mounts are created via `share --mount-at` / `join`
        // (a raft-replicated DT_MOUNT through the parent zone's state machine),
        // NOT via a client's gRPC `sys_setattr`. Routing this zoned mount into
        // `Kernel::sys_setattr` would, with a join `source` (which the proto
        // does not carry), install a successful-looking route without actually
        // joining — risking a split-brain zone; and the raft JoinZone path
        // `block_on`s, which must not run inline on a tonic worker. So bridging
        // federation over gRPC is a separate effort, out of scope for #4262.
        // Acking installs nothing and is safe.
        if req.backend_type.is_empty() {
            // Fail closed if construction params were supplied without the
            // dispatch key. A malformed / partially-upgraded client that set
            // s3_bucket/aws_region/etc. but dropped `backend_type` would
            // otherwise get a phantom-mount ack — and the client-side
            // version-skew guard only fires for known provider-built
            // backend_types, so it can't catch this. A genuine metadata-only /
            // federation mount carries none of these fields.
            let has_backend_params = !req.backend_params.is_empty();
            if has_backend_params {
                return error_setattr(Status::invalid_argument(
                    "DT_MOUNT carries backend-construction params but no \
                     backend_type; refusing to install a phantom mount",
                ));
            }
            return synthetic_setattr_ack(&req);
        }
        // Anything else that isn't a provider-built networked driver fails
        // closed (connector / LLM / typo / version-skewed / future driver).
        if !PROVIDER_BUILT.contains(&req.backend_type.as_str()) {
            return error_setattr(Status::unimplemented(format!(
                "DT_MOUNT backend_type {:?} is not supported by this server; \
                 no mount was installed",
                req.backend_type
            )));
        }

        let Some(provider) = get_provider() else {
            return error_setattr(Status::failed_precondition(
                "no ObjectStoreProvider registered; cannot build DT_MOUNT backend",
            ));
        };

        // Build the opaque params map from the proto's `backend_params`.
        // The proto map is already `HashMap<String, String>` — pass
        // it directly. Empty values are handled by the provider's
        // `param()` helper (coerces empty to None).
        let peer_client = self.kernel.peer_client_arc();
        let self_address = self.kernel.self_address_string();
        let args = ObjectStoreProviderArgs {
            backend_type: req.backend_type.as_str(),
            backend_name: req.backend_name.as_str(),
            mount_path: Some(req.path.as_str()),
            backend_params: &req.backend_params,
            peer_client: &peer_client,
            self_address: self_address.as_deref(),
            runtime: self.kernel.runtime(),
        };
        let built = match provider.build(&args) {
            Ok(b) => b,
            Err(e) => {
                return error_setattr(Status::internal(format!(
                    "ObjectStoreProvider failed to build '{}' backend for {}: {e}",
                    req.backend_type, req.path,
                )));
            }
        };

        // Mount the freshly-built backend (and any remote metastore the
        // provider produced) through the kernel.
        self.mount_via_kernel(&req, built.backend, built.pending_remote_meta_store)
    }

    /// Issue the DT_MOUNT `Kernel::sys_setattr` from a `SetattrRequest` with a
    /// caller-supplied backend: `Some(_)` from the provider for networked
    /// object stores, or `None` for a federation / zoned mount where the
    /// kernel creates the raft zone + route itself. Maps the kernel result
    /// onto the typed `SetattrResponse`.
    fn mount_via_kernel(
        &self,
        req: &SetattrRequest,
        backend: Option<Arc<dyn kernel::abc::object_store::ObjectStore>>,
        remote_metastore: Option<Arc<dyn kernel::meta_store::MetaStore>>,
    ) -> SetattrResponse {
        let zone_id = if req.zone_id.is_empty() {
            kernel::ROOT_ZONE_ID
        } else {
            req.zone_id.as_str()
        };
        match self.kernel.sys_setattr(
            &req.path,
            req.entry_type,
            &req.backend_name,
            backend,
            None, // metastore
            None, // raft_backend
            &req.io_profile,
            zone_id,
            req.is_external,
            req.capacity as usize,
            None, // read_fd
            None, // write_fd
            req.mime_type.as_deref(),
            req.modified_at_ms,
            req.content_id.as_deref(),
            req.size,
            req.version,
            req.created_at_ms,
            None,             // link_target
            None, // source — federation joins are not bridged over gRPC (see setattr_mount)
            remote_metastore, // remote arm installs a metastore
        ) {
            Ok(r) => SetattrResponse {
                path: r.path,
                created: r.created,
                entry_type: r.entry_type,
                is_error: false,
                error_payload: Vec::new(),
            },
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                SetattrResponse {
                    path: String::new(),
                    created: false,
                    entry_type: 0,
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }
            }
        }
    }

    /// Test-only constructor.
    #[cfg(test)]
    pub(crate) fn for_test(kernel: Arc<Kernel>) -> Self {
        Self {
            kernel,
            auth: Arc::new(crate::auth::NoAuth),
            server_started_at: Instant::now(),
            server_version: Arc::from("test"),
            started_secs: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Run a blocking kernel operation off the async runtime.
///
/// VFS handlers are co-hosted on the `ZoneManager` tokio runtime that also
/// drives raft consensus. Several kernel syscalls block (DT_PIPE/DT_STREAM
/// reads, VFS write lock waits, sys_watch up to 30s). Running those inline
/// parks a worker, and enough concurrent blocking calls starve the raft-
/// shared runtime. Offloading to the blocking pool keeps async workers free.
async fn run_blocking<F, T>(f: F) -> Result<T, Status>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Status::internal(format!("kernel blocking task join error: {e}")))
}

#[tonic::async_trait]
impl NexusVfsService for VfsServiceImpl {
    async fn read(&self, req: Request<ReadRequest>) -> Result<Response<ReadResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_read(s))),
        };
        // No federation guard: KernelAbi::sys_read consults ctx.zone_perms via
        // the permission gate (kernel::dispatch.rs:101). The same SSOT runs
        // whether the call entered via typed Read or generic Call.
        //
        // Honor the kernel's read-timeout contract: `timeout_ms == 0` is
        // O_NONBLOCK (return immediately; empty pipe yields b""), non-zero
        // blocks DT_PIPE/DT_STREAM reads up to N ms. Regular-file reads
        // ignore this — the VFS read lock uses `vfs_lock_timeout_ms()`.
        let timeout_ms = req.timeout_ms;
        // Offload: DT_PIPE/DT_STREAM reads block up to timeout_ms
        let kernel = self.kernel.clone();
        let path = req.path;
        let offset = req.offset;
        let read_res =
            run_blocking(move || KernelAbi::sys_read(&*kernel, &path, &ctx, timeout_ms, offset))
                .await?;
        match read_res {
            Ok(result) => {
                let bytes = result.data.unwrap_or_default();
                Ok(Response::new(ReadResponse {
                    size: bytes.len() as i64,
                    content: bytes,
                    content_id: result.content_id.unwrap_or_default(),
                    gen: result.gen,
                    is_error: false,
                    error_payload: Vec::new(),
                    entry_type: result.entry_type as i32,
                    stream_next_offset: result.stream_next_offset.map(|v| v as u64),
                    post_hook_needed: result.post_hook_needed,
                }))
            }
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(ReadResponse {
                    content: Vec::new(),
                    content_id: String::new(),
                    size: 0,
                    gen: 0,
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                    entry_type: 0,
                    stream_next_offset: None,
                    post_hook_needed: false,
                }))
            }
        }
    }

    async fn write(&self, req: Request<WriteRequest>) -> Result<Response<WriteResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_write(s))),
        };
        // No federation guard: ctx.zone_perms is enforced inside sys_write's
        // permission gate (kernel::dispatch.rs:101) — same SSOT as Call.
        // Offload: sys_write waits on VFS write lock
        let kernel = self.kernel.clone();
        let path = req.path;
        let content = req.content;
        let write_res =
            run_blocking(move || KernelAbi::sys_write(&*kernel, &path, &ctx, &content, 0)).await?;
        match write_res {
            Ok(result) => Ok(Response::new(WriteResponse {
                content_id: result.content_id.unwrap_or_default(),
                size: result.size as i64,
                gen: result.gen,
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(WriteResponse {
                    content_id: String::new(),
                    size: 0,
                    gen: 0,
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn delete(
        &self,
        req: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_delete(s))),
        };
        // No federation guard: ctx.zone_perms is enforced inside sys_unlink's
        // permission gate (kernel::dispatch.rs:101) — same SSOT as Call.
        // Offload: sys_unlink waits on VFS write lock
        let kernel = self.kernel.clone();
        let path = req.path;
        let recursive = req.recursive;
        let del_res =
            run_blocking(move || KernelAbi::sys_unlink(&*kernel, &path, &ctx, recursive)).await?;
        match del_res {
            Ok(result) => Ok(Response::new(DeleteResponse {
                success: result.hit,
                is_error: false,
                error_payload: Vec::new(),
                entry_type: result.entry_type as u32,
                path: result.path,
                content_id: result.content_id.unwrap_or_default(),
                size: result.size,
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(DeleteResponse {
                    success: false,
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                    entry_type: 0,
                    path: String::new(),
                    content_id: String::new(),
                    size: 0,
                }))
            }
        }
    }

    async fn mkdir(&self, req: Request<MkdirRequest>) -> Result<Response<MkdirResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_mkdir(s))),
        };
        match KernelConvenience::mkdir(&*self.kernel, &req.path, &ctx, req.parents, req.exist_ok) {
            Ok(r) => Ok(Response::new(MkdirResponse {
                hit: r.hit,
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(MkdirResponse {
                    hit: false,
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn stat(&self, req: Request<StatRequest>) -> Result<Response<StatResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_stat(s))),
        };
        let zone_id = if req.zone_id.is_empty() {
            ctx.zone_id.as_str()
        } else {
            req.zone_id.as_str()
        };
        // `sys_stat` returns `Option` — `None` is "no such path", a
        // normal result surfaced as `found = false` (not an error).
        match self.kernel.sys_stat(&req.path, zone_id) {
            Some(s) => Ok(Response::new(StatResponse {
                found: true,
                path: s.path,
                size: s.size as i64,
                content_id: s.content_id.unwrap_or_default(),
                mime_type: s.mime_type,
                is_directory: s.is_directory,
                entry_type: s.entry_type as i32,
                mode: s.mode,
                version: s.version,
                gen: s.gen,
                zone_id: s.zone_id.unwrap_or_default(),
                created_at_ms: s.created_at_ms,
                modified_at_ms: s.modified_at_ms,
                last_writer_address: s.last_writer_address.unwrap_or_default(),
                link_target: s.link_target.unwrap_or_default(),
                owner_id: s.owner_id.unwrap_or_default(),
                is_error: false,
                error_payload: Vec::new(),
            })),
            None => Ok(Response::new(StatResponse {
                found: false,
                ..Default::default()
            })),
        }
    }

    async fn readdir(
        &self,
        req: Request<ReaddirRequest>,
    ) -> Result<Response<ReaddirResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_readdir(s))),
        };
        let zone_id = if req.zone_id.is_empty() {
            ctx.zone_id.as_str()
        } else {
            req.zone_id.as_str()
        };
        // `is_admin` comes from the auth-resolved context, never the
        // request — clients can't spoof admin reads of `/__sys__/zones/`.
        //
        // `from_peer`: when set, this request is a fan-out from a peer
        // whose local `sys_readdir` came up empty.  Route to
        // `sys_readdir_peer_dispatch` (allow_fanout=false) so we run
        // only our local scan and do NOT re-dispatch — prevents
        // ping-pong loops in 3+ node topologies where every hop's
        // local search misses.
        let entries = if req.from_peer {
            self.kernel
                .sys_readdir_peer_dispatch(&req.path, zone_id, ctx.is_admin)
        } else {
            self.kernel.sys_readdir(&req.path, zone_id, ctx.is_admin)
        };
        let mapped: Vec<ReaddirEntry> = entries
            .into_iter()
            .map(|(name, dt)| ReaddirEntry {
                name,
                entry_type: dt as u32,
            })
            .collect();
        Ok(Response::new(ReaddirResponse {
            entries: mapped,
            is_error: false,
            error_payload: Vec::new(),
        }))
    }

    async fn setattr(
        &self,
        req: Request<SetattrRequest>,
    ) -> Result<Response<SetattrResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_setattr(s))),
        };
        // DT_MOUNT (entry_type == 2) — bridge-2 (#4262): build a live
        // backend via the registered `ObjectStoreProvider` for the
        // networked object-store drivers it constructs from wire params
        // (`s3` — including S3-compatible Cloudflare R2 / MinIO — plus the
        // forward-compat `gcs` / `remote` arms), then mount it through
        // `Kernel::sys_setattr`. `setattr_mount` owns the admin gate, the
        // build-vs-ack-vs-error discriminator, and the rationale. Dispatched
        // with the auth context and before `zone_id` is moved out of `req`,
        // so the helper gets an intact request.
        if req.entry_type == 2 {
            return Ok(Response::new(self.setattr_mount(req, &ctx)));
        }
        let _ = ctx; // non-mount typed setattr does not gate on ctx today

        let zone_id_str = req.zone_id;
        let zone_id = if zone_id_str.is_empty() {
            kernel::ROOT_ZONE_ID
        } else {
            &zone_id_str
        };

        match self.kernel.sys_setattr(
            &req.path,
            req.entry_type,
            &req.backend_name,
            None, // backend (non-mount entry types don't need one)
            None, // metastore
            None, // raft_backend
            &req.io_profile,
            zone_id,
            req.is_external,
            req.capacity as usize,
            None, // read_fd  — DT_PIPE stdio uses the in-process AcpSubprocess path
            None, // write_fd
            req.mime_type.as_deref(),
            req.modified_at_ms,
            req.content_id.as_deref(),
            req.size,
            req.version,
            req.created_at_ms,
            None, // link_target — DT_LINK creation isn't on the JSON-wire today
            None, // source
            None, // remote_metastore
        ) {
            Ok(r) => Ok(Response::new(SetattrResponse {
                path: r.path,
                created: r.created,
                entry_type: r.entry_type,
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(SetattrResponse {
                    path: String::new(),
                    created: false,
                    entry_type: 0,
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn rename(
        &self,
        req: Request<RenameRequest>,
    ) -> Result<Response<RenameResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_rename(s))),
        };
        // Offload: sys_rename waits on VFS write lock
        let kernel = self.kernel.clone();
        let path = req.path;
        let new_path = req.new_path;
        let rename_res =
            run_blocking(move || KernelAbi::sys_rename(&*kernel, &path, &new_path, &ctx)).await?;
        match rename_res {
            Ok(r) => Ok(Response::new(RenameResponse {
                hit: r.hit,
                success: r.success,
                is_directory: r.is_directory,
                old_content_id: r.old_content_id,
                old_size: r.old_size,
                old_version: r.old_version,
                old_modified_at_ms: r.old_modified_at_ms,
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(RenameResponse {
                    hit: false,
                    success: false,
                    is_directory: false,
                    old_content_id: None,
                    old_size: None,
                    old_version: None,
                    old_modified_at_ms: None,
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn copy(&self, req: Request<CopyRequest>) -> Result<Response<CopyResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_copy(s))),
        };
        // Offload: sys_copy waits on VFS write lock
        let kernel = self.kernel.clone();
        let src = req.src;
        let dst = req.dst;
        let copy_res =
            run_blocking(move || KernelAbi::sys_copy(&*kernel, &src, &dst, &ctx)).await?;
        match copy_res {
            Ok(r) => Ok(Response::new(CopyResponse {
                hit: r.hit,
                dst_path: r.dst_path,
                content_id: r.content_id,
                size: r.size,
                version: r.version,
                gen: r.gen,
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(CopyResponse {
                    hit: false,
                    dst_path: String::new(),
                    content_id: None,
                    size: 0,
                    version: 0,
                    gen: 0,
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn lock(&self, req: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_lock(s))),
        };
        // Match the Call wire surface (mode / max_holders / ttl_secs are
        // hardcoded on the JSON path; expose only when there's a caller
        // that needs to vary them).
        let ttl_secs = req.timeout_ms / 1000 + 1;
        // Offload: sys_lock may contend on lock table
        let kernel = self.kernel.clone();
        let path = req.path;
        let lock_id_req = req.lock_id;
        let lock_res =
            run_blocking(move || kernel.sys_lock(&path, &lock_id_req, 1, ttl_secs, "")).await?;
        match lock_res {
            Ok(Some(id)) => Ok(Response::new(LockResponse {
                acquired: true,
                lock_id: id,
                is_error: false,
                error_payload: Vec::new(),
            })),
            Ok(None) => Ok(Response::new(LockResponse {
                acquired: false,
                lock_id: String::new(),
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(LockResponse {
                    acquired: false,
                    lock_id: String::new(),
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn unlock(
        &self,
        req: Request<UnlockRequest>,
    ) -> Result<Response<UnlockResponse>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_unlock(s))),
        };
        match self.kernel.sys_unlock(&req.path, &req.lock_id, req.force) {
            Ok(released) => Ok(Response::new(UnlockResponse {
                released,
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(UnlockResponse {
                    released: false,
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn watch(&self, req: Request<WatchRequest>) -> Result<Response<WatchResponse>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_watch(s))),
        };
        // Offload: sys_watch blocks up to 30s waiting for events
        let kernel = self.kernel.clone();
        let path = req.path;
        let timeout_ms = req.timeout_ms;
        let matched = run_blocking(move || {
            kernel
                .sys_watch(&path, timeout_ms)
                .map(|evt| (evt.path().to_string(), format!("{:?}", evt.event_type)))
        })
        .await?;
        match matched {
            Some((path, event_type)) => Ok(Response::new(WatchResponse {
                matched: true,
                path,
                event_type,
                is_error: false,
                error_payload: Vec::new(),
            })),
            None => Ok(Response::new(WatchResponse {
                matched: false,
                path: String::new(),
                event_type: String::new(),
                is_error: false,
                error_payload: Vec::new(),
            })),
        }
    }

    async fn get_xattr(
        &self,
        req: Request<GetXattrRequest>,
    ) -> Result<Response<GetXattrResponse>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_get_xattr(s))),
        };
        match KernelConvenience::get_xattr(&*self.kernel, &req.path, &req.key, kernel::ROOT_ZONE_ID)
        {
            Ok(Some(value)) => Ok(Response::new(GetXattrResponse {
                found: true,
                value,
                is_error: false,
                error_payload: Vec::new(),
            })),
            Ok(None) => Ok(Response::new(GetXattrResponse {
                found: false,
                value: String::new(),
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(GetXattrResponse {
                    found: false,
                    value: String::new(),
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn set_xattr(
        &self,
        req: Request<SetXattrRequest>,
    ) -> Result<Response<SetXattrResponse>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_set_xattr(s))),
        };
        match KernelConvenience::set_xattr(
            &*self.kernel,
            &req.path,
            &req.key,
            req.value,
            kernel::ROOT_ZONE_ID,
        ) {
            Ok(()) => Ok(Response::new(SetXattrResponse {
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(SetXattrResponse {
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn get_xattr_bulk(
        &self,
        req: Request<GetXattrBulkRequest>,
    ) -> Result<Response<GetXattrBulkResponse>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_get_xattr_bulk(s))),
        };
        match KernelConvenience::get_xattr_bulk(
            &*self.kernel,
            &req.paths,
            &req.key,
            kernel::ROOT_ZONE_ID,
        ) {
            Ok(rows) => Ok(Response::new(GetXattrBulkResponse {
                items: rows
                    .into_iter()
                    .map(|(p, v)| GetXattrBulkItem {
                        path: p,
                        found: v.is_some(),
                        value: v.unwrap_or_default(),
                    })
                    .collect(),
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(GetXattrBulkResponse {
                    items: Vec::new(),
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn close_pipe(&self, req: Request<IpcPathRequest>) -> Result<Response<IpcAck>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_ipc_ack(s))),
        };
        match self.kernel.close_pipe(&req.path) {
            Ok(()) => Ok(Response::new(IpcAck {
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(IpcAck {
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn has_pipe(
        &self,
        req: Request<IpcPathRequest>,
    ) -> Result<Response<IpcHasResponse>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_ipc_has(s))),
        };
        Ok(Response::new(IpcHasResponse {
            present: self.kernel.has_pipe(&req.path),
            is_error: false,
            error_payload: Vec::new(),
        }))
    }

    async fn close_all_pipes(&self, req: Request<IpcEmpty>) -> Result<Response<IpcAck>, Status> {
        let (_ctx, _req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_ipc_ack(s))),
        };
        self.kernel.close_all_pipes();
        Ok(Response::new(IpcAck {
            is_error: false,
            error_payload: Vec::new(),
        }))
    }

    async fn close_stream(&self, req: Request<IpcPathRequest>) -> Result<Response<IpcAck>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_ipc_ack(s))),
        };
        match self.kernel.close_stream(&req.path) {
            Ok(()) => Ok(Response::new(IpcAck {
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(IpcAck {
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn has_stream(
        &self,
        req: Request<IpcPathRequest>,
    ) -> Result<Response<IpcHasResponse>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_ipc_has(s))),
        };
        Ok(Response::new(IpcHasResponse {
            present: self.kernel.has_stream(&req.path),
            is_error: false,
            error_payload: Vec::new(),
        }))
    }

    async fn stream_write_nowait(
        &self,
        req: Request<StreamWriteRequest>,
    ) -> Result<Response<StreamWriteResponse>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_stream_write(s))),
        };
        match self.kernel.stream_write_nowait(&req.path, &req.data) {
            Ok(offset) => Ok(Response::new(StreamWriteResponse {
                offset: offset as u64,
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(StreamWriteResponse {
                    offset: 0,
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn stream_read_at(
        &self,
        req: Request<StreamReadAtRequest>,
    ) -> Result<Response<StreamReadAtResponse>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_stream_read(s))),
        };
        if req.blocking {
            // Offload: blocking stream read waits up to timeout_ms
            let kernel = self.kernel.clone();
            let path = req.path;
            let offset = req.offset as usize;
            let timeout_ms = req.timeout_ms;
            let blk_res =
                run_blocking(move || kernel.stream_read_at_blocking(&path, offset, timeout_ms))
                    .await?;
            match blk_res {
                Ok((data, next)) => Ok(Response::new(StreamReadAtResponse {
                    data,
                    next_offset: next as u64,
                    eof: false,
                    is_error: false,
                    error_payload: Vec::new(),
                })),
                Err(err) => {
                    let (code, msg) = self.map_kernel_err(err);
                    Ok(Response::new(StreamReadAtResponse {
                        data: Vec::new(),
                        next_offset: 0,
                        eof: false,
                        is_error: true,
                        error_payload: encode_rpc_error(code, &msg),
                    }))
                }
            }
        } else {
            match self.kernel.stream_read_at(&req.path, req.offset as usize) {
                Ok(Some((data, next))) => Ok(Response::new(StreamReadAtResponse {
                    data,
                    next_offset: next as u64,
                    eof: false,
                    is_error: false,
                    error_payload: Vec::new(),
                })),
                Ok(None) => Ok(Response::new(StreamReadAtResponse {
                    data: Vec::new(),
                    next_offset: req.offset,
                    eof: true,
                    is_error: false,
                    error_payload: Vec::new(),
                })),
                Err(err) => {
                    let (code, msg) = self.map_kernel_err(err);
                    Ok(Response::new(StreamReadAtResponse {
                        data: Vec::new(),
                        next_offset: 0,
                        eof: false,
                        is_error: true,
                        error_payload: encode_rpc_error(code, &msg),
                    }))
                }
            }
        }
    }

    async fn stream_collect_all(
        &self,
        req: Request<IpcPathRequest>,
    ) -> Result<Response<StreamCollectAllResponse>, Status> {
        let (_ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Ok(Response::new(error_stream_collect(s))),
        };
        match self.kernel.stream_collect_all(&req.path) {
            Ok(data) => Ok(Response::new(StreamCollectAllResponse {
                data,
                is_error: false,
                error_payload: Vec::new(),
            })),
            Err(err) => {
                let (code, msg) = self.map_kernel_err(err);
                Ok(Response::new(StreamCollectAllResponse {
                    data: Vec::new(),
                    is_error: true,
                    error_payload: encode_rpc_error(code, &msg),
                }))
            }
        }
    }

    async fn ping(&self, req: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let (ctx, _req) = self.authenticate(req)?;
        let uptime = self.server_started_at.elapsed().as_secs() as i64;
        self.started_secs.store(uptime as u64, Ordering::Relaxed);
        Ok(Response::new(PingResponse {
            version: self.server_version.to_string(),
            zone_id: ctx.zone_id,
            uptime_seconds: uptime,
        }))
    }

    async fn batch_read(
        &self,
        req: Request<BatchReadRequest>,
    ) -> Result<Response<BatchReadResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Err(s),
        };
        // No federation guard: read_batch composes per-item sys_read on the
        // KernelConvenience SSOT, which honors ctx.zone_perms in the
        // permission gate (kernel::dispatch.rs:101).

        let rust_reqs: Vec<kernel::kernel::ReadRequest> = req
            .items
            .into_iter()
            .map(|it| kernel::kernel::ReadRequest {
                path: it.path,
                offset: it.offset,
                len: it.length,
                timeout_ms: 5000,
            })
            .collect();

        // Offload: batch read may block on DT_PIPE/DT_STREAM items
        let kernel = self.kernel.clone();
        let results = run_blocking(move || kernel.sys_read(&rust_reqs, &ctx)).await?;

        let max_agg = self.kernel.read_batch_max_aggregate_bytes();
        let mut total = 0usize;
        for r in results.iter().filter_map(|r| r.as_ref().ok()) {
            total = total.saturating_add(r.data.as_ref().map(|b| b.len()).unwrap_or(0));
            if total > max_agg {
                return Err(Status::resource_exhausted(format!(
                    "batch read response {} bytes exceeds {} MB",
                    total,
                    max_agg / (1024 * 1024)
                )));
            }
        }

        let mapped: Vec<BatchReadItemResponse> = results
            .into_iter()
            .map(|r| match r {
                Ok(r) => BatchReadItemResponse {
                    content: r.data.unwrap_or_default(),
                    is_error: false,
                    error_payload: Vec::new(),
                    content_id: r.content_id.unwrap_or_default(),
                    gen: r.gen,
                },
                Err(e) => {
                    let (code, msg) = self.map_kernel_err(e);
                    BatchReadItemResponse {
                        content: Vec::new(),
                        is_error: true,
                        error_payload: encode_rpc_error(code, &msg),
                        content_id: String::new(),
                        gen: 0,
                    }
                }
            })
            .collect();

        Ok(Response::new(BatchReadResponse { results: mapped }))
    }

    async fn batch_stat(
        &self,
        req: Request<BatchStatRequest>,
    ) -> Result<Response<BatchStatResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Err(s),
        };
        // No federation guard: stat_batch goes through metastore-direct path
        // and the per-path sys_stat fallback, both of which inherit the
        // permission gate's zone_perms enforcement.
        let zone_id = if req.zone_id.is_empty() {
            ctx.zone_id.as_str()
        } else {
            req.zone_id.as_str()
        };

        // KernelConvenience::stat_batch picks the optimized path on
        // Kernel — single redb read txn via `with_metastore::get_batch`,
        // falling back to per-path sys_stat for implicit dirs / procfs.
        let results = KernelConvenience::stat_batch(&*self.kernel, &req.paths, zone_id);
        let mapped: Vec<BatchStatItem> = results
            .into_iter()
            .map(|opt| match opt {
                Some(s) => BatchStatItem {
                    found: true,
                    path: s.path,
                    size: s.size as i64,
                    content_id: s.content_id.unwrap_or_default(),
                    mime_type: s.mime_type,
                    is_directory: s.is_directory,
                    entry_type: s.entry_type as i32,
                    mode: s.mode,
                    version: s.version,
                    gen: s.gen,
                    zone_id: s.zone_id.unwrap_or_default(),
                    created_at_ms: s.created_at_ms,
                    modified_at_ms: s.modified_at_ms,
                    last_writer_address: s.last_writer_address.unwrap_or_default(),
                    link_target: s.link_target.unwrap_or_default(),
                    owner_id: s.owner_id.unwrap_or_default(),
                },
                None => BatchStatItem {
                    found: false,
                    ..Default::default()
                },
            })
            .collect();
        Ok(Response::new(BatchStatResponse { results: mapped }))
    }

    async fn batch_write(
        &self,
        req: Request<BatchWriteRequest>,
    ) -> Result<Response<BatchWriteResponse>, Status> {
        let (ctx, req) = match self.authenticate(req) {
            Ok(v) => v,
            Err(s) => return Err(s),
        };
        // No federation guard: write_batch composes per-item KernelConvenience
        // ::write on the SSOT, which honors ctx.zone_perms in the permission
        // gate (kernel::dispatch.rs:101).

        // Tier 2 `write_batch`: create-or-overwrite per item, each item
        // independent. One bad path no longer aborts the batch the way
        // the generic `write_batch` Call did (it looped Tier 1 sys_write
        // and `return Err`d on the first failure — and never created
        // missing files). The positional per-item result vector matches
        // the input order.
        let items: Vec<(String, Vec<u8>)> = req
            .items
            .into_iter()
            .map(|it| (it.path, it.content))
            .collect();

        // Offload: batch write waits on VFS write lock per item
        let kernel = self.kernel.clone();
        let results =
            run_blocking(move || KernelConvenience::write_batch(&*kernel, &items, &ctx)).await?;

        let mapped: Vec<BatchWriteItemResponse> = results
            .into_iter()
            .map(|r| match r {
                Ok(r) => BatchWriteItemResponse {
                    content_id: r.content_id.unwrap_or_default(),
                    size: r.size as i64,
                    gen: r.gen,
                    version: r.version,
                    is_error: false,
                    error_payload: Vec::new(),
                },
                Err(e) => {
                    let (code, msg) = self.map_kernel_err(e);
                    BatchWriteItemResponse {
                        content_id: String::new(),
                        size: 0,
                        gen: 0,
                        version: 0,
                        is_error: true,
                        error_payload: encode_rpc_error(code, &msg),
                    }
                }
            })
            .collect();

        Ok(Response::new(BatchWriteResponse { results: mapped }))
    }

    async fn call(&self, req: Request<CallRequest>) -> Result<Response<CallResponse>, Status> {
        let (ctx, req) = self.authenticate(req)?;
        // Offload: call dispatch may invoke blocking kernel ops
        let kernel = self.kernel.clone();
        let method = req.method;
        let payload = req.payload;
        run_blocking(move || crate::call_dispatch::dispatch(&kernel, &ctx, &method, &payload))
            .await?
    }
}

/// Spawn the VFS gRPC server on a dedicated tokio runtime and return a
/// shutdown handle.
pub fn spawn(
    kernel: Arc<Kernel>,
    cfg: VfsGrpcConfig,
    auth: Arc<dyn AuthProvider>,
) -> Result<VfsGrpcHandle, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("nexus-vfs-grpc")
        .enable_all()
        .build()
        .map_err(|e| format!("vfs-grpc runtime: {e}"))?;

    let routes = build_vfs_routes(kernel, auth, cfg.max_message_bytes, &cfg.server_version);

    let mut server_builder = lib::transport_primitives::apply_server_limits(Server::builder())
        .timeout(std::time::Duration::from_secs(60));

    if let Some(tls) = cfg.tls {
        let identity = tonic::transport::Identity::from_pem(&tls.cert_pem, &tls.key_pem);
        let ca = tonic::transport::Certificate::from_pem(&tls.ca_pem);
        let tls_cfg = tonic::transport::ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(ca);
        server_builder = server_builder
            .tls_config(tls_cfg)
            .map_err(|e| format!("TLS config: {e}"))?;
    }

    let router = server_builder.add_routes(routes);

    let (tx, rx) = oneshot::channel::<()>();
    let bind = cfg.bind_addr;
    runtime.spawn(async move {
        let result = router
            .serve_with_shutdown(bind, async move {
                let _ = rx.await;
            })
            .await;
        if let Err(e) = result {
            tracing::error!("VFS gRPC server stopped: {e}");
        }
    });

    Ok(VfsGrpcHandle {
        shutdown_tx: Some(tx),
        runtime: Some(runtime),
    })
}

/// Build the VFS gRPC service as type-erased `tonic::service::Routes`.
///
/// Returns `Routes` (not a concrete generic type) so callers don't
/// need to name `VfsServiceImpl`, keeping it `pub(crate)`.
///
/// Used by:
/// - `nexusd-cluster`: passes the Routes to `ZoneManager` for shared-port co-hosting.
/// - `spawn()`: wraps the Routes in a standalone tonic server.
pub fn build_vfs_routes(
    kernel: Arc<Kernel>,
    auth: Arc<dyn AuthProvider>,
    max_message_bytes: usize,
    server_version: &str,
) -> tonic::service::Routes {
    let svc = VfsServiceImpl {
        kernel,
        auth,
        server_started_at: Instant::now(),
        server_version: Arc::from(server_version),
        started_secs: Arc::new(AtomicU64::new(0)),
    };
    let server = NexusVfsServiceServer::new(svc)
        .max_decoding_message_size(max_message_bytes)
        .max_encoding_message_size(max_message_bytes);
    tonic::service::Routes::new(server)
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Subset of `RPCErrorCode` from `nexus.contracts.rpc_types`.
#[derive(Copy, Clone)]
pub(crate) enum RpcErrorCode {
    InvalidPath = -32004,
    PermissionError = -32003,
    AccessDenied = -32018,
    FileNotFound = -32007,
    ValidationError = -32005,
    Conflict = -32006,
    InternalError = -32603,
}

pub(crate) fn encode_rpc_error(code: RpcErrorCode, message: &str) -> Vec<u8> {
    encode_rpc_error_bytes(code, message)
}

pub(crate) fn encode_rpc_error_bytes(code: RpcErrorCode, message: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "code": code as i64,
        "message": message,
    }))
    .unwrap_or_else(|_| b"{}".to_vec())
}

fn error_read(status: Status) -> ReadResponse {
    ReadResponse {
        content: Vec::new(),
        content_id: String::new(),
        size: 0,
        gen: 0,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
        entry_type: 0,
        stream_next_offset: None,
        post_hook_needed: false,
    }
}

fn error_write(status: Status) -> WriteResponse {
    WriteResponse {
        content_id: String::new(),
        size: 0,
        gen: 0,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_delete(status: Status) -> DeleteResponse {
    DeleteResponse {
        success: false,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
        entry_type: 0,
        path: String::new(),
        content_id: String::new(),
        size: 0,
    }
}

fn error_mkdir(status: Status) -> MkdirResponse {
    MkdirResponse {
        hit: false,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_readdir(status: Status) -> ReaddirResponse {
    ReaddirResponse {
        entries: Vec::new(),
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_ipc_ack(status: Status) -> IpcAck {
    IpcAck {
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_ipc_has(status: Status) -> IpcHasResponse {
    IpcHasResponse {
        present: false,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_stream_write(status: Status) -> StreamWriteResponse {
    StreamWriteResponse {
        offset: 0,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_stream_read(status: Status) -> StreamReadAtResponse {
    StreamReadAtResponse {
        data: Vec::new(),
        next_offset: 0,
        eof: false,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_stream_collect(status: Status) -> StreamCollectAllResponse {
    StreamCollectAllResponse {
        data: Vec::new(),
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_get_xattr(status: Status) -> GetXattrResponse {
    GetXattrResponse {
        found: false,
        value: String::new(),
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_set_xattr(status: Status) -> SetXattrResponse {
    SetXattrResponse {
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_get_xattr_bulk(status: Status) -> GetXattrBulkResponse {
    GetXattrBulkResponse {
        items: Vec::new(),
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_lock(status: Status) -> LockResponse {
    LockResponse {
        acquired: false,
        lock_id: String::new(),
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_unlock(status: Status) -> UnlockResponse {
    UnlockResponse {
        released: false,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_watch(status: Status) -> WatchResponse {
    WatchResponse {
        matched: false,
        path: String::new(),
        event_type: String::new(),
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_rename(status: Status) -> RenameResponse {
    RenameResponse {
        hit: false,
        success: false,
        is_directory: false,
        old_content_id: None,
        old_size: None,
        old_version: None,
        old_modified_at_ms: None,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_copy(status: Status) -> CopyResponse {
    CopyResponse {
        hit: false,
        dst_path: String::new(),
        content_id: None,
        size: 0,
        version: 0,
        gen: 0,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

/// Treat a present-but-empty wire string as absent. Proto3 `optional` fields
/// Historical synthetic ack for a DT_MOUNT the server intentionally does not
/// build (metadata-only / federation no-op, or the boot-owned root remount):
/// `created=false`, no error, no state change.
fn synthetic_setattr_ack(req: &SetattrRequest) -> SetattrResponse {
    SetattrResponse {
        path: req.path.clone(),
        created: false,
        entry_type: req.entry_type,
        is_error: false,
        error_payload: Vec::new(),
    }
}

fn error_setattr(status: Status) -> SetattrResponse {
    SetattrResponse {
        path: String::new(),
        created: false,
        entry_type: 0,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
    }
}

fn error_stat(status: Status) -> StatResponse {
    StatResponse {
        found: false,
        is_error: true,
        error_payload: encode_rpc_error_bytes(status_to_code(&status), status.message()),
        ..Default::default()
    }
}

fn status_to_code(s: &Status) -> RpcErrorCode {
    use tonic::Code;
    match s.code() {
        Code::Unauthenticated => RpcErrorCode::AccessDenied,
        Code::PermissionDenied => RpcErrorCode::PermissionError,
        Code::NotFound => RpcErrorCode::FileNotFound,
        Code::InvalidArgument => RpcErrorCode::InvalidPath,
        _ => RpcErrorCode::InternalError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    use kernel::abc::object_store::{ObjectStore, StorageError, WriteResult};
    use kernel::kernel::convenience::{KernelConvenience, MountOptions};
    use kernel::kernel::vfs_proto::{
        nexus_vfs_service_server::NexusVfsService, BatchReadItemRequest, BatchReadRequest,
        BatchWriteItemRequest, BatchWriteRequest, ReadRequest, SetattrRequest, StatRequest,
    };
    use kernel::kernel::Kernel;

    #[derive(Default)]
    struct MemBackend {
        blobs: StdMutex<HashMap<String, Vec<u8>>>,
    }

    impl ObjectStore for MemBackend {
        fn name(&self) -> &str {
            "mem"
        }

        fn write_content(
            &self,
            content: &[u8],
            content_id: &str,
            _ctx: &kernel::kernel::OperationContext,
            offset: u64,
        ) -> Result<WriteResult, StorageError> {
            let mut map = self.blobs.lock().unwrap();
            let entry = map.entry(content_id.to_string()).or_default();
            let start = offset as usize;
            if start > entry.len() {
                entry.resize(start, 0);
            }
            let end = start + content.len();
            if end > entry.len() {
                entry.resize(end, 0);
            }
            entry[start..end].copy_from_slice(content);
            let size = entry.len() as u64;
            Ok(WriteResult {
                content_id: content_id.to_string(),
                version: content_id.to_string(),
                size,
            })
        }

        fn read_content(
            &self,
            content_id: &str,
            _ctx: &kernel::kernel::OperationContext,
        ) -> Result<Vec<u8>, StorageError> {
            self.blobs
                .lock()
                .unwrap()
                .get(content_id)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(content_id.into()))
        }
    }

    fn kernel_with_mem_backend() -> Kernel {
        let k = Kernel::new();
        let backend: std::sync::Arc<dyn ObjectStore> = std::sync::Arc::new(MemBackend::default());
        k.mount(
            "/",
            MountOptions::new("mem")
                .with_backend(backend)
                .with_io_profile(""),
        )
        .expect("kernel_with_mem_backend: mount DT_MOUNT");
        k
    }

    // ── Issue #4273: sub-path remote mount path reconstruction (e2e) ──
    //
    // `RemoteBackend` is the cluster's CLIENT to a federation hub. In
    // production that hub is the Python Nexus server, which serves the
    // generic `Call` RPC (sys_write/sys_stat/sys_rename/mkdir/sys_rmdir) plus
    // typed Read/Delete. The native Rust `VfsServiceImpl` deliberately stubs
    // `Call`, so this test stands up a faithful hub stub that mirrors the
    // Python hub's contract (path-shaped, zone-prefixed content IDs) and drives
    // a real `RemoteBackend` against it over a real `RpcTransport` / gRPC.

    use kernel::kernel::vfs_proto::nexus_vfs_service_server::NexusVfsServiceServer;

    /// In-memory federation hub stub. Stores blobs keyed by the ABSOLUTE server
    /// path it receives, and records every write path so the test can assert
    /// what `RemoteBackend` reconstructed onto the wire.
    #[derive(Clone, Default)]
    struct HubStub {
        blobs: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
        writes: Arc<StdMutex<Vec<String>>>,
    }

    impl HubStub {
        fn write_paths(&self) -> Vec<String> {
            self.writes.lock().unwrap().clone()
        }
        fn ok(payload: serde_json::Value) -> Result<Response<CallResponse>, Status> {
            Ok(Response::new(CallResponse {
                payload: serde_json::to_vec(&payload).unwrap(),
                is_error: false,
            }))
        }
        fn call_err(msg: &str) -> Result<Response<CallResponse>, Status> {
            Ok(Response::new(CallResponse {
                payload: serde_json::to_vec(&serde_json::json!({"code": -32603, "message": msg}))
                    .unwrap(),
                is_error: true,
            }))
        }
    }

    #[tonic::async_trait]
    impl NexusVfsService for HubStub {
        async fn call(
            &self,
            request: Request<CallRequest>,
        ) -> Result<Response<CallResponse>, Status> {
            let req = request.into_inner();
            let v: serde_json::Value = serde_json::from_slice(&req.payload)
                .map_err(|e| Status::internal(e.to_string()))?;
            match req.method.as_str() {
                "sys_write" => {
                    let path = v.get("path").and_then(|p| p.as_str()).unwrap_or("");
                    let b64 = v
                        .get("buf")
                        .and_then(|b| b.get("data"))
                        .and_then(|d| d.as_str())
                        .unwrap_or("");
                    use base64::Engine;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(b64)
                        .map_err(|e| Status::internal(e.to_string()))?;
                    let n = bytes.len() as u64;
                    self.writes.lock().unwrap().push(path.to_string());
                    self.blobs.lock().unwrap().insert(path.to_string(), bytes);
                    // Hub echoes a zone-prefixed (slash-stripped) path content id.
                    Self::ok(serde_json::json!({
                        "result": {
                            "content_id": path.trim_start_matches('/'),
                            "size": n,
                            "bytes_written": n,
                        }
                    }))
                }
                "sys_stat" => {
                    let path = v.get("path").and_then(|p| p.as_str()).unwrap_or("");
                    match self.blobs.lock().unwrap().get(path) {
                        Some(b) => Self::ok(serde_json::json!({"result": {"size": b.len()}})),
                        None => Self::call_err(&format!("sys_stat({path}): not found")),
                    }
                }
                "sys_rename" => {
                    let old = v.get("old_path").and_then(|p| p.as_str()).unwrap_or("");
                    let new = v.get("new_path").and_then(|p| p.as_str()).unwrap_or("");
                    let mut blobs = self.blobs.lock().unwrap();
                    match blobs.remove(old) {
                        Some(data) => {
                            blobs.insert(new.to_string(), data);
                            Self::ok(serde_json::json!({"result": {}}))
                        }
                        None => {
                            drop(blobs);
                            Self::call_err(&format!("sys_rename({old}): not found"))
                        }
                    }
                }
                "mkdir" | "sys_rmdir" => Self::ok(serde_json::json!({"result": {}})),
                other => Self::call_err(&format!("unknown Call method: {other}")),
            }
        }

        async fn read(
            &self,
            request: Request<ReadRequest>,
        ) -> Result<Response<ReadResponse>, Status> {
            let path = request.into_inner().path;
            match self.blobs.lock().unwrap().get(&path) {
                Some(b) => Ok(Response::new(ReadResponse {
                    content: b.clone(),
                    content_id: path.trim_start_matches('/').to_string(),
                    size: b.len() as i64,
                    is_error: false,
                    ..Default::default()
                })),
                None => Ok(Response::new(ReadResponse {
                    is_error: true,
                    error_payload: br#"{"code":-32603,"message":"not found"}"#.to_vec(),
                    ..Default::default()
                })),
            }
        }

        async fn delete(
            &self,
            request: Request<DeleteRequest>,
        ) -> Result<Response<DeleteResponse>, Status> {
            let path = request.into_inner().path;
            let removed = self.blobs.lock().unwrap().remove(&path).is_some();
            Ok(Response::new(DeleteResponse {
                success: removed,
                is_error: false,
                ..Default::default()
            }))
        }

        async fn ping(
            &self,
            _request: Request<PingRequest>,
        ) -> Result<Response<PingResponse>, Status> {
            Ok(Response::new(PingResponse {
                version: "hub-stub".into(),
                ..Default::default()
            }))
        }

        // RemoteBackend never invokes these against the hub; stub them out.
        async fn write(&self, _: Request<WriteRequest>) -> Result<Response<WriteResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn batch_read(
            &self,
            _: Request<BatchReadRequest>,
        ) -> Result<Response<BatchReadResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn batch_write(
            &self,
            _: Request<BatchWriteRequest>,
        ) -> Result<Response<BatchWriteResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn stat(&self, _: Request<StatRequest>) -> Result<Response<StatResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn readdir(
            &self,
            _: Request<ReaddirRequest>,
        ) -> Result<Response<ReaddirResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn batch_stat(
            &self,
            _: Request<BatchStatRequest>,
        ) -> Result<Response<BatchStatResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn setattr(
            &self,
            _: Request<SetattrRequest>,
        ) -> Result<Response<SetattrResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn rename(
            &self,
            _: Request<RenameRequest>,
        ) -> Result<Response<RenameResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn copy(&self, _: Request<CopyRequest>) -> Result<Response<CopyResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn lock(&self, _: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn unlock(
            &self,
            _: Request<UnlockRequest>,
        ) -> Result<Response<UnlockResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn watch(&self, _: Request<WatchRequest>) -> Result<Response<WatchResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn get_xattr(
            &self,
            _: Request<GetXattrRequest>,
        ) -> Result<Response<GetXattrResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn set_xattr(
            &self,
            _: Request<SetXattrRequest>,
        ) -> Result<Response<SetXattrResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn get_xattr_bulk(
            &self,
            _: Request<GetXattrBulkRequest>,
        ) -> Result<Response<GetXattrBulkResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn mkdir(&self, _: Request<MkdirRequest>) -> Result<Response<MkdirResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn close_pipe(&self, _: Request<IpcPathRequest>) -> Result<Response<IpcAck>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn has_pipe(
            &self,
            _: Request<IpcPathRequest>,
        ) -> Result<Response<IpcHasResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn close_all_pipes(&self, _: Request<IpcEmpty>) -> Result<Response<IpcAck>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn close_stream(
            &self,
            _: Request<IpcPathRequest>,
        ) -> Result<Response<IpcAck>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn has_stream(
            &self,
            _: Request<IpcPathRequest>,
        ) -> Result<Response<IpcHasResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn stream_write_nowait(
            &self,
            _: Request<StreamWriteRequest>,
        ) -> Result<Response<StreamWriteResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn stream_read_at(
            &self,
            _: Request<StreamReadAtRequest>,
        ) -> Result<Response<StreamReadAtResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
        async fn stream_collect_all(
            &self,
            _: Request<IpcPathRequest>,
        ) -> Result<Response<StreamCollectAllResponse>, Status> {
            Err(Status::unimplemented("hub stub"))
        }
    }

    /// Compare a server-received path ignoring an optional leading slash.
    fn path_eq(got: &str, want: &str) -> bool {
        got.trim_start_matches('/') == want.trim_start_matches('/')
    }

    /// Full end-to-end: a `RemoteBackend` mounted at the sub-path `/zone/acme`
    /// drives a faithful federation hub stub over a real `RpcTransport` / gRPC.
    /// Validates Issue #4273 path reconstruction on the wire: writes land at
    /// `/zone/acme/...`, write→read/stat/rename/delete all round-trip, the
    /// stored content id is mount-relative, and a crafted relative path stays
    /// inside the subtree.
    #[test]
    fn remote_subpath_mount_e2e_over_grpc() {
        use backends::storage::remote::RemoteBackend;
        use kernel::rpc_transport::RpcTransport;
        use std::net::TcpListener;
        use std::time::Duration;

        let hub = HubStub::default();

        // Ephemeral port + a real tonic server hosting the hub stub.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let bind: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let server_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        {
            let svc = NexusVfsServiceServer::new(hub.clone());
            server_rt.spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(svc)
                    .serve(bind)
                    .await
                    .ok();
            });
        }

        // Client: RpcTransport → RemoteBackend at sub-path /zone/acme.
        let client_rt = std::sync::Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
        );
        let addr = format!("127.0.0.1:{port}");
        let transport = std::sync::Arc::new(
            RpcTransport::new(client_rt, &addr, "", None, Duration::from_secs(10))
                .expect("rpc transport"),
        );

        // The channel is lazy and the server binds asynchronously — wait until
        // it actually answers before asserting.
        let mut ready = false;
        for _ in 0..50 {
            if transport.ping().is_ok() {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(ready, "server did not become reachable");

        let backend =
            RemoteBackend::with_zone_path(std::sync::Arc::clone(&transport), "/zone/acme");
        let ctx = kernel::kernel::OperationContext::new("test", "root", false, None, false);

        // 1. write → hub must receive the reconstructed absolute path. The
        //    content id is persisted VERBATIM (the hub's own zone-prefixed id)
        //    so the remote metastore writes the correct id back to the hub
        //    (Issue #4273 — do NOT rewrite it to a mount-relative value).
        let wr = backend
            .write_content(b"hello sub-path", "file.txt", &ctx, 0)
            .expect("write_content");
        assert_eq!(
            wr.content_id, "zone/acme/file.txt",
            "stored content_id must be the hub's verbatim zone-prefixed id (Issue #4273)"
        );
        assert!(
            hub.write_paths()
                .iter()
                .any(|p| path_eq(p, "zone/acme/file.txt")),
            "hub should receive /zone/acme/file.txt; saw {:?}",
            hub.write_paths()
        );

        // 2. read back through the stored (mount-relative) content_id round-trips.
        let data = backend
            .read_content(&wr.content_id, &ctx)
            .expect("read_content");
        assert_eq!(data, b"hello sub-path", "write->read round-trip failed");

        // 3. stat resolves on the hub (path reconstruction for sys_stat).
        let size = backend
            .get_content_size("file.txt")
            .expect("get_content_size");
        assert_eq!(size, b"hello sub-path".len() as u64);

        // 4. rename then read the new name (path reconstruction for sys_rename).
        backend.rename("file.txt", "renamed.txt").expect("rename");
        let after = backend
            .read_content("renamed.txt", &ctx)
            .expect("read renamed");
        assert_eq!(after, b"hello sub-path");

        // 5. delete then confirm gone (path reconstruction for sys_unlink).
        backend.delete_file("renamed.txt").expect("delete_file");
        assert!(
            backend.read_content("renamed.txt", &ctx).is_err(),
            "file should be gone after delete"
        );

        // 6. a crafted relative path cannot escape the mounted subtree.
        let _ = backend.write_content(b"x", "zone/acme2/secret", &ctx, 0);
        let writes = hub.write_paths();
        assert!(
            writes
                .iter()
                .any(|p| path_eq(p, "zone/acme/zone/acme2/secret")),
            "crafted path should be contained under the mount; saw {writes:?}"
        );
        assert!(
            !writes.iter().any(|p| path_eq(p, "zone/acme2/secret")),
            "crafted path ESCAPED to a sibling subtree: {writes:?}"
        );

        // 7. Federation read-repair correctness (round-3 review case): the
        //    kernel cache-write passes a stored content id (e.g.
        //    "zone/acme/file.txt") through write_content. It is already
        //    zone-prefixed, so it must map to "/zone/acme/file.txt" — NOT be
        //    re-prefixed to "/zone/acme/zone/acme/file.txt" (which would orphan
        //    or corrupt hub data on a failover read miss).
        let wr2 = backend
            .write_content(b"repair", "zone/acme/repair.txt", &ctx, 0)
            .expect("write content-id");
        let writes2 = hub.write_paths();
        assert!(
            writes2.iter().any(|p| path_eq(p, "zone/acme/repair.txt")),
            "zone-prefixed write must pass through, not double; saw {writes2:?}"
        );
        assert!(
            !writes2
                .iter()
                .any(|p| path_eq(p, "zone/acme/zone/acme/repair.txt")),
            "zone-prefixed write was double-prefixed (read-repair misroute): {writes2:?}"
        );
        // Readback round-trips through the same pass-through reconstruction.
        assert_eq!(
            backend
                .read_content(&wr2.content_id, &ctx)
                .expect("read content-id"),
            b"repair"
        );
        // NOTE: a real route path that literally re-uses the mount prefix
        // (`/zone/acme/zone/acme/...`) is indistinguishable from a content id
        // and is consistently aliased to the collapsed path — the documented
        // kernel-API limitation (see RemoteBackend::to_server_path).

        drop(server_rt);
    }

    // ── bridge-2 (#4262): DT_MOUNT builds a live backend via the provider ──

    use kernel::hal::object_store_provider::{
        set_provider, ObjectStoreBuildResult, ObjectStoreProviderArgs,
    };

    /// A minimal `ObjectStoreProvider` that hands back an in-memory backend
    /// for `backend_type == "s3"`. Stands in for `DefaultObjectStoreProvider`
    /// (whose real `s3` arm needs the aws-sdk that the `transport` crate
    /// deliberately does not compile), so the DT_MOUNT→provider→kernel→
    /// read/write bridge can be exercised in-process. It requires the S3
    /// params, proving the handler actually threads them off the wire.
    struct FakeS3Provider;

    impl kernel::hal::object_store_provider::ObjectStoreProvider for FakeS3Provider {
        fn build(
            &self,
            args: &ObjectStoreProviderArgs<'_>,
        ) -> Result<ObjectStoreBuildResult, String> {
            match args.backend_type {
                "s3" => {
                    // The handler must thread the request's S3 params through.
                    let _bucket = args
                        .backend_params
                        .get("s3_bucket")
                        .filter(|v| !v.is_empty())
                        .ok_or("fake s3: missing s3_bucket")?;
                    let _region = args
                        .backend_params
                        .get("aws_region")
                        .filter(|v| !v.is_empty())
                        .ok_or("fake s3: missing aws_region")?;
                    Ok(ObjectStoreBuildResult {
                        backend: Some(std::sync::Arc::new(MemBackend::default())),
                        pending_remote_meta_store: None,
                    })
                }
                other => Err(format!("fake provider: unsupported backend_type '{other}'")),
            }
        }
    }

    /// S3 DT_MOUNT over the wire builds a live backend via the provider and a
    /// subsequent read/write through the new mount round-trips. (S3-compatible
    /// Cloudflare R2 / MinIO ride the same arm via `s3_endpoint`.)
    #[tokio::test]
    async fn setattr_dt_mount_s3_builds_backend_and_serves_io() {
        // Provider slot is process-global + set-once; tolerate a prior set.
        let _ = set_provider(std::sync::Arc::new(FakeS3Provider));

        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel.clone());

        let resp = svc
            .setattr(tonic::Request::new(SetattrRequest {
                path: "/r2".into(),
                auth_token: "test-key".into(),
                entry_type: 2,
                backend_name: "r2".into(),
                backend_type: "s3".into(),
                backend_params: HashMap::from([
                    ("s3_bucket".into(), "nexus-test".into()),
                    ("aws_region".into(), "auto".into()),
                    ("aws_access_key".into(), "AKID".into()),
                    ("aws_secret_key".into(), "SECRET".into()),
                    (
                        "s3_endpoint".into(),
                        "https://acct.r2.cloudflarestorage.com".into(),
                    ),
                ]),
                ..Default::default()
            }))
            .await
            .expect("setattr rpc ok")
            .into_inner();
        assert!(!resp.is_error, "s3 mount should not error: {resp:?}");
        assert!(
            resp.created,
            "s3 mount must report a live build (created=true), not a synthetic ack"
        );

        // I/O through the freshly-built mount must round-trip.
        let ctx = OperationContext::new("test", "root", true, None, true);
        KernelAbi::sys_write(&*kernel, "/r2/hello.txt", &ctx, b"r2 bytes", 0)
            .expect("write into s3 mount");
        let read = svc
            .read(tonic::Request::new(ReadRequest {
                path: "/r2/hello.txt".into(),
                auth_token: "test-key".into(),
                timeout_ms: 0,
                ..Default::default()
            }))
            .await
            .expect("read rpc ok")
            .into_inner();
        assert!(!read.is_error, "read through s3 mount errored: {read:?}");
        assert_eq!(read.content, b"r2 bytes");
    }

    /// A provider-built DT_MOUNT with a present-but-EMPTY required param
    /// (`s3_bucket = ""`) must fail the build (fail-loud), not coerce to a
    /// degenerate backend that reports created=true and breaks later at I/O.
    /// The handler normalizes empty wire strings to absent so the provider's
    /// required-arg check rejects them.
    #[tokio::test]
    async fn setattr_dt_mount_s3_empty_required_param_errors() {
        let _ = set_provider(std::sync::Arc::new(FakeS3Provider));
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel);

        let resp = svc
            .setattr(tonic::Request::new(SetattrRequest {
                path: "/r2".into(),
                auth_token: "test-key".into(),
                entry_type: 2,
                backend_type: "s3".into(),
                backend_params: HashMap::from([
                    ("s3_bucket".into(), String::new()), // present-but-empty → treated as absent
                    ("aws_region".into(), "auto".into()),
                    ("aws_access_key".into(), "k".into()),
                    ("aws_secret_key".into(), "s".into()),
                ]),
                ..Default::default()
            }))
            .await
            .expect("setattr rpc ok")
            .into_inner();
        assert!(
            resp.is_error,
            "empty required s3 param must fail the build, not create a degenerate mount: {resp:?}"
        );
        assert!(!resp.created);
    }

    /// A local-host `backend_type` at the ROOT path keeps the historical
    /// synthetic ack — it must NOT rebuild/clobber the live boot mount the
    /// host binary owns.
    #[tokio::test]
    async fn setattr_dt_mount_root_local_backend_type_synthetic_acks() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel.clone());

        // Seed a file through the live "/" mount.
        let ctx = OperationContext::new("test", "root", true, None, true);
        KernelAbi::sys_write(&*kernel, "/seed.txt", &ctx, b"alive", 0).expect("seed write");

        // Re-emit DT_MOUNT for "/" with a local backend_type (as the Python
        // factory does at boot). Must ack synthetically, not rebuild.
        let resp = svc
            .setattr(tonic::Request::new(SetattrRequest {
                path: "/".into(),
                auth_token: "test-key".into(),
                entry_type: 2,
                backend_name: "local".into(),
                backend_type: "cas-local".into(),
                ..Default::default()
            }))
            .await
            .expect("setattr rpc ok")
            .into_inner();
        assert!(!resp.is_error, "local DT_MOUNT must not error: {resp:?}");
        assert!(
            !resp.created,
            "local DT_MOUNT must be a synthetic ack (created=false)"
        );

        // The live "/" mount is intact — the seeded file still reads back.
        let read = svc
            .read(tonic::Request::new(ReadRequest {
                path: "/seed.txt".into(),
                auth_token: "test-key".into(),
                timeout_ms: 0,
                ..Default::default()
            }))
            .await
            .expect("read rpc ok")
            .into_inner();
        assert!(!read.is_error, "boot mount was clobbered: {read:?}");
        assert_eq!(read.content, b"alive");
    }

    /// A local-host `backend_type` at a NON-root path synthetic-acks (like the
    /// root remount): the host binary serves the path through its `/` host-fs
    /// mount, so the write falls through and lands on disk. This is the
    /// established behavior the self-contained e2e suite relies on — it mounts
    /// `cas-local` at `/files` over gRPC, then writes/reads it.
    #[tokio::test]
    async fn setattr_dt_mount_non_root_local_backend_acks() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel);

        for bt in ["path_local", "cas-local", "local_connector"] {
            let resp = svc
                .setattr(tonic::Request::new(SetattrRequest {
                    path: "/files".into(),
                    auth_token: "test-key".into(),
                    entry_type: 2,
                    backend_name: "local".into(),
                    backend_type: bt.into(),
                    ..Default::default()
                }))
                .await
                .expect("setattr rpc ok")
                .into_inner();
            assert!(
                !resp.is_error,
                "non-root local DT_MOUNT {bt:?} must ack, not error: {resp:?}"
            );
            assert!(!resp.created, "local DT_MOUNT is a synthetic ack: {resp:?}");
        }
    }

    /// metadata-only / federation DT_MOUNTs (empty `backend_type`) keep the
    /// synthetic ack and never consult the provider.
    #[tokio::test]
    async fn setattr_dt_mount_empty_backend_type_synthetic_acks() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel);

        let resp = svc
            .setattr(tonic::Request::new(SetattrRequest {
                path: "/__fed_zones__/z".into(),
                auth_token: "test-key".into(),
                entry_type: 2,
                // backend_type defaults to "" → synthetic ack.
                ..Default::default()
            }))
            .await
            .expect("setattr rpc ok")
            .into_inner();
        assert!(
            !resp.is_error,
            "empty-backend DT_MOUNT must not error: {resp:?}"
        );
        assert!(
            !resp.created,
            "empty backend_type DT_MOUNT (no zone) must synthetic-ack (created=false)"
        );
    }

    /// Empty backend_type WITH backend-construction params (a malformed /
    /// partially-upgraded client that dropped the dispatch key) must fail
    /// closed, not phantom-ack a mount that installs nothing. The client-side
    /// version-skew guard can't catch this (it only fires for known
    /// backend_types), so the server must.
    #[tokio::test]
    async fn setattr_dt_mount_empty_backend_type_with_params_errors() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel);

        let resp = svc
            .setattr(tonic::Request::new(SetattrRequest {
                path: "/mnt".into(),
                auth_token: "test-key".into(),
                entry_type: 2,
                // backend_type omitted (empty) but S3 params present → malformed.
                backend_params: HashMap::from([
                    ("s3_bucket".into(), "b".into()),
                    ("aws_region".into(), "auto".into()),
                ]),
                ..Default::default()
            }))
            .await
            .expect("setattr rpc ok")
            .into_inner();
        assert!(
            resp.is_error,
            "empty backend_type WITH backend params must fail closed: {resp:?}"
        );
        assert!(!resp.created);
    }

    /// A zoned empty-backend DT_MOUNT (federation: empty backend_type + a
    /// zone_id) is a no-op ack over gRPC for now — federation zone create/join
    /// is not bridged through a Python gRPC DT_MOUNT (the cluster Kernel isn't
    /// wired to the raft coordinator, and JoinZone must not run inline on the
    /// tonic runtime — see `setattr_mount`). It acks (created=false, no error)
    /// installing nothing, rather than routing and risking a split-brain zone.
    #[tokio::test]
    async fn setattr_dt_mount_federation_zoned_is_noop_ack() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel);

        let resp = svc
            .setattr(tonic::Request::new(SetattrRequest {
                path: "/data".into(),
                auth_token: "test-key".into(),
                entry_type: 2,
                zone_id: "shared-zone".into(),
                // empty backend_type + zone_id → federation; deferred → ack.
                ..Default::default()
            }))
            .await
            .expect("setattr rpc ok")
            .into_inner();
        assert!(
            !resp.is_error,
            "zoned empty-backend DT_MOUNT must not error: {resp:?}"
        );
        assert!(
            !resp.created,
            "zoned empty-backend DT_MOUNT is a deferred-federation no-op ack: {resp:?}"
        );
    }

    /// An unrecognized non-empty backend_type fails closed (error), never a
    /// silent ack — so a typo / legacy name can't masquerade as a mount that
    /// was never installed (writes would otherwise land on the parent mount).
    #[tokio::test]
    async fn setattr_dt_mount_unknown_backend_type_errors() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel);

        let resp = svc
            .setattr(tonic::Request::new(SetattrRequest {
                path: "/typo".into(),
                auth_token: "test-key".into(),
                entry_type: 2,
                backend_type: "path_s3".into(), // typo / unknown driver
                ..Default::default()
            }))
            .await
            .expect("setattr rpc ok")
            .into_inner();
        assert!(
            resp.is_error,
            "unknown backend_type must fail closed, not synthetic-ack: {resp:?}"
        );
        assert!(!resp.created);
    }

    /// A connector / LLM backend_type this server cannot build also fails
    /// closed (it is NOT in the synthetic-ack set), rather than acking a
    /// mount that was never installed.
    #[tokio::test]
    async fn setattr_dt_mount_connector_backend_type_errors() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel);

        for bt in ["gdrive", "cli", "openai"] {
            let resp = svc
                .setattr(tonic::Request::new(SetattrRequest {
                    path: format!("/conn/{bt}"),
                    auth_token: "test-key".into(),
                    entry_type: 2,
                    backend_type: bt.into(),
                    ..Default::default()
                }))
                .await
                .expect("setattr rpc ok")
                .into_inner();
            assert!(
                resp.is_error,
                "connector backend_type {bt:?} must fail closed, not ack: {resp:?}"
            );
            assert!(!resp.created);
        }
    }

    /// DT_MOUNT is admin-gated: a non-privileged context is rejected before
    /// any provider build / mount state change. (Called directly with a
    /// non-admin context — the gRPC `for_test` path uses NoAuth, which is
    /// admin+system.)
    #[test]
    fn setattr_mount_requires_admin_context() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel);
        // Non-admin, non-system context.
        let ctx = OperationContext::new("intruder", "root", false, None, false);

        let resp = svc.setattr_mount(
            SetattrRequest {
                path: "/r2".into(),
                entry_type: 2,
                backend_type: "s3".into(),
                backend_params: HashMap::from([
                    ("s3_bucket".into(), "b".into()),
                    ("aws_region".into(), "auto".into()),
                ]),
                ..Default::default()
            },
            &ctx,
        );
        assert!(resp.is_error, "non-admin DT_MOUNT must be rejected");
        assert!(!resp.created);
    }

    #[tokio::test]
    async fn batch_read_returns_per_item_results_in_order() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let ctx = OperationContext::new("test", "root", true, None, true);
        KernelAbi::sys_write(&*kernel, "/x.txt", &ctx, b"hello", 0).expect("write");

        let svc = VfsServiceImpl::for_test(kernel.clone());

        let req = tonic::Request::new(BatchReadRequest {
            auth_token: "test-key".into(),
            items: vec![
                BatchReadItemRequest {
                    path: "/x.txt".into(),
                    offset: 0,
                    length: None,
                },
                BatchReadItemRequest {
                    path: "/missing.txt".into(),
                    offset: 0,
                    length: None,
                },
                BatchReadItemRequest {
                    path: "/x.txt".into(),
                    offset: 1,
                    length: Some(3),
                },
            ],
        });

        let resp = svc.batch_read(req).await.expect("rpc ok").into_inner();
        assert_eq!(resp.results.len(), 3);
        assert!(!resp.results[0].is_error);
        assert_eq!(resp.results[0].content, b"hello");
        assert!(resp.results[1].is_error);
        assert!(!resp.results[2].is_error);
        assert_eq!(resp.results[2].content, b"ell");
    }

    #[tokio::test]
    async fn batch_read_empty_items_returns_empty_results() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel);

        let req = tonic::Request::new(BatchReadRequest {
            auth_token: "test-key".into(),
            items: vec![],
        });

        let resp = svc.batch_read(req).await.expect("rpc ok").into_inner();
        assert_eq!(resp.results.len(), 0);
    }

    /// Regression: a pipe read with `timeout_ms == 0` must be O_NONBLOCK —
    /// return immediately, never block. A prior bug overrode 0 to 5000ms.
    #[tokio::test]
    async fn read_empty_pipe_with_zero_timeout_is_nonblocking() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel);

        // Create an empty DT_PIPE (entry_type 3).
        let created = svc
            .setattr(tonic::Request::new(SetattrRequest {
                path: "/nexus/pipes/regression-test".into(),
                auth_token: "test-key".into(),
                entry_type: 3,
                capacity: 65_536,
                ..Default::default()
            }))
            .await
            .expect("setattr rpc ok")
            .into_inner();
        assert!(!created.is_error, "pipe create failed: {created:?}");

        let start = std::time::Instant::now();
        let resp = svc
            .read(tonic::Request::new(ReadRequest {
                path: "/nexus/pipes/regression-test".into(),
                auth_token: "test-key".into(),
                timeout_ms: 0,
                ..Default::default()
            }))
            .await
            .expect("read rpc ok")
            .into_inner();
        let elapsed = start.elapsed();

        assert!(!resp.is_error, "non-blocking pipe read should not error");
        assert!(resp.content.is_empty(), "empty pipe should yield no bytes");
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "timeout_ms=0 pipe read must be non-blocking; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn batch_write_creates_all_items_and_reports_per_item() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel.clone());

        let req = tonic::Request::new(BatchWriteRequest {
            auth_token: "test-key".into(),
            items: vec![
                BatchWriteItemRequest {
                    path: "/a.txt".into(),
                    content: b"alpha".to_vec(),
                },
                BatchWriteItemRequest {
                    path: "/b.txt".into(),
                    content: b"bravo!".to_vec(),
                },
            ],
        });

        let resp = svc.batch_write(req).await.expect("rpc ok").into_inner();
        assert_eq!(resp.results.len(), 2);
        assert!(!resp.results[0].is_error);
        assert_eq!(resp.results[0].size, 5);
        assert!(!resp.results[1].is_error);
        assert_eq!(resp.results[1].size, 6);

        // Tier 2 create-or-overwrite landed the bytes — read /a.txt back.
        let ctx = OperationContext::new("test", "root", true, None, true);
        let read = KernelAbi::sys_read(&*kernel, "/a.txt", &ctx, 5000, 0).expect("read");
        assert_eq!(read.data.unwrap_or_default(), b"alpha");
    }

    #[tokio::test]
    async fn stat_reports_metadata_and_not_found() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let ctx = OperationContext::new("test", "root", true, None, true);
        // Create-or-overwrite so a metastore entry exists for stat.
        let _ = KernelConvenience::write_batch(
            &*kernel,
            &[("/s.txt".to_string(), b"stat-me".to_vec())],
            &ctx,
        );

        let svc = VfsServiceImpl::for_test(kernel);

        let found = svc
            .stat(tonic::Request::new(StatRequest {
                path: "/s.txt".into(),
                auth_token: "test-key".into(),
                zone_id: String::new(),
            }))
            .await
            .expect("rpc ok")
            .into_inner();
        assert!(found.found);
        assert!(!found.is_error);
        assert_eq!(found.path, "/s.txt");
        assert_eq!(found.size, 7);
        assert!(!found.is_directory);

        let missing = svc
            .stat(tonic::Request::new(StatRequest {
                path: "/nope.txt".into(),
                auth_token: "test-key".into(),
                zone_id: String::new(),
            }))
            .await
            .expect("rpc ok")
            .into_inner();
        assert!(!missing.found);
        assert!(!missing.is_error);
    }

    #[tokio::test]
    async fn batch_write_empty_items_returns_empty_results() {
        let kernel = std::sync::Arc::new(kernel_with_mem_backend());
        let svc = VfsServiceImpl::for_test(kernel);

        let req = tonic::Request::new(BatchWriteRequest {
            auth_token: "test-key".into(),
            items: vec![],
        });

        let resp = svc.batch_write(req).await.expect("rpc ok").into_inner();
        assert_eq!(resp.results.len(), 0);
    }
}
