//! Bridge plugin-exported gRPC services into the cluster's tonic
//! `Routes` without crossing tonic types over the dlopen boundary.
//!
//! ## Why this exists
//!
//! Plugin cdylibs declare which fully-qualified gRPC services they
//! handle through the optional `nexus_plugin_grpc_services` ABI symbol
//! (see `plugin-abi::symbols::SERVICE_GRPC_SERVICES`).  The kernel
//! [`PluginGrpcEndpoint`] surface (one entry per `(service_name, plugin)`)
//! wraps each plugin's dispatcher behind `Arc<dyn RustService>` — a
//! pure bytes-in / bytes-out contract that does not name tonic types.
//!
//! This module is the cluster-side glue: for every endpoint, register
//! a tower `Service` at `/{service_name}/{{*method}}` on the same
//! `tonic::service::Routes` the built-in VFS routes ride on.  The
//! proxy:
//!
//! 1. Waits out the boot gate (the same `DataPlaneReady` door the VFS
//!    face holds requests at) and authenticates the caller — the token
//!    rides the standard `authorization` gRPC metadata (HTTP/2 header)
//!    and resolves through the SAME `AuthProvider` the VFS face uses.
//!    This door used to be unauthenticated, which silently bypassed the
//!    v7 "authorize by caller credentials" contract for any plugin that
//!    relied on it.
//! 2. Strips the gRPC frame header (1-byte compression flag + 4-byte
//!    big-endian length) from the inbound HTTP/2 body.
//! 3. Hands the raw proto bytes to the plugin via
//!    `RustService::dispatch_with_context(ctx, path, payload)` — `path`
//!    is the full URL (e.g.
//!    `/nexus.secrets.v1.GenericSecretsService/PutSecret`), so the
//!    plugin can multiplex many methods through one dispatcher; `ctx`
//!    is the authenticated caller (the v7 `nexus_service_dispatch_v2`
//!    shape).
//! 4. Wraps the returned bytes in a fresh gRPC frame and emits
//!    `grpc-status: 0` trailers on success (or the matching tonic
//!    `Code` for `RustCallError` variants).
//!
//! ## Authentication boundary (deliberate, documented)
//!
//! Token-only: this raw tower service does not see tonic's
//! `Extensions`, so the mTLS peer identity (client-cert classification)
//! is NOT available here — the bearer token is the credential.  An
//! mTLS-only deployment whose callers present no token is REFUSED on
//! this face (fail-closed).  Under the `NoAuth` provider the face
//! behaves exactly like the VFS face (admitted; exposure is bounded by
//! the auth-posture bind rules).
//!
//! ## Contract crossing the dlopen boundary
//!
//! Only `(ctx, method: &str, payload: &[u8]) -> Result<Vec<u8>, _>` — the
//! existing v2 `nexus_service_dispatch` shape.  No tonic types, no
//! `tonic::service::Routes`, no `axum::Router`.  The plugin author is
//! free to use a different tonic / axum / prost version than the
//! cluster ships; only their proto wire bytes need to agree.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{BufMut, Bytes, BytesMut};
use contracts::rust_service::RustCallError;
use http::HeaderMap;
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use kernel::kernel::PluginGrpcEndpoint;
use tower::Service;

use crate::auth::{AuthCredentials, AuthProvider};
use crate::grpc::{DataPlaneReady, DATA_PLANE_READY_BUDGET};
use kernel::kernel::OperationContext;

/// A tower `Service` that proxies one fully-qualified gRPC service
/// name through a plugin's bytes-level dispatcher.
///
/// Cheap to `Clone` — wraps `Arc<PluginGrpcEndpoint>`.
#[derive(Clone)]
pub struct PluginProxyService {
    inner: Arc<PluginGrpcEndpoint>,
    auth: Arc<dyn AuthProvider>,
    ready: Arc<DataPlaneReady>,
}

impl PluginProxyService {
    pub fn new(
        endpoint: PluginGrpcEndpoint,
        auth: Arc<dyn AuthProvider>,
        ready: Arc<DataPlaneReady>,
    ) -> Self {
        Self {
            inner: Arc::new(endpoint),
            auth,
            ready,
        }
    }

    /// The boot gate + token authentication every proxied call passes
    /// through (see the module doc for the token-only boundary).
    async fn authenticate(&self, headers: &HeaderMap) -> Result<OperationContext, tonic::Code> {
        if !self.ready.wait(DATA_PLANE_READY_BUDGET).await {
            return Err(tonic::Code::Unavailable);
        }
        let raw = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let token = raw.strip_prefix("Bearer ").unwrap_or(raw);
        self.auth
            .resolve(&AuthCredentials::from_token(token))
            .map_err(|_| tonic::Code::Unauthenticated)
    }
}

impl Service<http::Request<axum::body::Body>> for PluginProxyService {
    type Response = http::Response<axum::body::Body>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<axum::body::Body>) -> Self::Future {
        let this = self.clone();
        let endpoint = Arc::clone(&self.inner);
        Box::pin(async move {
            let path = req.uri().path().to_string();
            // Same door as the VFS face: boot gate, then token
            // authentication (see the module doc for the token-only
            // boundary). A refused caller never reaches the plugin.
            let headers = req.headers().clone();
            let ctx = match this.authenticate(&headers).await {
                Ok(ctx) => ctx,
                Err(code) => {
                    return Ok(grpc_trailer_only(
                        code,
                        "plugin-proxy: caller not authenticated",
                    ));
                }
            };
            let body_bytes = match req.into_body().collect().await {
                Ok(c) => c.to_bytes(),
                Err(_) => {
                    return Ok(grpc_trailer_only(
                        tonic::Code::Internal,
                        "plugin-proxy: failed to read request body",
                    ));
                }
            };
            // gRPC frame header is exactly 5 bytes (1 compression flag
            // + 4 big-endian length); reject anything shorter.
            if body_bytes.len() < 5 {
                return Ok(grpc_trailer_only(
                    tonic::Code::InvalidArgument,
                    "plugin-proxy: request body shorter than gRPC frame header",
                ));
            }
            let payload = body_bytes.slice(5..);

            // FFI dispatch may block (the plugin reaches into redb,
            // libsodium, etc.).  Move it off the tokio reactor.
            let dispatch_path = path.clone();
            let result = tokio::task::spawn_blocking(move || {
                endpoint
                    .service
                    .dispatch_with_context(&ctx, &dispatch_path, &payload)
            })
            .await;

            let response_bytes: Vec<u8> = match result {
                Ok(Ok(b)) => b,
                Ok(Err(RustCallError::NotFound)) => {
                    return Ok(grpc_trailer_only(
                        tonic::Code::Unimplemented,
                        &format!("plugin-proxy: {path}: not implemented"),
                    ));
                }
                Ok(Err(RustCallError::InvalidArgument(msg))) => {
                    return Ok(grpc_trailer_only(tonic::Code::InvalidArgument, &msg));
                }
                Ok(Err(RustCallError::PermissionDenied(msg))) => {
                    return Ok(grpc_trailer_only(tonic::Code::PermissionDenied, &msg));
                }
                Ok(Err(RustCallError::Internal(msg))) => {
                    return Ok(grpc_trailer_only(tonic::Code::Internal, &msg));
                }
                Err(join_err) => {
                    return Ok(grpc_trailer_only(
                        tonic::Code::Internal,
                        &format!("plugin-proxy: dispatch task aborted: {join_err}"),
                    ));
                }
            };

            // Frame the response: 1-byte compression flag (0 = none) +
            // 4-byte BE length + payload.
            let mut framed = BytesMut::with_capacity(5 + response_bytes.len());
            framed.put_u8(0);
            framed.put_u32(response_bytes.len() as u32);
            framed.put_slice(&response_bytes);
            Ok(grpc_data_response(framed.freeze()))
        })
    }
}

// ── Response construction helpers ──────────────────────────────────

/// Build a successful gRPC response: one DATA frame followed by
/// trailers carrying `grpc-status: 0`.
fn grpc_data_response(framed: Bytes) -> http::Response<axum::body::Body> {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));

    let data_frame: Result<Frame<Bytes>, Infallible> = Ok(Frame::data(framed));
    let trailers_frame: Result<Frame<Bytes>, Infallible> = Ok(Frame::trailers(trailers));
    let stream = futures::stream::iter([data_frame, trailers_frame]);
    let body = axum::body::Body::new(StreamBody::new(stream));

    let mut response = http::Response::new(body);
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc"),
    );
    response
}

/// Build a gRPC error response: trailers-only body carrying the given
/// `grpc-status` code and `grpc-message`.  HTTP status remains 200 —
/// gRPC ferries the error through trailers, not the HTTP status line.
fn grpc_trailer_only(code: tonic::Code, message: &str) -> http::Response<axum::body::Body> {
    let mut trailers = HeaderMap::new();
    trailers.insert(
        "grpc-status",
        http::HeaderValue::from_str(&(code as i32).to_string())
            .unwrap_or_else(|_| http::HeaderValue::from_static("13")),
    );
    if !message.is_empty() {
        if let Ok(v) = http::HeaderValue::from_str(message) {
            trailers.insert("grpc-message", v);
        }
    }
    let trailers_frame: Result<Frame<Bytes>, Infallible> = Ok(Frame::trailers(trailers));
    let stream = futures::stream::iter([trailers_frame]);
    let body = axum::body::Body::new(StreamBody::new(stream));

    let mut response = http::Response::new(body);
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc"),
    );
    response
}

// ── Routes glue ────────────────────────────────────────────────────

/// Consume the kernel's loaded-plugin gRPC opt-ins and add one route
/// per `(plugin × service_name)` to the supplied `Routes`.
///
/// Every route authenticates through `auth` behind the `ready` boot
/// gate — the same door the VFS face uses — and dispatches with the
/// authenticated caller context (v7).
///
/// Idempotent against repeated calls only insofar as
/// `Kernel::plugin_grpc_endpoints` is a snapshot — re-running this on
/// the same routes with overlapping endpoints would attempt to bind
/// the same axum path twice and panic.  Callers wire this exactly
/// once per `Routes` instance.
///
/// Returns the extended `Routes` (consumes the input).
pub fn extend_routes_with_plugin_endpoints(
    routes: tonic::service::Routes,
    endpoints: Vec<PluginGrpcEndpoint>,
    auth: Arc<dyn AuthProvider>,
    ready: Arc<DataPlaneReady>,
) -> tonic::service::Routes {
    if endpoints.is_empty() {
        return routes;
    }
    let mut router = routes.into_axum_router();
    for ep in endpoints {
        let plugin_name = ep.plugin_name.clone();
        let service_name = ep.service_name.clone();
        let svc = PluginProxyService::new(ep, Arc::clone(&auth), Arc::clone(&ready));
        router = router.route_service(&format!("/{service_name}/{{*method}}"), svc);
        tracing::info!(
            plugin = plugin_name,
            service = service_name,
            "plugin gRPC service routed",
        );
    }
    tonic::service::Routes::from(router)
}
