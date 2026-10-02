//! Route unary gRPC calls to plugin C entry points while preserving metadata,
//! verified peer provenance, and gRPC statuses. Host policies authorize requests
//! and responses; the plugin owns its protobuf dispatch.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::grpc::{DataPlaneReady, ForeignCaVerifierSlot, DATA_PLANE_READY_BUDGET};
use crate::grpc_plugin_access::PluginGrpcPolicy;
use bytes::{BufMut, Bytes, BytesMut};
use http::HeaderMap;
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use kernel::kernel::PluginGrpcEndpoint;
use nexus_plugin_abi::grpc::{GrpcContext, GrpcPeer};
use tower::Service;

/// A tower `Service` that proxies one fully-qualified gRPC service
/// name through a plugin's bytes-level dispatcher.
///
/// Cheap to `Clone` — wraps `Arc<PluginGrpcEndpoint>`.
#[derive(Clone)]
pub struct PluginProxyService {
    inner: Arc<PluginGrpcEndpoint>,
    verifier: ForeignCaVerifierSlot,
    ready: Arc<DataPlaneReady>,
    policy: Arc<dyn PluginGrpcPolicy>,
}

impl PluginProxyService {
    pub fn new(
        endpoint: PluginGrpcEndpoint,
        verifier: ForeignCaVerifierSlot,
        ready: Arc<DataPlaneReady>,
        policy: Arc<dyn PluginGrpcPolicy>,
    ) -> Self {
        Self {
            inner: Arc::new(endpoint),
            verifier,
            ready,
            policy,
        }
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
        let endpoint = Arc::clone(&self.inner);
        let verifier = Arc::clone(&self.verifier);
        let ready = Arc::clone(&self.ready);
        let policy = Arc::clone(&self.policy);
        Box::pin(async move {
            if !ready.wait(DATA_PLANE_READY_BUDGET).await {
                return Ok(grpc_trailer_only(
                    tonic::Code::Unavailable,
                    "data plane is not ready",
                ));
            }
            let path = req.uri().path().to_string();
            let req = tonic::Request::from_http(req);
            // An unset verifier cannot vouch for a node, including during boot.
            // The same live trust roots classify VFS and plugin callers.
            let peer = verifier.get().and_then(|v| {
                crate::peer_identity::classify_from_request(
                    &req,
                    v.cluster_ca_der(),
                    &v.foreign_anchors(),
                )
            });
            let is_cluster_node = peer
                .as_ref()
                .is_some_and(crate::auth::PeerIdentity::is_cluster_node);
            let metadata = req.metadata().clone();
            let context = GrpcContext {
                headers: req
                    .metadata()
                    .clone()
                    .into_headers()
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
                    .collect(),
                peer: GrpcPeer { is_cluster_node },
            };

            let body_bytes = match req.into_inner().collect().await {
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

            if body_bytes[0] != 0 {
                return Ok(grpc_trailer_only(
                    tonic::Code::Unimplemented,
                    "plugin-proxy: compressed requests are unsupported",
                ));
            }
            let declared = u32::from_be_bytes(body_bytes[1..5].try_into().unwrap()) as usize;
            if declared != body_bytes.len() - 5 {
                return Ok(grpc_trailer_only(
                    tonic::Code::InvalidArgument,
                    "plugin-proxy: expected one complete unary gRPC message",
                ));
            }
            let mut payload = body_bytes[5..].to_vec();

            // FFI dispatch may block (the plugin reaches into redb,
            // libsodium, etc.).  Move it off the tokio reactor.
            let dispatch_path = path.clone();
            let result = tokio::task::spawn_blocking(move || {
                let authorized =
                    policy.authorize(&dispatch_path, &mut payload, &metadata, peer.as_ref())?;
                let response = endpoint
                    .service
                    .call(&dispatch_path, &payload, &context)
                    .map_err(|error| {
                        tonic::Status::new(tonic::Code::from_i32(error.code as i32), error.message)
                    })?;
                authorized.complete(response)
            })
            .await;

            let response_bytes: Vec<u8> = match result {
                Ok(Ok(b)) => b,
                Ok(Err(status)) => {
                    return Ok(grpc_trailer_only(status.code(), status.message()));
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
    // tonic encodes grpc-message correctly, including Unicode and percent signs.
    tonic::Status::new(code, message).into_http()
}

// ── Routes glue ────────────────────────────────────────────────────

/// Consume the kernel's loaded-plugin gRPC opt-ins and add one route
/// per `(plugin × service_name)` to the supplied `Routes`.
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
    verifier: ForeignCaVerifierSlot,
    ready: Arc<DataPlaneReady>,
    policy: impl Fn(&PluginGrpcEndpoint) -> Arc<dyn PluginGrpcPolicy>,
) -> tonic::service::Routes {
    if endpoints.is_empty() {
        return routes;
    }
    let mut router = routes.into_axum_router();
    for ep in endpoints {
        let plugin_name = ep.plugin_name.clone();
        let service_name = ep.service_name.clone();
        let access = policy(&ep);
        let svc = PluginProxyService::new(ep, Arc::clone(&verifier), Arc::clone(&ready), access);
        router = router.route_service(&format!("/{service_name}/{{*method}}"), svc);
        tracing::info!(
            plugin = plugin_name,
            service = service_name,
            "plugin gRPC service routed",
        );
    }
    tonic::service::Routes::from(router)
}
