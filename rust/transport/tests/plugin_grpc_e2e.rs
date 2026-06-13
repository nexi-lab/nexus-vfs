//! End-to-end regression for the plugin-as-gRPC-service path.
//!
//! Real user journey: a plugin opts in via the `nexus_plugin_grpc_services`
//! ABI symbol → cluster glue calls
//! [`transport::grpc_plugin_proxy::extend_routes_with_plugin_endpoints`]
//! → an **external** tonic client makes a real gRPC unary call →
//! the request bytes survive HTTP/2 framing, gRPC wire framing, the
//! tower router, and the plugin's bytes-level dispatcher; the
//! response bytes survive the reverse trip with `grpc-status: 0`
//! trailers.
//!
//! Catches the Discovery (1) regression: before Phase P, the cluster
//! tonic server was built from `transport::grpc::build_vfs_routes`
//! alone and returned `UNIMPLEMENTED` for plugin services because
//! nothing wired them into `Routes`.
//!
//! The dlopen + signature-verify side of the plugin path is already
//! covered by `kernel::plugins::loader` unit tests; reproducing it
//! here would duplicate coverage without testing the broken contract.
//! What was broken is the routing/framing/dispatch contract — that
//! is what this test exercises.

use std::sync::Arc;
use std::time::Duration;

use contracts::rust_service::{RustCallError, RustService};
use kernel::kernel::PluginGrpcEndpoint;
use prost::Message as _;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Endpoint, Server};
use tonic::Request;
use transport::grpc_plugin_proxy::extend_routes_with_plugin_endpoints;

/// Single-field bytes message — the wire shape is one byte tag (0x0a)
/// + a varint length + payload, so we can also sanity-check that prost
/// and our `PluginProxyService` framing agree on byte boundaries.
#[derive(Clone, PartialEq, prost::Message)]
struct EchoMsg {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

/// Stand-in for the real plugin's bytes-in / bytes-out dispatcher.
///
/// `method` is the full URL path (`/echo.v1.EchoService/Echo`), proving
/// the contract the cluster glue offers to plugin authors; `payload`
/// is the proto-encoded request body bytes (gRPC frame already
/// stripped by the proxy).  Returns proto-encoded response bytes.
struct EchoDispatcher;

impl RustService for EchoDispatcher {
    fn name(&self) -> &str {
        "echo-test"
    }

    fn dispatch(&self, method: &str, payload: &[u8]) -> Result<Vec<u8>, RustCallError> {
        assert!(
            method.starts_with("/echo.v1.EchoService/"),
            "proxy must hand the full URL path to plugin dispatch, got {method:?}",
        );
        assert!(method.ends_with("/Echo"), "got {method:?}");
        let req = EchoMsg::decode(payload)
            .map_err(|e| RustCallError::InvalidArgument(format!("decode EchoRequest: {e}")))?;
        let resp = EchoMsg { data: req.data };
        let mut buf = Vec::with_capacity(resp.encoded_len());
        resp.encode(&mut buf)
            .map_err(|e| RustCallError::Internal(format!("encode EchoResponse: {e}")))?;
        Ok(buf)
    }
}

#[tokio::test]
async fn external_grpc_client_round_trips_through_plugin_proxy() {
    let _ = tracing_subscriber::fmt::try_init();

    // ── 1. Build Routes that mirror what the cluster does on boot ──
    let endpoints = vec![PluginGrpcEndpoint {
        service_name: "echo.v1.EchoService".to_string(),
        plugin_name: "echo-test".to_string(),
        service: Arc::new(EchoDispatcher),
    }];
    let routes = extend_routes_with_plugin_endpoints(tonic::service::Routes::default(), endpoints);

    // ── 2. Serve on an ephemeral port ──────────────────────────────
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let incoming = TcpListenerStream::new(listener);

    let server_handle = tokio::spawn(async move {
        Server::builder()
            .add_routes(routes)
            .serve_with_incoming(incoming)
            .await
            .expect("server.serve_with_incoming");
    });

    // tonic Server spawns its accept loop on next tick; one yield is
    // enough on Linux but Windows sometimes needs a real sleep before
    // the TCP backlog accepts SYN.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ── 3. Drive a real tonic unary call through the proxy ─────────
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint url")
        .connect()
        .await
        .expect("connect");
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.expect("ready");

    let codec: tonic_prost::ProstCodec<EchoMsg, EchoMsg> = tonic_prost::ProstCodec::default();
    let path: http::uri::PathAndQuery = "/echo.v1.EchoService/Echo".parse().expect("parse path");

    let payload = b"hello from external client".to_vec();
    let response = grpc
        .unary(
            Request::new(EchoMsg {
                data: payload.clone(),
            }),
            path,
            codec,
        )
        .await
        .expect("unary call");

    let body = response.into_inner();
    assert_eq!(
        body.data, payload,
        "proto bytes must round-trip exactly through framing + plugin dispatch",
    );

    server_handle.abort();
}

#[tokio::test]
async fn empty_endpoints_passes_routes_through_unchanged() {
    // Cluster boots without any plugin opting in → glue must not
    // perturb existing Routes (otherwise it would silently break the
    // VFS route by reshuffling the axum fallback).
    let routes = extend_routes_with_plugin_endpoints(tonic::service::Routes::default(), vec![]);
    // No panic on into_axum_router → routes survived.
    let _ = routes.into_axum_router();
}
