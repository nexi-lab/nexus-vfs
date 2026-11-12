//! Actual mTLS peer for content and federation client regression tests.
use nexus_raft::transport::proto::nexus::raft::{
    JoinZoneRequest, JoinZoneResponse, ReadBlobRequest, ReadBlobResponse, ReadZoneBlobRequest,
};
use nexus_raft::transport::{generate_node_cert, generate_zone_ca};
use std::convert::Infallible;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tonic::codegen::Service;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

pub(crate) const BODY: &[u8] = b"private peer fixture";

pub(crate) type ScopedCall = (Option<u64>, String, String);

#[derive(Clone)]
struct BlobService {
    calls: Arc<Mutex<Vec<Option<u64>>>>,
    scoped_calls: Arc<Mutex<Vec<ScopedCall>>>,
    supports_scoped: bool,
    ca_der: Arc<Vec<u8>>,
}

impl BlobService {
    fn peer_node<T>(&self, request: &tonic::Request<T>) -> Option<u64> {
        request
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .and_then(|info| info.peer_certs())
            .and_then(|certs| certs.first().cloned())
            .map(|leaf| {
                nexus_raft::transport::current_local_node_certificate(leaf.as_ref(), &self.ca_der)
                    .unwrap()
                    .node_id
            })
    }
}

impl tonic::server::NamedService for BlobService {
    const NAME: &'static str = "nexus.raft.ZoneApiService";
}

impl tonic::server::UnaryService<ReadBlobRequest> for BlobService {
    type Response = ReadBlobResponse;
    type Future = Ready<Result<tonic::Response<ReadBlobResponse>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<ReadBlobRequest>) -> Self::Future {
        let node = self.peer_node(&request);
        self.calls.lock().unwrap().push(node);
        ready(Ok(tonic::Response::new(ReadBlobResponse {
            content: BODY.to_vec(),
            error: String::new(),
        })))
    }
}

impl tonic::server::UnaryService<ReadZoneBlobRequest> for BlobService {
    type Response = ReadBlobResponse;
    type Future = Ready<Result<tonic::Response<ReadBlobResponse>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<ReadZoneBlobRequest>) -> Self::Future {
        let node = self.peer_node(&request);
        let request = request.into_inner();
        self.scoped_calls.lock().unwrap().push((
            node,
            request.zone_id.clone(),
            request.content_id.clone(),
        ));
        if request.zone_id != "agent-alice" || request.content_id != "/sessions/shared" {
            return ready(Err(tonic::Status::permission_denied(
                "unavailable zone content",
            )));
        }
        ready(Ok(tonic::Response::new(ReadBlobResponse {
            content: BODY.to_vec(),
            error: String::new(),
        })))
    }
}

impl tonic::server::UnaryService<JoinZoneRequest> for BlobService {
    type Response = JoinZoneResponse;
    type Future = Ready<Result<tonic::Response<JoinZoneResponse>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<JoinZoneRequest>) -> Self::Future {
        self.calls.lock().unwrap().push(self.peer_node(&request));
        ready(Ok(tonic::Response::new(JoinZoneResponse {
            success: true,
            ..Default::default()
        })))
    }
}

impl Service<http::Request<tonic::body::Body>> for BlobService {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let handler = self.clone();
        Box::pin(async move {
            if request.uri().path() == "/nexus.raft.ZoneApiService/JoinZone" {
                let codec = tonic_prost::ProstCodec::<JoinZoneResponse, JoinZoneRequest>::default();
                return Ok(tonic::server::Grpc::new(codec)
                    .unary(handler, request)
                    .await);
            }
            if handler.supports_scoped
                && request.uri().path() == "/nexus.raft.ZoneApiService/ReadZoneBlob"
            {
                let codec =
                    tonic_prost::ProstCodec::<ReadBlobResponse, ReadZoneBlobRequest>::default();
                return Ok(tonic::server::Grpc::new(codec)
                    .unary(handler, request)
                    .await);
            }
            if request.uri().path() != "/nexus.raft.ZoneApiService/ReadBlob" {
                return Ok(http::Response::builder()
                    .status(200)
                    .header("grpc-status", "12")
                    .header("content-type", "application/grpc")
                    .body(tonic::body::Body::empty())
                    .unwrap());
            }
            let codec = tonic_prost::ProstCodec::<ReadBlobResponse, ReadBlobRequest>::default();
            Ok(tonic::server::Grpc::new(codec)
                .unary(handler, request)
                .await)
        })
    }
}

pub(crate) struct Fixture {
    pub(crate) address: String,
    pub(crate) calls: Arc<Mutex<Vec<Option<u64>>>>,
    pub(crate) scoped_calls: Arc<Mutex<Vec<ScopedCall>>>,
    pub(crate) shared_tls: Option<lib::transport_primitives::SharedTlsConfig>,
    ca: Vec<u8>,
    ca_key: Vec<u8>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Fixture {
    pub(crate) async fn start(is_tls: bool) -> Self {
        Self::start_with_scoped(is_tls, false).await
    }

    pub(crate) async fn start_with_scoped(is_tls: bool, supports_scoped: bool) -> Self {
        Self::start_with_options(is_tls, supports_scoped, false).await
    }

    pub(crate) async fn start_with_shared_tls() -> Self {
        Self::start_with_options(true, true, true).await
    }

    async fn start_with_options(is_tls: bool, supports_scoped: bool, is_shared: bool) -> Self {
        lib::transport_primitives::ensure_crypto_provider();
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let (cert, key) = generate_node_cert(1, "root", &ca, &ca_key, &[], None).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let scoped_calls = Arc::new(Mutex::new(Vec::new()));
        let service = BlobService {
            calls: Arc::clone(&calls),
            scoped_calls: Arc::clone(&scoped_calls),
            supports_scoped,
            ca_der: Arc::new(pem::parse(&ca).unwrap().into_contents()),
        };
        let mut builder = Server::builder();
        let shared_tls = is_shared.then(|| {
            lib::transport_primitives::SharedTlsConfig::new(Some(
                lib::transport_primitives::TlsConfig {
                    cert_pem: cert.clone(),
                    key_pem: key.clone(),
                    ca_pem: ca.clone(),
                },
            ))
        });
        if is_tls && !is_shared {
            builder = builder
                .tls_config(
                    ServerTlsConfig::new()
                        .identity(Identity::from_pem(cert, key))
                        .client_ca_root(Certificate::from_pem(&ca)),
                )
                .unwrap();
        }
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving_tls = shared_tls.clone();
        let task = tokio::spawn(async move {
            let router = builder.add_service(service);
            let shutdown = async {
                let _ = stopped.await;
            };
            if let Some(source) = serving_tls {
                router
                    .serve_with_incoming_shutdown(
                        lib::transport_primitives::shared_tls_incoming(listener, source, None)
                            .unwrap(),
                        shutdown,
                    )
                    .await
                    .unwrap();
            } else {
                router
                    .serve_with_incoming_shutdown(
                        tokio_stream::wrappers::TcpListenerStream::new(listener),
                        shutdown,
                    )
                    .await
                    .unwrap();
            }
        });
        Self {
            address,
            calls,
            scoped_calls,
            shared_tls,
            ca,
            ca_key,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub(crate) fn tls(&self, node: u64) -> lib::transport_primitives::TlsConfig {
        let (cert_pem, key_pem) =
            generate_node_cert(node, "root", &self.ca, &self.ca_key, &[], None).unwrap();
        lib::transport_primitives::TlsConfig {
            ca_pem: self.ca.clone(),
            cert_pem,
            key_pem,
        }
    }

    pub(crate) async fn shutdown(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(5), self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Pause a real TCP connection before forwarding its TLS handshake.
pub(crate) struct PausedDial {
    pub(crate) address: String,
    connected: tokio::sync::oneshot::Receiver<()>,
    release: Option<tokio::sync::oneshot::Sender<()>>,
    worker: tokio::task::JoinHandle<()>,
}

impl PausedDial {
    pub(crate) async fn start(backend: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let backend = backend.to_owned();
        let (connected, accepted) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            let (mut incoming, _) = listener.accept().await.unwrap();
            let _ = connected.send(());
            released.await.unwrap();
            let mut outgoing = tokio::net::TcpStream::connect(&backend).await.unwrap();
            let mut connections = tokio::task::JoinSet::new();
            connections.spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
            });
            loop {
                let (mut incoming, _) = listener.accept().await.unwrap();
                let mut outgoing = tokio::net::TcpStream::connect(&backend).await.unwrap();
                connections.spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                });
            }
        });
        Self {
            address,
            connected: accepted,
            release: Some(release),
            worker,
        }
    }

    pub(crate) async fn wait_for_connection(&mut self) {
        tokio::time::timeout(Duration::from_secs(5), &mut self.connected)
            .await
            .unwrap()
            .unwrap();
    }

    pub(crate) fn release(&mut self) {
        self.release.take().unwrap().send(()).unwrap();
    }
}

impl Drop for PausedDial {
    fn drop(&mut self) {
        self.worker.abort();
    }
}
