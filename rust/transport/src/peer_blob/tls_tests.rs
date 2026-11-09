//! Exercise the production peer client against a bound tonic/mTLS endpoint.
use super::*;
use std::convert::Infallible;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use nexus_raft::transport::proto::nexus::raft::ReadBlobResponse;
use nexus_raft::transport::{generate_node_cert, generate_zone_ca};
use tonic::codegen::Service;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

const BODY: &[u8] = b"private peer fixture";

#[derive(Clone)]
struct BlobService {
    calls: Arc<Mutex<Vec<Option<u64>>>>,
    ca_der: Arc<Vec<u8>>,
}

impl tonic::server::NamedService for BlobService {
    const NAME: &'static str = "nexus.raft.ZoneApiService";
}

impl tonic::server::UnaryService<ReadBlobRequest> for BlobService {
    type Response = ReadBlobResponse;
    type Future = Ready<Result<tonic::Response<ReadBlobResponse>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<ReadBlobRequest>) -> Self::Future {
        let node = request
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .and_then(|info| info.peer_certs())
            .and_then(|certs| certs.first().cloned())
            .map(|leaf| {
                nexus_raft::transport::current_local_node_certificate(leaf.as_ref(), &self.ca_der)
                    .unwrap()
                    .node_id
            });
        self.calls.lock().unwrap().push(node);
        ready(Ok(tonic::Response::new(ReadBlobResponse {
            content: BODY.to_vec(),
            error: String::new(),
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
            assert_eq!(request.uri().path(), "/nexus.raft.ZoneApiService/ReadBlob");
            let codec = tonic_prost::ProstCodec::<ReadBlobResponse, ReadBlobRequest>::default();
            Ok(tonic::server::Grpc::new(codec)
                .unary(handler, request)
                .await)
        })
    }
}

struct Fixture {
    address: String,
    calls: Arc<Mutex<Vec<Option<u64>>>>,
    ca: Vec<u8>,
    ca_key: Vec<u8>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Fixture {
    async fn start(is_tls: bool) -> Self {
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let (cert, key) = generate_node_cert(1, "root", &ca, &ca_key, &[], None).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let service = BlobService {
            calls: Arc::clone(&calls),
            ca_der: Arc::new(pem::parse(&ca).unwrap().into_contents()),
        };
        let mut builder = Server::builder();
        if is_tls {
            builder = builder
                .tls_config(
                    ServerTlsConfig::new()
                        .identity(Identity::from_pem(cert, key))
                        .client_ca_root(Certificate::from_pem(&ca)),
                )
                .unwrap();
        }
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            builder
                .add_service(service)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = stopped.await;
                    },
                )
                .await
                .unwrap();
        });
        Self {
            address,
            calls,
            ca,
            ca_key,
            stop: Some(stop),
            task: Some(task),
        }
    }

    fn tls(&self, node: u64) -> lib::transport_primitives::TlsConfig {
        let (cert_pem, key_pem) =
            generate_node_cert(node, "root", &self.ca, &self.ca_key, &[], None).unwrap();
        lib::transport_primitives::TlsConfig {
            ca_pem: self.ca.clone(),
            cert_pem,
            key_pem,
        }
    }

    async fn shutdown(mut self) {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_configuration_encrypts_even_when_the_routing_uri_says_http() {
    let server = Fixture::start(true).await;
    let client = PeerBlobClient::new(tokio::runtime::Handle::current());
    client.install_tls_config(server.tls(2));
    let bytes = client
        .fetch_async(&format!("http://{}", server.address), "/private")
        .await
        .unwrap();
    assert_eq!(bytes, BODY);
    assert_eq!(*server.calls.lock().unwrap(), vec![Some(2)]);
    drop(client);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_tls_cannot_send_a_plaintext_blob_request() {
    let server = Fixture::start(false).await;
    let client = PeerBlobClient::new(tokio::runtime::Handle::current());
    client.install_tls_config(server.tls(2));
    assert!(client
        .fetch_async(&format!("http://{}", server.address), "/private")
        .await
        .is_err());
    assert!(server.calls.lock().unwrap().is_empty());
    drop(client);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_credentials_invalidate_a_cached_plaintext_channel() {
    use kernel::hal::peer::PeerBlobClient as _;
    let server = Fixture::start(false).await;
    let client = PeerBlobClient::new(tokio::runtime::Handle::current());
    assert_eq!(
        client
            .fetch_async(&server.address, "/private")
            .await
            .unwrap(),
        BODY
    );
    let credentials = server.tls(2);
    for (cert, key) in [
        (Some(credentials.cert_pem.as_slice()), None),
        (None, Some(credentials.key_pem.as_slice())),
        (None, None),
    ] {
        client.install_tls(&credentials.ca_pem, cert, key);
        let error = client
            .fetch_async(&server.address, "/private")
            .await
            .unwrap_err();
        assert!(error.contains("requires both"), "{error}");
        assert!(client.channels.is_empty());
        assert_eq!(*server.calls.lock().unwrap(), vec![None]);
    }
    drop(client);
    server.shutdown().await;
}

struct TaskGuard(tokio::task::JoinHandle<()>);
impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_old_dial_cannot_publish_its_channel_after_tls_rotation() {
    let server = Fixture::start(true).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let backend = server.address.clone();
    let (connected, accepted) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let proxy = TaskGuard(tokio::spawn(async move {
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
    }));
    let client = Arc::new(PeerBlobClient::new(tokio::runtime::Handle::current()));
    client.install_tls_config(server.tls(2));
    let old_client = Arc::clone(&client);
    let old_address = address.clone();
    let old = tokio::spawn(async move { old_client.fetch_async(&old_address, "/private").await });
    tokio::time::timeout(Duration::from_secs(5), accepted)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !old.is_finished(),
        "the old TLS handshake must still be pending"
    );
    assert!(client.channels.is_empty());
    client.install_tls_config(server.tls(3));
    release.send(()).unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), old)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.contains("changed while connecting"), "{error}");
    assert!(server.calls.lock().unwrap().is_empty());
    assert_eq!(
        client.fetch_async(&address, "/private").await.unwrap(),
        BODY
    );
    assert_eq!(*server.calls.lock().unwrap(), vec![Some(3)]);
    drop(client);
    drop(proxy);
    server.shutdown().await;
}
