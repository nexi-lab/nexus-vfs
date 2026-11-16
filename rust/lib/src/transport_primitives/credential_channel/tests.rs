use super::*;
use crate::transport_primitives::TlsPolicy;
use std::future::poll_fn;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct TestBody {
    frames: std::collections::VecDeque<Frame<Bytes>>,
    retire_on_poll: Option<SharedTlsConfig>,
    polls: Arc<AtomicUsize>,
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if let Some(source) = self.retire_on_poll.take() {
            source.replace(TlsPolicy::Plaintext);
        }
        Poll::Ready(self.frames.pop_front().map(Ok))
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn guarded_body(source: &SharedTlsConfig, retire_on_poll: bool) -> (TonicBody, Arc<AtomicUsize>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
    let inner = TestBody {
        frames: [
            Frame::data(Bytes::from_static(b"original reply")),
            Frame::trailers(trailers),
        ]
        .into(),
        retire_on_poll: retire_on_poll.then(|| source.clone()),
        polls: Arc::clone(&polls),
    };
    let guard = CredentialGuard {
        source: source.clone(),
        snapshot: source.snapshot(),
    };
    (guard.body(TonicBody::new(inner)), polls)
}

async fn frame(body: &mut TonicBody) -> Option<Result<Frame<Bytes>, tonic::Status>> {
    poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await
}

#[test]
fn current_body_preserves_payload_trailers_and_completion() {
    runtime().block_on(async {
        let source = SharedTlsConfig::default();
        let (mut body, polls) = guarded_body(&source, false);
        assert_eq!(
            frame(&mut body)
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            b"original reply"[..]
        );
        assert_eq!(
            frame(&mut body)
                .await
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap()["grpc-status"],
            "0"
        );
        assert!(frame(&mut body).await.is_none());
        assert!(body.is_end_stream());
        assert_eq!(polls.load(Ordering::SeqCst), 3);
    });
}

#[test]
fn replaced_body_refuses_before_reading_another_frame() {
    runtime().block_on(async {
        let source = SharedTlsConfig::default();
        let (mut body, polls) = guarded_body(&source, false);
        assert!(frame(&mut body).await.unwrap().unwrap().is_data());
        source.replace(TlsPolicy::Plaintext);
        assert_eq!(
            frame(&mut body).await.unwrap().unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert!(frame(&mut body).await.is_none());
    });
}

#[test]
fn replacement_during_inner_poll_refuses_the_produced_frame() {
    runtime().block_on(async {
        let source = SharedTlsConfig::default();
        let (mut body, polls) = guarded_body(&source, true);
        assert_eq!(
            frame(&mut body).await.unwrap().unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn rejected_empty_body_keeps_its_final_credential_check() {
    runtime().block_on(async {
        let source = SharedTlsConfig::default();
        let guard = CredentialGuard {
            source: source.clone(),
            snapshot: source.snapshot(),
        };
        let mut body = guard.body(TonicBody::empty());
        assert!(!body.is_end_stream());
        source.replace(TlsPolicy::Rejected("withdrawn"));
        assert_eq!(
            frame(&mut body).await.unwrap().unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    });
}

#[test]
fn retained_channel_refuses_identical_reinstallation_before_submission() {
    runtime().block_on(async {
        let source = SharedTlsConfig::default();
        let raw = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let mut channel = CredentialChannel::new(raw, source.clone(), source.snapshot());
        source.replace(TlsPolicy::Plaintext);
        let error = poll_fn(|cx| channel.poll_ready(cx)).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<tonic::Status>().unwrap().code(),
            tonic::Code::Unauthenticated
        );
        let error = channel
            .call(http::Request::new(TonicBody::empty()))
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<tonic::Status>().unwrap().code(),
            tonic::Code::Unauthenticated
        );
    });
}

#[derive(Clone)]
struct WireService {
    calls: Arc<AtomicUsize>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    expected_client: Option<Vec<u8>>,
}

impl tonic::server::NamedService for WireService {
    const NAME: &'static str = "guard.Test";
}

impl Service<http::Request<TonicBody>> for WireService {
    type Response = http::Response<TonicBody>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<TonicBody>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            if let Some(expected) = &service.expected_client {
                let info = request
                    .extensions()
                    .get::<tonic::transport::server::TlsConnectInfo<
                        tonic::transport::server::TcpConnectInfo,
                    >>()
                    .expect("the request must arrive through actual mutual TLS");
                let peers = info.peer_certs().expect("client certificate is required");
                assert_eq!(peers[0].as_ref(), expected);
            }
            service.calls.fetch_add(1, Ordering::SeqCst);
            if request.uri().path() == "/guard.Test/Hold" {
                service.entered.notify_one();
                service.release.notified().await;
            }
            let body = TestBody {
                frames: [Frame::data(Bytes::from_static(b"actual wire response"))].into(),
                retire_on_poll: None,
                polls: Arc::new(AtomicUsize::new(0)),
            };
            Ok(http::Response::builder()
                .status(200)
                .body(TonicBody::new(body))
                .unwrap())
        })
    }
}

fn request(path: &str) -> http::Request<TonicBody> {
    http::Request::builder()
        .uri(path)
        .body(TonicBody::empty())
        .unwrap()
}

async fn submit(
    channel: &mut CredentialChannel,
    path: &str,
) -> Result<http::Response<TonicBody>, StdError> {
    poll_fn(|cx| channel.poll_ready(cx)).await?;
    channel.call(request(path)).await
}

#[test]
fn actual_pending_wire_response_refuses_replacement_and_fresh_calls_work() {
    pending_wire_response(None);
}

#[test]
fn actual_mutual_tls_response_and_retained_client_follow_the_installation() {
    use crate::transport_primitives::TlsConfig;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    crate::transport_primitives::ensure_crypto_provider();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    let ca = params.self_signed(&key).unwrap();
    let issuer = Issuer::new(params, key);
    let leaf = || {
        let mut params =
            CertificateParams::new(vec![TlsConfig::CLUSTER_SERVER_NAME.into()]).unwrap();
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().unwrap();
        TlsConfig {
            ca_pem: ca.pem().into_bytes(),
            cert_pem: params.signed_by(&key, &issuer).unwrap().pem().into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
        }
    };
    pending_wire_response(Some((leaf(), leaf())));
}

fn pending_wire_response(
    tls: Option<(
        crate::transport_primitives::TlsConfig,
        crate::transport_primitives::TlsConfig,
    )>,
) {
    runtime().block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let scheme = if tls.is_some() { "https" } else { "http" };
            let endpoint = format!("{scheme}://{}", listener.local_addr().unwrap());
            let service = WireService {
                calls: Arc::new(AtomicUsize::new(0)),
                entered: Arc::new(tokio::sync::Notify::new()),
                release: Arc::new(tokio::sync::Notify::new()),
                expected_client: tls
                    .as_ref()
                    .map(|(_, client)| pem::parse(&client.cert_pem).unwrap().into_contents()),
            };
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            let acceptor = tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    if sender.send(Ok::<_, std::io::Error>(stream)).await.is_err() {
                        break;
                    }
                }
            });
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let mut builder = tonic::transport::Server::builder();
            let mut endpoint = tonic::transport::Endpoint::from_shared(endpoint).unwrap();
            if let Some((server, client)) = &tls {
                use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};
                builder = builder
                    .tls_config(
                        ServerTlsConfig::new()
                            .identity(Identity::from_pem(&server.cert_pem, &server.key_pem))
                            .client_ca_root(Certificate::from_pem(&server.ca_pem)),
                    )
                    .unwrap();
                endpoint = endpoint
                    .tls_config(
                        ClientTlsConfig::new()
                            .domain_name(
                                crate::transport_primitives::TlsConfig::CLUSTER_SERVER_NAME,
                            )
                            .ca_certificate(Certificate::from_pem(&client.ca_pem))
                            .identity(Identity::from_pem(&client.cert_pem, &client.key_pem)),
                    )
                    .unwrap();
            }
            let server = tokio::spawn(
                builder
                    .add_service(service.clone())
                    .serve_with_incoming_shutdown(
                        tokio_stream::wrappers::ReceiverStream::new(receiver),
                        async {
                            let _ = stopped.await;
                        },
                    ),
            );
            let raw = endpoint.connect().await.unwrap();
            let material = tls.as_ref().map(|(_, client)| client.clone());
            let source = SharedTlsConfig::new(material.clone());
            let mut first = CredentialChannel::new(raw.clone(), source.clone(), source.snapshot());
            let mut response = submit(&mut first, "/guard.Test/Now")
                .await
                .unwrap()
                .into_body();
            assert_eq!(
                frame(&mut response)
                    .await
                    .unwrap()
                    .unwrap()
                    .into_data()
                    .unwrap(),
                b"actual wire response"[..]
            );
            while let Some(result) = frame(&mut response).await {
                result.unwrap();
            }
            let retained = first.clone();
            let pending = tokio::spawn(async move { submit(&mut first, "/guard.Test/Hold").await });
            service.entered.notified().await;
            source.replace(material.map_or(TlsPolicy::Plaintext, TlsPolicy::Configured));
            service.release.notify_one();
            let error = pending.await.unwrap().unwrap_err();
            assert_eq!(
                error.downcast_ref::<tonic::Status>().unwrap().code(),
                tonic::Code::Unauthenticated
            );
            let mut retained = retained;
            assert!(submit(&mut retained, "/guard.Test/Now").await.is_err());
            assert_eq!(service.calls.load(Ordering::SeqCst), 2);
            let mut fresh = CredentialChannel::new(
                endpoint.connect().await.unwrap(),
                source.clone(),
                source.snapshot(),
            );
            let mut response = submit(&mut fresh, "/guard.Test/Now")
                .await
                .unwrap()
                .into_body();
            assert_eq!(
                frame(&mut response)
                    .await
                    .unwrap()
                    .unwrap()
                    .into_data()
                    .unwrap(),
                b"actual wire response"[..]
            );
            while let Some(result) = frame(&mut response).await {
                result.unwrap();
            }
            assert_eq!(service.calls.load(Ordering::SeqCst), 3);
            source.replace(TlsPolicy::Rejected("withdrawn"));
            assert!(submit(&mut fresh, "/guard.Test/Now").await.is_err());
            assert_eq!(service.calls.load(Ordering::SeqCst), 3);
            drop(fresh);
            drop(retained);
            drop(raw);
            stop.send(()).unwrap();
            server.await.unwrap().unwrap();
            acceptor.abort();
            assert!(acceptor.await.unwrap_err().is_cancelled());
        })
        .await
        .expect("original wire fixture must complete");
    });
}
