//! Exercise the production peer client against a bound tonic/mTLS endpoint.
use super::*;
use crate::test_peer::{Fixture, PausedDial, BODY};
use nexus_raft::transport::{generate_node_cert, generate_zone_ca};

mod kernel_reads;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn channel_connection_bounds_a_peer_that_accepts_without_handshaking() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let (ca_pem, ca_key) = generate_zone_ca("root").unwrap();
    let (cert_pem, key_pem) = generate_node_cert(2, "root", &ca_pem, &ca_key, &[], None).unwrap();
    let connection = tokio::spawn(async move {
        lib::transport_primitives::create_channel(
            &endpoint,
            &lib::transport_primitives::ClientConfig {
                connect_timeout: Duration::from_millis(250),
                tls: Some(lib::transport_primitives::TlsConfig {
                    ca_pem,
                    cert_pem,
                    key_pem,
                }),
                ..Default::default()
            },
        )
        .await
    });
    // Retain the actual socket: the peer neither closes it nor completes TLS.
    let (_socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), connection)
        .await
        .expect("channel establishment exceeded its configured timeout")
        .unwrap();
    assert!(
        result.is_err(),
        "a silent peer completed channel establishment"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_tls_rejects_other_uri_schemes_before_an_rpc() {
    let fixture = Fixture::start(false).await;
    let config = lib::transport_primitives::ClientConfig {
        tls: Some(fixture.tls(2)),
        ..Default::default()
    };
    for scheme in ["ws", "h2c", "nexus"] {
        let result = lib::transport_primitives::create_channel(
            &format!("{scheme}://{}", fixture.address),
            &config,
        )
        .await;
        assert!(
            matches!(
                result,
                Err(lib::transport_primitives::TransportError::InvalidAddress(_))
            ),
            "{scheme}: {result:?}"
        );
    }
    assert!(fixture.calls.lock().unwrap().is_empty());
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_content_never_falls_back_to_the_legacy_unscoped_rpc() {
    let fixture = Fixture::start(true).await;
    let client = PeerBlobClient::new(tokio::runtime::Handle::current());
    client.install_tls_config(fixture.tls(2));
    let error = client
        .fetch_in_zone_async(&fixture.address, "agent-alice", "private")
        .await
        .unwrap_err();
    assert!(
        error.contains(&tonic::Code::Unimplemented.to_string()),
        "{error}"
    );
    assert!(fixture.calls.lock().unwrap().is_empty());
    for zone in ["", "root", "__control__", "../agent-alice"] {
        assert!(client
            .fetch_in_zone_async(&fixture.address, zone, "private")
            .await
            .is_err());
    }
    assert!(fixture.calls.lock().unwrap().is_empty());
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_content_fetch_preserves_tls_and_scope() {
    let fixture = Fixture::start(true).await;
    let client = PeerBlobClient::new(tokio::runtime::Handle::current());
    client.install_tls_config(fixture.tls(2));
    assert_eq!(
        client
            .fetch(&format!("http://{}", fixture.address), "private")
            .unwrap(),
        BODY
    );
    let error = client
        .fetch_in_zone(&fixture.address, "agent-alice", "private")
        .unwrap_err();
    assert!(
        error.contains(&tonic::Code::Unimplemented.to_string()),
        "{error}"
    );
    for zone in ["", "root", "__control__", "../agent-alice"] {
        let error = client
            .fetch_in_zone(&fixture.address, zone, "private")
            .unwrap_err();
        assert!(!error.contains("ReadZoneBlob"), "{zone}: {error}");
    }
    assert_eq!(*fixture.calls.lock().unwrap(), vec![Some(2)]);
    drop(client);
    fixture.shutdown().await;
}

#[test]
fn blocking_content_fetch_uses_the_kernel_runtime_from_sync_and_current_thread_callers() {
    let kernel = build_kernel_runtime();
    let fixture = kernel.block_on(Fixture::start(true));
    let client = PeerBlobClient::new(kernel.handle().clone());
    client.install_tls_config(fixture.tls(2));
    assert_eq!(client.fetch(&fixture.address, "private").unwrap(), BODY);

    let agent = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    agent.block_on(async {
        assert_eq!(client.fetch(&fixture.address, "private").unwrap(), BODY);
        let error = client
            .fetch_in_zone(&fixture.address, "agent-alice", "private")
            .unwrap_err();
        assert!(
            error.contains(&tonic::Code::Unimplemented.to_string()),
            "{error}"
        );
    });
    assert_eq!(*fixture.calls.lock().unwrap(), vec![Some(2), Some(2)]);
    drop(client);
    kernel.block_on(fixture.shutdown());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_configuration_encrypts_even_when_the_routing_uri_says_http() {
    let server = Fixture::start(true).await;
    let client = PeerBlobClient::new(tokio::runtime::Handle::current());
    client.install_tls_config(server.tls(2));
    let bytes = client
        .fetch_async(&format!("http://{}", server.address), "/private")
        .await
        .expect("configured routing URI must complete an authenticated TLS read");
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
    assert!(
        client
            .fetch_async(&format!("http://{}", server.address), "/private")
            .await
            .is_err(),
        "TLS configuration must not admit a plaintext response"
    );
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
            .expect_err("incomplete credentials must reject an existing plaintext channel");
        assert!(error.contains("requires both"), "{error}");
        assert!(client.channels.is_empty());
        assert_eq!(*server.calls.lock().unwrap(), vec![None]);
    }
    drop(client);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_old_dial_cannot_publish_its_channel_after_tls_rotation() {
    let server = Fixture::start(true).await;
    let mut proxy = PausedDial::start(&server.address).await;
    let client = Arc::new(PeerBlobClient::new(tokio::runtime::Handle::current()));
    client.install_tls_config(server.tls(2));
    let old_client = Arc::clone(&client);
    let old_address = proxy.address.clone();
    let old = tokio::spawn(async move { old_client.fetch_async(&old_address, "/private").await });
    proxy.wait_for_connection().await;
    assert!(
        !old.is_finished(),
        "the old TLS handshake must still be pending"
    );
    assert!(client.channels.is_empty());
    client.install_tls_config(server.tls(3));
    proxy.release();
    let error = tokio::time::timeout(Duration::from_secs(5), old)
        .await
        .unwrap()
        .unwrap()
        .expect_err("credential rotation must reject the previous in-flight dial");
    assert!(error.contains("changed while connecting"), "{error}");
    assert!(server.calls.lock().unwrap().is_empty());
    assert_eq!(
        client
            .fetch_async(&proxy.address, "/private")
            .await
            .unwrap(),
        BODY
    );
    assert_eq!(*server.calls.lock().unwrap(), vec![Some(3)]);
    drop(client);
    drop(proxy);
    server.shutdown().await;
}
