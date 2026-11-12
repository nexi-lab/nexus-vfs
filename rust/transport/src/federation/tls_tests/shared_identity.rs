use super::*;
use crate::peer_blob::PeerBlobClient;
use crate::test_peer::BODY;
use lib::transport_primitives::{create_node_channel, SharedTlsConfig, TlsPolicy};
use std::num::NonZeroU64;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_federation_and_content_share_one_replacement() {
    let server = Fixture::start_with_shared_tls().await;
    let source = server.shared_tls.as_ref().unwrap().clone();
    let federation =
        FederationClient::with_shared_tls(tokio::runtime::Handle::current(), source.clone());
    let blobs = PeerBlobClient::with_shared_tls(tokio::runtime::Handle::current(), source.clone());
    federation
        .request_join_zone(&server.address, "agent-alice", 1, "local:1", true, 0)
        .await
        .unwrap();
    assert_eq!(
        blobs.fetch_async(&server.address, "body").await.unwrap(),
        BODY
    );
    assert_eq!(*server.calls.lock().unwrap(), vec![Some(1), Some(1)]);

    let replacement = server.tls(3);
    source.replace(TlsPolicy::Configured(replacement.clone()));
    federation
        .request_join_zone(&server.address, "agent-alice", 3, "local:3", true, 0)
        .await
        .unwrap();
    assert_eq!(
        blobs.fetch_async(&server.address, "body").await.unwrap(),
        BODY
    );
    assert_eq!(
        *server.calls.lock().unwrap(),
        vec![Some(1), Some(1), Some(3), Some(3)]
    );

    let independent = lib::transport_primitives::ClientConfig {
        tls: Some(server.tls(2)),
        ..Default::default()
    };
    let endpoint = format!("http://{}", server.address);
    assert!(
        create_node_channel(&endpoint, &independent, NonZeroU64::new(1).unwrap())
            .await
            .is_err(),
        "listener still presents the original Node"
    );
    let current = create_node_channel(&endpoint, &independent, NonZeroU64::new(3).unwrap())
        .await
        .unwrap();
    drop(current);

    let mut changed_anchor = replacement.clone();
    changed_anchor.ca_pem = nexus_raft::transport::generate_zone_ca("root").unwrap().0;
    source.replace(TlsPolicy::Configured(changed_anchor));
    assert!(
        create_node_channel(&endpoint, &independent, NonZeroU64::new(3).unwrap())
            .await
            .is_err(),
        "credential rotation changed the listener trust anchor"
    );
    let mut mismatched_key = replacement.clone();
    mismatched_key.key_pem = server.tls(4).key_pem;
    source.replace(TlsPolicy::Configured(mismatched_key));
    assert!(
        create_node_channel(&endpoint, &independent, NonZeroU64::new(3).unwrap())
            .await
            .is_err(),
        "listener reused a cached configuration after a key mismatch"
    );
    source.replace(TlsPolicy::Configured(replacement));
    federation
        .request_join_zone(&server.address, "agent-alice", 3, "local:3", true, 0)
        .await
        .unwrap();

    source.replace(TlsPolicy::Rejected("replica removed"));
    let error = federation
        .request_join_zone(&server.address, "agent-alice", 3, "local:3", true, 0)
        .await
        .unwrap_err();
    assert!(error.contains("replica removed"), "{error}");
    assert!(blobs
        .fetch_async(&server.address, "body")
        .await
        .unwrap_err()
        .contains("replica removed"));
    assert!(
        create_node_channel(&endpoint, &independent, NonZeroU64::new(3).unwrap())
            .await
            .is_err(),
        "rejected listener admitted a new handshake"
    );
    assert_eq!(server.calls.lock().unwrap().len(), 5);
    drop((federation, blobs));
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_incoming_handshake_cannot_finish_under_a_replaced_identity() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = Fixture::start_with_shared_tls().await;
    let source = server.shared_tls.as_ref().unwrap().clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let backend = server.address.clone();
    let (observed, selected) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let proxy = tokio::spawn(async move {
        let (incoming, _) = listener.accept().await.unwrap();
        let outgoing = tokio::net::TcpStream::connect(backend).await.unwrap();
        let (mut client_read, mut client_write) = incoming.into_split();
        let (mut server_read, mut server_write) = outgoing.into_split();
        let forward = async {
            let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
            let _ = server_write.shutdown().await;
        };
        let response = async {
            let mut bytes = [0; 8192];
            let count = server_read.read(&mut bytes).await.unwrap();
            assert!(
                count > 0,
                "the original server selected its actual TLS identity"
            );
            observed.send(()).unwrap();
            released.await.unwrap();
            client_write.write_all(&bytes[..count]).await.unwrap();
            let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
            let _ = client_write.shutdown().await;
        };
        tokio::join!(forward, response);
    });
    let config = lib::transport_primitives::ClientConfig {
        tls: Some(server.tls(2)),
        ..Default::default()
    };
    let old = tokio::spawn(async move {
        let channel = create_node_channel(&endpoint, &config, NonZeroU64::new(1).unwrap())
            .await
            .map_err(|error| error.to_string())?;
        ZoneApiServiceClient::new(channel)
            .join_zone(JoinZoneRequest::default())
            .await
            .map_err(|error| error.to_string())
    });
    tokio::time::timeout(Duration::from_secs(5), selected)
        .await
        .unwrap()
        .unwrap();
    assert!(!old.is_finished());
    source.replace(TlsPolicy::Configured(server.tls(3)));
    release.send(()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), old)
            .await
            .unwrap()
            .unwrap()
            .is_err(),
        "old server identity admitted an RPC after replacement"
    );
    assert!(server.calls.lock().unwrap().is_empty());
    let client = FederationClient::new(tokio::runtime::Handle::current(), Some(server.tls(2)));
    client
        .request_join_zone(&server.address, "agent-alice", 2, "local:2", true, 0)
        .await
        .unwrap();
    assert_eq!(*server.calls.lock().unwrap(), vec![Some(2)]);
    proxy.abort();
    let _ = proxy.await;
    drop(client);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replacing_then_restoring_identical_bytes_refuses_the_original_dial() {
    let server = Fixture::start(true).await;
    let original = server.tls(2);
    let source = SharedTlsConfig::new(Some(original.clone()));
    let client = Arc::new(FederationClient::with_shared_tls(
        tokio::runtime::Handle::current(),
        source.clone(),
    ));
    let mut proxy = PausedDial::start(&server.address).await;
    let old_client = Arc::clone(&client);
    let address = proxy.address.clone();
    let old = tokio::spawn(async move {
        old_client
            .request_join_zone(&address, "agent-alice", 2, "local:2", true, 0)
            .await
    });
    proxy.wait_for_connection().await;
    source.replace(TlsPolicy::Rejected("rotation in progress"));
    source.replace(TlsPolicy::Configured(original));
    proxy.release();
    let error = tokio::time::timeout(Duration::from_secs(5), old)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.contains("changed while connecting"), "{error}");
    assert!(server.calls.lock().unwrap().is_empty());
    client
        .request_join_zone(&proxy.address, "agent-alice", 2, "local:2", true, 0)
        .await
        .unwrap();
    assert_eq!(*server.calls.lock().unwrap(), vec![Some(2)]);
    drop(client);
    drop(proxy);
    server.shutdown().await;
}
