use super::*;
use crate::test_peer::{Fixture, PausedDial};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cached_membership_connection_uses_the_replacement_identity() {
    let server = Fixture::start(true).await;
    let client = FederationClient::new(tokio::runtime::Handle::current(), Some(server.tls(2)));
    client
        .request_join_zone(&server.address, "agent-alice", 2, "local:2", true, 0)
        .await
        .unwrap();
    assert_eq!(*server.calls.lock().unwrap(), vec![Some(2)]);
    assert!(!client.channels.is_empty());

    let mut invalid = server.tls(3);
    invalid.ca_pem = nexus_raft::transport::generate_zone_ca("root").unwrap().0;
    client.install_tls(invalid);
    let refused = client
        .request_join_zone(&server.address, "agent-alice", 3, "local:3", true, 0)
        .await;
    assert!(
        refused.is_err(),
        "the cached identity cannot survive replacement"
    );
    assert!(client.channels.is_empty());
    assert_eq!(*server.calls.lock().unwrap(), vec![Some(2)]);

    client.install_tls(server.tls(3));
    client
        .request_join_zone(&server.address, "agent-alice", 3, "local:3", true, 0)
        .await
        .unwrap();
    assert_eq!(*server.calls.lock().unwrap(), vec![Some(2), Some(3)]);
    drop(client);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_membership_connection_cannot_republish_the_previous_identity() {
    let server = Fixture::start(true).await;
    let mut proxy = PausedDial::start(&server.address).await;
    let client = Arc::new(FederationClient::new(
        tokio::runtime::Handle::current(),
        Some(server.tls(2)),
    ));
    let old_client = Arc::clone(&client);
    let old_address = proxy.address.clone();
    let old = tokio::spawn(async move {
        old_client
            .request_join_zone(&old_address, "agent-alice", 2, "local:2", true, 0)
            .await
    });
    proxy.wait_for_connection().await;
    assert!(!old.is_finished(), "the actual previous TLS dial is paused");
    assert!(client.channels.is_empty());
    client.install_tls(server.tls(3));
    proxy.release();
    let error = tokio::time::timeout(Duration::from_secs(5), old)
        .await
        .unwrap()
        .unwrap()
        .expect_err("the previous dial must not send a membership mutation");
    assert!(error.contains("changed while connecting"), "{error}");
    assert!(server.calls.lock().unwrap().is_empty());
    assert!(client.channels.is_empty());

    client
        .request_join_zone(&proxy.address, "agent-alice", 3, "local:3", true, 0)
        .await
        .unwrap();
    assert_eq!(*server.calls.lock().unwrap(), vec![Some(3)]);
    drop(client);
    drop(proxy);
    server.shutdown().await;
}
