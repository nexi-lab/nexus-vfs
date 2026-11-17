use nexus_raft::transport::{
    add_revoked_serial, add_revoked_serial_with_expiry, call_get_crl, crl_revoked_serials,
    generate_agent_cert, generate_zone_ca, prune_expired_serials, serial_from_cert_pem,
    serve_node_enrollment,
};

async fn start_issuer(
    directory: &std::path::Path,
    ca: &[u8],
    ca_key: &[u8],
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<nexus_raft::transport::Result<()>>,
) {
    let address = super::common::node_bind_socket_addr();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_node_enrollment(
        address,
        ca.to_vec(),
        ca_key.to_vec(),
        directory.join("join-token-hashes"),
        None,
        Some(directory.join("revoked-serials")),
        async {
            let _ = stopped.await;
        },
    ));
    super::listener_ready(&address.to_string()).await;
    (address, stop, server)
}

#[tokio::test]
async fn current_crl_rpc_refuses_corruption_and_retains_the_original_revocation() {
    lib::transport_primitives::ensure_crypto_provider();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("revoked-serials");
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert, _) = generate_agent_cert("revoked-principal", &ca, &ca_key).unwrap();
    let serial = serial_from_cert_pem(&cert).unwrap();
    add_revoked_serial(&path, &serial).unwrap();
    let original = std::fs::read(&path).unwrap();
    let (address, stop, server) = start_issuer(directory.path(), &ca, &ca_key).await;
    let crl = call_get_crl(&address.to_string(), 5).await.unwrap();
    assert_eq!(
        crl_revoked_serials(&crl, &ca).unwrap(),
        vec![serial.clone()]
    );

    let mut corrupt = original.clone();
    corrupt.extend_from_slice(b"!!!malformed!!!\n");
    std::fs::write(&path, &corrupt).unwrap();
    let error = call_get_crl(&address.to_string(), 5).await.unwrap_err();
    assert!(
        error.to_string().contains("read current revocations"),
        "{error}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    assert!(add_revoked_serial(&path, b"another").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);

    std::fs::write(&path, original).unwrap();
    let crl = call_get_crl(&address.to_string(), 5).await.unwrap();
    assert_eq!(crl_revoked_serials(&crl, &ca).unwrap(), vec![serial]);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn crl_rpc_keeps_its_sequence_after_pruning_and_listener_restart() {
    use lib::transport_primitives::verify_signed_crl;
    lib::transport_primitives::ensure_crypto_provider();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("revoked-serials");
    let (ca, key) = generate_zone_ca("root").unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    add_revoked_serial_with_expiry(&path, b"expired", Some(now - 7200)).unwrap();
    add_revoked_serial(&path, b"retained").unwrap();
    let (address, stop, server) = start_issuer(directory.path(), &ca, &key).await;
    let first = call_get_crl(&address.to_string(), 5).await.unwrap();
    let first_number = verify_signed_crl(&first, &ca).unwrap().number().to_vec();
    assert!(
        first_number.len() > 8,
        "the first durable number exceeds every old u64 count"
    );
    assert_eq!(prune_expired_serials(&path, now, 3600).unwrap(), 1);
    let pruned = call_get_crl(&address.to_string(), 5).await.unwrap();
    let pruned = verify_signed_crl(&pruned, &ca).unwrap();
    assert!(
        pruned.number() > first_number.as_slice(),
        "pruning advances the served CRL"
    );
    assert_eq!(pruned.revoked_serials(), &[b"retained".to_vec()]);
    add_revoked_serial(&path, b"replacement").unwrap();
    let replacement = call_get_crl(&address.to_string(), 5).await.unwrap();
    let replacement = verify_signed_crl(&replacement, &ca).unwrap();
    assert!(replacement.number() > pruned.number());
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();

    let (address, stop, server) = start_issuer(directory.path(), &ca, &key).await;
    let restored = call_get_crl(&address.to_string(), 5).await.unwrap();
    let restored = verify_signed_crl(&restored, &ca).unwrap();
    assert!(
        restored.number() >= replacement.number(),
        "restart keeps durable issuance order"
    );
    assert_eq!(restored.revoked_serials(), replacement.revoked_serials());
    add_revoked_serial(&path, b"after-restart").unwrap();
    let next = call_get_crl(&address.to_string(), 5).await.unwrap();
    let next = verify_signed_crl(&next, &ca).unwrap();
    assert!(next.number() > restored.number());
    assert!(next.is_revoked(b"after-restart"));
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
