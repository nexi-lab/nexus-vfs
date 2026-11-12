use nexus_raft::transport::{
    add_revoked_serial, call_get_crl, crl_revoked_serials, generate_agent_cert, generate_zone_ca,
    serial_from_cert_pem, serve_node_enrollment,
};

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
    let address = super::common::node_bind_socket_addr();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_node_enrollment(
        address,
        ca.clone(),
        ca_key,
        directory.path().join("join-token-hashes"),
        None,
        Some(path.clone()),
        async {
            let _ = stopped.await;
        },
    ));
    super::listener_ready(&address.to_string()).await;
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
