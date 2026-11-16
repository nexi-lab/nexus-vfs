use nexus_raft::transport::{
    append_join_token_hash, call_join_cluster, generate_join_token, generate_node_key_request,
    generate_zone_ca, local_node_identity, serve_node_enrollment,
};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Token enrollment certifies the joiner's OWN key: the request carries a CSR,
/// the response only the certificate and CA, and the certificate's key is the
/// one the joiner generated. A request without a proven key is refused.
#[tokio::test]
async fn enrollment_certifies_the_joiners_own_key() {
    lib::transport_primitives::ensure_crypto_provider();
    let directory = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (token, hash) = generate_join_token(&ca).unwrap();
    let hashes = directory.path().join("join-token-hash");
    append_join_token_hash(&hashes, &hash).unwrap();
    let password = token
        .strip_prefix("K10")
        .and_then(|body| body.split_once("::server:"))
        .map(|(password, _)| password.to_string())
        .unwrap();
    let address = super::common::node_bind_socket_addr();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_node_enrollment(
        address,
        ca.clone(),
        ca_key,
        hashes,
        None,
        None,
        async {
            let _ = stopped.await;
        },
    ));
    let endpoint = format!("http://{address}");
    super::listener_ready(&address.to_string()).await;

    let (csr, key) = generate_node_key_request().unwrap();
    let joined = call_join_cluster(&endpoint, 9, "", "root", &password, &csr, 5)
        .await
        .unwrap();
    assert_eq!(joined.ca_pem, ca);
    assert_eq!(
        local_node_identity(&joined.node_cert_pem, &ca)
            .unwrap()
            .node_id,
        9
    );
    let leaf = ::pem::parse(&joined.node_cert_pem).unwrap();
    let (_, leaf) = X509Certificate::from_der(leaf.contents()).unwrap();
    let generated = rcgen::KeyPair::from_pem(std::str::from_utf8(&key).unwrap()).unwrap();
    assert_eq!(
        leaf.public_key().raw,
        rcgen::PublicKeyData::subject_public_key_info(&generated).as_slice(),
        "the issued certificate binds the key the joiner generated"
    );

    let refused = call_join_cluster(&endpoint, 9, "", "root", &password, b"", 5)
        .await
        .err()
        .expect("a request without a CSR must be refused");
    assert!(refused.to_string().contains("CSR"), "{refused}");
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
