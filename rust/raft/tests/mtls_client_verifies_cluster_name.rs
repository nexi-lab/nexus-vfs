//! The mTLS client verifies the server against the fixed **cluster server
//! name**, not the address it dialed.
//!
//! This is the isolation guard for the cross-machine handshake contract: a
//! node's identity is "signed by the cluster CA" + its `nexus://…` URI SAN;
//! the network address is pure routing. So `apply_tls` pins
//! `domain_name(TlsConfig::CLUSTER_SERVER_NAME)` and every node cert carries
//! that name as a SAN (`generate_node_cert`) — a client can then dial an
//! overlay IP that appears in **no** cert and still complete the handshake.
//!
//! The existing mTLS e2e (`test_mtls_federation`) cannot catch a regression
//! here: its certs carry both the cluster name AND `127.0.0.1`, and every
//! endpoint dials `127.0.0.1`, so the handshake passes whether the client
//! verifies the name or the IP. This test removes that ambiguity by giving the
//! server a cert that carries the cluster name but **not** the loopback address
//! it is reached at — so the handshake can succeed *only* through cluster-name
//! verification. If someone dropped the `domain_name` pin, the client would
//! fall back to verifying the dialed `127.0.0.1` (absent from the cert) and
//! this test would fail.
//!
//! The journey (each step feeds the next):
//!   1. Mint one cluster CA; sign a server cert whose only DNS SAN is the
//!      cluster name (no loopback IP) and a client cert that chains to the CA.
//!   2. Stand up a real `RaftGrpcServer` (mTLS on) at `127.0.0.1:PORT` with the
//!      cluster-name-only cert, then dial `https://127.0.0.1:PORT`. The
//!      handshake SUCCEEDS — verification used the cluster name, not the IP.
//!   3. Reuse the SAME client against a second server whose cert carries a
//!      DIFFERENT name (and still no IP): the handshake FAILS — proving the
//!      name check is a real gate, not accept-any-name.

#![cfg(all(feature = "grpc", has_protos))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lib::transport_primitives::{create_channel, ClientConfig, TlsConfig};
use nexus_raft::raft::ZoneRaftRegistry;
use nexus_raft::transport::{generate_node_cert, generate_zone_ca, RaftGrpcServer, ServerConfig};

/// Sign a leaf cert carrying EXACTLY `dns_sans` as its subject-alt-names — no
/// IP SANs, no localhost. Mirrors `certgen::generate_node_cert` (EC P-256,
/// serverAuth+clientAuth, chained to the cluster CA) but lets a test pin an
/// arbitrary name set, which `generate_node_cert` (always localhost /
/// 127.0.0.1 / ::1 + the URI SAN) cannot express.
fn sign_leaf_with_dns_sans(
    ca_pem: &[u8],
    ca_key_pem: &[u8],
    dns_sans: &[&str],
) -> (Vec<u8>, Vec<u8>) {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
    };

    let ca_key = KeyPair::from_pem(std::str::from_utf8(ca_key_pem).expect("CA key utf-8"))
        .expect("parse CA key");
    let issuer =
        Issuer::from_ca_cert_pem(std::str::from_utf8(ca_pem).expect("CA cert utf-8"), ca_key)
            .expect("parse CA cert");

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Nexus");
    dn.push(DnType::CommonName, "isolation-test-leaf");
    params.distinguished_name = dn;
    params.subject_alt_names = dns_sans
        .iter()
        .map(|name| SanType::DnsName((*name).try_into().expect("DNS SAN")))
        .collect();
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.is_ca = IsCa::NoCa;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(1);

    let cert = params.signed_by(&leaf_key, &issuer).expect("sign leaf");
    (
        cert.pem().into_bytes(),
        leaf_key.serialize_pem().into_bytes(),
    )
}

/// Reserve a loopback port, then start a real mTLS `RaftGrpcServer` bound to it
/// presenting `server_cert`/`server_key` (verifying clients against `ca_pem`).
/// Returns the `https://` endpoint, its bind address, and a shutdown handle —
/// hold the handle for the server's lifetime; dropping it stops the server. No
/// zones are created: the TLS handshake is all this test exercises.
async fn spawn_mtls_server(
    ca_pem: &[u8],
    server_cert: &[u8],
    server_key: &[u8],
) -> (String, SocketAddr, tokio::sync::oneshot::Sender<()>) {
    // Reserve a free loopback port, then drop the probe so RaftGrpcServer can
    // rebind it (the make_tls_node pattern in test_mtls_federation).
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let addr = probe.local_addr().expect("local_addr");
    drop(probe);

    let tmp = tempfile::TempDir::new().expect("tempdir");
    let registry = Arc::new(ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1));
    let config = ServerConfig {
        bind_address: addr,
        tls: Some(TlsConfig {
            cert_pem: server_cert.to_vec(),
            key_pem: server_key.to_vec(),
            ca_pem: ca_pem.to_vec(),
        }),
        ..Default::default()
    };
    let server = RaftGrpcServer::new(registry, config);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        // Hold the data dir open for the server's lifetime.
        let _tmp = tmp;
        let shutdown = async move {
            let _ = rx.await;
        };
        let _ = server.serve_with_shutdown(shutdown).await;
    });
    (format!("https://{addr}"), addr, tx)
}

/// Block until `addr` accepts a raw TCP connection, so a subsequent mTLS
/// failure is attributable to the handshake — not to connection-refused
/// because the listener had not come up yet.
async fn wait_until_accepting(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "server at {addr} never started accepting connections"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mtls_client_verifies_the_cluster_name_not_the_dialed_address() {
    lib::transport_primitives::ensure_crypto_provider();

    // 1. One cluster CA + a client cert that chains to it. The client cert's
    //    SANs are irrelevant — the server only checks it chains to the CA
    //    (`client_ca_root`) — so the real minting path is fine here.
    let (ca_pem, ca_key_pem) = generate_zone_ca("sharedzone").expect("cluster CA");
    let (client_cert, client_key) =
        generate_node_cert(2, "sharedzone", &ca_pem, &ca_key_pem, &[], Some("client"))
            .expect("client cert");

    let client_cfg = ClientConfig {
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(5),
        tls: Some(TlsConfig {
            cert_pem: client_cert,
            key_pem: client_key,
            ca_pem: ca_pem.clone(),
        }),
        ..Default::default()
    };

    // 2. Server cert carries the cluster name but NOT the loopback IP it is
    //    reached at → the dial to 127.0.0.1 can only verify via the name.
    let (ok_cert, ok_key) =
        sign_leaf_with_dns_sans(&ca_pem, &ca_key_pem, &[TlsConfig::CLUSTER_SERVER_NAME]);
    let (ok_url, ok_addr, _ok_shutdown) = spawn_mtls_server(&ca_pem, &ok_cert, &ok_key).await;
    wait_until_accepting(ok_addr).await;

    // The dialed address (127.0.0.1) is in NO cert — a completed handshake
    // proves the client verified `TlsConfig::CLUSTER_SERVER_NAME`, exactly the
    // cross-machine case (dial an overlay IP absent from the cert). Retry only
    // to absorb H2-readiness right after the listener binds.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_err = None;
    let mut connected = false;
    while Instant::now() < deadline {
        match create_channel(&ok_url, &client_cfg).await {
            Ok(_) => {
                connected = true;
                break;
            }
            Err(e) => {
                last_err = Some(format!("{e}"));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    assert!(
        connected,
        "mTLS handshake to a cluster-name-only cert must succeed via cluster-name \
         verification (the dialed IP is absent from the cert); last error: {last_err:?}"
    );

    // 3. Same client, a server whose cert carries a DIFFERENT name (still no
    //    IP): the handshake must FAIL — the name check is a real gate, not
    //    accept-any-name.
    let (bad_cert, bad_key) =
        sign_leaf_with_dns_sans(&ca_pem, &ca_key_pem, &["not-the-cluster-name"]);
    let (bad_url, bad_addr, _bad_shutdown) = spawn_mtls_server(&ca_pem, &bad_cert, &bad_key).await;
    wait_until_accepting(bad_addr).await;

    // The listener is up (raw TCP connected above), so an Err here is the
    // server-name mismatch, not connection-refused.
    let bad = create_channel(&bad_url, &client_cfg).await;
    assert!(
        bad.is_err(),
        "mTLS handshake to a cert whose name is neither the cluster name nor the \
         dialed IP must be refused; got a successful channel"
    );
}
