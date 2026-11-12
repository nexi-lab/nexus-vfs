//! Black-box E2E: Node certificates renew in place, without a restart.
//!
//! A founder and a joiner that auto-enrolled with a join token (its key was
//! generated on the joiner and certified through a CSR) federate `sharedzone`
//! over mTLS. Then, each step consuming the last:
//!
//! 1. MEMBER — `renew-certificate` on the joiner: its daemon generates a new
//!    key, the founder certifies it for the joiner's own Node, and the joiner
//!    serves it to new handshakes at once. The old key is gone from disk, and
//!    replication keeps flowing both ways with no restart.
//! 2. FOUNDER — `renew-certificate` on the founder renews it through its own
//!    daemon over loopback, the same path, and replication still flows.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{await_replicated, cli, free_port, free_port_pair, Daemon, Vfs, LOG_FILTER};
use nexus_raft::transport::{local_node_identity, TlsConfig};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(120);

fn node_tls(data: &str) -> TlsConfig {
    let tls = std::path::Path::new(data).join("tls");
    let read = |name: &str| std::fs::read(tls.join(name)).unwrap();
    TlsConfig {
        cert_pem: read("node.pem"),
        key_pem: read("node-key.pem"),
        ca_pem: read("ca.pem"),
    }
}

fn node_id(data: &str) -> u64 {
    let bytes = std::fs::read(std::path::Path::new(data).join(".node_id")).unwrap();
    u64::from_be_bytes(bytes.as_slice().try_into().unwrap())
}

fn leaf_der(cert_pem: &[u8]) -> Vec<u8> {
    ::pem::parse(cert_pem).unwrap().into_contents()
}

/// Whether the bundle's key is the private key of its certificate.
fn belongs_together(tls: &TlsConfig) -> bool {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let der = leaf_der(&tls.cert_pem);
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    let key = rcgen::KeyPair::from_pem(std::str::from_utf8(&tls.key_pem).unwrap()).unwrap();
    rcgen::PublicKeyData::subject_public_key_info(&key) == cert.public_key().raw
}

/// The certificate the daemon on `port` presents to a NEW handshake.
async fn served_leaf(port: u16, client: &TlsConfig) -> Vec<u8> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    lib::transport_primitives::ensure_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(leaf_der(&client.ca_pem)))
        .unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![CertificateDer::from(leaf_der(&client.cert_pem))],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                ::pem::parse(&client.key_pem).unwrap().into_contents(),
            )),
        )
        .unwrap();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from(TlsConfig::CLUSTER_SERVER_NAME).unwrap(),
            tcp,
        )
        .await
        .unwrap();
    stream.get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

/// Renew `data`'s Node through its running daemon and check what changed on
/// disk: a new key and certificate for the same Node, the old key nowhere in
/// the TLS directory, nothing staged left behind.
fn renew(env: &[(&str, &str)], data: &str) -> TlsConfig {
    let before = node_tls(data);
    let (ok, out, err) = cli(env, &["renew-certificate"]);
    assert!(ok, "renew-certificate failed: {err}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let not_after: i64 = out.trim().parse().expect("notAfter on stdout");
    assert!(
        not_after > now + 80 * 86_400,
        "a fresh 90-day leaf: {not_after}"
    );
    let after = node_tls(data);
    assert!(belongs_together(&after));
    assert_ne!(after.cert_pem, before.cert_pem);
    assert_ne!(after.key_pem, before.key_pem);
    assert_eq!(after.ca_pem, before.ca_pem);
    assert_eq!(
        local_node_identity(&after.cert_pem, &after.ca_pem)
            .unwrap()
            .node_id,
        node_id(data),
        "renewal keeps the Node identity"
    );
    let tls_dir = std::path::Path::new(data).join("tls");
    for entry in std::fs::read_dir(&tls_dir).unwrap() {
        let path = entry.unwrap().path();
        assert!(
            !path.to_string_lossy().ends_with(".next"),
            "nothing stays staged: {}",
            path.display()
        );
        assert_ne!(
            std::fs::read(&path).unwrap(),
            before.key_pem,
            "the replaced key is gone from disk ({})",
            path.display()
        );
    }
    after
}

/// `writer` writes `path`; `reader` sees it replicate in with the same bytes.
async fn replicates(writer: &mut Vfs, reader: &mut Vfs, path: &str) {
    writer
        .write_file(path, path.as_bytes(), "")
        .await
        .unwrap_or_else(|e| panic!("write {path}: {e}"));
    await_replicated(reader, path, "", BUDGET).await;
    assert_eq!(reader.read_file(path, "").await.unwrap(), path.as_bytes());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_certificates_renew_in_place_on_members_and_the_founder() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = |name: &str| tmp.path().join(name).to_string_lossy().into_owned();
    let (fdata, fid, jdata, jid) = (path("f-data"), path("f-id"), path("j-data"), path("j-id"));
    let fport = free_port_pair();
    let jport = loop {
        let port = free_port();
        if port != fport && port != fport + 1 {
            break port;
        }
    };
    let (fadv, jadv) = (format!("127.0.0.1:{fport}"), format!("127.0.0.1:{jport}"));
    let mounts = format!("{MOUNT}={ZONE}");
    let founder_env = vec![
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", fadv.as_str()),
        ("NEXUS_ACCEPT_ENROLLMENTS", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let (ok, token, err) = cli(&founder_env, &["enroll-token"]);
    assert!(ok, "enroll-token failed: {err}");
    let mut founder = Daemon::spawn(&["--bind-addr", &fadv], &founder_env);
    founder
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("founder serves");

    let joiner_env = vec![
        ("NEXUS_DATA_DIR", jdata.as_str()),
        ("NEXUS_IDENTITY_DIR", jid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", jadv.as_str()),
        ("NEXUS_PEERS", fadv.as_str()),
        ("NEXUS_JOIN_TOKEN", token.trim()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut joiner = Daemon::spawn(&["--bind-addr", &jadv], &joiner_env);
    joiner
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("auto-enrolled joiner serves");
    // Enrollment certified the key the joiner generated and kept.
    let enrolled = node_tls(&jdata);
    assert!(belongs_together(&enrolled));

    let connect = |port: u16, tls: TlsConfig| async move {
        Vfs::connect_mtls(port, &tls.ca_pem, &tls.cert_pem, &tls.key_pem, BUDGET).await
    };
    let mut on_founder = connect(fport, node_tls(&fdata)).await;
    let mut on_joiner = connect(jport, enrolled.clone()).await;
    replicates(
        &mut on_founder,
        &mut on_joiner,
        "/agents/before-renewal.txt",
    )
    .await;
    assert_eq!(
        served_leaf(jport, &enrolled).await,
        leaf_der(&enrolled.cert_pem)
    );

    // ── 1. MEMBER: renewed through the founder, served without a restart ──
    let renewed = renew(&joiner_env, &jdata);
    assert_eq!(
        served_leaf(jport, &node_tls(&fdata)).await,
        leaf_der(&renewed.cert_pem),
        "a new handshake gets the renewed certificate"
    );
    assert!(joiner.log_contains("renewed Node identity installed"));
    replicates(
        &mut on_joiner,
        &mut on_founder,
        "/agents/member-renewed.txt",
    )
    .await;
    replicates(
        &mut on_founder,
        &mut on_joiner,
        "/agents/founder-after-member.txt",
    )
    .await;
    let mut renewed_client = connect(fport, renewed.clone()).await;
    assert_eq!(
        renewed_client
            .read_file("/agents/member-renewed.txt", "")
            .await
            .unwrap(),
        b"/agents/member-renewed.txt",
        "the founder admits the renewed leaf"
    );

    // ── 2. FOUNDER: renews itself through its own daemon over loopback ────
    let founder_before = node_tls(&fdata);
    let founder_renewed = renew(&founder_env, &fdata);
    assert_eq!(
        served_leaf(fport, &renewed).await,
        leaf_der(&founder_renewed.cert_pem)
    );
    assert_ne!(founder_renewed.cert_pem, founder_before.cert_pem);
    replicates(
        &mut on_founder,
        &mut on_joiner,
        "/agents/founder-renewed.txt",
    )
    .await;
    replicates(
        &mut on_joiner,
        &mut on_founder,
        "/agents/member-after-founder.txt",
    )
    .await;
    assert!(!founder.drain().contains("panicked"));
    assert!(!joiner.drain().contains("panicked"));
}
