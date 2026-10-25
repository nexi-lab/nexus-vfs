#![cfg(feature = "experimental-managed-agent-csr")]

//! The full CLI, native issuer and real control store. No model, managed
//! allocation or live endpoint. The operation retains one key through replay.
mod common;

use common::{cli, free_port_pair, Daemon, LOG_FILTER};
use lib::transport_primitives::AgentCredential;
use serde_json::Value;
use std::time::Duration;

fn invoke(
    env: &[(&str, &str)],
    verb: &str,
    endpoint: &str,
    pending: &str,
    output: Option<&str>,
) -> Value {
    let mut args = vec![
        "auth",
        "csr",
        verb,
        "--endpoint",
        endpoint,
        "--agent",
        "operator-product-agent",
        "--owner",
        "native-owner",
        "--display-name",
        "原产品身份",
        "--operation",
        "original-operator-operation",
        "--pending-file",
        pending,
    ];
    if let Some(output) = output {
        args.extend(["--bundle-dir", output]);
    }
    let (ok, stdout, stderr) = cli(env, &args);
    assert!(ok, "CSR {verb} failed: {stderr}");
    serde_json::from_str(stdout.trim()).expect("one machine receipt, no credential material")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_cli_keeps_original_key_and_only_publishes_verified_stored_f() {
    let private = tempfile::tempdir().unwrap();
    let data = private.path().join("data");
    let identity = private.path().join("identity");
    let data_s = data.to_string_lossy().into_owned();
    let identity_s = identity.to_string_lossy().into_owned();
    let port = free_port_pair();
    let address = format!("127.0.0.1:{port}");
    let endpoint = format!("https://{address}");
    let env = [
        ("NEXUS_DATA_DIR", data_s.as_str()),
        ("NEXUS_IDENTITY_DIR", identity_s.as_str()),
        ("NEXUS_ADVERTISE_ADDR", address.as_str()),
        ("NEXUS_CLUSTER_INIT", "operator-test"),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut daemon = Daemon::spawn(&["--bind-addr", &address], &env);
    daemon
        .wait_for_log("session-mint allow-list bound", Duration::from_secs(120))
        .await
        .expect("authoritative store must be bound before an issuance");
    let pending = private.path().join("pending.json");
    let pending_s = pending.to_string_lossy().into_owned();
    let bundle = private.path().join("bundle-v1");
    let bundle_s = bundle.to_string_lossy().into_owned();
    let prepared = invoke(&env, "prepare", &endpoint, &pending_s, None);
    assert_eq!(prepared["status"], "prepared");
    assert_eq!(prepared["issuanceSubmitted"], false);
    let original = std::fs::read(&pending).unwrap();
    assert!(!bundle.exists());
    let absent = invoke(&env, "query", &endpoint, &pending_s, None);
    assert_eq!(absent["nativeState"], "not_observed");
    assert_eq!(absent["issuanceSubmitted"], false);
    let final_reply = invoke(&env, "issue", &endpoint, &pending_s, None);
    assert_eq!(final_reply["nativeState"], "finalized");
    assert_eq!(final_reply["issuanceSubmitted"], true);
    assert_eq!(prepared["requestSha256"], final_reply["requestSha256"]);
    assert_eq!(final_reply["managedRuntimeActivated"], false);
    // Neither a read-only query nor replay of selected F may load a signing key.
    let ca_key = data.join("tls/ca-key.pem");
    let held = data.join("tls/held-ca-key.pem");
    std::fs::rename(&ca_key, &held).unwrap();
    let queried = invoke(&env, "query", &endpoint, &pending_s, None);
    let replay = invoke(&env, "issue", &endpoint, &pending_s, None);
    assert_eq!(
        queried["certificateSha256"],
        final_reply["certificateSha256"]
    );
    assert_eq!(
        replay["certificateSha256"],
        final_reply["certificateSha256"]
    );
    assert_eq!(replay["serial"], final_reply["serial"]);
    let published = invoke(&env, "publish", &endpoint, &pending_s, Some(&bundle_s));
    assert_eq!(published["status"], "published");
    assert_eq!(published["issuanceSubmitted"], false);
    let credential = AgentCredential::load(&bundle).unwrap();
    assert_eq!(credential.agent, "operator-product-agent");
    assert!(!credential.key_pem.is_empty());
    assert!(
        std::fs::read(&pending).unwrap() == original,
        "original key/request changed"
    );
    let second = invoke(&env, "publish", &endpoint, &pending_s, Some(&bundle_s));
    assert_eq!(
        second["credentialManifest"],
        published["credentialManifest"]
    );
    assert!(
        std::fs::read(&pending).unwrap() == original,
        "replay changed pending key/request"
    );
    std::fs::rename(held, ca_key).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_native_issuer_never_creates_a_pending_key_or_falls_back_offline() {
    use lib::transport_primitives::write_secret;
    use nexus_raft::raft::ZoneRaftRegistry;
    use nexus_raft::transport::{
        generate_node_cert, generate_zone_ca, RaftGrpcServer, ServerConfig, TlsConfig,
    };
    use std::sync::Arc;
    let private = tempfile::tempdir().unwrap();
    let data = private.path().join("data");
    let tls = data.join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    let (ca, ca_key) = generate_zone_ca("unarmed-operator").unwrap();
    let (server_cert, server_key) = generate_node_cert(1, "root", &ca, &ca_key, &[], None).unwrap();
    let (caller_cert, caller_key) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    for (name, bytes) in [
        ("ca.pem", &ca),
        ("node.pem", &caller_cert),
        ("node-key.pem", &caller_key),
    ] {
        write_secret(&tls.join(name), bytes).unwrap();
    }
    let address = format!("127.0.0.1:{}", free_port_pair());
    let server = RaftGrpcServer::new(
        Arc::new(ZoneRaftRegistry::new(private.path().join("raft"), 1)),
        ServerConfig {
            bind_address: address.parse().unwrap(),
            tls: Some(TlsConfig {
                ca_pem: ca,
                cert_pem: server_cert,
                key_pem: server_key,
            }),
            ..Default::default()
        },
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        server
            .serve_with_shutdown(async {
                stopped.await.expect("test shutdown signal");
            })
            .await
            .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while tokio::net::TcpStream::connect(&address).await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let pending = private.path().join("must-not-exist.json");
    let data_s = data.to_string_lossy().into_owned();
    let pending_s = pending.to_string_lossy().into_owned();
    let identity_s = private
        .path()
        .join("identity")
        .to_string_lossy()
        .into_owned();
    let endpoint = format!("https://{address}");
    let env = [
        ("NEXUS_DATA_DIR", data_s.as_str()),
        ("NEXUS_IDENTITY_DIR", identity_s.as_str()),
    ];
    let (ok, stdout, stderr) = cli(
        &env,
        &[
            "auth",
            "csr",
            "prepare",
            "--endpoint",
            &endpoint,
            "--agent",
            "operator-agent",
            "--owner",
            "owner",
            "--operation",
            "original-unsupported",
            "--pending-file",
            &pending_s,
        ],
    );
    assert!(!ok, "unsupported issuer must refuse: {stderr}");
    let receipt: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(receipt["status"], "not_submitted");
    assert_eq!(receipt["issuanceSubmitted"], false);
    assert!(!pending.exists());
    assert!(
        !tls.join("ca-key.pem").exists(),
        "operator command bootstrapped a local issuer"
    );
    stop.send(()).expect("unarmed server is still running");
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap();
}
