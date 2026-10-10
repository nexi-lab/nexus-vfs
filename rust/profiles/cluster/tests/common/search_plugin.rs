use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use nexus_search_plugin::search_proto::search_service_client::SearchServiceClient;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

pub fn signed_plugin(root: &Path) -> PathBuf {
    // Always ask Cargo: an existing cdylib may predate the source under test.
    let mut build = std::process::Command::new(env!("CARGO"));
    build.args(["build", "-p", "nexus-search-plugin"]);
    if !cfg!(debug_assertions) {
        build.arg("--release");
    }
    assert!(build.status().expect("build search plugin").success());
    let exe = std::env::current_exe().unwrap();
    let profile = exe.parent().unwrap().parent().unwrap();
    let name = format!(
        "{}nexus_search_plugin{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let plugins = root.join("plugins");
    let trust = root.join("trust");
    std::fs::create_dir_all(&plugins).unwrap();
    std::fs::create_dir_all(&trust).unwrap();
    let plugin = plugins.join(&name);
    std::fs::copy(profile.join(&name), &plugin).expect("copy built plugin");
    sign_plugin(&plugin, &trust);
    plugins
}

pub fn sign_plugin(plugin: &Path, trust: &Path) {
    let key = SigningKey::from_bytes(&[42; 32]);
    let signature = key.sign(&std::fs::read(plugin).unwrap());
    std::fs::write(format!("{}.sig", plugin.display()), signature.to_bytes()).unwrap();
    std::fs::write(
        trust.join("test.pub"),
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes()),
    )
    .unwrap();
}

pub async fn mtls_client(
    port: u16,
    ca: &[u8],
    cert: &[u8],
    key: &[u8],
) -> SearchServiceClient<Channel> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key))
        .domain_name("localhost");
    let channel = Endpoint::from_shared(format!("https://127.0.0.1:{port}"))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(10))
        .connect()
        .await
        .unwrap();
    SearchServiceClient::new(channel)
}
