use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use std::path::{Path, PathBuf};

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
