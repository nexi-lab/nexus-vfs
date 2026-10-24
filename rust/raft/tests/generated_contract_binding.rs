//! Compile the production guard itself with private matching/stale inputs.
//! No shared target files are changed and no cache is deleted.
use std::{path::Path, process::Command};

#[test]
fn generated_contracts_must_match_all_current_source_inputs() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository = manifest.parent().unwrap().parent().unwrap();
    let private = tempfile::tempdir().unwrap();
    let copied_manifest = private.path().join("source tree/rust/raft");
    let copied_root = private.path().join("source tree/proto");
    let generated = private.path().join("generated");
    std::fs::create_dir_all(&copied_manifest).unwrap();
    std::fs::create_dir(&generated).unwrap();
    let guard = private.path().join("guard.rs");
    std::fs::copy(manifest.join("src/transport/proto_binding.rs"), &guard).unwrap();
    let inputs = [
        (
            "nexus/raft/transport.proto",
            "raft-transport.source.proto",
            "transport",
        ),
        (
            "nexus/raft/commands.proto",
            "raft-commands.source.proto",
            "command",
        ),
        (
            "nexus/core/metadata.proto",
            "raft-metadata.source.proto",
            "metadata",
        ),
    ];
    for (source, snapshot, _) in &inputs {
        let target = copied_root.join(source);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(repository.join("proto").join(source), &target).unwrap();
        std::fs::copy(target, generated.join(snapshot)).unwrap();
    }
    let compile = || {
        Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
            .args([
                "--crate-name",
                "contract_guard",
                "--crate-type=lib",
                "--edition=2021",
                "--emit=metadata",
            ])
            .arg(&guard)
            .arg("-o")
            .arg(private.path().join("guard.rmeta"))
            .env("CARGO_MANIFEST_DIR", &copied_manifest)
            .env("OUT_DIR", &generated)
            .output()
            .unwrap()
    };
    let clean = compile();
    assert!(
        clean.status.success(),
        "matching production guard failed: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    for (_, snapshot, label) in inputs {
        let path = generated.join(snapshot);
        let original = std::fs::read(&path).unwrap();
        let mut stale = original.clone();
        stale.extend_from_slice(b"\n// stale generation\n");
        std::fs::write(&path, stale).unwrap();
        let mismatch = compile();
        assert!(!mismatch.status.success(), "stale {label} was accepted");
        assert!(String::from_utf8_lossy(&mismatch.stderr)
            .contains(&format!("stale generated Raft {label} contract")));
        std::fs::write(path, original).unwrap();
    }
}
