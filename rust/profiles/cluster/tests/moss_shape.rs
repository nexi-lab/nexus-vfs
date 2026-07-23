//! Black-box E2E: the shape moss actually runs — a plaintext, tokenless daemon
//! on loopback storing enterprise secrets at `/secrets/org:{orgId}:system/*.json`.
//!
//! The COLON in the namespace is the whole point: the VFS maps a path onto a
//! host filename, and Windows rejects `:` outright — so every earlier probe had
//! to substitute a colon-free namespace, meaning moss's REAL path shape was
//! never actually tested. This is it. Linux-only (`#![cfg(target_os = "linux")]`)
//! for exactly that reason. Rust replacement for the retired
//! `tests/docker/moss_shape_probe.py` — a plain Linux runner is Linux, so no
//! container is needed; the boot-refuse half of that probe is covered by
//! `loopback_invariant`. The journey: BOOT moss's invocation (`--bind-addr
//! 127.0.0.1:P --no-tls`, empty token, and NO `--bootstrap-mode` — the flag
//! Phase G deleted); WRITE moss's real path shape `/secrets/org:acme:system/*.json`
//! (colons and all) with an empty token; READ one back byte-exact; READDIR it at
//! the key and namespace levels — the evidence that moss's SQLite secrets index
//! is a redundant second SSOT.

#![cfg(target_os = "linux")]

mod common;

use std::time::Duration;

use common::{free_port, Daemon, Vfs};

const NAMESPACE: &str = "org:acme:system";
const BUDGET: Duration = Duration::from_secs(90);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn moss_deployment_shape_roundtrips_colon_paths() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    let data = data.to_string_lossy();
    let ident = tmp.path().join("id");
    let ident = ident.to_string_lossy();
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");

    // ── 1. moss's invocation boots (loopback + no-tls + empty token, no flags) ──
    let mut d = Daemon::spawn(
        &["--bind-addr", &bind, "--no-tls"],
        &[("NEXUS_DATA_DIR", &data), ("NEXUS_IDENTITY_DIR", &ident)],
    );
    d.wait_tcp(port, BUDGET)
        .await
        .expect("moss's invocation must boot on the current binary, with no auth flags");
    let mut c = Vfs::dial(port).await.expect("dial");

    // ── 2. moss's real path shape round-trips — note the colons ─────────
    let secrets = [
        ("openai", r#"{"key":"sk-fake"}"#),
        ("anthropic", r#"{"key":"x"}"#),
        ("slack", r#"{"key":"y"}"#),
    ];
    for (name, body) in secrets {
        let path = format!("/secrets/{NAMESPACE}/{name}.json");
        c.write_file(&path, body.as_bytes(), "")
            .await
            .unwrap_or_else(|e| {
                panic!("write {path} (moss's colon path shape must round-trip): {e}")
            });
    }

    // ── 3. read one back byte-exact ─────────────────────────────────────
    let got = c
        .read_file(&format!("/secrets/{NAMESPACE}/openai.json"), "")
        .await
        .expect("read back");
    assert_eq!(
        got, br#"{"key":"sk-fake"}"#,
        "moss's colon path must round-trip byte-exact"
    );

    // ── 4. Readdir lists it — the SQLite index is a redundant second SSOT ──
    let key_level = c
        .readdir_names(&format!("/secrets/{NAMESPACE}"), "")
        .await
        .expect("readdir key level");
    assert_eq!(
        key_level.len(),
        secrets.len(),
        "key-level Readdir must list every secret; got {key_level:?}"
    );

    let ns_level = c
        .readdir_names("/secrets", "")
        .await
        .expect("readdir namespace level");
    assert!(
        ns_level.iter().any(|n| n.contains(NAMESPACE)),
        "namespace-level Readdir must list the colon namespace; got {ns_level:?}"
    );
}
