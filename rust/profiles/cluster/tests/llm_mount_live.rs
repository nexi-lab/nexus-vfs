//! LIVE E2E: a real daemon, a real gRPC client, and a real model.
//!
//! Everything else that covers this path stops short of one thing. The
//! `llm-mount` integration test drives an in-process kernel against a mock SSE
//! server it wrote itself; it proves the wiring and proves nothing about a
//! provider. This proves the rest: that `nexusd-cluster` built with
//! `--features driver-ai` boots with the service registered, that a connector
//! mount can be created over the wire the way an operator creates one, and
//! that writing a `.prompt` makes a real model answer on the `.reply`.
//!
//! `#[ignore]` on purpose. It needs a funded API key and spends real money, so
//! CI must not run it — and `ignored` is reported as ignored, never folded in
//! with the passes. Run it deliberately:
//!
//! ```text
//! NEXUS_E2E_LLM_KEY=sk-... NEXUS_E2E_LLM_BASE_URL=https://api.sudorouter.ai/v1 \
//!   cargo test -p nexus-cluster --features driver-ai --test llm_mount_live -- --ignored --nocapture
//! ```
//!
//! It refuses rather than skips when the key is absent. A live test that
//! quietly passes with no key is worse than no live test: it reports success
//! for a thing it did not do.

mod common;

use std::time::Duration;

use common::{free_port_pair, Daemon, Vfs, LOG_FILTER};

const MOUNT: &str = "/llm";
const PROMPT: &str = "/llm/live-check.prompt";
const REPLY: &str = "/llm/live-check.reply";
const BUDGET: Duration = Duration::from_secs(120);

/// The sentinel the model is asked to produce. Short, and nothing the harness
/// could emit by accident — if it is in the reply stream, a model put it there.
const SENTINEL: &str = "NEXUS-LIVE-OK";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live: needs NEXUS_E2E_LLM_KEY and spends real money"]
async fn a_prompt_write_reaches_a_real_model_and_the_reply_streams_back() {
    let key = std::env::var("NEXUS_E2E_LLM_KEY").expect(
        "NEXUS_E2E_LLM_KEY is required — this test is the live one, and a run \
         without a key would prove nothing while looking like it passed",
    );
    let base_url = std::env::var("NEXUS_E2E_LLM_BASE_URL")
        .unwrap_or_else(|_| "https://api.sudorouter.ai/v1".to_string());
    let model = std::env::var("NEXUS_E2E_LLM_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());

    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    let ident = tmp.path().join("id");
    std::fs::create_dir_all(&data).unwrap();
    let blob_root = tmp.path().join("llm-blobs");
    std::fs::create_dir_all(&blob_root).unwrap();

    let port = free_port_pair();
    let bind = format!("127.0.0.1:{port}");
    let data_s = data.to_string_lossy().to_string();
    let ident_s = ident.to_string_lossy().to_string();
    let env = vec![
        ("NEXUS_DATA_DIR", data_s.as_str()),
        ("NEXUS_IDENTITY_DIR", ident_s.as_str()),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_NO_TLS", "true"),
        ("RUST_LOG", LOG_FILTER),
    ];

    let mut daemon = Daemon::spawn(&["--bind-addr", &bind], &env);
    daemon
        .wait_tcp(port, BUDGET)
        .await
        .expect("daemon serves; if this fails the binary did not boot");

    // The service is only in a `driver-ai` build. Assert it came up, so a
    // default-feature build fails here with a clear reason instead of later
    // with a stream that never appears.
    assert!(
        daemon.log_contains("llm_mount"),
        "llm_mount service did not register — is this built with --features \
         driver-ai? log:\n{}",
        daemon.drain()
    );

    let mut vfs = Vfs::connect_serving(port, BUDGET).await;

    // Mount the connector the way an operator does: over the wire, by
    // backend_type + params. Nothing in this test constructs a backend.
    let blob_root_s = blob_root.to_string_lossy().to_string();
    vfs.mount_backend(
        MOUNT,
        "openai",
        &[
            ("blob_root", blob_root_s.as_str()),
            ("base_url", base_url.as_str()),
            ("api_key", key.as_str()),
            ("default_model", model.as_str()),
        ],
        "",
    )
    .await
    .expect("openai mount created over gRPC");

    // The request is an ordinary write. That is the whole contract.
    let request = serde_json::json!({
        "model": model,
        "messages": [{
            "role": "user",
            "content": format!("Reply with exactly this and nothing else: {SENTINEL}"),
        }],
        "max_tokens": 32,
    })
    .to_string();
    vfs.write_file(PROMPT, request.as_bytes(), "")
        .await
        .expect("prompt write");

    // And the answer is an ordinary stream read.
    let deadline = std::time::Instant::now() + BUDGET;
    let mut seen = String::new();
    loop {
        if let Ok(bytes) = vfs.stream_collect_all(REPLY, "").await {
            seen = String::from_utf8_lossy(&bytes).to_string();
            if seen.contains("\"done\"") || seen.contains("\"error\"") {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the reply stream never terminated. got so far: {seen:?}\ndaemon log:\n{}",
            daemon.drain()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    eprintln!("--- live reply stream ---\n{seen}\n-------------------------");
    assert!(
        !seen.contains("\"error\""),
        "the provider refused the call: {seen}"
    );
    assert!(
        seen.contains(SENTINEL),
        "a real model's tokens must be in the reply stream; got {seen:?}"
    );
    assert!(
        seen.contains("\"done\""),
        "the reply must be terminated by a done frame; got {seen:?}"
    );
}
