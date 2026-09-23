//! End-to-end: a write on an LLM mount produces a streamed reply, and both
//! directions are inside the write-hook seam.
//!
//! Real kernel, real mount built through the real provider, real HTTP against
//! a mock SSE server on loopback. Nothing here stubs the connector or the
//! stream — the only thing standing in for production is the model itself,
//! which is the one piece a test cannot have.
//!
//! The three things proven, in order of what the FR actually asked for:
//!
//! 1. a write starts a completion and the answer arrives on the sibling
//!    stream — the half that did not exist at all;
//! 2. a write hook SEES the model's output, which is what makes sanitising an
//!    untrusted reply on the way back in possible;
//! 3. a write hook can REFUSE it, so "sees" means the hook's answer binds
//!    rather than merely being logged.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kernel::core::dispatch::{HookContext, HookOutcome, NativeInterceptHook};
use kernel::hal::object_store_provider::{ObjectStoreProvider, ObjectStoreProviderArgs};
use kernel::kernel::convenience::MountOptions;
use kernel::kernel::Kernel;
use llm_mount::reply_path_for;

const MOUNT: &str = "/llm";
const ASK: &str = "/llm/ask.prompt";

/// Two token frames, a finish, usage, and `[DONE]` — the shape the OpenAI
/// connector's own tests use, so this exercises the real SSE state machine.
fn sse_body() -> String {
    [
        r#"data: {"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hel"}}]}"#,
        r#"data: {"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"lo"}}]}"#,
        r#"data: {"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        r#"data: {"model":"gpt-4o","usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}"#,
        r#"data: [DONE]"#,
    ]
    .iter()
    .map(|f| format!("{f}\n\n"))
    .collect()
}

/// One-shot SSE server on loopback. Returns its base URL.
fn serve_once(body: String) -> (std::thread::JoinHandle<()>, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = vec![0u8; 8192];
            let _ = sock.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes());
            let _ = sock.flush();
        }
    });
    (handle, url)
}

fn ctx() -> contracts::OperationContext {
    contracts::OperationContext::new("alice", "root", false, None, false)
}

/// A kernel with the llm_mount service up and an OpenAI mount at `/llm`
/// pointed at `base_url`.
///
/// The mount is built through `DefaultObjectStoreProvider` — the same path
/// `sys_setattr(DT_MOUNT, backend_type="openai")` takes in the daemon — rather
/// than by constructing the backend directly, so the test cannot pass while
/// the production construction path is broken.
fn kernel_with_llm_mount(base_url: &str) -> (Arc<Kernel>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Kernel::new());
    kernel
        .bring_up_services(vec![llm_mount::service_decl()])
        .expect("llm_mount installs");

    let blob_root = tmp.path().to_string_lossy().to_string();
    let params: HashMap<String, String> = [
        ("blob_root".to_string(), blob_root),
        ("base_url".to_string(), base_url.to_string()),
        ("api_key".to_string(), "sk-test".to_string()),
        ("default_model".to_string(), "gpt-4o".to_string()),
    ]
    .into_iter()
    .collect();

    let peer = kernel::hal::peer::NoopPeerBlobClient::arc();
    let runtime = Arc::clone(kernel.runtime());
    let args = ObjectStoreProviderArgs {
        backend_type: "openai",
        backend_name: "llm",
        mount_path: Some(MOUNT),
        backend_params: &params,
        peer_client: &peer,
        self_address: None,
        runtime: &runtime,
    };
    let built = backends::provider::DefaultObjectStoreProvider
        .build(&args)
        .expect("openai mount builds through the real provider");
    let backend = built.backend.expect("provider returns a backend");

    use kernel::kernel::convenience::KernelConvenience;
    kernel
        .mount(MOUNT, MountOptions::new("llm").with_backend(backend))
        .expect("mount");
    (kernel, tmp)
}

/// Read the reply stream until it closes or the budget runs out, returning
/// everything that landed.
///
/// Polls rather than blocking forever on purpose: a hung completion should
/// fail this test as an assertion, not as a test binary that never exits.
fn drain_reply(kernel: &Arc<Kernel>, path: &str, budget: Duration) -> String {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if let Ok(bytes) = kernel.stream_collect_all(path) {
            let s = String::from_utf8_lossy(&bytes).to_string();
            // The connector's terminal frame — everything has arrived.
            if s.contains("\"done\"") || s.contains("\"error\"") {
                return s;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "reply stream never terminated within budget; got so far: {:?}",
            kernel
                .stream_collect_all(path)
                .map(|b| String::from_utf8_lossy(&b).to_string())
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The half that did not exist: writing a request makes a completion happen,
/// and the answer arrives on the sibling stream.
#[test]
fn a_write_starts_a_completion_and_the_reply_arrives_on_the_sibling_stream() {
    let (_srv, url) = serve_once(sse_body());
    let (kernel, _tmp) = kernel_with_llm_mount(&url);

    let request = br#"{"messages":[{"role":"user","content":"hi"}],"model":"gpt-4o"}"#;
    use kernel::kernel::convenience::KernelConvenience;
    kernel
        .write(ASK, &ctx(), request, 0)
        .expect("request write");

    let reply = drain_reply(
        &kernel,
        &reply_path_for(ASK).unwrap(),
        Duration::from_secs(30),
    );
    assert!(
        reply.starts_with("Hello"),
        "the model's tokens must arrive on the reply stream; got {reply:?}"
    );
    assert!(
        reply.contains("\"done\""),
        "a terminal done frame must close the reply; got {reply:?}"
    );
}

/// Q2, the property the FR is actually about: the reply is untrusted content
/// entering the trust boundary, and a write hook sees it.
///
/// Asserted on the REPLY path specifically. A hook seeing only the request
/// would leave the direction that matters most — what a model said, coming
/// back in — invisible, which is exactly the state this work found.
#[test]
fn a_write_hook_sees_the_models_reply() {
    struct Watcher {
        replies: Arc<AtomicUsize>,
    }
    impl NativeInterceptHook for Watcher {
        fn name(&self) -> &str {
            "reply-watcher"
        }
        fn mutating_path_suffixes(&self) -> &'static [&'static str] {
            &[llm_mount::REPLY_SUFFIX]
        }
        fn on_pre(&self, ctx: &HookContext) -> Result<HookOutcome, String> {
            if let HookContext::Write(w) = ctx {
                if w.path.ends_with(llm_mount::REPLY_SUFFIX) {
                    self.replies.fetch_add(1, Ordering::SeqCst);
                }
            }
            Ok(HookOutcome::Pass)
        }
    }

    let (_srv, url) = serve_once(sse_body());
    let (kernel, _tmp) = kernel_with_llm_mount(&url);
    let replies = Arc::new(AtomicUsize::new(0));
    let handle = kernel
        .enlist_hook_only_service("reply-watcher")
        .expect("enlist");
    kernel.register_service_hook(
        &handle,
        Box::new(Watcher {
            replies: Arc::clone(&replies),
        }),
    );

    use kernel::kernel::convenience::KernelConvenience;
    kernel
        .write(
            ASK,
            &ctx(),
            br#"{"messages":[{"role":"user","content":"hi"}],"model":"gpt-4o"}"#,
            0,
        )
        .expect("request write");
    drain_reply(
        &kernel,
        &reply_path_for(ASK).unwrap(),
        Duration::from_secs(30),
    );

    assert!(
        replies.load(Ordering::SeqCst) > 0,
        "a hook must see the model's reply frames; if this is 0 the reply \
         went around the write seam"
    );
}

/// And the hook's answer binds: a refusal keeps the model's output out of the
/// stream rather than merely recording that it was seen.
///
/// This is what "sanitise on the way back in" needs in order to be more than
/// an aspiration — a hook that could only observe would leave every deployment
/// writing detectors that cannot actually stop anything.
#[test]
fn a_write_hook_can_refuse_the_models_reply() {
    struct Censor {
        blocked: Arc<Mutex<Vec<String>>>,
    }
    impl NativeInterceptHook for Censor {
        fn name(&self) -> &str {
            "censor"
        }
        fn mutating_path_suffixes(&self) -> &'static [&'static str] {
            &[llm_mount::REPLY_SUFFIX]
        }
        fn on_pre(&self, ctx: &HookContext) -> Result<HookOutcome, String> {
            if let HookContext::Write(w) = ctx {
                let text = String::from_utf8_lossy(&w.content).to_string();
                // Refuse token frames, admit the terminal control frame so the
                // reader still learns the completion ended.
                if !text.is_empty() && !text.starts_with('{') {
                    self.blocked.lock().unwrap().push(text);
                    return Err("blocked by policy".to_string());
                }
            }
            Ok(HookOutcome::Pass)
        }
    }

    let (_srv, url) = serve_once(sse_body());
    let (kernel, _tmp) = kernel_with_llm_mount(&url);
    let blocked = Arc::new(Mutex::new(Vec::new()));
    let handle = kernel.enlist_hook_only_service("censor").expect("enlist");
    kernel.register_service_hook(
        &handle,
        Box::new(Censor {
            blocked: Arc::clone(&blocked),
        }),
    );

    use kernel::kernel::convenience::KernelConvenience;
    kernel
        .write(
            ASK,
            &ctx(),
            br#"{"messages":[{"role":"user","content":"hi"}],"model":"gpt-4o"}"#,
            0,
        )
        .expect("request write");
    let reply = drain_reply(
        &kernel,
        &reply_path_for(ASK).unwrap(),
        Duration::from_secs(30),
    );

    assert!(
        !blocked.lock().unwrap().is_empty(),
        "the censor must have been offered the model's tokens"
    );
    assert!(
        !reply.contains("Hello"),
        "refused tokens must not be in the stream; got {reply:?}"
    );
}
