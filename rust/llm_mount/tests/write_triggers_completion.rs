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
    sse_body_saying("Hello")
}

/// The same frame sequence, saying `text` instead — so two calls can be told
/// apart by what came back rather than by counting them.
fn sse_body_saying(text: &str) -> String {
    let (head, tail) = text.split_at(text.len() / 2);
    [
        format!(r#"data: {{"model":"gpt-4o","choices":[{{"index":0,"delta":{{"content":"{head}"}}}}]}}"#),
        format!(r#"data: {{"model":"gpt-4o","choices":[{{"index":0,"delta":{{"content":"{tail}"}}}}]}}"#),
        r#"data: {"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#.to_string(),
        r#"data: {"model":"gpt-4o","usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}"#.to_string(),
        r#"data: [DONE]"#.to_string(),
    ]
    .iter()
    .map(|f| format!("{f}\n\n"))
    .collect()
}

/// Serve `bodies` to successive connections, one each, in order. Lets a single
/// mount answer two asks differently, so a repeat can be told apart by what
/// came back rather than by counting connections.
fn serve_sequence(bodies: Vec<String>) -> (std::thread::JoinHandle<()>, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut workers = Vec::new();
        for body in bodies {
            let Ok((mut sock, _)) = listener.accept() else {
                break;
            };
            // Each connection is served on its OWN thread, so callers overlap.
            // Answering them one after another would serialise the completions
            // and silently defeat any test trying to race them — this mock
            // began that way, and a concurrency test over it passed with the
            // lock under test removed.
            workers.push(std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut buf = vec![0u8; 8192];
                let _ = sock.read(&mut buf);
                // A beat before answering, so the racers are in flight
                // together rather than finishing as fast as they arrive.
                std::thread::sleep(std::time::Duration::from_millis(80));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes());
                let _ = sock.flush();
            }));
        }
        for w in workers {
            let _ = w.join();
        }
    });
    (handle, url)
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

/// Writing the same prompt path again must ask again.
///
/// The FR reporter asked us to write down whether a repeat is a re-ask or an
/// idempotent no-op. Checking rather than documenting the assumption found it
/// was neither: `create_stream` refuses a path that already exists, so the
/// hook logged a warning and returned. The caller's second write succeeded
/// and nothing happened — leaving the FIRST answer on `.reply` to be read as
/// if it were the second. Silently serving a stale answer is the worst of the
/// three behaviours it could have had.
#[test]
fn asking_twice_replaces_the_first_answer() {
    let (_srv, url) = serve_sequence(vec![
        sse_body_saying("FIRSTFIRST"),
        sse_body_saying("SECONDSECOND"),
    ]);
    let (kernel, _tmp) = kernel_with_llm_mount(&url);
    let reply = reply_path_for(ASK).unwrap();

    use kernel::kernel::convenience::KernelConvenience;
    let req = br#"{"messages":[{"role":"user","content":"hi"}],"model":"gpt-4o"}"#;

    kernel.write(ASK, &ctx(), req, 0).expect("first prompt");
    let first = drain_reply(&kernel, &reply, Duration::from_secs(30));
    assert!(first.starts_with("FIRSTFIRST"), "got {first:?}");

    kernel.write(ASK, &ctx(), req, 0).expect("second prompt");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let now = kernel
            .stream_collect_all(&reply)
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();
        if now.starts_with("SECONDSECOND") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the second ask never replaced the first answer; reply still reads {now:?}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Racing asks on ONE stem must still leave a usable reply stream.
///
/// The reset is a read-modify-write (destroy, then create). Unlocked, two
/// racers can both destroy and then one create wins — the loser returns
/// having done nothing, which is the silent no-op this work exists to remove,
/// reappearing in exactly the case hardest to notice.
///
/// The assertion is deliberately about the stream being THERE and complete,
/// not about which answer won: the later ask winning a reused slot is the
/// documented contract, and pinning a winner would be pinning a race.
#[test]
fn racing_asks_on_one_stem_still_leave_a_complete_reply() {
    const RACERS: usize = 6;
    let (_srv, url) = serve_sequence((0..RACERS).map(|_| sse_body_saying("Hello")).collect());
    let (kernel, _tmp) = kernel_with_llm_mount(&url);
    let reply = reply_path_for(ASK).unwrap();

    let mut hands = Vec::new();
    for _ in 0..RACERS {
        let k = Arc::clone(&kernel);
        hands.push(std::thread::spawn(move || {
            use kernel::kernel::convenience::KernelConvenience;
            let _ = k.write(
                ASK,
                &ctx(),
                br#"{"messages":[{"role":"user","content":"hi"}],"model":"gpt-4o"}"#,
                0,
            );
        }));
    }
    for h in hands {
        h.join().unwrap();
    }

    let got = drain_reply(&kernel, &reply, Duration::from_secs(30));
    assert!(
        got.contains("\"done\""),
        "a complete answer must survive the race; got {got:?}"
    );
    assert!(
        got.starts_with("Hello"),
        "the surviving answer must not be a torn prefix; got {got:?}"
    );
}
