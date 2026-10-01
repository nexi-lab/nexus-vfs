//! Native provider payloads cross a real mount and its policy hooks unchanged.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use contracts::OperationContext;
use kernel::core::dispatch::{HookContext, HookOutcome, NativeInterceptHook};
use kernel::hal::object_store_provider::{ObjectStoreProvider, ObjectStoreProviderArgs};
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::Kernel;
use serde_json::{json, Value};

fn caller() -> OperationContext {
    OperationContext::new("alice", "root", false, Some("agent-a"), false)
}

fn mount(provider: &str, url: &str) -> (Arc<Kernel>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Kernel::new());
    kernel
        .bring_up_services(vec![llm_mount::service_decl()])
        .unwrap();
    let params: HashMap<_, _> = [
        (
            "blob_root".into(),
            dir.path().to_string_lossy().into_owned(),
        ),
        ("base_url".into(), url.into()),
        ("api_key".into(), "mount-credential".into()),
        ("default_model".into(), "test-model".into()),
    ]
    .into_iter()
    .collect();
    let peer = kernel::hal::peer::NoopPeerBlobClient::arc();
    let built = backends::provider::DefaultObjectStoreProvider
        .build(&ObjectStoreProviderArgs {
            backend_type: provider,
            backend_name: "model",
            mount_path: Some("/model"),
            backend_params: &params,
            peer_client: &peer,
            self_address: None,
            runtime: kernel.runtime(),
        })
        .unwrap();
    kernel
        .mount(
            "/model",
            MountOptions::new("model").with_backend(built.backend.unwrap()),
        )
        .unwrap();
    (kernel, dir)
}

fn server(
    status: u16,
    body: &'static str,
) -> (
    String,
    mpsc::Receiver<(String, Value)>,
    std::thread::JoinHandle<()>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "provider was never called");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut bytes = Vec::new();
        let (header, body_start, length) = loop {
            let mut chunk = [0; 4096];
            let n = socket.read(&mut chunk).unwrap();
            assert_ne!(n, 0, "request truncated");
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let header = String::from_utf8(bytes[..end].to_vec()).unwrap();
                let length: usize = header
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .unwrap()
                    .parse()
                    .unwrap();
                break (header, end + 4, length);
            }
        };
        while bytes.len() < body_start + length {
            let mut chunk = [0; 4096];
            let n = socket.read(&mut chunk).unwrap();
            assert_ne!(n, 0);
            bytes.extend_from_slice(&chunk[..n]);
        }
        tx.send((
            header,
            serde_json::from_slice(&bytes[body_start..body_start + length]).unwrap(),
        ))
        .unwrap();
        write!(socket, "HTTP/1.1 {status} Test\r\nContent-Type: text/event-stream\r\nRetry-After: 2\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    });
    (url, rx, worker)
}

fn exchange(path: &str) -> Value {
    json!({"nexus_http": {"version": 1, "path": path, "headers": {"anthropic-beta": "prompt-caching-2024-07-31"}}, "body": {
        "model": "test-model", "stream": true,
        "system": [{"type": "text", "text": "system", "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "assistant", "content": [{"type": "thinking", "thinking": "reasoning", "signature": "sig"}, {"type": "tool_use", "id": "call-1", "name": "read", "input": {"path": "a"}}]}],
        "tools": [{"name": "read", "input_schema": {"type": "object"}}],
        "thinking": {"type": "enabled", "budget_tokens": 1024}, "max_tokens": 2048
    }})
}

fn read_reply(kernel: &Kernel) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut records = Vec::new();
    let mut cursor = 0;
    loop {
        assert!(Instant::now() < deadline, "reply did not terminate");
        match KernelSyscall::sys_read(kernel, "/model/request.reply", &caller(), 100, cursor) {
            Ok(result) => {
                if let Some(bytes) = result.data.filter(|b| !b.is_empty()) {
                    cursor = result.stream_next_offset.unwrap() as u64;
                    let terminal = bytes.first() != Some(&0)
                        && serde_json::from_slice::<Value>(&bytes)
                            .is_ok_and(|v| matches!(v["type"].as_str(), Some("done" | "error")));
                    records.push(bytes);
                    if terminal {
                        return records;
                    }
                }
            }
            Err(kernel::kernel::KernelError::FileNotFound(_)) if cursor == 0 => {}
            Err(error) => panic!("reply read: {error:?}"),
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn native_provider_payload_status_and_bytes_survive_the_mount() {
    // Includes text that looks like a terminal frame: it must remain body data.
    const BODY: &str = "event: content_block_delta\ndata: {\"type\":\"thinking_delta\",\"thinking\":\"hello\",\"signature\":\"sig\"}\n\ndata: {\"type\":\"done\"}\n\n";
    for (provider, path, status) in [
        ("openai", "chat/completions", 200),
        ("openai", "responses", 429),
        ("anthropic", "v1/messages", 200),
        ("anthropic", "v1/messages/count_tokens", 200),
    ] {
        let (url, captured, worker) = server(status, BODY);
        let (kernel, _dir) = mount(provider, &url);
        let request = exchange(path);
        kernel
            .write(
                "/model/request.prompt",
                &caller(),
                &serde_json::to_vec(&request).unwrap(),
                0,
            )
            .unwrap();
        let records = read_reply(&kernel);
        let (header, body) = captured.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(header.starts_with(&format!("POST /{path} ")));
        assert!(header.contains("mount-credential"));
        assert_eq!(body, request["body"]);
        let head: Value = serde_json::from_slice(&records[0]).unwrap();
        assert_eq!(head["status"], status);
        assert_eq!(head["headers"]["retry-after"], "2");
        let data: Vec<u8> = records
            .iter()
            .filter(|r| r.first() == Some(&0))
            .flat_map(|r| r[1..].iter().copied())
            .collect();
        assert_eq!(data, BODY.as_bytes());
        assert_eq!(
            serde_json::from_slice::<Value>(records.last().unwrap()).unwrap()["type"],
            "done"
        );
        worker.join().unwrap();
    }
}

#[test]
fn output_policy_sees_raw_bytes_and_can_refuse_them() {
    struct RefuseBody;
    impl NativeInterceptHook for RefuseBody {
        fn name(&self) -> &str {
            "refuse-model-body"
        }
        fn mutating_path_suffixes(&self) -> &'static [&'static str] {
            &[".reply"]
        }
        fn on_pre(&self, ctx: &HookContext) -> Result<HookOutcome, String> {
            if let HookContext::Write(w) = ctx {
                assert_eq!(w.identity.user_id, "alice");
                if w.content.first() == Some(&0) {
                    assert!(String::from_utf8_lossy(&w.content).contains("private output"));
                    return Err("output refused by policy".into());
                }
            }
            Ok(HookOutcome::Pass)
        }
    }
    let (url, _captured, worker) = server(200, "private output");
    let (kernel, _dir) = mount("openai", &url);
    let owner = kernel
        .enlist_hook_only_service("refuse-model-body")
        .unwrap();
    kernel.register_service_hook(&owner, Box::new(RefuseBody));
    kernel
        .write(
            "/model/request.prompt",
            &caller(),
            &serde_json::to_vec(&exchange("chat/completions")).unwrap(),
            0,
        )
        .unwrap();
    let records = read_reply(&kernel);
    assert!(!records.iter().any(|r| r.first() == Some(&0)));
    let error: Value = serde_json::from_slice(records.last().unwrap()).unwrap();
    assert_eq!(error["type"], "error");
    assert!(error["message"]
        .as_str()
        .unwrap()
        .contains("output refused"));
    worker.join().unwrap();
}

#[test]
fn request_cannot_override_destination_or_mount_credentials() {
    for request in [exchange("http://elsewhere/chat/completions"), {
        let mut request = exchange("chat/completions");
        request["nexus_http"]["headers"]["authorization"] = json!("Bearer override");
        request
    }] {
        let (kernel, _dir) = mount("openai", "http://127.0.0.1:1");
        kernel
            .write(
                "/model/request.prompt",
                &caller(),
                &serde_json::to_vec(&request).unwrap(),
                0,
            )
            .unwrap();
        let records = read_reply(&kernel);
        let error: Value = serde_json::from_slice(records.last().unwrap()).unwrap();
        assert_eq!(error["type"], "error");
        assert!(error["message"].as_str().unwrap().contains("not supported"));
    }
}
