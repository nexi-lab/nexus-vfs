#![cfg(feature = "subprocess-host")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use a2a::session::{SessionCodec, SessionEndpoint, SessionPayload, SessionSide};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, OperationContext};
use serde_json::{json, Value};

fn call(kernel: &Kernel, method: &str, payload: Value) -> Result<Value, String> {
    let ctx = OperationContext::new("operator", "root", false, Some("operator"), false);
    let response = kernel
        .dispatch_rust_call(
            "managed_agent",
            method,
            payload.to_string().as_bytes(),
            &ctx,
        )
        .expect("installed service")
        .map_err(|e| format!("{e:?}"))?;
    serde_json::from_slice(&response).map_err(|e| e.to_string())
}

fn receive(
    kernel: &Kernel,
    endpoint: &SessionEndpoint,
    codec: &mut SessionCodec,
    offset: &mut usize,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some((data, next)) = kernel
            .stream_read_at(&endpoint.transcript, *offset)
            .unwrap()
        {
            *offset = next;
            match codec.decode(&data).unwrap() {
                Some(SessionPayload::Rpc { message }) => return message,
                Some(SessionPayload::Closed { reason }) => panic!("unexpected closure: {reason}"),
                None => {}
            }
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    panic!("timed out waiting for a session message")
}

fn send(
    kernel: &Kernel,
    endpoint: &SessionEndpoint,
    codec: &mut SessionCodec,
    message: Value,
) -> Vec<u8> {
    let bytes = codec.encode(SessionPayload::Rpc { message }).unwrap();
    let ctx = OperationContext::new("operator", "root", false, Some("operator"), false);
    assert!(
        KernelSyscall::sys_write(kernel, &endpoint.transcript, &ctx, &bytes, 0)
            .unwrap()
            .hit
    );
    bytes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subprocess_streams_approvals_and_accepts_cancel_without_public_fd_streams() {
    let kernel = Arc::new(Kernel::new());
    kernel.vfs_router_arc().add_mount("/", "root", None, false);
    a2a::install_a2a_stamp_hook(&kernel, true).unwrap();
    managed_agent::install_managed_agent(&kernel).unwrap();
    // This fixture has no raft WAL. Use the kernel's framed memory stream;
    // production provisions the same record API over the replicated WAL.
    let path = a2a::conversation_transcript_path(&a2a::conversation_id("worker", "operator"));
    let parent = path.rsplit_once('/').unwrap().0;
    // Fixture provisioning: the kernel-level ctx the typed sys_setattr
    // requires; not the subject under test.
    let ctx = contracts::OperationContext::new("system", "root", true, None, true);
    kernel
        .sys_setattr(
            parent,
            &ctx,
            1,
            "",
            None,
            None,
            None,
            "balanced",
            "root",
            false,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    kernel
        .sys_setattr(
            &path,
            &ctx,
            4,
            "",
            None,
            None,
            None,
            "memory",
            "root",
            false,
            1 << 20,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    let test_kernel = Arc::clone(&kernel);
    tokio::task::spawn_blocking(move || {
        let kernel = test_kernel;
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/session_agent.py");
        let python = if cfg!(windows) { "python" } else { "python3" };
        let environment: std::collections::HashMap<String, String> = std::env::vars().collect();
        let started = call(&kernel, "start_session_v1", json!({
            "agent_id":"worker", "spawn_spec":{"cmd":python,"args":["-u",fixture],"env":environment}
        })).unwrap();
        let pid = started["session_id"].as_str().unwrap();
        let endpoint: SessionEndpoint = serde_json::from_value(started["session_endpoint"].clone()).unwrap();
        assert_eq!(endpoint.controller, "operator");
        assert!(started["os_pid"].as_u64().is_some());
        for fd in 0..3 { assert!(kernel.sys_stat(&format!("/proc/{pid}/fd/{fd}"), "root").is_none()); }
        let mut codec = SessionCodec::new(endpoint.clone(), SessionSide::Controller).unwrap();
        let mut offset = 0;
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":1}}));
        let initialized = receive(&kernel, &endpoint, &mut codec, &mut offset);
        assert_eq!(initialized["id"], 0, "initialize response: {initialized}");
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":"new","method":"session/new","params":{"cwd":"/"}}));
        assert_eq!(receive(&kernel, &endpoint, &mut codec, &mut offset)["result"]["sessionId"], "durable-fixture-session");
        for (turn, cancelled) in [("first", true), ("second", false)] {
            let prompt = send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":turn,"method":"session/prompt","params":{"sessionId":"durable-fixture-session","prompt":[{"type":"text","text":"edit"}]}}));
            // An uncertain append may be retried with identical bytes. It must
            // not start another turn in the child, including while awaiting approval.
            let ctx = OperationContext::new("operator", "root", false, Some("operator"), false);
            KernelSyscall::sys_write(kernel.as_ref(), &endpoint.transcript, &ctx, &prompt, 0).unwrap();
            assert_eq!(receive(&kernel, &endpoint, &mut codec, &mut offset)["method"], "session/update");
            let approval = receive(&kernel, &endpoint, &mut codec, &mut offset);
            assert_eq!(approval["method"], "session/request_permission");
            if cancelled {
                send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"durable-fixture-session"}}));
            } else {
                send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":approval["id"],"result":{"outcome":{"outcome":"selected","optionId":"yes"}}}));
                assert_eq!(receive(&kernel, &endpoint, &mut codec, &mut offset)["params"]["update"]["status"], "completed");
            }
            let terminal = receive(&kernel, &endpoint, &mut codec, &mut offset);
            assert_eq!(terminal["id"], turn);
            assert_eq!(terminal["result"]["stopReason"], if cancelled { "cancelled" } else { "end_turn" });
        }
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","method":"test/close_stdout"}));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some((bytes, next)) = kernel.stream_read_at(&endpoint.transcript, offset).unwrap() {
                offset = next;
                if let Some(SessionPayload::Closed { reason }) = codec.decode(&bytes).unwrap() {
                    assert!(reason.contains("closed stdout"), "{reason}");
                    break;
                }
            }
            assert!(Instant::now() < deadline, "stdout EOF must close and reap a still-running child");
            std::thread::sleep(Duration::from_millis(10));
        }
    }).await.unwrap();
}
