#![cfg(feature = "subprocess-host")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use a2a::session::{SessionCodec, SessionEndpoint, SessionPayload, SessionSide};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, OperationContext};
use serde_json::json;

#[path = "common/session_control.rs"]
mod session_control;
use session_control::{call, receive, send, session_kernel};

struct LiveController {
    kernel: Arc<Kernel>,
    pid: String,
    endpoint: SessionEndpoint,
    sent: u64,
}

impl LiveController {
    fn start(agent: &str) -> Self {
        let kernel = session_kernel(agent);
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/session_agent.py");
        let environment: std::collections::HashMap<String, String> = std::env::vars().collect();
        let started = call(
            &kernel,
            "start_session_v1",
            json!({
                "agent_id":agent, "session_protocol":"acp-live/1",
                "spawn_spec":{"cmd":if cfg!(windows) { "python" } else { "python3" },
                    "args":["-u",fixture],"env":environment}
            }),
        )
        .unwrap();
        let endpoint: SessionEndpoint =
            serde_json::from_value(started["session_endpoint"].clone()).unwrap();
        assert_eq!(endpoint.protocol, "acp-live/1");
        assert!(endpoint.transcript.is_empty());
        assert!(SessionCodec::new(endpoint.clone(), SessionSide::Controller).is_err());
        Self {
            kernel,
            pid: started["session_id"].as_str().unwrap().into(),
            endpoint,
            sent: 0,
        }
    }

    fn submit(
        &self,
        sequence: u64,
        message: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        call(
            &self.kernel,
            "session_submit_v1",
            json!({
                "session_id":self.pid,"channel_id":self.endpoint.channel_id,
                "sequence":sequence,"payload":{"type":"rpc","message":message}
            }),
        )
    }

    fn send(&mut self, message: serde_json::Value) {
        let next = self.sent + 1;
        assert_eq!(
            self.submit(next, message).unwrap()["accepted_sequence"],
            next
        );
        self.sent = next;
    }

    fn read(&self, after: u64) -> a2a::session_live::ReadSessionResponse {
        serde_json::from_value(
            call(
                &self.kernel,
                "session_read_v1",
                json!({
                    "session_id":self.pid,"channel_id":self.endpoint.channel_id,
                    "after_sequence":after,"timeout_ms":200
                }),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn wait_for(
        &self,
        after: u64,
        predicate: impl Fn(&a2a::session_live::ReadSessionResponse) -> bool,
    ) -> a2a::session_live::ReadSessionResponse {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let response = self.read(after);
            if predicate(&response) {
                return response;
            }
            assert!(
                Instant::now() < deadline,
                "live ACP response timed out: {response:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for LiveController {
    fn drop(&mut self) {
        let _ = call(
            &self.kernel,
            "cancel_v2",
            json!({
                "session_id":self.pid,"channel_id":self.endpoint.channel_id
            }),
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_acp_replays_without_reexecuting_input_or_writing_the_peer_log() {
    tokio::task::spawn_blocking(|| {
        let mut controller = LiveController::start("live-replay");
        controller.send(json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}));
        let initial = controller.wait_for(0, |response| !response.frames.is_empty());
        assert_eq!(initial.frames[0].sequence, 1);
        assert_eq!(initial.accepted_sequence, 1);
        assert_eq!(controller.read(0).frames[0].payload, initial.frames[0].payload);
        controller.send(json!({"jsonrpc":"2.0","id":1,"method":"session/new","params":{}}));
        controller.wait_for(1, |response| !response.frames.is_empty());
        let prompt = json!({"jsonrpc":"2.0","id":2,"method":"session/prompt","params":{"sessionId":"durable-fixture-session"}});
        controller.send(prompt.clone());
        let permission = controller.wait_for(2, |response| response.frames.len() == 2);
        assert!(controller.submit(controller.sent, prompt).unwrap_err().contains("input sequence"));
        assert_eq!(controller.read(2).frames.len(), 2, "reconnect replays existing delivery");
        assert_eq!(permission.accepted_sequence, controller.sent);
        controller.send(json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"durable-fixture-session"}}));
        let terminal = controller.wait_for(4, |response| !response.frames.is_empty());
        let SessionPayload::Rpc { message } = &terminal.frames[0].payload else { panic!("missing terminal response") };
        assert_eq!(message["result"]["stopReason"], "cancelled");
        let path = a2a::conversation_transcript_path(&a2a::conversation_id("live-replay", "operator"));
        assert!(controller.kernel.stream_read_at(&path, 0).unwrap().is_none(), "live ACP must not enter the peer log");
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_acp_reports_retention_loss_and_batches_the_retained_tail() {
    tokio::task::spawn_blocking(|| {
        let mut controller = LiveController::start("live-retention");
        controller
            .send(json!({"jsonrpc":"2.0","id":1,"method":"test/burst","params":{"count":1200}}));
        let gap = controller.wait_for(0, |response| response.latest_sequence == 1201);
        assert!(gap.resync_required);
        assert!(
            gap.frames.is_empty(),
            "a gap must not masquerade as complete replay"
        );
        assert!(gap.earliest_sequence > 1);
        let batch = controller.read(gap.earliest_sequence - 1);
        assert!(!batch.resync_required);
        assert!(batch.frames.len() > 1 && batch.frames.len() <= 128);
        let tail = controller.read(gap.latest_sequence - 1);
        let SessionPayload::Rpc { message } = &tail.frames[0].payload else {
            panic!("missing final burst response")
        };
        assert_eq!(message["result"]["emitted"], 1200);
        assert_eq!(tail.accepted_sequence, 1);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_acp_final_response_survives_retirement_but_rejects_other_identities_and_old_inputs() {
    tokio::task::spawn_blocking(|| {
        let mut controller = LiveController::start("live-final");
        for (owner, zone, actor) in [("operator", "root", "intruder"), ("intruder", "root", "operator"), ("operator", "other", "operator")] {
            // Even an administrator cannot impersonate a private ACP controller.
            let ctx = OperationContext::new(owner, zone, true, Some(actor), false);
            let result = controller.kernel.dispatch_rust_call("managed_agent", "session_read_v1",
                json!({"session_id":controller.pid,"channel_id":controller.endpoint.channel_id,"after_sequence":0}).to_string().as_bytes(), &ctx).unwrap();
            assert!(matches!(result, Err(contracts::RustCallError::PermissionDenied(_))));
        }
        controller.send(json!({"jsonrpc":"2.0","id":"final","method":"test/close_final"}));
        let deadline = Instant::now() + Duration::from_secs(10);
        while controller.kernel.agent_registry().get(&controller.pid).is_some() {
            assert!(Instant::now() < deadline, "actual subprocess must retire");
            std::thread::sleep(Duration::from_millis(5));
        }
        let final_delivery = controller.read(0);
        assert!(final_delivery.closed && final_delivery.retired);
        assert_eq!(final_delivery.frames.len(), 2);
        let SessionPayload::Rpc { message } = &final_delivery.frames[0].payload else { panic!("lost final response") };
        assert_eq!(message["result"]["final"], true);
        assert!(matches!(final_delivery.frames[1].payload, SessionPayload::Closed { .. }));
        assert!(controller.submit(2, json!({"jsonrpc":"2.0","id":2,"method":"initialize"})).is_err());
        assert!(controller.kernel.agent_registry().register(kernel::core::agents::registry::AgentDescriptor {
            pid: controller.pid.clone(), name: "replacement".into(), owner_id: "operator".into(), zone_id: "root".into(), ..Default::default()
        }));
        assert!(controller.submit(2, json!({"jsonrpc":"2.0","id":2,"method":"initialize"})).is_err());
        assert_eq!(controller.read(0).frames.len(), 2);
        controller.kernel.agent_registry().kill(&controller.pid, 0).unwrap();
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subprocess_streams_approvals_and_accepts_cancel_without_public_fd_streams() {
    let kernel = session_kernel("worker");
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
        let native = started["os_pid"].as_u64().expect("real child OS PID");
        assert_eq!(pid, native.to_string());
        assert_ne!(native, u64::from(std::process::id()));
        for fd in 0..3 { assert!(kernel.sys_stat(&format!("/proc/{pid}/fd/{fd}"), "root").is_none()); }
        let mut codec = SessionCodec::new(endpoint.clone(), SessionSide::Controller).unwrap();
        let mut offset = 0;
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":1}}));
        let initialized = receive(&kernel, &endpoint, &mut codec, &mut offset);
        assert_eq!(initialized["id"], 0, "initialize response: {initialized}");
        assert_eq!(initialized["result"]["_meta"]["nativePid"], native, "PID must be the actual Python process, not the broker");
        let unbound = call(&kernel, "get_session_v1", json!({"session_id":pid})).unwrap();
        assert!(unbound.get("durable_session_id").is_none());
        assert_eq!(unbound["state"], "warming_up");
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":"new","method":"session/new","params":{"cwd":"/"}}));
        assert_eq!(receive(&kernel, &endpoint, &mut codec, &mut offset)["result"]["sessionId"], "durable-fixture-session");
        assert_eq!(call(&kernel, "get_session_v1", json!({"session_id":pid})).unwrap()["durable_session_id"], "durable-fixture-session");
        let (instance, _) = kernel.agent_registry().get_instance(pid).unwrap();
        assert!(kernel.agent_registry().is_managed_host_bound(&instance));
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

fn wait_for_close(
    kernel: &Kernel,
    endpoint: &SessionEndpoint,
    codec: &mut SessionCodec,
    offset: &mut usize,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some((bytes, next)) = kernel
            .stream_read_at(&endpoint.transcript, *offset)
            .unwrap()
        {
            *offset = next;
            if let Some(SessionPayload::Closed { reason }) = codec.decode(&bytes).unwrap() {
                return reason;
            }
        }
        assert!(
            Instant::now() < deadline,
            "expected original connection closure"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selected_raw_resume_binds_only_after_the_original_load_response() {
    let kernel = session_kernel("resume-worker");
    tokio::task::spawn_blocking(move || {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/session_agent.py");
        let python = if cfg!(windows) { "python" } else { "python3" };
        let environment: std::collections::HashMap<String, String> = std::env::vars().collect();
        let started = call(&kernel, "start_session_v1", json!({
            "agent_id":"resume-worker", "resume_session_id":"durable-fixture-session",
            "spawn_spec":{"cmd":python,"args":["-u",fixture],"env":environment}
        })).unwrap();
        let pid = started["session_id"].as_str().unwrap();
        assert!(started.get("durable_session_id").is_none());
        let endpoint: SessionEndpoint = serde_json::from_value(started["session_endpoint"].clone()).unwrap();
        let (instance, _) = kernel.agent_registry().get_instance(pid).unwrap();
        assert!(!kernel.agent_registry().is_managed_host_bound(&instance));
        let mut codec = SessionCodec::new(endpoint.clone(), SessionSide::Controller).unwrap();
        let mut offset = 0;
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1}}));
        receive(&kernel, &endpoint, &mut codec, &mut offset);
        assert!(call(&kernel, "get_session_v1", json!({"session_id":pid})).unwrap().get("durable_session_id").is_none());
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":2,"method":"session/load","params":{"sessionId":"durable-fixture-session","cwd":"/"}}));
        assert_eq!(receive(&kernel, &endpoint, &mut codec, &mut offset), json!({"jsonrpc":"2.0","id":2,"result":{}}));
        assert_eq!(call(&kernel, "get_session_v1", json!({"session_id":pid})).unwrap()["durable_session_id"], "durable-fixture-session");
        assert!(kernel.agent_registry().is_managed_host_bound(&instance));
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":3,"method":"test/counts"}));
        assert_eq!(receive(&kernel, &endpoint, &mut codec, &mut offset)["result"], json!({"new":0,"load":1}));
        call(&kernel, "cancel_v2", json!({"session_id":pid,"channel_id":endpoint.channel_id})).unwrap();
        wait_for_close(&kernel, &endpoint, &mut codec, &mut offset);
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_raw_load_preserves_error_and_refuses_fresh_fallback() {
    let kernel = session_kernel("missing-worker");
    tokio::task::spawn_blocking(move || {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/session_agent.py");
        let python = if cfg!(windows) { "python" } else { "python3" };
        let environment: std::collections::HashMap<String, String> = std::env::vars().collect();
        let started = call(&kernel, "start_session_v1", json!({
            "agent_id":"missing-worker", "resume_session_id":"missing",
            "spawn_spec":{"cmd":python,"args":["-u",fixture],"env":environment}
        })).unwrap();
        let pid = started["session_id"].as_str().unwrap();
        let endpoint: SessionEndpoint = serde_json::from_value(started["session_endpoint"].clone()).unwrap();
        let mut codec = SessionCodec::new(endpoint.clone(), SessionSide::Controller).unwrap();
        let mut offset = 0;
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":1,"method":"session/load","params":{"sessionId":"missing"}}));
        let response = receive(&kernel, &endpoint, &mut codec, &mut offset);
        assert_eq!(response["error"], json!({"code":-32002,"message":"not found","data":{"sessionId":"missing"}}));
        assert!(call(&kernel, "get_session_v1", json!({"session_id":pid})).unwrap().get("durable_session_id").is_none());
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":2,"method":"test/counts"}));
        assert_eq!(receive(&kernel, &endpoint, &mut codec, &mut offset)["result"], json!({"new":0,"load":1}));
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":3,"method":"session/new","params":{"cwd":"/"}}));
        assert!(wait_for_close(&kernel, &endpoint, &mut codec, &mut offset).contains("one durable session establishment"));
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mismatched_raw_load_success_cannot_publish_a_durable_binding() {
    let kernel = session_kernel("mismatch-worker");
    tokio::task::spawn_blocking(move || {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/session_agent.py");
        let python = if cfg!(windows) { "python" } else { "python3" };
        let environment: std::collections::HashMap<String, String> = std::env::vars().collect();
        let started = call(&kernel, "start_session_v1", json!({
            "agent_id":"mismatch-worker", "resume_session_id":"wrong-load-result",
            "spawn_spec":{"cmd":python,"args":["-u",fixture],"env":environment}
        })).unwrap();
        let pid = started["session_id"].as_str().unwrap();
        let (instance, _) = kernel.agent_registry().get_instance(pid).unwrap();
        let endpoint: SessionEndpoint = serde_json::from_value(started["session_endpoint"].clone()).unwrap();
        let mut codec = SessionCodec::new(endpoint.clone(), SessionSide::Controller).unwrap();
        let mut offset = 0;
        send(&kernel, &endpoint, &mut codec, json!({"jsonrpc":"2.0","id":1,"method":"session/load","params":{"sessionId":"wrong-load-result"}}));
        assert!(wait_for_close(&kernel, &endpoint, &mut codec, &mut offset).contains("another durable session ID"));
        assert!(!kernel.agent_registry().is_managed_host_bound(&instance));
    }).await.unwrap();
}

/// Cancellation reaps the old PCB immediately; its child supervisor can still
/// drain inherited stdio. Simulate allocator reuse through a new registration
/// and exercise that delayed supervisor against the real subprocess adapter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retired_subprocess_cleanup_preserves_a_reused_pid() {
    let kernel = session_kernel("retired-worker");
    tokio::task::spawn_blocking(move || {
        struct Release { path: std::path::PathBuf, active: bool }
        impl Drop for Release {
            fn drop(&mut self) {
                if self.active { let _ = std::fs::write(&self.path, b"release"); }
            }
        }
        let mut gate = Release {
            path: std::env::temp_dir().join(format!("nexus-pid-reuse-{}", uuid::Uuid::new_v4())),
            active: true,
        };
        let python = if cfg!(windows) { "python" } else { "python3" };
        let grandchild = "import os,sys,time; deadline=time.monotonic()+15; exec('while not os.path.exists(sys.argv[1]) and time.monotonic()<deadline: time.sleep(0.02)')";
        let parent = "import json,subprocess,sys,time; subprocess.Popen([sys.executable,'-u','-c',sys.argv[1],sys.argv[2]]); print(json.dumps({'jsonrpc':'2.0','method':'fixture/ready'}),flush=True); time.sleep(30)";
        let environment: std::collections::HashMap<String, String> = std::env::vars().collect();
        let started = call(&kernel, "start_session_v1", json!({
            "agent_id":"retired-worker", "spawn_spec":{
                "cmd":python,"args":["-u","-c",parent,grandchild,gate.path],"env":environment
            }
        })).unwrap();
        let pid = started["session_id"].as_str().unwrap();
        assert_eq!(pid, started["os_pid"].as_u64().unwrap().to_string());
        let endpoint: SessionEndpoint = serde_json::from_value(started["session_endpoint"].clone()).unwrap();
        let mut codec = SessionCodec::new(endpoint.clone(), SessionSide::Controller).unwrap();
        let mut offset = 0;
        assert_eq!(receive(&kernel, &endpoint, &mut codec, &mut offset)["method"], "fixture/ready");
        call(&kernel, "cancel_v2", json!({"session_id":pid,"channel_id":endpoint.channel_id})).unwrap();
        assert!(kernel.agent_registry().get(pid).is_none());
        // Registration is deliberately controlled; no assumption about when
        // the native allocator will choose this numeric PID again is needed.
        assert!(kernel.agent_registry().register(kernel::core::agents::registry::AgentDescriptor {
            pid: pid.into(), name: "replacement-worker".into(), owner_id: "operator".into(),
            zone_id: "root".into(), ..Default::default()
        }));
        std::fs::write(&gate.path, b"release").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some((data, next)) = kernel.stream_read_at(&endpoint.transcript, offset).unwrap() {
                offset = next;
                if let Some(SessionPayload::Closed { .. }) = codec.decode(&data).unwrap() {
                    break;
                }
            }
            assert!(Instant::now() < deadline, "old supervisor must drain and close");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Closed is appended just before the final lifecycle call. Observe the
        // replacement while the supervisor returns to ensure that call ran.
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            let desc = kernel.agent_registry().get(pid).expect("old cleanup removed the replacement");
            assert_eq!(desc.name, "replacement-worker");
            assert_eq!(desc.state, kernel::core::agents::registry::AgentState::Registered);
            std::thread::sleep(Duration::from_millis(10));
        }
        kernel.agent_registry().kill(pid, 0).unwrap();
        // The grandchild has closed both inherited pipes by this point.
        std::fs::remove_file(&gate.path).unwrap();
        gate.active = false;
    }).await.unwrap();
}
