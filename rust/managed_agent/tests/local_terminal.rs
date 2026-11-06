#![cfg(feature = "subprocess-host")]

//! Real managed-service dispatch and local launcher. Terminal ownership itself
//! is exercised by subprocess's native PTY/ConPTY suite, not inferred here.

#[path = "common/session_control.rs"]
mod session_control;

use std::sync::Arc;
use std::time::{Duration, Instant};

use a2a::session::{SessionCodec, SessionEndpoint, SessionSide};
use kernel::kernel::OperationContext;
use serde_json::{json, Value};
use subprocess::terminal::{connect_bootstrap, TerminalLauncher, BOOTSTRAP_ENV};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use session_control::{call, receive, send, session_kernel};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_terminal_uses_managed_authorization_control_and_instance_retirement() {
    let launcher = TerminalLauncher::bind().await.unwrap();
    let offer = serde_json::to_value(launcher.offer()).unwrap();
    let kernel = session_kernel("terminal-worker");
    let control_kernel = Arc::clone(&kernel);
    let controller = tokio::task::spawn_blocking(move || {
        let request = json!({"agent_id":"terminal-worker", "local_launch":offer});
        // A public user ID alone must not consume a launch capability or
        // bypass the existing verified-controller admission requirement.
        let stranger = OperationContext::new("stranger", "root", false, None, false);
        assert!(control_kernel
            .dispatch_rust_call(
                "managed_agent",
                "start_session_v1",
                request.to_string().as_bytes(),
                &stranger
            )
            .unwrap()
            .is_err());
        let started = call(&control_kernel, "start_session_v1", request).unwrap();
        assert!(
            started["os_pid"].is_null(),
            "a delegated launch must not claim a daemon-attested OS PID"
        );
        let pid = started["session_id"].as_str().unwrap();
        let endpoint: SessionEndpoint =
            serde_json::from_value(started["session_endpoint"].clone()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let snapshot =
                call(&control_kernel, "get_session_v1", json!({"session_id":pid})).unwrap();
            if snapshot["state"] == "ready" {
                assert_eq!(snapshot["durable_session_id"], "terminal-durable-fixture");
                assert_eq!(snapshot["owner_id"], "operator");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "native runtime never became ready: {snapshot}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut codec = SessionCodec::new(endpoint.clone(), SessionSide::Controller).unwrap();
        let mut offset = 0;
        send(
            &control_kernel,
            &endpoint,
            &mut codec,
            json!({"jsonrpc":"2.0","id":1,"method":"fixture/echo","params":{"text":"control only"}}),
        );
        let answer = receive(&control_kernel, &endpoint, &mut codec, &mut offset);
        assert_eq!(
            answer,
            json!({"jsonrpc":"2.0","id":1,"result":{"text":"control only"}})
        );
        // Native and cohost transitions use the same registry writer; private
        // lifecycle notifications must not leak into the controller's ACP lane.
        for (id, state) in [(2, "busy"), (3, "awaiting_input"), (4, "ready")] {
            send(
                &control_kernel,
                &endpoint,
                &mut codec,
                json!({"jsonrpc":"2.0","id":id,"method":"fixture/state","params":{"state":state}}),
            );
            let reply = receive(&control_kernel, &endpoint, &mut codec, &mut offset);
            assert_eq!(reply["id"], id);
            let snapshot =
                call(&control_kernel, "get_session_v1", json!({"session_id":pid})).unwrap();
            assert_eq!(snapshot["state"], state);
            assert_eq!(snapshot["durable_session_id"], "terminal-durable-fixture");
        }
        send(
            &control_kernel,
            &endpoint,
            &mut codec,
            json!({"jsonrpc":"2.0","id":5,"method":"fixture/session","params":{"session_id":"terminal-replaced-fixture"}}),
        );
        let reply = receive(&control_kernel, &endpoint, &mut codec, &mut offset);
        assert_eq!(reply["id"], 5);
        let snapshot = call(&control_kernel, "get_session_v1", json!({"session_id":pid})).unwrap();
        assert_eq!(snapshot["durable_session_id"], "terminal-replaced-fixture");
        assert_eq!(snapshot["session_endpoint"], started["session_endpoint"]);
        let stopped = call(
            &control_kernel,
            "cancel_v2",
            json!({"session_id":pid,"channel_id":endpoint.channel_id}),
        )
        .unwrap();
        assert_eq!(stopped["cancelled"], true);
        assert!(call(&control_kernel, "get_session_v1", json!({"session_id":pid})).is_err());
    });
    let binary = std::env::current_exe().unwrap();
    let argv = vec![
        binary.display().to_string(),
        "--exact".into(),
        "native_runtime_fixture".into(),
        "--ignored".into(),
        "--nocapture".into(),
    ];
    let exit = launcher
        .run(argv, std::env::vars().collect(), std::path::Path::new("."))
        .await
        .unwrap();
    controller.await.unwrap();
    assert_eq!(
        exit.code,
        Some(0),
        "native control EOF should allow graceful exit"
    );
    assert_eq!(exit.signal, None);
}

#[test]
#[ignore = "native runtime fixture executed by the real local launcher"]
fn native_runtime_fixture() {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let offer = serde_json::from_str(&std::env::var(BOOTSTRAP_ENV).unwrap()).unwrap();
        let (mut stream, grant) = connect_bootstrap(offer).await.unwrap();
        assert_eq!(grant["instance"]["name"], "terminal-worker");
        assert_eq!(grant["instance"]["owner_id"], "operator");
        assert_eq!(grant["instance"]["zone_id"], "root");
        let readiness = json!({"jsonrpc":"2.0", "method":contracts::local_launch::TERMINAL_READY_METHOD,
            "params":{"session_id":"terminal-durable-fixture"}});
        stream.write_all(format!("{readiness}\n").as_bytes()).await.unwrap();
        // This output must stay on inherited stdout, never enter the ACP wire.
        println!("NATIVE_TERMINAL_STDOUT");
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await.unwrap() {
            let request: Value = serde_json::from_str(&line).unwrap();
            if request["method"] == "fixture/state" {
                let state = json!({"jsonrpc":"2.0","method":contracts::local_launch::TERMINAL_STATE_METHOD,
                    "params":{"state":request["params"]["state"],"reason":null}});
                writer.write_all(format!("{state}\n").as_bytes()).await.unwrap();
            } else if request["method"] == "fixture/session" {
                let identity = json!({"jsonrpc":"2.0","method":contracts::local_launch::TERMINAL_SESSION_METHOD,
                    "params":request["params"]});
                writer.write_all(format!("{identity}\n").as_bytes()).await.unwrap();
            } else {
                assert_eq!(request["method"], "fixture/echo");
            }
            let reply = json!({"jsonrpc":"2.0", "id":request["id"], "result":request["params"]});
            writer.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
        }
    });
}
