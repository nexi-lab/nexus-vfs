//! The model plane — the third way out — gated on what actually goes over
//! the wire.
//!
//! The assertion is made on the HTTP request the OpenAI connector sends
//! upstream, captured by a loopback server, not on the hook's return value.
//! That is the only place "the identifier did not leave" means anything: a
//! hook that rewrote its context but whose rewrite never reached the
//! connector would pass every hook-level test and still leak.
//!
//! Real kernel, real `llm_mount` service, real mount built through the real
//! provider, real connector HTTP. The model is the one thing a test cannot
//! have, so a mock SSE server stands in for it — and records what it was
//! sent.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use egress_gate::{DeterministicRules, EgressPlane, GatePolicy};
use kernel::hal::object_store_provider::{ObjectStoreProvider, ObjectStoreProviderArgs};
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::Kernel;

/// Checksum-valid GB 11643 specimen, issued to nobody.
const ID_SPECIMEN: &str = "11010519491231002X";
const EGRESS_MOUNT: &str = "/cloud-model";
const LOCAL_MOUNT: &str = "/model";

fn sse_body() -> String {
    [
        r#"data: {"model":"m","choices":[{"index":0,"delta":{"content":"ok"}}]}"#,
        r#"data: {"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        r#"data: [DONE]"#,
    ]
    .iter()
    .map(|f| format!("{f}\n\n"))
    .collect()
}

/// A one-shot upstream that hands back the full request it received.
///
/// Reads the header block, then exactly `Content-Length` body bytes, so the
/// capture is the whole request rather than whatever one `read` returned.
fn capturing_upstream() -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut sock, _)) = listener.accept() else {
            return;
        };
        sock.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let header_end = loop {
            let n = sock.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break None;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break Some(i + 4);
            }
        };
        if let Some(end) = header_end {
            let headers = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let want = headers
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while buf.len() < end + want {
                let n = sock.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
        let body = sse_body();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = sock.write_all(resp.as_bytes());
        let _ = sock.flush();
        let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
    });
    (url, rx)
}

fn ctx() -> contracts::OperationContext {
    contracts::OperationContext::new("alice", "root", false, Some("edge-agent"), false)
}

/// Mount an OpenAI connector at `mount`, through the same provider path the
/// daemon's `sys_setattr(DT_MOUNT, backend_type="openai")` takes.
fn mount_model(kernel: &Arc<Kernel>, mount: &str, base_url: &str, blob_root: &str) {
    let params: HashMap<String, String> = [
        ("blob_root", blob_root),
        ("base_url", base_url),
        ("api_key", "sk-test"),
        ("default_model", "m"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let peer = kernel::hal::peer::NoopPeerBlobClient::arc();
    let runtime = Arc::clone(kernel.runtime());
    let built = backends::provider::DefaultObjectStoreProvider
        .build(&ObjectStoreProviderArgs {
            backend_type: "openai",
            backend_name: mount.trim_start_matches('/'),
            mount_path: Some(mount),
            backend_params: &params,
            peer_client: &peer,
            self_address: None,
            runtime: &runtime,
        })
        .expect("openai mount builds through the real provider");
    kernel
        .mount(
            mount,
            MountOptions::new(mount.trim_start_matches('/'))
                .with_backend(built.backend.expect("provider returns a backend")),
        )
        .expect("mount");
}

/// A kernel with the LLM driver and the gate, the gate confined to
/// [`EGRESS_MOUNT`] for prompts.
fn gated_kernel(policy: GatePolicy) -> Arc<Kernel> {
    let kernel = Arc::new(Kernel::new());
    let mut planes = EgressPlane::a2a_transcripts();
    planes.push(EgressPlane::under(llm_mount::PROMPT_SUFFIX, [EGRESS_MOUNT]).unwrap());
    kernel
        .bring_up_services(vec![
            llm_mount::service_decl(),
            egress_gate::service_decl(Arc::new(DeterministicRules::new()), policy, planes),
        ])
        .expect("services install");
    kernel
}

fn prompt_with_id() -> Vec<u8> {
    format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"客户身份证 {ID_SPECIMEN}，请汇总"}}]}}"#
    )
    .into_bytes()
}

/// The request body as the upstream received it.
fn upstream_body(rx: &mpsc::Receiver<String>) -> String {
    let req = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the connector must have called upstream");
    req.split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or(req)
}

#[test]
fn a_prompt_to_an_egress_mount_leaves_redacted() {
    let tmp = tempfile::tempdir().unwrap();
    let (url, rx) = capturing_upstream();
    let kernel = gated_kernel(GatePolicy::default());
    mount_model(&kernel, EGRESS_MOUNT, &url, &tmp.path().to_string_lossy());

    kernel
        .write(
            &format!("{EGRESS_MOUNT}/ask-1.prompt"),
            &ctx(),
            &prompt_with_id(),
            0,
        )
        .expect("a redacted prompt is still a prompt");

    let sent = upstream_body(&rx);
    assert!(
        !sent.contains(ID_SPECIMEN),
        "the identifier must not reach the upstream model; it sent: {sent}"
    );
    assert!(
        sent.contains("[REDACTED:PRC-ID]"),
        "the upstream must receive the redacted prompt, not some other body: {sent}"
    );
    assert!(
        sent.contains("请汇总"),
        "everything that was not sensitive must still reach the model: {sent}"
    );
}

#[test]
fn a_prompt_to_a_local_mount_reaches_the_model_intact() {
    // The local model is the one permitted to see customer data. If this
    // fails, the gate has broken the private-data path it exists to protect.
    let tmp = tempfile::tempdir().unwrap();
    let (url, rx) = capturing_upstream();
    let kernel = gated_kernel(GatePolicy::default());
    mount_model(&kernel, LOCAL_MOUNT, &url, &tmp.path().to_string_lossy());

    kernel
        .write(
            &format!("{LOCAL_MOUNT}/ask-1.prompt"),
            &ctx(),
            &prompt_with_id(),
            0,
        )
        .expect("prompt write");

    let sent = upstream_body(&rx);
    assert!(
        sent.contains(ID_SPECIMEN),
        "a local model's prompt must arrive unredacted; it sent: {sent}"
    );
}

#[test]
fn a_denied_prompt_never_reaches_the_upstream() {
    let tmp = tempfile::tempdir().unwrap();
    let (url, rx) = capturing_upstream();
    let kernel = gated_kernel(GatePolicy::deny_on_finding());
    mount_model(&kernel, EGRESS_MOUNT, &url, &tmp.path().to_string_lossy());

    let res = kernel.write(
        &format!("{EGRESS_MOUNT}/ask-1.prompt"),
        &ctx(),
        &prompt_with_id(),
        0,
    );
    assert!(res.is_err(), "a deny verdict must fail the write");
    assert!(
        rx.recv_timeout(Duration::from_secs(3)).is_err(),
        "a denied prompt must not open a connection to the model at all"
    );
}

fn model_directory_alias(kernel: &Kernel) -> &'static str {
    use kernel::kernel::syscall::KernelSyscall;
    let alias = "/proc/edge/workspace/cloud";
    KernelSyscall::sys_setattr(
        kernel,
        alias,
        6,
        "",
        None,
        None,
        None,
        "memory",
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
        Some(EGRESS_MOUNT),
        None,
        None,
    )
    .expect("register a model directory alias");
    alias
}

#[test]
fn a_directory_alias_cannot_bypass_redaction_on_the_egress_mount() {
    let tmp = tempfile::tempdir().unwrap();
    let (url, rx) = capturing_upstream();
    let kernel = gated_kernel(GatePolicy::default());
    mount_model(&kernel, EGRESS_MOUNT, &url, &tmp.path().to_string_lossy());
    let alias = model_directory_alias(&kernel);
    kernel
        .write(
            &format!("{alias}/alias.prompt"),
            &ctx(),
            &prompt_with_id(),
            0,
        )
        .unwrap();
    let sent = upstream_body(&rx);
    assert!(!sent.contains(ID_SPECIMEN));
    assert!(sent.contains("[REDACTED:PRC-ID]"));
}

#[test]
fn a_directory_alias_cannot_bypass_denial_on_the_egress_mount() {
    let tmp = tempfile::tempdir().unwrap();
    let (url, rx) = capturing_upstream();
    let kernel = gated_kernel(GatePolicy::deny_on_finding());
    mount_model(&kernel, EGRESS_MOUNT, &url, &tmp.path().to_string_lossy());
    let alias = model_directory_alias(&kernel);
    assert!(kernel
        .write(
            &format!("{alias}/alias.prompt"),
            &ctx(),
            &prompt_with_id(),
            0
        )
        .is_err());
    assert!(rx.recv_timeout(Duration::from_secs(3)).is_err());
}
