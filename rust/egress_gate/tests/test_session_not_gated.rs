//! A managed session's turns are an A2A conversation (`a2a::session`
//! addresses every session as the transcript between agent and controller).
//! The gate must not redact what a user tells the agent on their own node;
//! only conversations under a configured cross-domain mount are egress.
//!
//! This pins the failure the earlier default had: gating every transcript
//! would have redacted a customer's own prompts to the box's local agent the
//! moment the gate was built into the session runtime.

use std::sync::Arc;

use a2a::{conversation_id, conversation_transcript_path, install_a2a_stamp_hook};
use egress_gate::{GateConfig, GatePolicy};
use kernel::kernel::{Kernel, OperationContext};

/// Checksum-valid GB 11643 specimen, issued to nobody.
const ID_SPECIMEN: &str = "11010519491231002X";

fn kernel_with(config: &GateConfig) -> Arc<Kernel> {
    let kernel = Arc::new(Kernel::new());
    install_a2a_stamp_hook(&kernel, true).expect("stamp");
    egress_gate::install_egress_content_gate(
        &kernel,
        config.classifier().expect("classifier"),
        config.policy,
        config.planes(None).expect("planes"),
    )
    .expect("gate");
    kernel
}

fn config(a2a_mounts: &[&str]) -> GateConfig {
    GateConfig {
        policy: GatePolicy::default(),
        model_mounts: Vec::new(),
        a2a_mounts: a2a_mounts.iter().map(|m| m.to_string()).collect(),
        presidio: None,
    }
}

/// Write `body` as `agent` to the transcript at `path`; return the body
/// that landed.
fn send(kernel: &Arc<Kernel>, path: &str, agent: &str, body: &str) -> String {
    kernel.create_stream(path, 64 * 1024).expect("stream");
    let ctx = OperationContext::new("operator", "root", false, Some(agent), false);
    let envelope = serde_json::json!({"from": agent, "to": "peer", "body": body});
    kernel
        .stream_write_nowait(path, envelope.to_string().as_bytes(), &ctx)
        .expect("write");
    let (data, _) = kernel.stream_read_at(path, 0).unwrap().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&data).unwrap();
    v["body"].as_str().unwrap().to_string()
}

/// The address `a2a::session` gives a session between `agent` and the
/// controller that drives it.
fn session_transcript(agent: &str, controller: &str) -> String {
    conversation_transcript_path(&conversation_id(agent, controller))
}

#[test]
fn a_session_turn_is_not_gated_by_default() {
    let kernel = kernel_with(&config(&[]));
    let body = format!("客户身份证 {ID_SPECIMEN}，请核对");
    let landed = send(
        &kernel,
        &session_transcript("edge-agent", "moss"),
        "moss",
        &body,
    );
    assert_eq!(
        landed, body,
        "a user's turn to their own node's agent must arrive intact"
    );
}

#[test]
fn only_transcripts_under_a_cross_domain_mount_are_gated() {
    let kernel = kernel_with(&config(&["/xdomain"]));
    let body = format!("客户身份证 {ID_SPECIMEN}");

    let local = send(
        &kernel,
        &session_transcript("edge-agent", "moss"),
        "moss",
        &body,
    );
    assert_eq!(
        local, body,
        "a local session stays intact beside a gated mount"
    );

    let crossing = send(
        &kernel,
        "/xdomain/conversations/abc/transcript",
        "edge-agent",
        &body,
    );
    assert!(!crossing.contains(ID_SPECIMEN), "{crossing}");
    assert!(crossing.contains("[REDACTED:PRC-ID]"), "{crossing}");
}

#[test]
fn no_configured_plane_means_no_plane() {
    assert!(config(&[]).planes(Some(".prompt")).unwrap().is_empty());
}
