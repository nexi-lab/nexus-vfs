//! The gate and the A2A `from`-stamp both claim `*/transcript`, both
//! rewrite, and both must survive.
//!
//! This is the test that matters most for this crate, because the failure
//! it guards against is silent. Two mutating hooks on one path return
//! their rewrites against the content they were handed; if the dispatcher
//! does not thread the chain, whichever ran last wins and the other's
//! rewrite is gone with no error anywhere. Concretely the node would
//! either ship an unredacted identifier or ship a forgeable `from`,
//! decided by nothing more than the order of `default_service_decls`.
//!
//! Driven through `stream_write_nowait` rather than the hook trait
//! directly: the A2A transcript is a DT_STREAM, so that is the write path
//! a real message takes, and it exercises `apply_mutating_write_hooks`
//! end to end.

use std::sync::Arc;

use a2a::{conversation_id, conversation_transcript_path, install_a2a_stamp_hook};
use egress_gate::{service_decl_deterministic, EgressPlane, GatePolicy};
use kernel::kernel::{Kernel, OperationContext};

/// Checksum-valid GB 11643 specimen, issued to nobody.
const ID_SPECIMEN: &str = "11010519491231002X";

fn transcript() -> String {
    conversation_transcript_path(&conversation_id("win-ai", "mac-ai"))
}

/// A forged `from` plus a sensitive identifier in the body — one message
/// that needs both guarantees applied to it.
fn forged_message_with_id() -> Vec<u8> {
    format!(r#"{{"from":"impostor","to":"mac-ai","body":"身份证 {ID_SPECIMEN}"}}"#).into_bytes()
}

fn write_and_read_back(kernel: &Arc<Kernel>, body: &[u8]) -> serde_json::Value {
    let mbox = transcript();
    kernel
        .create_stream(&mbox, 64 * 1024)
        .expect("create the mailbox stream");
    let win = OperationContext::new("operator", "root", false, Some("win-ai"), false);
    kernel
        .stream_write_nowait(&mbox, body, &win)
        .expect("authenticated transcript write must be accepted");
    let (data, _next) = kernel
        .stream_read_at(&mbox, 0)
        .expect("read")
        .expect("one entry present");
    serde_json::from_slice(&data).expect("the written frame must still be valid JSON")
}

fn assert_both_guarantees_held(envelope: &serde_json::Value) {
    assert_eq!(
        envelope.get("from").and_then(|v| v.as_str()),
        Some("win-ai"),
        "the A2A stamp must survive the gate's rewrite — `from` is the \
         unforgeable-sender guarantee"
    );
    let body = envelope
        .get("body")
        .and_then(|v| v.as_str())
        .expect("body preserved");
    assert!(
        !body.contains(ID_SPECIMEN),
        "the identifier must not leave the node: {body}"
    );
    assert!(
        body.contains("[REDACTED:PRC-ID]"),
        "the gate's redaction must survive the stamp: {body}"
    );
}

#[test]
fn stamp_then_gate_both_apply() {
    let kernel = Arc::new(Kernel::new());
    install_a2a_stamp_hook(&kernel, /* fail_closed */ true).expect("install stamp");
    (service_decl_deterministic().install)(&kernel).expect("install gate");

    assert_both_guarantees_held(&write_and_read_back(&kernel, &forged_message_with_id()));
}

#[test]
fn gate_then_stamp_both_apply() {
    // The reverse registration order must reach the same result. If it
    // does not, the node's guarantees depend on a service list's ordering,
    // which is not a property anyone can audit.
    let kernel = Arc::new(Kernel::new());
    (service_decl_deterministic().install)(&kernel).expect("install gate");
    install_a2a_stamp_hook(&kernel, /* fail_closed */ true).expect("install stamp");

    assert_both_guarantees_held(&write_and_read_back(&kernel, &forged_message_with_id()));
}

#[test]
fn clean_message_is_stamped_and_otherwise_untouched() {
    let kernel = Arc::new(Kernel::new());
    install_a2a_stamp_hook(&kernel, /* fail_closed */ true).expect("install stamp");
    (service_decl_deterministic().install)(&kernel).expect("install gate");

    let envelope = write_and_read_back(
        &kernel,
        br#"{"from":"impostor","to":"mac-ai","body":"the quarterly rollup, please"}"#,
    );
    assert_eq!(
        envelope.get("from").and_then(|v| v.as_str()),
        Some("win-ai")
    );
    assert_eq!(
        envelope.get("body").and_then(|v| v.as_str()),
        Some("the quarterly rollup, please"),
        "a clean body must pass through byte-identical"
    );
}

#[test]
fn deny_policy_aborts_the_stream_write() {
    // Under a deny posture the write does not land at all — the hook's
    // `Err` propagates out of `apply_mutating_write_hooks`, so there is
    // nothing in the stream to read.
    let kernel = Arc::new(Kernel::new());
    install_a2a_stamp_hook(&kernel, /* fail_closed */ true).expect("install stamp");
    egress_gate::install_egress_content_gate(
        &kernel,
        Arc::new(egress_gate::DeterministicRules::new()),
        GatePolicy::deny_on_finding(),
        EgressPlane::a2a_transcripts(),
    )
    .expect("install gate");

    let mbox = transcript();
    kernel
        .create_stream(&mbox, 64 * 1024)
        .expect("create the mailbox stream");
    let win = OperationContext::new("operator", "root", false, Some("win-ai"), false);
    assert!(
        kernel
            .stream_write_nowait(&mbox, &forged_message_with_id(), &win)
            .is_err(),
        "a deny verdict must abort the write"
    );
    assert!(
        kernel.stream_read_at(&mbox, 0).expect("read").is_none(),
        "a denied write must leave nothing in the stream"
    );
}

#[test]
fn a_path_the_gate_does_not_claim_is_untouched() {
    let kernel = Arc::new(Kernel::new());
    (service_decl_deterministic().install)(&kernel).expect("install gate");

    // Same write RPC, same sensitive content, a leaf the gate never
    // claimed — so it must land byte-identical.
    let path = "/conversations/abc/scratch";
    kernel
        .create_stream(path, 64 * 1024)
        .expect("create stream");
    let body = format!("身份证 {ID_SPECIMEN}");
    let ctx = OperationContext::new("operator", "root", false, Some("win-ai"), false);
    kernel
        .stream_write_nowait(path, body.as_bytes(), &ctx)
        .expect("an unclaimed path must not be gated");
    let (data, _next) = kernel
        .stream_read_at(path, 0)
        .expect("read")
        .expect("one entry present");
    assert_eq!(
        data,
        body.as_bytes(),
        "the gate must not rewrite content on paths it never claimed"
    );
}
