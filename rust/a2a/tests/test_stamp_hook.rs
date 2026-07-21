//! `install_a2a_stamp_hook` registers the `from`-stamp hook so a
//! `chat-with-me` write is rewritten through the exact
//! `dispatch_native_pre_with_replacement` seam `sys_write` uses.
//!
//! The cross-machine stream-wakeup (a replicated `AppendStreamEntry`
//! waking a parked `sys_watch` on a replica) is a generic raft primitive
//! armed by the composition root, NOT a2a — its coverage lives in the
//! raft crate's `test_stream_wakeup_replication`.

use std::sync::Arc;

use a2a::install_a2a_stamp_hook;
use kernel::core::dispatch::{HookContext, HookIdentity, WriteHookCtx};
use kernel::kernel::Kernel;

fn write_ctx(agent_id: &str, content: &[u8]) -> HookContext {
    HookContext::Write(WriteHookCtx {
        path: "/agents/win-ai/chat-with-me".to_string(),
        identity: HookIdentity {
            user_id: "operator".to_string(),
            zone_id: "root".to_string(),
            agent_id: agent_id.to_string(),
            is_admin: false,
        },
        content: content.to_vec(),
        is_new_file: false,
        content_id: None,
        new_version: 0,
        size_bytes: None,
    })
}

#[test]
fn stamps_from_through_dispatch_after_install() {
    let kernel = Arc::new(Kernel::new());
    install_a2a_stamp_hook(&kernel, /* fail_closed */ false).expect("install a2a stamp hook");

    // A forged `from` on a chat-with-me write must be rewritten to the
    // real caller `agent_id` by the registered hook.
    let ctx = write_ctx(
        "win-ai",
        br#"{"from":"impostor","to":"mac-ai","body":"hi"}"#,
    );
    let replacement = kernel
        .dispatch_native_pre_with_replacement(&ctx)
        .expect("hook must accept")
        .expect("hook must REPLACE (from was forged)");
    let envelope: serde_json::Value =
        serde_json::from_slice(&replacement).expect("stamped envelope is valid JSON");
    assert_eq!(
        envelope.get("from").and_then(|v| v.as_str()),
        Some("win-ai"),
        "install_a2a_stamp_hook's hook must rewrite `from` to the caller agent_id"
    );
}

#[test]
fn empty_agent_id_passes_through_unrewritten_when_fail_open() {
    // Fail-open posture (NoAuth bring-up): empty agent_id ⇒ the policy
    // returns None ⇒ no rewrite AND no rejection (behaviour-preserving).
    let kernel = Arc::new(Kernel::new());
    install_a2a_stamp_hook(&kernel, /* fail_closed */ false).expect("install a2a stamp hook");

    let ctx = write_ctx("", br#"{"to":"mac-ai","body":"hi"}"#);
    assert!(
        kernel
            .dispatch_native_pre_with_replacement(&ctx)
            .expect("hook must accept")
            .is_none(),
        "fail-open: empty agent_id must pass through, not rewrite and not reject"
    );
}

#[test]
fn fail_closed_rejects_empty_agent_id_mailbox_write() {
    // Fail-closed posture (auth armed): a mailbox write with no caller
    // agent_id is REJECTED — the pre-hook returns Err, which the dispatch
    // seam surfaces as a write abort. This is what makes `from` unforgeable
    // when auth is on: an unauthenticated writer cannot land a mailbox
    // message at all.
    let kernel = Arc::new(Kernel::new());
    install_a2a_stamp_hook(&kernel, /* fail_closed */ true).expect("install a2a stamp hook");

    let ctx = write_ctx("", br#"{"to":"mac-ai","body":"hi"}"#);
    assert!(
        kernel.dispatch_native_pre_with_replacement(&ctx).is_err(),
        "fail-closed: an empty-agent_id mailbox write must be rejected"
    );

    // A genuine authenticated write still succeeds (and gets stamped) under
    // the same fail-closed posture — the gate rejects only the empty case.
    let authed = write_ctx(
        "win-ai",
        br#"{"from":"impostor","to":"mac-ai","body":"hi"}"#,
    );
    let replacement = kernel
        .dispatch_native_pre_with_replacement(&authed)
        .expect("authenticated mailbox write must be accepted under fail-closed")
        .expect("hook must REPLACE (from was forged)");
    let envelope: serde_json::Value =
        serde_json::from_slice(&replacement).expect("stamped envelope is valid JSON");
    assert_eq!(
        envelope.get("from").and_then(|v| v.as_str()),
        Some("win-ai"),
        "fail-closed still stamps an authenticated write"
    );
}
