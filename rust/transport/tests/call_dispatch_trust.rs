use std::sync::Arc;

use kernel::kernel::{Kernel, OperationContext};
use transport::call_dispatch::dispatch;

fn call(
    kernel: &Arc<Kernel>,
    ctx: &OperationContext,
    method: &str,
    payload: serde_json::Value,
) -> kernel::kernel::vfs_proto::CallResponse {
    dispatch(
        kernel,
        ctx,
        method,
        &serde_json::to_vec(&payload).expect("payload"),
    )
    .expect("dispatch")
    .into_inner()
}

#[test]
fn low_privilege_context_cannot_forge_agent_owner_or_zone() {
    let kernel = Arc::new(Kernel::new());
    let ctx = OperationContext::new("alice", "tenant-a", false, None, false);

    let forged_owner = call(
        &kernel,
        &ctx,
        "agent_register",
        serde_json::json!({
            "name": "forged-owner",
            "owner_id": "bob",
            "zone_id": "tenant-a"
        }),
    );
    assert!(forged_owner.is_error);

    let forged_zone = call(
        &kernel,
        &ctx,
        "agent_register",
        serde_json::json!({
            "name": "forged-zone",
            "owner_id": "alice",
            "zone_id": "tenant-b"
        }),
    );
    assert!(forged_zone.is_error);
}

#[test]
fn low_privilege_context_cannot_signal_another_owners_agent() {
    let kernel = Arc::new(Kernel::new());
    let system = OperationContext::new("cluster-internal", "root", true, None, true);
    let registered = call(
        &kernel,
        &system,
        "agent_register",
        serde_json::json!({
            "name": "bob-agent",
            "owner_id": "bob",
            "zone_id": "tenant-b"
        }),
    );
    assert!(!registered.is_error);
    let registered: serde_json::Value =
        serde_json::from_slice(&registered.payload).expect("registered response");
    let pid = registered["result"]["pid"].as_str().expect("pid");

    let alice = OperationContext::new("alice", "tenant-a", false, None, false);
    let signalled = call(
        &kernel,
        &alice,
        "agent_signal",
        serde_json::json!({"pid": pid, "signal": "SIGTERM"}),
    );
    assert!(signalled.is_error);
}
