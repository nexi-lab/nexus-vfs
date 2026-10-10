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

#[test]
fn agent_get_enforces_ownership_like_every_other_agent_method() {
    let kernel = Arc::new(Kernel::new());
    let system = OperationContext::new("cluster-internal", "root", true, None, true);
    let registered = call(
        &kernel,
        &system,
        "agent_register",
        serde_json::json!({
            "name": "bobs-agent",
            "owner_id": "bob",
            "zone_id": "tenant-b"
        }),
    );
    assert!(!registered.is_error);
    let registered: serde_json::Value =
        serde_json::from_slice(&registered.payload).expect("registered response");
    let pid = registered["result"]["pid"]
        .as_str()
        .expect("pid")
        .to_string();

    // The owner reads their own descriptor.
    let bob = OperationContext::new("bob", "tenant-b", false, None, false);
    let own = call(
        &kernel,
        &bob,
        "agent_get",
        serde_json::json!({ "pid": pid }),
    );
    assert!(!own.is_error, "owner reads own agent");
    let own: serde_json::Value = serde_json::from_slice(&own.payload).expect("own response");
    assert_eq!(own["result"]["owner_id"], "bob");

    // A low-privilege caller is refused the cross-tenant descriptor.
    let alice = OperationContext::new("alice", "tenant-a", false, None, false);
    let denied = call(
        &kernel,
        &alice,
        "agent_get",
        serde_json::json!({ "pid": pid }),
    );
    assert!(denied.is_error, "agent_get must enforce ownership");

    // An admin may read it (the admin/system respect every other agent
    // method applies).
    let admin = OperationContext::new("root-admin", "root", true, None, false);
    let elevated = call(
        &kernel,
        &admin,
        "agent_get",
        serde_json::json!({ "pid": pid }),
    );
    assert!(!elevated.is_error, "admin reads any agent");

    // A missing pid answers with the SAME error as someone else's pid —
    // an error-vs-null split would be an existence oracle.
    let missing = call(
        &kernel,
        &alice,
        "agent_get",
        serde_json::json!({ "pid": "no.such.pid" }),
    );
    assert!(
        missing.is_error,
        "a missing pid must not be distinguishable from someone else's pid"
    );
}
