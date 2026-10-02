//! Exercise the public RPC dispatch and provider seam together.
use kernel::core::agents::registry::{AgentDescriptor, AgentState};
use kernel::kernel::{Kernel, OperationContext};
use managed_agent::{install_managed_agent_with_spawn, SpawnHandle, SpawnOptions, SpawnTask};
use serde_json::{json, Value};
use std::sync::Arc;

struct Provider;
struct Handle(String);
impl SpawnHandle for Handle {
    fn abort(&self) {}
    fn durable_session_id(&self) -> Option<&str> {
        Some(&self.0)
    }
}
impl SpawnTask<Kernel> for Provider {
    fn spawn(
        &self,
        _: Arc<Kernel>,
        _: AgentDescriptor,
        _: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>,
    ) -> Result<Box<dyn SpawnHandle>, String> {
        Ok(Box::new(Handle("durable-test-session".into())))
    }
    fn spawn_with_options(
        &self,
        kernel: Arc<Kernel>,
        desc: AgentDescriptor,
        options: SpawnOptions,
        observer: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>,
    ) -> Result<Box<dyn SpawnHandle>, String> {
        match options.resume_session_id {
            Some(id) => Ok(Box::new(Handle(id))),
            None => self.spawn(kernel, desc, observer),
        }
    }
}
struct LegacyProvider;
impl SpawnTask<Kernel> for LegacyProvider {
    fn spawn(
        &self,
        _: Arc<Kernel>,
        _: AgentDescriptor,
        _: Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>,
    ) -> Result<Box<dyn SpawnHandle>, String> {
        Ok(Box::new(Handle("legacy-session".into())))
    }
}
fn call(kernel: &Kernel, method: &str, payload: Value) -> Result<Value, String> {
    let context = OperationContext::new("operator", "root", true, None, true);
    let bytes = kernel
        .dispatch_rust_call(
            "managed_agent",
            method,
            payload.to_string().as_bytes(),
            &context,
        )
        .expect("installed service")
        .map_err(|e| format!("{e:?}"))?;
    Ok(serde_json::from_slice(&bytes).unwrap())
}
#[test]
fn durable_identity_survives_a_new_pid_without_changing_get_and_cancel() {
    let kernel = Arc::new(Kernel::new());
    install_managed_agent_with_spawn(&kernel, Arc::new(Provider)).unwrap();
    let first = call(&kernel, "start_session_v1", json!({"agent_id":"agent"})).unwrap();
    let pid = first["session_id"].as_str().unwrap();
    let sid = first["durable_session_id"].as_str().unwrap();
    assert!(pid.starts_with("pid-"));
    assert_ne!(pid, sid);
    let snapshot = call(&kernel, "get_session_v1", json!({"session_id":pid})).unwrap();
    assert_eq!(snapshot["durable_session_id"], sid);
    assert!(call(&kernel, "get_session_v1", json!({"session_id":sid})).is_err());
    assert_eq!(
        call(
            &kernel,
            "cancel_v1",
            json!({"session_id":pid,"mode":"session"})
        )
        .unwrap()["cancelled"],
        true
    );
    let second = call(
        &kernel,
        "start_session_v1",
        json!({"agent_id":"agent","resume_session_id":sid}),
    )
    .unwrap();
    assert_ne!(second["session_id"], pid);
    assert_eq!(second["durable_session_id"], sid);
}
#[test]
fn providers_without_recovery_reject_it_instead_of_starting_fresh() {
    let kernel = Arc::new(Kernel::new());
    install_managed_agent_with_spawn(&kernel, Arc::new(LegacyProvider)).unwrap();
    assert!(call(&kernel, "start_session_v1", json!({"agent_id":"legacy"})).is_ok());
    let error = call(
        &kernel,
        "start_session_v1",
        json!({"agent_id":"legacy","resume_session_id":"existing"}),
    )
    .unwrap_err();
    assert!(
        error.contains("does not support resume_session_id"),
        "{error}"
    );
}
#[test]
fn raw_spawns_and_paths_cannot_be_used_as_durable_recovery() {
    let kernel = Arc::new(Kernel::new());
    install_managed_agent_with_spawn(&kernel, Arc::new(Provider)).unwrap();
    for id in ["", "../outside", "/sessions/other", "a\\b"] {
        assert!(call(
            &kernel,
            "start_session_v1",
            json!({"agent_id":"agent","resume_session_id":id})
        )
        .is_err());
    }
    assert!(call(
        &kernel,
        "start_session_v1",
        json!({"agent_id":"agent","resume_session_id":"saved","spawn_spec":{"cmd":"echo"}})
    )
    .is_err());
    let slim = Arc::new(Kernel::new());
    managed_agent::install_managed_agent(&slim).unwrap();
    assert!(call(
        &slim,
        "start_session_v1",
        json!({"agent_id":"agent","resume_session_id":"saved"})
    )
    .is_err());
    assert!(call(&slim, "start_session_v1", json!({"agent_id":"agent"}))
        .unwrap()
        .get("durable_session_id")
        .is_none());
}
