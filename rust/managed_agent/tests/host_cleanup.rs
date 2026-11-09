//! Real service/registry composition; the runtime body is an explicit fixture.
use kernel::core::agents::host_cleanup::{HostCleanupOutcome, ManagedHostCleanup};
use kernel::core::agents::registry::{AgentDescriptor, AgentState};
use kernel::kernel::{Kernel, OperationContext};
use managed_agent::{install_managed_agent_with_spawn, SpawnHandle, SpawnOptions, SpawnTask};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

type Observer = Arc<dyn Fn(AgentState, Option<String>) + Send + Sync>;
#[derive(Default)]
struct Body {
    owner: Mutex<Option<(ManagedHostCleanup, Observer)>>,
    stops: AtomicUsize,
    dropped_handles: AtomicUsize,
    malformed: bool,
    cancel_during_spawn: bool,
    complete_during_spawn: bool,
}
struct Handle {
    body: Arc<Body>,
    endpoint: Option<a2a::session::SessionEndpoint>,
    stopped: AtomicBool,
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.body.dropped_handles.fetch_add(1, Ordering::SeqCst);
    }
}
impl SpawnHandle for Handle {
    fn abort(&self) {
        if !self.stopped.swap(true, Ordering::SeqCst) {
            self.body.stops.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn session_endpoint(&self) -> Option<&a2a::session::SessionEndpoint> {
        self.endpoint.as_ref()
    }
    fn durable_session_id(&self) -> Option<&str> {
        Some("session-original-transcript")
    }
}
struct Provider(Arc<Body>);
impl SpawnTask<Kernel> for Provider {
    fn spawn(
        &self,
        _: Arc<Kernel>,
        _: AgentDescriptor,
        _: Observer,
    ) -> Result<Box<dyn SpawnHandle>, String> {
        panic!("the legacy startup must not be used")
    }
    fn spawn_with_cleanup(
        &self,
        kernel: Arc<Kernel>,
        desc: AgentDescriptor,
        options: SpawnOptions,
        cleanup: ManagedHostCleanup,
        observer: Observer,
    ) -> Result<Box<dyn SpawnHandle>, String> {
        observer(AgentState::Ready, None);
        if self.0.complete_during_spawn {
            // No runtime threads exist in this fixture. Model the real race:
            // all joins and the original terminal callback finish before the
            // provider returns its newly created handle to the service.
            assert!(cleanup.complete(Ok(())));
            observer(AgentState::Terminated, None);
        }
        *self.0.owner.lock().unwrap() = Some((cleanup, observer));
        if self.0.cancel_during_spawn {
            assert!(kernel.agent_registry().kill(&desc.pid, 0).is_err());
        }
        Ok(Box::new(Handle {
            body: Arc::clone(&self.0),
            endpoint: if self.0.malformed {
                None
            } else {
                options.session_endpoint
            },
            stopped: AtomicBool::new(false),
        }))
    }
}
fn call(kernel: &Kernel, method: &str, payload: Value) -> Result<Value, String> {
    let ctx = OperationContext::new("owner", "root", true, Some("controller"), true);
    let bytes = kernel
        .dispatch_rust_call(
            "managed_agent",
            method,
            payload.to_string().as_bytes(),
            &ctx,
        )
        .expect("installed")
        .map_err(|e| format!("{e:?}"))?;
    Ok(serde_json::from_slice(&bytes).unwrap())
}
fn fixture(body: Body) -> (Arc<Kernel>, Arc<Body>) {
    let kernel = Arc::new(Kernel::new());
    let body = Arc::new(body);
    install_managed_agent_with_spawn(&kernel, Arc::new(Provider(Arc::clone(&body)))).unwrap();
    (kernel, body)
}

#[test]
fn cancel_retains_host_until_its_original_completion_and_never_reports_ready() {
    let (kernel, body) = fixture(Body::default());
    let started = call(&kernel, "start_session_v1", json!({"agent_id":"agent"})).unwrap();
    let pid = started["session_id"].as_str().unwrap();
    let (instance, _) = kernel.agent_registry().get_instance(pid).unwrap();
    assert!(kernel.agent_registry().is_managed_host_bound(&instance));
    for _ in 0..2 {
        let error = call(
            &kernel,
            "cancel_v1",
            json!({"session_id":pid,"mode":"session"}),
        )
        .unwrap_err();
        assert!(error.contains("cleanup unconfirmed"), "{error}");
        assert!(call(&kernel, "get_session_v1", json!({"session_id":pid})).is_err());
        assert!(!kernel.agent_registry().reap(pid));
    }
    assert_eq!(body.stops.load(Ordering::SeqCst), 1);
    assert!(kernel.agent_registry().is_current_instance(&instance));
    assert!(!kernel.agent_registry().is_managed_host_bound(&instance));
    let (cleanup, observer) = body.owner.lock().unwrap().as_ref().unwrap().clone();
    assert!(cleanup.complete(Ok(())));
    observer(AgentState::Terminated, None);
    assert_eq!(
        kernel.agent_registry().get(pid).unwrap().state,
        AgentState::Terminated
    );
    assert!(kernel.agent_registry().reap(pid));
}

#[test]
fn premature_terminal_and_second_empty_cleanup_do_not_release_the_writer() {
    let (kernel, body) = fixture(Body::default());
    let started = call(&kernel, "start_session_v1", json!({"agent_id":"agent"})).unwrap();
    let pid = started["session_id"].as_str().unwrap();
    let (cleanup, observer) = body.owner.lock().unwrap().as_ref().unwrap().clone();
    observer(AgentState::Terminated, None);
    assert_eq!(
        kernel.agent_registry().get(pid).unwrap().state,
        AgentState::Ready
    );
    assert_eq!(body.stops.load(Ordering::SeqCst), 1);
    assert!(!cleanup.complete(Err("original writer still running".into())));
    assert!(!cleanup.complete(Ok(())));
    observer(AgentState::Terminated, None);
    kernel.agent_registry().close_all();
    assert!(!kernel.agent_registry().reap(pid));
    assert_eq!(
        cleanup.outcome(),
        HostCleanupOutcome::Unconfirmed("original writer still running".into())
    );
    assert!(!kernel.agent_registry().register(AgentDescriptor {
        pid: pid.into(),
        ..Default::default()
    }));
}

#[test]
fn malformed_handle_and_cancel_during_spawn_keep_custody_and_deliver_stop() {
    for malformed in [false, true] {
        let (kernel, body) = fixture(Body {
            malformed,
            cancel_during_spawn: !malformed,
            ..Default::default()
        });
        assert!(call(&kernel, "start_session_v1", json!({"agent_id":"agent"})).is_err());
        assert_eq!(body.stops.load(Ordering::SeqCst), 1);
        let records = kernel.agent_registry().list(None, None, None, None);
        assert_eq!(records.len(), 1);
        assert!(!kernel.agent_registry().reap(&records[0].pid));
        let (cleanup, _) = body.owner.lock().unwrap().as_ref().unwrap().clone();
        assert_eq!(cleanup.outcome(), HostCleanupOutcome::Pending);
        assert!(cleanup.complete(Ok(())));
        kernel.agent_registry().kill(&records[0].pid, 0).unwrap();
    }
}

#[test]
fn legacy_provider_is_refused_before_creating_any_runtime() {
    struct Legacy;
    impl SpawnTask<Kernel> for Legacy {
        fn spawn(
            &self,
            _: Arc<Kernel>,
            _: AgentDescriptor,
            _: Observer,
        ) -> Result<Box<dyn SpawnHandle>, String> {
            panic!("unqualified legacy provider must not run")
        }
    }
    let kernel = Arc::new(Kernel::new());
    install_managed_agent_with_spawn(&kernel, Arc::new(Legacy)).unwrap();
    let error = call(&kernel, "start_session_v1", json!({"agent_id":"agent"})).unwrap_err();
    assert!(error.contains("joined host cleanup completion"), "{error}");
    assert!(kernel
        .agent_registry()
        .list(None, None, None, None)
        .is_empty());
}

#[test]
fn completed_before_attachment_does_not_retain_an_already_retired_handle() {
    let (kernel, body) = fixture(Body {
        complete_during_spawn: true,
        ..Default::default()
    });
    let error = call(&kernel, "start_session_v1", json!({"agent_id":"agent"})).unwrap_err();
    assert!(
        error.contains("retired before handle attachment"),
        "{error}"
    );
    assert_eq!(body.stops.load(Ordering::SeqCst), 1);
    assert_eq!(body.dropped_handles.load(Ordering::SeqCst), 1);
    let records = kernel.agent_registry().list(None, None, None, None);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, AgentState::Terminated);
}
