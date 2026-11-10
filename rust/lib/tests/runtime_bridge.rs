use lib::rt::{block_on_portable, block_on_via, OwnedRuntime};

fn inner() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("inner runtime")
}

// block_on_via — the owned-inner-runtime bridge — across all three contexts.
#[test]
fn via_no_ambient_runtime() {
    let rt = inner();
    assert_eq!(block_on_via(rt.handle(), async { 40 + 2 }), 42);
}

#[test]
fn via_multi_thread_ambient() {
    let rt = inner();
    let outer = inner();
    assert_eq!(
        outer.block_on(async { block_on_via(rt.handle(), async { 6 * 7 }) }),
        42
    );
}

#[test]
fn via_current_thread_ambient_does_not_panic() {
    // THE REGRESSION: the co-host managed-agent (current-thread) runtime
    // reaching a federated kernel op. Pre-fix this panicked.
    let rt = inner();
    let agent = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let value = String::from("borrowed across the runtime bridge");
    let observed = agent.block_on(async {
        block_on_via(rt.handle(), async {
            tokio::task::yield_now().await;
            value.as_str()
        })
    });
    assert_eq!(observed, value.as_str());
}

// block_on_portable — the self-contained tool-bridge form — same matrix.
#[test]
fn portable_no_ambient_runtime() {
    assert_eq!(block_on_portable(async { 40 + 2 }), 42);
}

#[test]
fn portable_multi_thread_ambient() {
    let outer = inner();
    let value = String::from("borrowed on the existing executor");
    let observed = outer.block_on(async {
        block_on_portable(async {
            tokio::task::yield_now().await;
            value.as_str()
        })
    });
    assert_eq!(observed, value.as_str());
}

// OwnedRuntime — the drop rule, in the context where a bare drop panics.
#[test]
fn owned_runtime_drops_inside_an_async_context() {
    // The shape that panics with a bare `Runtime`: a fallible constructor that
    // builds one and then returns `Err`, with an ambient runtime around it. What
    // must survive is the error — the caller's reason, not a tokio backtrace.
    fn fails_after_building_one() -> Result<OwnedRuntime, &'static str> {
        let _rt = OwnedRuntime::new(inner());
        Err("the reason the operator needs to see")
    }
    let outer = inner();
    let reason = outer.block_on(async { fails_after_building_one().err() });
    assert_eq!(reason, Some("the reason the operator needs to see"));
}

#[test]
fn owned_runtime_still_runs_work_and_drops_from_sync() {
    let rt = OwnedRuntime::new(inner());
    // Deref: an owner uses it exactly like the `Runtime` it wraps.
    assert_eq!(rt.block_on(async { 40 + 2 }), 42);
    assert_eq!(block_on_via(rt.handle(), async { 42 }), 42);
    drop(rt); // no ambient runtime: the blocking shutdown, as intended
}

#[test]
fn portable_current_thread_ambient_does_not_panic() {
    // The bash / MCP / VLM tool-call shape from a current-thread agent turn.
    let agent = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let value = String::from("borrowed across an ephemeral executor");
    let observed = agent.block_on(async {
        block_on_portable(async {
            tokio::task::yield_now().await;
            value.as_str()
        })
    });
    assert_eq!(observed, value.as_str());
}
