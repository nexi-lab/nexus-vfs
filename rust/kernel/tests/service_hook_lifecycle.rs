//! Integration tests for service hook lifecycle management.
//!
//! Validates the kernel's service ↔ hook ownership tracking through
//! the handle-based enforced surface (nexus-vfs #125 design):
//!   - `register_service_hook(&ServiceHandle, hook)` records ownership
//!   - `unregister_service` batch-removes owned hooks
//!   - `swap_managed_service` unhooks old service before replacing
//!   - Multi-service hook isolation (unhook one, others survive)
//!   - Hook-only services enlist without RPC surface
//!   - Handle Clone shares one enlist across many install sites
//!   - Non-existent service returns `None` from `service_handle`
//!
//! All tests exercise the public Kernel API only — no `pub(crate)` internals.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use kernel::abc::object_store::{ObjectStore, StorageError, WriteResult};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, OperationContext};
use kernel::service_registry::ServiceLifecycle;
use kernel::{HookContext, HookOutcome, NativeInterceptHook};

// ── Shared test infrastructure ────────────────────────────────────────

/// Minimal in-memory backend for sys_write to succeed.
#[derive(Default)]
struct MemBackend {
    blobs: std::sync::Mutex<HashMap<String, Vec<u8>>>,
}

impl ObjectStore for MemBackend {
    fn name(&self) -> &str {
        "mem"
    }

    fn write_content(
        &self,
        content: &[u8],
        content_id: &str,
        _ctx: &OperationContext,
        offset: u64,
    ) -> Result<WriteResult, StorageError> {
        let mut map = self.blobs.lock().unwrap();
        let entry = map.entry(content_id.to_string()).or_default();
        let start = offset as usize;
        if start > entry.len() {
            entry.resize(start, 0);
        }
        let end = start + content.len();
        if end > entry.len() {
            entry.resize(end, 0);
        }
        entry[start..end].copy_from_slice(content);
        let size = entry.len() as u64;
        Ok(WriteResult {
            content_id: content_id.to_string(),
            version: content_id.to_string(),
            size,
        })
    }

    fn read_content(
        &self,
        content_id: &str,
        _ctx: &OperationContext,
    ) -> Result<Vec<u8>, StorageError> {
        self.blobs
            .lock()
            .unwrap()
            .get(content_id)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(content_id.into()))
    }

    fn get_content_size(&self, content_id: &str) -> Result<u64, StorageError> {
        self.blobs
            .lock()
            .unwrap()
            .get(content_id)
            .map(|d| d.len() as u64)
            .ok_or_else(|| StorageError::NotFound(content_id.into()))
    }
}

/// Counting hook — increments `pre_count` on every `on_pre` call.
struct CountingHook {
    hook_name: String,
    pre_count: Arc<AtomicU32>,
    post_count: Arc<AtomicU32>,
}

impl CountingHook {
    fn new(name: &str) -> (Self, Arc<AtomicU32>, Arc<AtomicU32>) {
        let pre = Arc::new(AtomicU32::new(0));
        let post = Arc::new(AtomicU32::new(0));
        (
            Self {
                hook_name: name.to_string(),
                pre_count: Arc::clone(&pre),
                post_count: Arc::clone(&post),
            },
            pre,
            post,
        )
    }
}

impl NativeInterceptHook for CountingHook {
    fn name(&self) -> &str {
        &self.hook_name
    }

    fn on_pre(&self, _ctx: &HookContext) -> Result<HookOutcome, String> {
        self.pre_count.fetch_add(1, Ordering::SeqCst);
        Ok(HookOutcome::Pass)
    }

    fn on_post(&self, _ctx: &HookContext) {
        self.post_count.fetch_add(1, Ordering::SeqCst);
    }
}

/// Stub ServiceLifecycle — no-op lifecycle for test service registration.
struct StubService {
    type_label: String,
}

impl StubService {
    fn new(label: &str) -> Self {
        Self {
            type_label: label.to_string(),
        }
    }
}

impl ServiceLifecycle for StubService {
    fn start(&self, _timeout_secs: f64) -> Result<(), String> {
        Ok(())
    }
    fn stop(&self, _timeout_secs: f64) -> Result<(), String> {
        Ok(())
    }
    fn close(&self) -> Result<(), String> {
        Ok(())
    }
    fn type_name(&self) -> String {
        self.type_label.clone()
    }
    fn clone_box(&self) -> Box<dyn ServiceLifecycle> {
        Box::new(StubService {
            type_label: self.type_label.clone(),
        })
    }
}

/// Bootstrap a kernel with a memory backend mounted at "/" and return it
/// along with a system OperationContext.
fn setup_kernel() -> (Kernel, OperationContext) {
    let k = Kernel::new();
    let backend = Arc::new(MemBackend::default());

    k.sys_setattr(
        "/",
        2, // DT_MOUNT
        "mem",
        Some(backend as Arc<dyn ObjectStore>),
        None,
        None,
        "",
        kernel::ROOT_ZONE_ID,
        false,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // created_at_ms
        None, // link_target
        None, // source
        None, // metastore
    )
    .expect("mount / with MemBackend");

    let ctx = OperationContext::new("test", "root", true, None, true);
    (k, ctx)
}

/// Helper: perform a single sys_write and return whether it succeeded.
fn do_write(k: &Kernel, ctx: &OperationContext, path: &str) -> bool {
    KernelSyscall::sys_write(k, path, ctx, b"hello", 0).is_ok()
}

// ── Test 1: register_service_hook fires, unhook via unregister_service ─

#[test]
fn hook_fires_then_stops_after_unregister_service() {
    let (k, ctx) = setup_kernel();

    // Register a managed service
    k.register_managed_service("svc-a", Box::new(StubService::new("StubA")), vec![], false)
        .expect("enlist svc-a");

    // Grab the handle for the enlisted service; register hook via handle.
    let handle = k.service_handle("svc-a").expect("handle for svc-a");
    let (hook, pre_count, _post_count) = CountingHook::new("svc-a-hook");
    k.register_service_hook(&handle, Box::new(hook));

    // Write triggers the hook
    assert!(do_write(&k, &ctx, "/test/file1.txt"));
    assert_eq!(pre_count.load(Ordering::SeqCst), 1, "hook should fire once");

    // Second write
    assert!(do_write(&k, &ctx, "/test/file2.txt"));
    assert_eq!(
        pre_count.load(Ordering::SeqCst),
        2,
        "hook should fire twice"
    );

    // Unregister the service — this must remove the hook
    let removed = k.unregister_service("svc-a");
    assert!(removed, "svc-a should have been found");

    // Write after unregister — hook must NOT fire
    assert!(do_write(&k, &ctx, "/test/file3.txt"));
    assert_eq!(
        pre_count.load(Ordering::SeqCst),
        2,
        "hook must not fire after unregister_service"
    );
}

// ── Test 2: unregister_service cleans up hooks ─────────────────────────

#[test]
fn unregister_service_removes_all_owned_hooks() {
    let (k, ctx) = setup_kernel();

    k.register_managed_service(
        "svc-cleanup",
        Box::new(StubService::new("Cleanup")),
        vec![],
        false,
    )
    .expect("enlist");
    let handle = k
        .service_handle("svc-cleanup")
        .expect("handle for svc-cleanup");

    // Register two hooks owned by the same service — same handle
    // shared via Clone.
    let (h1, pre1, _) = CountingHook::new("cleanup-hook-1");
    let (h2, pre2, _) = CountingHook::new("cleanup-hook-2");
    k.register_service_hook(&handle, Box::new(h1));
    k.register_service_hook(&handle, Box::new(h2));

    // Both hooks fire
    assert!(do_write(&k, &ctx, "/test/a.txt"));
    assert_eq!(pre1.load(Ordering::SeqCst), 1);
    assert_eq!(pre2.load(Ordering::SeqCst), 1);

    // Unregister removes both
    k.unregister_service("svc-cleanup");

    assert!(do_write(&k, &ctx, "/test/b.txt"));
    assert_eq!(pre1.load(Ordering::SeqCst), 1, "hook-1 must stop");
    assert_eq!(pre2.load(Ordering::SeqCst), 1, "hook-2 must stop");
}

// ── Test 3: swap_managed_service unhooks old service ───────────────────

#[test]
fn swap_managed_service_removes_old_hooks() {
    let (k, ctx) = setup_kernel();

    k.register_managed_service(
        "svc-swap",
        Box::new(StubService::new("OldImpl")),
        vec![],
        false,
    )
    .expect("enlist old");
    let handle = k.service_handle("svc-swap").expect("handle for svc-swap");

    // Hook for the old service
    let (old_hook, old_pre, _) = CountingHook::new("swap-old-hook");
    k.register_service_hook(&handle, Box::new(old_hook));

    // Verify old hook fires
    assert!(do_write(&k, &ctx, "/test/before.txt"));
    assert_eq!(old_pre.load(Ordering::SeqCst), 1);

    // Swap to new service instance
    k.swap_managed_service(
        "svc-swap",
        Box::new(StubService::new("NewImpl")),
        vec![],
        1000,
    )
    .expect("swap");

    // Old hook must be gone
    assert!(do_write(&k, &ctx, "/test/after.txt"));
    assert_eq!(
        old_pre.load(Ordering::SeqCst),
        1,
        "old hook must not fire after swap"
    );

    // Register a new hook for the swapped service (step 4 of swap flow).
    // Handle name persists across swap — the service entry is still
    // registered under "svc-swap", we grab a fresh handle for clarity.
    let handle_after_swap = k.service_handle("svc-swap").expect("handle survives swap");
    let (new_hook, new_pre, _) = CountingHook::new("swap-new-hook");
    k.register_service_hook(&handle_after_swap, Box::new(new_hook));

    assert!(do_write(&k, &ctx, "/test/new.txt"));
    assert_eq!(new_pre.load(Ordering::SeqCst), 1, "new hook must fire");
    assert_eq!(
        old_pre.load(Ordering::SeqCst),
        1,
        "old hook stays dead after new hook registered"
    );
}

// ── Test 4: multi-service hook isolation ───────────────────────────────

#[test]
fn unhook_one_service_leaves_others_intact() {
    let (k, ctx) = setup_kernel();

    // Service A
    k.register_managed_service(
        "svc-alpha",
        Box::new(StubService::new("Alpha")),
        vec![],
        false,
    )
    .expect("enlist alpha");
    let alpha = k.service_handle("svc-alpha").expect("handle alpha");
    let (ha, pre_a, _) = CountingHook::new("alpha-hook");
    k.register_service_hook(&alpha, Box::new(ha));

    // Service B
    k.register_managed_service(
        "svc-beta",
        Box::new(StubService::new("Beta")),
        vec![],
        false,
    )
    .expect("enlist beta");
    let beta = k.service_handle("svc-beta").expect("handle beta");
    let (hb, pre_b, _) = CountingHook::new("beta-hook");
    k.register_service_hook(&beta, Box::new(hb));

    // Both fire
    assert!(do_write(&k, &ctx, "/test/both.txt"));
    assert_eq!(pre_a.load(Ordering::SeqCst), 1);
    assert_eq!(pre_b.load(Ordering::SeqCst), 1);

    // Unregister service A only
    k.unregister_service("svc-alpha");

    // Write again — only B should fire
    assert!(do_write(&k, &ctx, "/test/only_b.txt"));
    assert_eq!(
        pre_a.load(Ordering::SeqCst),
        1,
        "alpha hook must stop after unregister"
    );
    assert_eq!(pre_b.load(Ordering::SeqCst), 2, "beta hook must still fire");

    // One more write for good measure
    assert!(do_write(&k, &ctx, "/test/only_b2.txt"));
    assert_eq!(pre_a.load(Ordering::SeqCst), 1);
    assert_eq!(pre_b.load(Ordering::SeqCst), 3);
}

// ── Test 5: hook-only service enlist + register + unregister lifecycle ─

/// Full lifecycle for the new `HookOnly` variant: enlist without a
/// managed / rust service, register hooks under the handle, verify
/// they fire, unregister the hook-only service, verify hooks stop.
///
/// This is the primary end-state for `services::audit::install_root`
/// once migrated — audit is a hook-only service with no RPC surface.
#[test]
fn hook_only_service_full_lifecycle() {
    let (k, ctx) = setup_kernel();

    // Enlist as hook-only — no ServiceLifecycle, no RustService.
    let handle = k
        .enlist_hook_only_service("audit-like")
        .expect("hook-only enlist");

    // Register two hooks under it.
    let (h1, pre1, _) = CountingHook::new("audit-hook-1");
    let (h2, pre2, _) = CountingHook::new("audit-hook-2");
    k.register_service_hook(&handle, Box::new(h1));
    k.register_service_hook(&handle, Box::new(h2));

    // Both fire on writes.
    assert!(do_write(&k, &ctx, "/test/hookonly_a.txt"));
    assert_eq!(pre1.load(Ordering::SeqCst), 1);
    assert_eq!(pre2.load(Ordering::SeqCst), 1);

    assert!(do_write(&k, &ctx, "/test/hookonly_b.txt"));
    assert_eq!(pre1.load(Ordering::SeqCst), 2);
    assert_eq!(pre2.load(Ordering::SeqCst), 2);

    // Unregister the hook-only service — both hooks must batch-remove.
    let removed = k.unregister_service("audit-like");
    assert!(removed, "hook-only service must be unregisterable");

    assert!(do_write(&k, &ctx, "/test/hookonly_c.txt"));
    assert_eq!(
        pre1.load(Ordering::SeqCst),
        2,
        "hook-1 must stop after hook-only unregister"
    );
    assert_eq!(
        pre2.load(Ordering::SeqCst),
        2,
        "hook-2 must stop after hook-only unregister"
    );
}

// ── Test 6: handle Clone shares one enlist across install sites ───────

/// Cloning a `ServiceHandle` is cheap (single Arc<String> refcount
/// bump) and installs from any clone all bind to the same underlying
/// entry — a single `unregister_service` still drains them.  Mirrors
/// the shape audit's `install_root` will take: enlist once, hand a
/// clone to `ZoneAuditAutoWire` and another to per-zone
/// `install_for_zone` calls.
#[test]
fn cloned_handle_installs_bind_to_same_service_entry() {
    let (k, ctx) = setup_kernel();

    let handle = k
        .enlist_hook_only_service("multi-install")
        .expect("hook-only enlist");

    // Two independent install sites, each using their own clone.
    let handle_a = handle.clone();
    let handle_b = handle.clone();

    let (h1, pre1, _) = CountingHook::new("multi-hook-1");
    let (h2, pre2, _) = CountingHook::new("multi-hook-2");
    k.register_service_hook(&handle_a, Box::new(h1));
    k.register_service_hook(&handle_b, Box::new(h2));

    // Both fire.
    assert!(do_write(&k, &ctx, "/test/multi_a.txt"));
    assert_eq!(pre1.load(Ordering::SeqCst), 1);
    assert_eq!(pre2.load(Ordering::SeqCst), 1);

    // One unregister drains BOTH hooks — they share the same entry.
    k.unregister_service("multi-install");

    assert!(do_write(&k, &ctx, "/test/multi_b.txt"));
    assert_eq!(
        pre1.load(Ordering::SeqCst),
        1,
        "hook-1 batch-removed via one unregister"
    );
    assert_eq!(
        pre2.load(Ordering::SeqCst),
        1,
        "hook-2 batch-removed via one unregister"
    );

    // Original handle is still cheap to hold post-drop; it just
    // resolves to nothing on subsequent register attempts.
    assert_eq!(handle.name(), "multi-install");
}

// ── Test 7: handle for non-existent service returns None ──────────────

/// The `service_handle(name)` accessor returns `None` when no service
/// is registered under the given name — this is what protects handle
/// consumers from binding hooks to a non-existent owner.
#[test]
fn service_handle_returns_none_for_unregistered_name() {
    let (k, _ctx) = setup_kernel();

    // Nothing enlisted under this name.
    assert!(k.service_handle("never-registered").is_none());

    // Enlist something else — the miss for a different name still stands.
    k.register_managed_service(
        "some-other-svc",
        Box::new(StubService::new("Other")),
        vec![],
        false,
    )
    .expect("enlist other");
    assert!(k.service_handle("never-registered").is_none());
    assert!(k.service_handle("some-other-svc").is_some());
}

// ── Test 8: variant mismatch on re-enlist ─────────────────────────────

/// Enlisting a name as HookOnly when it's already Managed / Rust must
/// fail cleanly with a variant-mismatch error — the two variants have
/// different lifecycle semantics and silently coercing would surprise
/// the caller.  Re-enlisting an existing HookOnly is idempotent
/// (returns a fresh handle to the same entry).
#[test]
fn hook_only_enlist_rejects_variant_mismatch() {
    let (k, _ctx) = setup_kernel();

    // Enlist as Managed first.
    k.register_managed_service(
        "conflict",
        Box::new(StubService::new("ManagedFirst")),
        vec![],
        false,
    )
    .expect("enlist managed");

    // Attempt hook-only enlist under the same name — must fail.
    let err = k
        .enlist_hook_only_service("conflict")
        .expect_err("must reject Managed→HookOnly re-enlist");
    assert!(
        err.contains("already registered as Managed"),
        "error should identify the existing variant, got: {err}",
    );

    // Idempotent re-enlist path: fresh hook-only name.
    let h1 = k
        .enlist_hook_only_service("fresh-hook-only")
        .expect("first enlist");
    let h2 = k
        .enlist_hook_only_service("fresh-hook-only")
        .expect("second enlist idempotent");
    // Both handles carry the same name.
    assert_eq!(h1.name(), h2.name());
}
