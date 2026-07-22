//! Native INTERCEPT hook dispatch — `dispatch_native_pre`,
//! `dispatch_native_post`, `register_native_hook`.
//!
//! Every method stays a member of [`Kernel`] via this submodule's
//! `impl Kernel { ... }` block.

use crate::core::vfs_router::RouteResult;
use crate::dispatch::{
    HookContext, HookIdentity, NativeInterceptHook, Permission, PermissionProvider, WriteHookCtx,
};

use super::{Kernel, KernelError, OperationContext, RwLockExt};

use std::sync::Arc;

impl Kernel {
    // ── Native INTERCEPT hook dispatch ─────────────────

    /// Dispatch PRE-INTERCEPT hooks from NativeHookRegistry.
    /// Returns Err(KernelError) if any hook aborts.
    /// No-op when registry is empty (zero-cost lock check).
    ///
    /// Uses ``read_unconditional()`` (not the writer-fair variant) so a
    /// hook that re-enters ``sys_read`` — typical of ReBAC's permission_hook
    /// reading its own ``/__sys__/rebac/namespaces/...`` config during a
    /// permission check — does not deadlock on the recursive shared lock.
    /// The only writer here is ``register_native_hook`` at startup, so the
    /// usual writer-starvation concern doesn't apply.
    pub fn dispatch_native_pre(&self, ctx: &HookContext) -> Result<(), KernelError> {
        let registry = self.native_hooks.read_unconditional();
        if registry.count() == 0 {
            return Ok(());
        }
        // The hook chain may return a HookOutcome::Replace; the
        // accept/reject path drops the replacement — `sys_write` calls
        // `dispatch_native_pre_with_replacement` instead so it can
        // thread the replacement bytes through to the EXECUTE phase.
        registry
            .dispatch_pre(ctx)
            .map(|_replacement| ())
            .map_err(KernelError::PermissionDenied)
    }

    /// Like [`Self::dispatch_native_pre`] but returns the
    /// `HookOutcome::Replace` payload so callers can substitute write
    /// content at the EXECUTE phase. `sys_write` is the only consumer
    /// today — `MailboxStampingHook` (registered for `*/chat-with-me`)
    /// rewrites the envelope's `from` field through this path, and the
    /// caller passes `replacement.unwrap_or(content)` into DT_STREAM
    /// push / DT_FILE backend write. Empty registry returns
    /// `Ok(None)` so the no-hook hot path stays allocation-free.
    pub fn dispatch_native_pre_with_replacement(
        &self,
        ctx: &HookContext,
    ) -> Result<Option<Vec<u8>>, KernelError> {
        let registry = self.native_hooks.read_unconditional();
        if registry.count() == 0 {
            return Ok(None);
        }
        registry
            .dispatch_pre(ctx)
            .map_err(KernelError::PermissionDenied)
    }

    /// Returns true when at least one registered hook declared a
    /// `mutating_path_suffix` that matches `path`. `sys_write` uses
    /// this as a clone gate: only when a mutating hook matches does the
    /// dispatcher clone the write content into `WriteHookCtx`. The
    /// steady-state path (no mutating hooks) returns false on the
    /// empty-Vec check before any string comparison.
    pub fn has_mutating_hook_match(&self, path: &str) -> bool {
        self.native_hooks
            .read_unconditional()
            .has_mutating_match(path)
    }

    /// Run mutating native pre-hooks for a write to `path`, returning the
    /// hook's replacement content (`None` = no rewrite → use the caller's
    /// bytes). A fail-closed hook returns `Err`, which the caller MUST
    /// propagate to reject the write.
    ///
    /// This is the SINGLE seam every write syscall funnels through —
    /// `sys_write` / `write_batch` (DT_FILE), `stream_write_nowait`
    /// (DT_STREAM), `pipe_write_nowait` (DT_PIPE). A content guarantee such as
    /// the A2A `from` stamp therefore holds on EVERY write path, not just
    /// `sys_write`: it must not depend on which RPC the caller used. The
    /// `has_mutating_hook_match` clone gate keeps the no-hook hot path (e.g.
    /// LLM token streams) allocation-free.
    pub fn apply_mutating_write_hooks(
        &self,
        path: &str,
        ctx: &OperationContext,
        content: &[u8],
    ) -> Result<Option<Vec<u8>>, KernelError> {
        let hook_content = if self.has_mutating_hook_match(path) {
            content.to_vec()
        } else {
            Vec::new()
        };
        self.dispatch_native_pre_with_replacement(&HookContext::Write(WriteHookCtx {
            path: path.to_string(),
            identity: HookIdentity::from(ctx),
            content: hook_content,
            is_new_file: false,
            content_id: None,
            new_version: 0,
            size_bytes: None,
        }))
    }

    // ── §13 Permission gate ─────────────────────────────────────────

    /// Kernel permission gate — called BEFORE `dispatch_native_pre` on
    /// every syscall.  Delegates to the installed
    /// `Arc<dyn PermissionProvider>` slot; when the slot is `None`
    /// (kernel default) returns `Ok(())` immediately with zero
    /// authorization logic in the kernel tier.
    ///
    /// Use [`Self::check_permission_with_route`] from syscall bodies
    /// that have already resolved a `RouteResult` — the provider can
    /// then read the path's owning zone from the route instead of
    /// running a second `VFSRouter::route()` internally.
    #[inline]
    pub fn check_permission(
        &self,
        path: &str,
        permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        self.check_permission_with_route(path, None, permission, ctx)
    }

    /// Variant of [`Self::check_permission`] that passes a
    /// pre-computed `RouteResult` through to the provider.  Callers
    /// that route for I/O anyway should prefer this to avoid a
    /// duplicate `VFSRouter::route` inside the provider.
    #[inline]
    pub fn check_permission_with_route(
        &self,
        path: &str,
        route: Option<&RouteResult>,
        permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        // System-level short-circuits stay in the kernel — they are
        // language-of-the-kernel concepts (procfs, system contexts),
        // not authorization decisions.
        if path.starts_with("/__sys__/") {
            return Ok(());
        }
        if ctx.is_system {
            return Ok(());
        }
        // Default: no provider registered ⇒ Ok.  ArcSwapOption's
        // `load` returns a Guard<Option<Arc<T>>>; None fast-path is
        // one atomic load + branch (~2ns).
        let guard = self.permission_provider.load();
        let provider = match guard.as_ref() {
            Some(p) => p,
            None => return Ok(()),
        };
        provider.check(path, route, permission, ctx)
    }

    /// Install the kernel's authorization policy.  See the
    /// `permission` crate's top-level docstring for the 1-slot +
    /// composition contract and canonical impls.
    ///
    /// Called at composition-root time by a profile binary that
    /// terminates external client authorization.  `nexusd-cluster`
    /// does not call this — the slot stays `None`, gate stays no-op.
    ///
    /// Overwriting the slot is safe: an in-flight check that already
    /// dereferenced the previous provider completes against it
    /// (ArcSwapOption keeps the old Arc alive until the last Guard
    /// drops), and every subsequent check sees the new one.
    pub fn set_permission_provider(&self, provider: Arc<Box<dyn PermissionProvider>>) {
        self.permission_provider.store(Some(provider));
    }

    /// Dispatch POST-INTERCEPT hooks from NativeHookRegistry (fire-and-forget).
    /// No-op when registry is empty (zero-cost lock check).
    /// Uses ``read_unconditional`` for the same recursion reason as the pre dispatch.
    pub fn dispatch_native_post(&self, ctx: &HookContext) {
        let registry = self.native_hooks.read_unconditional();
        if registry.count() == 0 {
            return;
        }
        registry.dispatch_post(ctx);
    }

    /// Low-level insertion of a native Rust hook into the dispatch
    /// registry.  This primitive does NOT bind the hook to a service
    /// lifecycle, so it is `pub(crate)` — kernel-internal only.
    ///
    /// External / service callers MUST go through
    /// [`Self::register_service_hook`], which binds the hook to a
    /// [`ServiceHandle`](crate::service_registry::ServiceHandle) so it
    /// load/unloads with its service (and is batch-removed on
    /// swap/unregister).  `register_service_hook` composes this method,
    /// keeping `native_hooks` insertion in one place (single SSOT).
    pub(crate) fn register_native_hook(&self, hook: Box<dyn NativeInterceptHook>) {
        self.native_hooks.write().register(hook);
    }

    /// Unregister a native Rust hook by name. Returns true if found.
    ///
    /// Used by the hook lifecycle coordinator during service swap/unregister
    /// to remove stale hooks before replacing a service.
    pub fn unregister_native_hook(&self, name: &str) -> bool {
        self.native_hooks.write().unregister(name)
    }

    // ── Service ↔ hook lifecycle ────────────────────────────────────────
    //
    // Port of Python `swap_service()` 4-step flow:
    //   1. Unhook old service's hooks (NativeHookRegistry + ObserverRegistry)
    //   2. Drain (ServiceRegistry.drain — refcount → 0)
    //   3. Replace (ServiceRegistry.swap / enlist)
    //   4. Rehook new service's hooks
    //
    // Services register hooks via `register_service_hook` /
    // `register_service_observer`, both threaded through a
    // `ServiceHandle` obtained from `enlist_hook_only_service` (for
    // hook-only services like `services::audit`) or `service_handle`
    // (for existing Managed / Rust entries).  The dispatch layer
    // records the mapping in `service_hook_names` /
    // `service_observer_names` keyed by the handle's name; swap /
    // unregister use the map to batch-remove stale hooks.  Handles
    // for non-existent entries cannot be constructed, so the
    // service-name tags in these maps cannot drift from
    // `ServiceRegistry`.

    /// Register a native hook, binding its ownership to the
    /// [`ServiceHandle`](crate::service_registry::ServiceHandle) issued
    /// at enlist time.  On unregister / swap of the underlying service,
    /// the kernel batch-removes every hook installed through the handle.
    ///
    /// The handle carries the service name — dispatch's
    /// `service_hook_names` bookkeeping keys off it the same way the
    /// prior string-tagged API did, but now the identity is issued by
    /// the registry rather than named by convention, so drift is
    /// impossible: handles for non-existent entries cannot be
    /// constructed.
    pub fn register_service_hook(
        &self,
        handle: &crate::service_registry::ServiceHandle,
        hook: Box<dyn NativeInterceptHook>,
    ) {
        let hook_name = hook.name().to_string();
        // Single insertion SSOT: the raw registry write lives only in
        // `register_native_hook`; this method adds the service-ownership
        // bookkeeping on top.
        self.register_native_hook(hook);
        self.service_hook_names
            .lock()
            .entry(handle.name().to_string())
            .or_default()
            .push(hook_name);
    }

    /// Register an observer, binding its ownership to the
    /// [`ServiceHandle`](crate::service_registry::ServiceHandle).
    /// See [`Self::register_service_hook`] for the ownership contract;
    /// same rules apply, keyed under `service_observer_names`.
    pub fn register_service_observer(
        &self,
        handle: &crate::service_registry::ServiceHandle,
        observer: std::sync::Arc<dyn crate::dispatch::MutationObserver>,
        observer_name: String,
        event_mask: u32,
    ) {
        let name_clone = observer_name.clone();
        self.observers
            .write()
            .register(observer, observer_name, event_mask);
        self.service_observer_names
            .lock()
            .entry(handle.name().to_string())
            .or_default()
            .push(name_clone);
    }

    /// Remove all hooks and observers belonging to a service.
    /// Called internally before swap/unregister.
    pub(crate) fn unhook_service(&self, service_name: &str) {
        // Remove native hooks
        if let Some(hook_names) = self.service_hook_names.lock().remove(service_name) {
            let mut registry = self.native_hooks.write();
            for name in &hook_names {
                registry.unregister(name);
            }
        }
        // Remove observers
        if let Some(observer_names) = self.service_observer_names.lock().remove(service_name) {
            let mut registry = self.observers.write();
            for name in &observer_names {
                registry.unregister(name);
            }
        }
    }

    // ── Service registry facade ───────────────────────────────────────
    //
    // Every ServiceRegistry method is exposed through Kernel so that
    // peer crates never reach the pub(crate) ServiceRegistry directly.

    /// Register a managed (language-agnostic) service.
    pub fn register_managed_service(
        &self,
        name: &str,
        instance: Box<dyn crate::service_registry::ServiceLifecycle>,
        exports: Vec<String>,
        allow_overwrite: bool,
    ) -> Result<(), String> {
        self.service_registry
            .enlist(name, instance, exports, allow_overwrite)
    }

    /// Enlist a hook-only service — an entry in `ServiceRegistry` that
    /// exists purely as a lifecycle-managed owner namespace for hooks
    /// and observers.  Returns the handle callers thread through
    /// [`Self::register_service_hook`] / [`Self::register_service_observer`]
    /// so ownership is enforceable at compile time (no more bare-string
    /// tags in `service_hook_names` bookkeeping).
    ///
    /// Idempotent — re-enlisting a hook-only service by the same name
    /// returns a fresh handle to the same entry; re-enlisting a name
    /// already registered as `Managed` or `Rust` fails with a variant
    /// mismatch.
    ///
    /// See `docs/hook-ownership-refactor.md` §3 for the design.
    pub fn enlist_hook_only_service(
        &self,
        name: &str,
    ) -> Result<crate::service_registry::ServiceHandle, String> {
        self.service_registry.enlist_hook_only(name)
    }

    /// Return a handle for an already-registered service, regardless
    /// of variant.  Existing `register_managed_service` /
    /// `register_rust_service` consumers use this to obtain a handle
    /// after enlist without changing the enlist call site.
    ///
    /// Returns `None` if no service is registered under `name`.
    pub fn service_handle(&self, name: &str) -> Option<crate::service_registry::ServiceHandle> {
        self.service_registry.service_handle(name)
    }

    /// Unregister a service by name. Removes associated hooks/observers
    /// first (Python `swap_service` unhook step). Returns true if found.
    pub fn unregister_service(&self, name: &str) -> bool {
        self.unhook_service(name);
        self.service_registry.unregister(name)
    }

    /// Hot-swap a managed service: unhook → drain → replace → (caller rehooks).
    ///
    /// Port of Python `nexus_fs.py:swap_service()` 4-step flow.
    /// Steps 1-3 are handled here; step 4 (rehook) is the caller's
    /// responsibility — they register new hooks via
    /// `register_service_hook` / `register_service_observer` after
    /// swap returns.
    pub fn swap_managed_service(
        &self,
        name: &str,
        new_instance: Box<dyn crate::service_registry::ServiceLifecycle>,
        exports: Vec<String>,
        timeout_ms: u64,
    ) -> Result<(), String> {
        // 1. Unhook old service's hooks
        self.unhook_service(name);
        // 2+3. Drain + replace (ServiceRegistry handles both)
        self.service_registry
            .swap(name, new_instance, exports, timeout_ms)
    }

    /// Look up a managed service by name.
    pub fn service_lookup_managed(
        &self,
        name: &str,
    ) -> Option<Box<dyn crate::service_registry::ServiceLifecycle>> {
        self.service_registry.lookup_managed(name)
    }

    /// Start all services (managed + Rust).
    pub fn service_start_all(&self, timeout_secs: f64) -> Result<Vec<String>, String> {
        self.service_registry.start_all(timeout_secs)
    }

    /// Stop all services (reverse order).
    pub fn service_stop_all(&self, timeout_secs: f64) -> Result<Vec<String>, String> {
        self.service_registry.stop_all(timeout_secs)
    }

    /// Close all managed services (reverse order).
    pub fn service_close_all(&self) {
        self.service_registry.close_all()
    }

    /// Mark bootstrap complete — future enlist() auto-starts.
    pub fn service_mark_bootstrapped(&self) {
        self.service_registry.mark_bootstrapped()
    }

    /// Check if a service is registered.
    pub fn service_contains(&self, name: &str) -> bool {
        self.service_registry.contains(name)
    }

    /// Number of registered services.
    pub fn service_count(&self) -> usize {
        self.service_registry.count()
    }

    /// Service names in registration order.
    pub fn service_names(&self) -> Vec<String> {
        self.service_registry.names()
    }

    /// Snapshot: list of (name, type_name, exports) for diagnostics.
    pub fn service_snapshot(&self) -> Vec<(String, String, Vec<String>)> {
        self.service_registry.snapshot()
    }

    /// Acquire a refcount for a service (for ServiceRef proxy).
    pub fn service_ref_acquire(&self, name: &str) {
        self.service_registry.ref_acquire(name)
    }

    /// Release a refcount. Notifies drain waiters if count reaches 0.
    pub fn service_ref_release(&self, name: &str) {
        self.service_registry.ref_release(name)
    }

    /// Drain: wait for refcount on `name` to reach 0.
    pub fn service_drain(&self, name: &str, timeout_ms: u64) {
        self.service_registry.drain(name, timeout_ms)
    }

    /// Register a Rust-flavoured service with the kernel's
    /// `ServiceRegistry`. The Rust-callable parallel of the
    /// `sys_setattr("/__sys__/services/X", service=…)` syscall —
    /// mirrors the way `Kernel::add_mount` is the Rust parallel of
    /// `sys_setattr(DT_MOUNT)` for backends.
    ///
    /// Cluster binary boot wiring calls this after the kernel finishes
    /// constructing itself; for services that pull hooks into the
    /// `KernelDispatch` chain, register the hooks inside the service's
    /// `start()` (called by the registry on enlist).
    #[allow(dead_code)]
    pub fn register_rust_service(
        &self,
        name: &str,
        instance: std::sync::Arc<dyn crate::service_registry::RustService>,
        exports: Vec<String>,
    ) -> Result<(), String> {
        self.service_registry
            .enlist_rust(name, instance, exports, false)
    }

    /// Look up a Rust-flavoured service by canonical name. The
    /// Rust-callable parallel of the Python-facing `service_lookup`
    /// (which Python reaches via `nx.service(name)`); both end up at
    /// the kernel-internal `ServiceRegistry`, but in-crate Rust
    /// callers go through this Kernel method so `ServiceRegistry`
    /// stays a kernel primitive (`pub(crate)`, KERNEL-ARCHITECTURE
    /// §4) — same layering that keeps callers off direct
    /// `vfs_router` / `lock_manager` / `dispatch` access.
    ///
    /// Returns `None` for unknown names and for names registered as
    /// `ServiceInstance::Python` (Python services are reached via
    /// `service_lookup`).
    #[allow(dead_code)]
    pub(crate) fn service_lookup_rust(
        &self,
        name: &str,
    ) -> Option<std::sync::Arc<dyn crate::service_registry::RustService>> {
        self.service_registry.lookup_rust(name)
    }

    /// Dispatch a JSON-encoded RPC to a Rust-flavoured service.
    ///
    /// `Some(Ok(bytes))` — service handled the call and returned a
    /// JSON response.
    /// `Some(Err(RustCallError))` — service exists but rejected the
    /// call (NotFound / InvalidArgument / Internal).
    /// `None` — `name` does not resolve as a Rust-flavoured service;
    /// the gRPC `Call` handler falls through to the Python
    /// `dispatch_method` path so `@rpc_expose` services keep working.
    ///
    /// Mirrors `service_lookup_rust` in keeping in-crate Rust callers
    /// off `ServiceRegistry`; the registry stays a kernel primitive
    /// (KERNEL-ARCHITECTURE §4) and consumers go through `Kernel`.
    #[allow(dead_code)]
    pub fn dispatch_rust_call(
        &self,
        name: &str,
        method: &str,
        payload: &[u8],
    ) -> Option<Result<Vec<u8>, crate::service_registry::RustCallError>> {
        // Built-in kernel plugin management (§10). Handled before
        // ServiceRegistry lookup so plugin.* methods are always
        // available regardless of what services are registered.
        if name == "plugin" {
            return Some(self.dispatch_plugin_call(method, payload));
        }
        let svc = self.service_registry.lookup_rust(name)?;
        Some(svc.dispatch(method, payload))
    }

    /// Handle `plugin.*` RPC methods — kernel-built-in, not a registered
    /// RustService. Needs &self (Kernel) to call load/unload/list.
    fn dispatch_plugin_call(
        &self,
        method: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, crate::service_registry::RustCallError> {
        use crate::service_registry::RustCallError;
        match method {
            "list" => {
                let plugins = self.plugin_loader.list();
                let list: Vec<serde_json::Value> = plugins
                    .iter()
                    .map(|(name, kind, path)| {
                        serde_json::json!({
                            "name": name,
                            "kind": format!("{:?}", kind),
                            "path": path.display().to_string(),
                        })
                    })
                    .collect();
                serde_json::to_vec(&list).map_err(|e| RustCallError::Internal(e.to_string()))
            }
            "unload" => {
                let req: serde_json::Value = serde_json::from_slice(payload)
                    .map_err(|e| RustCallError::InvalidArgument(e.to_string()))?;
                let name = req["name"]
                    .as_str()
                    .ok_or_else(|| RustCallError::InvalidArgument("missing 'name'".into()))?;
                self.unload_plugin(name).map_err(RustCallError::Internal)?;
                Ok(b"{}".to_vec())
            }
            // plugin.load and plugin.reload require Arc<Kernel> (self:
            // &Arc<Self>). They are called from the cluster binary's
            // --plugin-dir boot path, not through gRPC Call dispatch.
            // gRPC callers use the nexusd-cluster CLI subcommands.
            "load" | "reload" => Err(RustCallError::InvalidArgument(
                "plugin.load/reload must be invoked via CLI, not gRPC Call".into(),
            )),
            _ => Err(RustCallError::NotFound),
        }
    }
}

#[cfg(test)]
mod permission_gate_protective_tests {
    //! These tests pin the invariant that the kernel default has ZERO
    //! authorization logic: no provider installed ⇒ every
    //! `check_permission` returns `Ok(())` regardless of ctx.  The
    //! 2026-07-23 permission-service refactor deliberately removed the
    //! kernel-tier inline zone_perms + lease-cache pair and replaced
    //! them with an `Arc<dyn PermissionProvider>` slot; these tests
    //! prevent a future patch from accidentally re-introducing an
    //! always-on gate that would break the "kernel clean by default"
    //! contract documented in KERNEL-ARCHITECTURE.md §13.

    use super::*;
    use crate::kernel::Kernel;
    use contracts::ROOT_ZONE_ID;

    #[test]
    fn kernel_default_permission_provider_is_none_and_gate_is_no_op() {
        let kernel = Kernel::new();
        // Deny-shaped context: no agent_id, no zone_perms, non-system.
        // Under the pre-refactor gate this would still short-circuit
        // via `has_permission_provider=false`; under the post-refactor
        // slot it short-circuits via `permission_provider.load() == None`.
        let ctx = OperationContext::new("anon", ROOT_ZONE_ID, false, None, false);
        for perm in [Permission::Read, Permission::Write, Permission::Traverse] {
            for path in ["/", "/anywhere", "/deep/nested/path", "/other/zone/x"] {
                kernel
                    .check_permission(path, perm, &ctx)
                    .unwrap_or_else(|e| {
                        panic!(
                            "kernel default MUST allow {perm:?} on {path:?}; got {e:?} — \
                         a provider slipped into the default slot, or the fast-path \
                         early-return in `check_permission` was broken"
                        )
                    });
            }
        }
    }

    #[test]
    fn sys_paths_and_system_context_skip_provider_even_when_installed() {
        use crate::PermissionProvider;
        use std::sync::atomic::{AtomicUsize, Ordering as AOrdering};

        // Shared counter Arc — lets the test observe the provider's
        // call count without downcasting through `Box<dyn Trait>`.
        struct CountingDeny(std::sync::Arc<AtomicUsize>);
        impl PermissionProvider for CountingDeny {
            fn check(
                &self,
                _path: &str,
                _route: Option<&crate::vfs_router::RouteResult>,
                _permission: Permission,
                _ctx: &OperationContext,
            ) -> Result<(), KernelError> {
                self.0.fetch_add(1, AOrdering::Relaxed);
                Err(KernelError::PermissionDenied("deny-all provider".into()))
            }
        }

        let kernel = Kernel::new();
        let count = std::sync::Arc::new(AtomicUsize::new(0));
        let provider: std::sync::Arc<Box<dyn PermissionProvider>> =
            std::sync::Arc::new(Box::new(CountingDeny(std::sync::Arc::clone(&count)))
                as Box<dyn PermissionProvider>);
        kernel.set_permission_provider(provider);

        // /__sys__/ paths short-circuit inside the kernel gate — the
        // provider MUST NOT be called for them.
        let ctx = OperationContext::new("alice", ROOT_ZONE_ID, false, None, false);
        kernel
            .check_permission("/__sys__/anything", Permission::Read, &ctx)
            .expect("/__sys__/ must always allow, provider must not fire");
        assert_eq!(
            count.load(AOrdering::Relaxed),
            0,
            "provider was invoked on /__sys__/ path — short-circuit broken"
        );

        // `is_system` contexts also short-circuit.
        let sys_ctx = OperationContext::new("system", ROOT_ZONE_ID, true, None, true);
        kernel
            .check_permission("/regular/path", Permission::Write, &sys_ctx)
            .expect("is_system ctx must always allow, provider must not fire");
        assert_eq!(
            count.load(AOrdering::Relaxed),
            0,
            "provider was invoked on is_system context — short-circuit broken"
        );

        // Normal path with normal ctx: provider IS called → deny.
        kernel
            .check_permission("/regular/path", Permission::Read, &ctx)
            .expect_err("normal path should hit provider and get denied");
        assert_eq!(
            count.load(AOrdering::Relaxed),
            1,
            "provider must fire exactly once for a regular check"
        );
    }
}
