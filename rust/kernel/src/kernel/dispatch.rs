//! Native INTERCEPT hook dispatch — `dispatch_native_pre`,
//! `dispatch_native_post`, `register_native_hook`.
//!
//! Every method stays a member of [`Kernel`] via this submodule's
//! `impl Kernel { ... }` block.

use crate::dispatch::{HookContext, HookIdentity, NativeInterceptHook, Permission, WriteHookCtx};

use super::{Kernel, KernelError, OperationContext, RwLockExt};

use std::sync::atomic::Ordering;

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

    /// Kernel permission gate — called BEFORE `dispatch_native_pre`.
    #[inline]
    pub fn check_permission(
        &self,
        path: &str,
        permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        if path.starts_with("/__sys__/") {
            return Ok(());
        }
        if ctx.is_system {
            return Ok(());
        }
        if !self.has_permission_provider.load(Ordering::Relaxed) {
            return Ok(());
        }

        let agent_id = ctx.agent_id.as_deref().unwrap_or(&ctx.user_id);

        if self.permission_lease_cache.check(path, agent_id) {
            return Ok(());
        }

        // 5. Zone perms check (federation tokens)
        if !ctx.zone_perms.is_empty() {
            let perm_char = match permission {
                Permission::Read => "r",
                Permission::Write => "w",
                Permission::Traverse => "r",
            };
            let has_zone_grant = ctx
                .zone_perms
                .iter()
                .any(|(_zone_id, perm_chars)| perm_chars.contains(perm_char));
            if has_zone_grant {
                self.permission_lease_cache.stamp(path, agent_id);
                return Ok(());
            }
            return Err(KernelError::PermissionDenied(format!(
                "zone permission denied: no {perm_char} grant for '{path}'"
            )));
        }

        // Full permission check runs in NativeInterceptHook dispatch
        // Full permission check (admin bypass, zone boundary,
        // new-vs-existing file, ReBAC) runs in the NativeInterceptHook
        // chain (dispatch_native_pre) — the Python PermissionCheckHook
        // already has the caller's context and metadata access without
        // additional GIL crossing or OperationContext reconstruction.
        Ok(())
    }

    /// Enable the permission gate (zone perms + lease cache).
    ///
    /// Called once at boot when a permission hook is registered.
    /// When disabled (default), all permission checks are skipped
    /// (~1ns AtomicBool load).
    pub fn enable_permission_gate(&self) {
        self.has_permission_provider.store(true, Ordering::Relaxed);
    }

    /// Configure admin bypass (default: true).
    pub fn set_permission_admin_bypass(&self, enabled: bool) {
        self.permission_admin_bypass
            .store(enabled, Ordering::Relaxed);
    }

    /// Invalidate permission lease for a specific path.
    pub fn permission_lease_invalidate_path(&self, path: &str) {
        self.permission_lease_cache.invalidate_path(path);
    }

    /// Invalidate permission leases for a specific agent.
    pub fn permission_lease_invalidate_agent(&self, agent_id: &str) {
        self.permission_lease_cache.invalidate_agent(agent_id);
    }

    /// Invalidate all permission leases.
    pub fn permission_lease_invalidate_all(&self) {
        self.permission_lease_cache.invalidate_all();
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
