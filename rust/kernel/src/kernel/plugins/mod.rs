//! Plugin management — `Kernel` methods + `PluginLoader`.
//!
//! Contains:
//! - `loader.rs` — `PluginLoader` + `DylibRustService` wrapper (was `core/plugin_loader.rs`)
//! - `mod.rs` — `Kernel::load_plugin` / `unload_plugin` / `list_plugins` methods
//!
//! The `PluginLoader` was moved from `core/` because it is not a
//! shared kernel primitive — it is an implementation detail of plugin
//! management, only consumed by the `Kernel` methods in this module.

pub(crate) mod loader;

use std::path::Path;
use std::sync::Arc;

use contracts::OperationContext;
use nexus_plugin_abi::{KernelHandle, PluginKind};

use crate::kernel::Kernel;

pub use loader::PluginGrpcEndpoint;

impl Kernel {
    /// Build a `KernelHandle` vtable that plugins use to call back into
    /// the kernel. The handle is valid for the lifetime of the plugin
    /// (the kernel holds a strong Arc to itself while plugins are loaded).
    fn build_kernel_handle(self: &Arc<Self>) -> KernelHandle {
        // SAFETY: The function pointers below cast the opaque `kernel`
        // pointer back to `&Kernel`. The kernel guarantees the pointer
        // remains valid while any plugin referencing the handle is alive.
        KernelHandle {
            sys_read: kernel_cb_sys_read,
            sys_write: kernel_cb_sys_write,
            sys_stat: kernel_cb_sys_stat,
            sys_readdir: kernel_cb_sys_readdir,
            sys_unlink: kernel_cb_sys_unlink,
            sys_mkdir: kernel_cb_sys_mkdir,
            sys_rmdir: kernel_cb_sys_rmdir,
            sys_rename: kernel_cb_sys_rename,
            sys_stat_batch: kernel_cb_sys_stat_batch,
            kernel_ptr: Arc::as_ptr(self) as *const std::os::raw::c_void,
        }
    }

    /// Load a plugin from a shared library and register it.
    ///
    /// Service plugins are automatically registered into `ServiceRegistry`.
    /// Driver plugins are not yet supported.
    pub fn load_plugin(self: &Arc<Self>, path: &Path) -> Result<String, String> {
        let handle = self.build_kernel_handle();
        let (name, kind) = self.plugin_loader.load(path, &handle)?;

        match kind {
            PluginKind::Service => {
                let svc = self
                    .plugin_loader
                    .make_service(&name)
                    .ok_or_else(|| format!("failed to create DylibRustService for '{name}'"))?;
                self.service_registry
                    .enlist_rust(&name, Arc::new(svc), vec![], false)?;
                tracing::info!(name, path = %path.display(), "service plugin loaded + registered");
            }
            PluginKind::Driver => {
                // Driver instances aren't created here — they're minted
                // per-mount by `make_driver(name, config_json)` once the
                // operator supplies their JSON config via the cluster
                // binary's `--mount-driver` flag.  Loading just validates
                // the dylib's symbols + makes its name available for
                // subsequent `make_driver` lookups.
                tracing::info!(name, path = %path.display(), "driver plugin loaded");
            }
        }
        Ok(name)
    }

    /// Instantiate a driver plugin with the operator-supplied JSON
    /// config and return an `Arc<dyn ObjectStore>` ready to mount.
    ///
    /// Each call mints an independent driver instance so the same
    /// dylib can back multiple `--mount-driver` mounts with different
    /// configs.  The returned `Arc` owns the driver instance handle;
    /// drop it (or unmount the VFS path it backs) to call
    /// `nexus_driver_destroy` and release the driver's resources.
    pub fn make_driver(
        self: &Arc<Self>,
        name: &str,
        config_json: &str,
    ) -> Result<Arc<dyn crate::abc::object_store::ObjectStore>, String> {
        let handle = self.build_kernel_handle();
        let store = self.plugin_loader.make_driver(name, &handle, config_json)?;
        Ok(Arc::new(store))
    }

    /// Unload a plugin by name. Service plugins have their hooks removed
    /// and are unregistered from ServiceRegistry first (drain + stop).
    pub fn unload_plugin(&self, name: &str) -> Result<(), String> {
        // Check if it's a service — unhook + unregister before destroy
        if self.service_registry.contains(name) {
            self.unhook_service(name);
            self.service_registry.unregister(name);
        }
        self.plugin_loader.unload(name)
    }

    /// List loaded plugins: `(name, kind, path)`.
    pub fn list_plugins(&self) -> Vec<(String, PluginKind, std::path::PathBuf)> {
        self.plugin_loader.list()
    }

    /// Collect every `(service_name, dispatcher)` pair declared by a
    /// loaded service plugin via the optional
    /// `nexus_plugin_grpc_services` ABI symbol.  Consumed by the
    /// cluster glue (in `nexus-transport`) to merge plugin services
    /// into the same tonic Routes as the built-in VFS service —
    /// external gRPC clients reach plugin RPCs on the same port and
    /// trust root.
    ///
    /// Cheap: a snapshot copy + `Arc` clones.  Suitable to call at
    /// cluster boot after `load_plugin_dir`.
    pub fn plugin_grpc_endpoints(&self) -> Vec<PluginGrpcEndpoint> {
        self.plugin_loader.collect_grpc_endpoints()
    }

    /// Load every shared-library file in `dir` as a plugin.
    ///
    /// Accepts `.so` (Linux), `.dylib` (macOS), and `.dll` (Windows) —
    /// missing `.dll` was the symptom in nexi-lab/nexus-vfs#45 (Windows
    /// vault plugin silently not loading). Sibling `.sig` files are
    /// consumed by [`PluginLoader::load`] for signature verification and
    /// are not iterated here.
    pub fn load_plugin_dir(self: &Arc<Self>, dir: &Path) -> Result<Vec<String>, String> {
        let entries =
            std::fs::read_dir(dir).map_err(|e| format!("read_dir({}): {e}", dir.display()))?;

        let mut loaded = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "so" | "dylib" | "dll") {
                match self.load_plugin(&path) {
                    Ok(name) => loaded.push(name),
                    Err(e) => tracing::warn!(path = %path.display(), err = %e, "skip plugin"),
                }
            }
        }
        Ok(loaded)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Build a system-level `OperationContext` for plugin callbacks.
/// Bypasses all permission checks (`is_system = true`).
fn system_ctx() -> OperationContext {
    OperationContext::new("", contracts::ROOT_ZONE_ID, true, None, true)
}

// ── KernelHandle callback implementations ───────────────────────────
//
// These are `extern "C"` functions that the plugin calls through the
// KernelHandle vtable. They cast the opaque `kernel` pointer back to
// `&Kernel` and delegate to the syscall surface.

unsafe extern "C" fn kernel_cb_sys_read(
    kernel: *const std::os::raw::c_void,
    path: *const std::ffi::c_char,
    out_buf: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let kernel = &*(kernel as *const Kernel);
    let path = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2, // InvalidArgument
    };
    let ctx = system_ctx();
    match kernel.sys_read_single(path, &ctx, 1, 5000, 0) {
        Ok(result) => {
            let data = result.data.unwrap_or_default();
            let mut data = std::mem::ManuallyDrop::new(data);
            *out_buf = data.as_mut_ptr();
            *out_len = data.len();
            0
        }
        Err(_) => -3, // Internal
    }
}

unsafe extern "C" fn kernel_cb_sys_write(
    kernel: *const std::os::raw::c_void,
    path: *const std::ffi::c_char,
    data: *const u8,
    data_len: usize,
) -> i32 {
    let kernel = &*(kernel as *const Kernel);
    let path = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let content = if data.is_null() || data_len == 0 {
        vec![]
    } else {
        std::slice::from_raw_parts(data, data_len).to_vec()
    };
    let ctx = system_ctx();
    let req = crate::kernel::WriteRequest {
        path: path.to_string(),
        content,
        offset: 0,
    };
    let results = kernel.sys_write(&[req], &ctx);
    match results.into_iter().next() {
        Some(Ok(_)) => 0,
        _ => -3,
    }
}

unsafe extern "C" fn kernel_cb_sys_stat(
    kernel: *const std::os::raw::c_void,
    path: *const std::ffi::c_char,
    out_json: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let kernel = &*(kernel as *const Kernel);
    let path = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    match kernel.sys_stat(path, contracts::ROOT_ZONE_ID) {
        Some(result) => {
            // StatResult fields plugins typically need, serialized as JSON.
            let json = format!(
                r#"{{"path":"{}","entry_type":{},"size":{},"zone_id":"{}"}}"#,
                result.path,
                result.entry_type,
                result.size,
                result.zone_id.as_deref().unwrap_or("root"),
            );
            let mut json = std::mem::ManuallyDrop::new(json.into_bytes());
            *out_json = json.as_mut_ptr();
            *out_len = json.len();
            0
        }
        None => -1, // NotFound
    }
}

unsafe extern "C" fn kernel_cb_sys_readdir(
    kernel: *const std::os::raw::c_void,
    parent_path: *const std::ffi::c_char,
    out_json: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let kernel = &*(kernel as *const Kernel);
    let parent_path = match std::ffi::CStr::from_ptr(parent_path).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    // System-context readdir: bypass admin gating (the kernel-side
    // permission check is the SSOT for any access policy plugins
    // care about). Use the existence-aware variant so this honours the
    // documented C-ABI contract (NotFound = -1 for a path that does not
    // exist; an empty directory is still Ok(0) with `[]`) — the FUSE plugin
    // already codes against that, so this is behaviour it expects, not a
    // signature change.
    let entries = match kernel.sys_readdir_checked(parent_path, contracts::ROOT_ZONE_ID, true) {
        Ok(e) => e,
        Err(crate::kernel::KernelError::FileNotFound(_)) => return -1, // PluginResult::NotFound
        Err(crate::kernel::KernelError::InvalidPath(_)) => return -2, // PluginResult::InvalidArgument
        Err(_) => return -3,                                          // PluginResult::Internal
    };
    // `kernel.sys_readdir` returns each child's *full* VFS path (e.g.
    // `/alpha-dir`, not `alpha-dir`); the JSON shape this callback
    // exports is documented under key `"name"` and consumers like the
    // FUSE plugin feed it directly into `reply.add(_, _, kind, name)`
    // where a leading slash makes the kernel-side FUSE driver reject
    // the readdir reply with EIO.  Strip the parent-path prefix here
    // so the JSON `"name"` field actually is a name.  The kernel
    // already filters direct children only (see io.rs §sys_readdir
    // parent_depth check), so a single `rsplit_once('/')` is the
    // canonical leaf extraction.
    //
    // Hand-roll JSON to avoid a serde_json dep on the kernel-side
    // callback closure.  Each entry is one
    // `{"name":<escaped>,"entry_type":<u8>}` object.  Only `"` and
    // `\` need JSON-escape — extremely rare in path segments but
    // cheap to handle correctly.
    let mut json = String::from("[");
    let mut first = true;
    for (full_path, entry_type) in entries {
        let name = full_path
            .rsplit_once('/')
            .map(|(_, leaf)| leaf)
            .unwrap_or(full_path.as_str());
        if name.is_empty() {
            // Defensive: the parent itself slipped through (shouldn't
            // happen with the kernel's depth filter, but if it does the
            // FUSE layer would `reply.add` an empty name and the
            // kernel driver rejects the whole batch).
            continue;
        }
        if !first {
            json.push(',');
        }
        first = false;
        json.push_str("{\"name\":\"");
        for ch in name.chars() {
            match ch {
                '"' => json.push_str("\\\""),
                '\\' => json.push_str("\\\\"),
                c => json.push(c),
            }
        }
        json.push_str("\",\"entry_type\":");
        json.push_str(&entry_type.to_string());
        json.push('}');
    }
    json.push(']');
    let mut bytes = std::mem::ManuallyDrop::new(json.into_bytes());
    *out_json = bytes.as_mut_ptr();
    *out_len = bytes.len();
    0
}

unsafe extern "C" fn kernel_cb_sys_unlink(
    kernel: *const std::os::raw::c_void,
    path: *const std::ffi::c_char,
) -> i32 {
    let kernel = &*(kernel as *const Kernel);
    let path = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let ctx = system_ctx();
    let reqs = [crate::kernel::UnlinkRequest {
        path: path.to_string(),
        recursive: false,
    }];
    match kernel.sys_unlink(&reqs, &ctx).into_iter().next() {
        Some(Ok(_)) => 0,
        _ => -3,
    }
}

unsafe extern "C" fn kernel_cb_sys_mkdir(
    kernel: *const std::os::raw::c_void,
    path: *const std::ffi::c_char,
) -> i32 {
    let kernel = &*(kernel as *const Kernel);
    let path = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let ctx = system_ctx();
    // DT_DIR (entry_type=1) via tier-2 mkdir.  parents=false enforces
    // the ABI contract that the parent must already exist; exist_ok=
    // false surfaces EEXIST as -3 so the FUSE layer can translate.
    match kernel.mkdir(
        path, &ctx, /* parents */ false, /* exist_ok */ false,
    ) {
        Ok(_) => 0,
        Err(_) => -3,
    }
}

unsafe extern "C" fn kernel_cb_sys_rmdir(
    kernel: *const std::os::raw::c_void,
    path: *const std::ffi::c_char,
) -> i32 {
    let kernel = &*(kernel as *const Kernel);
    let path = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let ctx = system_ctx();
    // sys_unlink with recursive=false; the kernel surfaces ENOTEMPTY
    // for non-empty directories which maps to -3 here.
    let reqs = [crate::kernel::UnlinkRequest {
        path: path.to_string(),
        recursive: false,
    }];
    match kernel.sys_unlink(&reqs, &ctx).into_iter().next() {
        Some(Ok(_)) => 0,
        _ => -3,
    }
}

unsafe extern "C" fn kernel_cb_sys_rename(
    kernel: *const std::os::raw::c_void,
    old_path: *const std::ffi::c_char,
    new_path: *const std::ffi::c_char,
) -> i32 {
    let kernel = &*(kernel as *const Kernel);
    let old_path = match std::ffi::CStr::from_ptr(old_path).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let new_path = match std::ffi::CStr::from_ptr(new_path).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let ctx = system_ctx();
    match kernel.sys_rename(old_path, new_path, &ctx) {
        Ok(_) => 0,
        Err(_) => -3,
    }
}

unsafe extern "C" fn kernel_cb_sys_stat_batch(
    kernel: *const std::os::raw::c_void,
    paths_json: *const std::ffi::c_char,
    out_json: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let kernel = &*(kernel as *const Kernel);
    let paths_json = match std::ffi::CStr::from_ptr(paths_json).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    // Parse the input JSON array of path strings — same minimal
    // hand-rolled approach the other callbacks use to keep
    // `serde_json` off the kernel side.  Only the kernel-emitted
    // shape `["/foo","/bar"]` (or with the `"` and `\` escapes the
    // callback's matching output side handles) is accepted.
    let paths = parse_stat_batch_input(paths_json);
    use crate::kernel::convenience::KernelConvenience;
    let results = kernel.stat_batch(&paths, contracts::ROOT_ZONE_ID);
    // Hand-roll the response JSON.  Output shape per kernel-side
    // entry:
    //   * `Some(StatResult)` → `[<size>, <entry_type>]`
    //   * `None`             → `null`
    let mut json = String::from("[");
    let mut first = true;
    for r in results {
        if !first {
            json.push(',');
        }
        first = false;
        match r {
            Some(stat) => {
                json.push('[');
                json.push_str(&stat.size.to_string());
                json.push(',');
                json.push_str(&stat.entry_type.to_string());
                json.push(']');
            }
            None => json.push_str("null"),
        }
    }
    json.push(']');
    let mut bytes = std::mem::ManuallyDrop::new(json.into_bytes());
    *out_json = bytes.as_mut_ptr();
    *out_len = bytes.len();
    0
}

/// Parse the `sys_stat_batch` input JSON — an array of path strings,
/// `"`-quoted with `"` / `\` escapes the same way the readdir output
/// is escaped.  Returns paths as plain `String`s in array order;
/// invalid input parses what it can and discards the rest (an empty
/// vector hands the caller back an empty result array, not -2).
fn parse_stat_batch_input(json: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = json;
    while let Some((_, after_open)) = rest.split_once('"') {
        let mut name = String::new();
        let mut chars = after_open.chars();
        loop {
            match chars.next() {
                Some('\\') => match chars.next() {
                    Some(c) => name.push(c),
                    None => return out,
                },
                Some('"') => break,
                Some(c) => name.push(c),
                None => return out,
            }
        }
        out.push(name);
        rest = chars.as_str();
    }
    out
}
