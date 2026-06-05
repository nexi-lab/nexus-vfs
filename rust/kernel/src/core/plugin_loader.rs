//! PluginLoader — runtime `dlopen`-based loading of services and drivers
//! from shared libraries (`.so` / `.dylib`).
//!
//! Linux kernel module pattern: a stable C ABI contract (defined in the
//! `nexus-plugin-abi` crate) lets independently-compiled plugins register
//! into the same `ServiceRegistry` and `VFSRouter` that compiled-in code
//! uses. The kernel sees a uniform `Arc<dyn RustService>` or
//! `Arc<dyn ObjectStore>` regardless of how the code was loaded.
//!
//! See KERNEL-ARCHITECTURE.md §10 for the full design.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use contracts::rust_service::{RustCallError, RustService};
use nexus_plugin_abi::{
    KernelHandle, PluginKind, PluginResult, PLUGIN_API_VERSION,
    ServiceCreateFn, ServiceDestroyFn, ServiceDispatchFn,
};

// ── LoadedPlugin ────────────────────────────────────────────────────

/// A loaded plugin — tracks the library handle and instance pointer so
/// we can destroy the instance and dlclose the library on unload.
struct LoadedPlugin {
    /// The `libloading::Library` handle. Dropped last (after instance
    /// destroy) to keep the code pages alive while the destructor runs.
    _lib: libloading::Library,
    kind: PluginKind,
    name: String,
    path: PathBuf,
    /// Opaque instance pointer returned by `nexus_service_create` /
    /// `nexus_driver_create`. Null after destroy.
    handle: *mut c_void,
    /// Destroy function — called before dlclose.
    destroy_fn: unsafe extern "C" fn(*mut c_void),
}

// SAFETY: The plugin C ABI contract requires all plugin instances to be
// thread-safe (`Send + Sync`). The `handle` pointer is only accessed
// through the C ABI functions which are themselves `Send + Sync`.
unsafe impl Send for LoadedPlugin {}
unsafe impl Sync for LoadedPlugin {}

// ── DylibRustService ────────────────────────────────────────────────

/// Wraps a service plugin's C ABI function pointers as an
/// `Arc<dyn RustService>`. Registered into `ServiceRegistry` via
/// `enlist_rust()` so the gRPC `Call` handler dispatches to it through
/// the same path as compiled-in Rust services.
pub(crate) struct DylibRustService {
    svc_name: String,
    handle: *mut c_void,
    dispatch_fn: ServiceDispatchFn,
}

// SAFETY: Plugin C ABI contract requires thread-safe instances.
unsafe impl Send for DylibRustService {}
unsafe impl Sync for DylibRustService {}

impl RustService for DylibRustService {
    fn name(&self) -> &str {
        &self.svc_name
    }

    fn dispatch(&self, method: &str, payload: &[u8]) -> Result<Vec<u8>, RustCallError> {
        let method_c = CString::new(method).map_err(|_| {
            RustCallError::InvalidArgument("method contains null byte".to_string())
        })?;
        let mut out_buf: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let rc = unsafe {
            (self.dispatch_fn)(
                self.handle,
                method_c.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                &mut out_buf,
                &mut out_len,
            )
        };

        match rc {
            0 => {
                let data = if out_buf.is_null() || out_len == 0 {
                    Vec::new()
                } else {
                    // SAFETY: the plugin allocated this via Vec and handed
                    // ownership to us through ManuallyDrop.
                    unsafe { Vec::from_raw_parts(out_buf, out_len, out_len) }
                };
                Ok(data)
            }
            rc if rc == PluginResult::NotFound as i32 => Err(RustCallError::NotFound),
            rc if rc == PluginResult::InvalidArgument as i32 => {
                Err(RustCallError::InvalidArgument("plugin rejected argument".into()))
            }
            rc => Err(RustCallError::Internal(format!("plugin error code {rc}"))),
        }
    }
}

// ── PluginLoader ────────────────────────────────────────────────────

/// Runtime loader for service and driver plugins.
///
/// Thread-safe: all mutation goes through a `Mutex<HashMap>`. Reads
/// (list, lookup) also go through the mutex — plugin lifecycle is rare
/// (mount-time frequency), so the lock is invisible in practice.
pub struct PluginLoader {
    loaded: Mutex<HashMap<String, LoadedPlugin>>,
}

impl PluginLoader {
    pub fn new() -> Self {
        Self {
            loaded: Mutex::new(HashMap::new()),
        }
    }

    /// Load a plugin from a shared library.
    ///
    /// On success, returns `(name, kind)`. For service plugins, the
    /// caller should retrieve the `DylibRustService` from
    /// `take_service()` and register it into `ServiceRegistry`.
    pub fn load(
        &self,
        path: &Path,
        kernel_handle: &KernelHandle,
    ) -> Result<(String, PluginKind), String> {
        // 1. dlopen
        let lib = unsafe { libloading::Library::new(path) }
            .map_err(|e| format!("dlopen({}): {e}", path.display()))?;

        // 2. Resolve manifest symbols
        let api_version = unsafe {
            let sym: libloading::Symbol<unsafe extern "C" fn() -> u32> = lib
                .get(nexus_plugin_abi::symbols::API_VERSION.as_bytes())
                .map_err(|e| format!("symbol {}: {e}", nexus_plugin_abi::symbols::API_VERSION))?;
            sym()
        };
        if api_version != PLUGIN_API_VERSION {
            return Err(format!(
                "plugin API version mismatch: plugin={api_version}, kernel={PLUGIN_API_VERSION}"
            ));
        }

        let kind_raw = unsafe {
            let sym: libloading::Symbol<unsafe extern "C" fn() -> u32> = lib
                .get(nexus_plugin_abi::symbols::KIND.as_bytes())
                .map_err(|e| format!("symbol {}: {e}", nexus_plugin_abi::symbols::KIND))?;
            sym()
        };
        let kind = PluginKind::from_raw(kind_raw)
            .ok_or_else(|| format!("unknown plugin kind: {kind_raw}"))?;

        let name = unsafe {
            let sym: libloading::Symbol<unsafe extern "C" fn() -> *const std::ffi::c_char> = lib
                .get(nexus_plugin_abi::symbols::NAME.as_bytes())
                .map_err(|e| format!("symbol {}: {e}", nexus_plugin_abi::symbols::NAME))?;
            let ptr = sym();
            CStr::from_ptr(ptr)
                .to_str()
                .map_err(|e| format!("plugin name not valid UTF-8: {e}"))?
                .to_string()
        };

        // 3. Construct instance based on kind
        let (handle, destroy_fn) = match kind {
            PluginKind::Service => {
                let create_fn: ServiceCreateFn = unsafe {
                    *lib.get(nexus_plugin_abi::symbols::SERVICE_CREATE.as_bytes())
                        .map_err(|e| {
                            format!("symbol {}: {e}", nexus_plugin_abi::symbols::SERVICE_CREATE)
                        })?
                };
                let destroy_fn: ServiceDestroyFn = unsafe {
                    *lib.get(nexus_plugin_abi::symbols::SERVICE_DESTROY.as_bytes())
                        .map_err(|e| {
                            format!("symbol {}: {e}", nexus_plugin_abi::symbols::SERVICE_DESTROY)
                        })?
                };
                let handle = unsafe { create_fn(kernel_handle as *const KernelHandle) };
                if handle.is_null() {
                    return Err(format!("nexus_service_create returned null for '{name}'"));
                }
                (handle, destroy_fn)
            }
            PluginKind::Driver => {
                // Driver plugins will be implemented when we have a
                // concrete driver plugin to test with.
                return Err("driver plugins not yet implemented".to_string());
            }
        };

        // 4. Store in loaded map
        let loaded = LoadedPlugin {
            _lib: lib,
            kind,
            name: name.clone(),
            path: path.to_path_buf(),
            handle,
            destroy_fn,
        };

        let mut map = self.loaded.lock().unwrap();
        if map.contains_key(&name) {
            // Destroy the just-created instance before returning error
            unsafe { (loaded.destroy_fn)(loaded.handle) };
            return Err(format!("plugin '{name}' already loaded"));
        }
        map.insert(name.clone(), loaded);

        Ok((name, kind))
    }

    /// Take the `DylibRustService` wrapper for a loaded service plugin.
    /// The caller is responsible for registering it into ServiceRegistry.
    ///
    /// Returns `None` if the plugin is not loaded or is not a service.
    pub(crate) fn make_service(&self, name: &str) -> Option<DylibRustService> {
        let map = self.loaded.lock().unwrap();
        let plugin = map.get(name)?;
        if plugin.kind != PluginKind::Service {
            return None;
        }

        // Resolve the dispatch function pointer from the still-loaded library
        let dispatch_fn: ServiceDispatchFn = unsafe {
            *plugin
                ._lib
                .get(nexus_plugin_abi::symbols::SERVICE_DISPATCH.as_bytes())
                .ok()?
        };

        Some(DylibRustService {
            svc_name: name.to_string(),
            handle: plugin.handle,
            dispatch_fn,
        })
    }

    /// Unload a plugin by name. For service plugins, the caller must
    /// unregister from ServiceRegistry first (drain + stop).
    pub fn unload(&self, name: &str) -> Result<(), String> {
        let mut map = self.loaded.lock().unwrap();
        let plugin = map
            .remove(name)
            .ok_or_else(|| format!("plugin '{name}' not loaded"))?;

        // Destroy the instance before dlclose (which happens on
        // LoadedPlugin drop when `_lib` goes out of scope).
        if !plugin.handle.is_null() {
            unsafe { (plugin.destroy_fn)(plugin.handle) };
        }

        tracing::info!(name, path = %plugin.path.display(), "plugin unloaded");
        Ok(())
    }

    /// List all loaded plugins: `(name, kind, path)`.
    pub fn list(&self) -> Vec<(String, PluginKind, PathBuf)> {
        let map = self.loaded.lock().unwrap();
        map.values()
            .map(|p| (p.name.clone(), p.kind, p.path.clone()))
            .collect()
    }

    /// Unload all plugins (shutdown path).
    pub fn unload_all(&self) {
        let mut map = self.loaded.lock().unwrap();
        for (name, plugin) in map.drain() {
            if !plugin.handle.is_null() {
                unsafe { (plugin.destroy_fn)(plugin.handle) };
            }
            tracing::debug!(name, "plugin unloaded (shutdown)");
        }
    }
}

impl Drop for PluginLoader {
    fn drop(&mut self) {
        self.unload_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_loader_is_empty() {
        let loader = PluginLoader::new();
        assert!(loader.list().is_empty());
    }

    #[test]
    fn unload_nonexistent_returns_error() {
        let loader = PluginLoader::new();
        assert!(loader.unload("nope").is_err());
    }

    #[test]
    fn unload_all_on_empty_is_noop() {
        let loader = PluginLoader::new();
        loader.unload_all();
        assert!(loader.list().is_empty());
    }
}
