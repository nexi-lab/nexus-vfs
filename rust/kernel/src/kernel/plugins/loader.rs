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
    DriverCreateFn, DriverDestroyFn, DriverReadFn, DriverWriteFn, KernelHandle, PluginKind,
    PluginResult, ServiceCreateFn, ServiceDestroyFn, ServiceDispatchFn, PLUGIN_API_VERSION,
};

use crate::abc::object_store::{ObjectStore, StorageError, WriteResult};

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
        let method_c = CString::new(method)
            .map_err(|_| RustCallError::InvalidArgument("method contains null byte".to_string()))?;
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
            rc if rc == PluginResult::InvalidArgument as i32 => Err(
                RustCallError::InvalidArgument("plugin rejected argument".into()),
            ),
            rc => Err(RustCallError::Internal(format!("plugin error code {rc}"))),
        }
    }
}

// ── DylibObjectStore ────────────────────────────────────────────────

/// Wraps a driver plugin's C ABI function pointers as an
/// `Arc<dyn ObjectStore>`. Cluster binaries mount it like any compiled-
/// in backend (`PathLocalBackend`, `CasLocalBackend`) — the kernel sees
/// a uniform `ObjectStore` trait object regardless of how the driver
/// was loaded.
///
/// Only `name`, `read_content`, `write_content(offset=0)` are wired
/// through the C ABI in v1. All other `ObjectStore` methods fall
/// through to the trait's default `NotSupported` impls. Driver
/// authors that need `mkdir`/`rmdir`/`list_dir`/etc. through a dylib
/// will get their ABI extension when a concrete need lands — keeping
/// the C surface minimal until then.
///
/// Lifetime: a `DylibObjectStore` owns the driver instance handle —
/// `Drop` calls `nexus_driver_destroy(handle)` so each mount's
/// resources release deterministically when its `Arc` count hits zero.
/// The underlying `libloading::Library` is held by the
/// `PluginLoader::loaded` map; callers must keep the plugin loaded
/// (no `unload_plugin`) for the entire lifetime of any mount it
/// backs.
pub(crate) struct DylibObjectStore {
    drv_name: String,
    handle: *mut c_void,
    read_fn: DriverReadFn,
    write_fn: DriverWriteFn,
    destroy_fn: DriverDestroyFn,
}

impl Drop for DylibObjectStore {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle was returned by nexus_driver_create on the
            // same library; destroy_fn was resolved from the same
            // library. The PluginLoader keeps the library loaded for
            // the program lifetime, so the symbol stays valid here.
            unsafe { (self.destroy_fn)(self.handle) };
        }
    }
}

// SAFETY: The plugin C ABI contract requires thread-safe driver
// instances. The handle pointer is only accessed through the C ABI
// functions, which are themselves Send + Sync.
unsafe impl Send for DylibObjectStore {}
unsafe impl Sync for DylibObjectStore {}

impl ObjectStore for DylibObjectStore {
    fn name(&self) -> &str {
        &self.drv_name
    }

    fn write_content(
        &self,
        content: &[u8],
        content_id: &str,
        _ctx: &crate::kernel::OperationContext,
        offset: u64,
    ) -> Result<WriteResult, StorageError> {
        if offset != 0 {
            // pwrite slow path is the driver's responsibility to advertise
            // through an ABI extension; v1 ships full-overwrite only.
            return Err(StorageError::NotSupported(
                "DylibObjectStore: offset > 0 (pwrite) not supported in v1 ABI",
            ));
        }
        let path_c = CString::new(content_id).map_err(|_| {
            StorageError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "content_id contains null byte",
            ))
        })?;

        let rc = unsafe {
            (self.write_fn)(self.handle, path_c.as_ptr(), content.as_ptr(), content.len())
        };

        match rc {
            0 => Ok(WriteResult {
                content_id: content_id.to_string(),
                // Kernel-side hash so OCC version semantics stay
                // backend-agnostic. The driver only acks success; it
                // doesn't have to thread an ABI-stable hash back through
                // C.
                version: lib::hash::hash_content(content),
                size: content.len() as u64,
            }),
            rc if rc == PluginResult::NotFound as i32 => {
                Err(StorageError::NotFound(content_id.to_string()))
            }
            rc if rc == PluginResult::InvalidArgument as i32 => {
                Err(StorageError::IOError(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("driver '{}' rejected write to '{content_id}'", self.drv_name),
                )))
            }
            rc => Err(StorageError::IOError(std::io::Error::other(format!(
                "driver '{}' write_content returned {rc}",
                self.drv_name
            )))),
        }
    }

    fn read_content(
        &self,
        content_id: &str,
        _ctx: &crate::kernel::OperationContext,
    ) -> Result<Vec<u8>, StorageError> {
        let path_c = CString::new(content_id).map_err(|_| {
            StorageError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "content_id contains null byte",
            ))
        })?;
        let mut out_buf: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let rc = unsafe {
            (self.read_fn)(
                self.handle,
                path_c.as_ptr(),
                &mut out_buf,
                &mut out_len,
            )
        };

        match rc {
            0 => {
                let data = if out_buf.is_null() || out_len == 0 {
                    Vec::new()
                } else {
                    // SAFETY: the plugin allocated this Vec and handed
                    // ownership to us via ManuallyDrop in declare_driver_plugin!.
                    unsafe { Vec::from_raw_parts(out_buf, out_len, out_len) }
                };
                Ok(data)
            }
            rc if rc == PluginResult::NotFound as i32 => {
                Err(StorageError::NotFound(content_id.to_string()))
            }
            rc => Err(StorageError::IOError(std::io::Error::other(format!(
                "driver '{}' read_content returned {rc}",
                self.drv_name
            )))),
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

impl Default for PluginLoader {
    fn default() -> Self {
        Self {
            loaded: Mutex::new(HashMap::new()),
        }
    }
}

impl PluginLoader {
    pub fn new() -> Self {
        Self::default()
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
                // Driver instances are NOT created at load time. Driver
                // dylibs come up via `--plugin-dir` without any
                // operator config; the config (`local_root`, etc.) is
                // only known when `--mount-driver name:vfs-path:config`
                // is parsed. `make_driver` calls `nexus_driver_create`
                // with that JSON and returns a per-mount instance.
                //
                // Load-time validation still resolves all four driver
                // symbols so a malformed dylib fails fast rather than
                // surfacing as a confusing mount-time error.
                let _create_fn: DriverCreateFn = unsafe {
                    *lib.get(nexus_plugin_abi::symbols::DRIVER_CREATE.as_bytes())
                        .map_err(|e| {
                            format!("symbol {}: {e}", nexus_plugin_abi::symbols::DRIVER_CREATE)
                        })?
                };
                let _read_fn: DriverReadFn = unsafe {
                    *lib.get(nexus_plugin_abi::symbols::DRIVER_READ.as_bytes())
                        .map_err(|e| {
                            format!("symbol {}: {e}", nexus_plugin_abi::symbols::DRIVER_READ)
                        })?
                };
                let _write_fn: DriverWriteFn = unsafe {
                    *lib.get(nexus_plugin_abi::symbols::DRIVER_WRITE.as_bytes())
                        .map_err(|e| {
                            format!("symbol {}: {e}", nexus_plugin_abi::symbols::DRIVER_WRITE)
                        })?
                };
                let destroy_fn: DriverDestroyFn = unsafe {
                    *lib.get(nexus_plugin_abi::symbols::DRIVER_DESTROY.as_bytes())
                        .map_err(|e| {
                            format!("symbol {}: {e}", nexus_plugin_abi::symbols::DRIVER_DESTROY)
                        })?
                };
                // Handle stays null in the LoadedPlugin entry. Each
                // `make_driver` call mints its own (handle, destroy_fn)
                // pair owned by the returned DylibObjectStore.
                // `PluginLoader::unload` already skips destroy when
                // handle is null, so the lifecycle stays correct.
                (std::ptr::null_mut(), destroy_fn)
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

    /// Create a fresh driver instance for a loaded driver plugin and
    /// return a `DylibObjectStore` wrapping its handle.
    ///
    /// Calls `nexus_driver_create(kernel_handle, config_json)` on the
    /// dylib. Each invocation mints an independent instance — operators
    /// can `--mount-driver` the same dylib at multiple VFS paths with
    /// different `local_root` configs, and each mount gets its own
    /// state.
    ///
    /// Returns `Err` if the plugin is not loaded, is not a driver,
    /// missing a required symbol, or if `create_fn` returned null
    /// (typically: bad config JSON, or the driver rejected the config).
    pub(crate) fn make_driver(
        &self,
        name: &str,
        kernel_handle: &KernelHandle,
        config_json: &str,
    ) -> Result<DylibObjectStore, String> {
        let map = self.loaded.lock().unwrap();
        let plugin = map
            .get(name)
            .ok_or_else(|| format!("driver plugin '{name}' not loaded"))?;
        if plugin.kind != PluginKind::Driver {
            return Err(format!(
                "plugin '{name}' is not a driver (kind={:?})",
                plugin.kind
            ));
        }

        let create_fn: DriverCreateFn = unsafe {
            *plugin
                ._lib
                .get(nexus_plugin_abi::symbols::DRIVER_CREATE.as_bytes())
                .map_err(|e| format!("symbol {}: {e}", nexus_plugin_abi::symbols::DRIVER_CREATE))?
        };
        let read_fn: DriverReadFn = unsafe {
            *plugin
                ._lib
                .get(nexus_plugin_abi::symbols::DRIVER_READ.as_bytes())
                .map_err(|e| format!("symbol {}: {e}", nexus_plugin_abi::symbols::DRIVER_READ))?
        };
        let write_fn: DriverWriteFn = unsafe {
            *plugin
                ._lib
                .get(nexus_plugin_abi::symbols::DRIVER_WRITE.as_bytes())
                .map_err(|e| format!("symbol {}: {e}", nexus_plugin_abi::symbols::DRIVER_WRITE))?
        };
        let destroy_fn: DriverDestroyFn = unsafe {
            *plugin
                ._lib
                .get(nexus_plugin_abi::symbols::DRIVER_DESTROY.as_bytes())
                .map_err(|e| format!("symbol {}: {e}", nexus_plugin_abi::symbols::DRIVER_DESTROY))?
        };

        let config_c = CString::new(config_json)
            .map_err(|_| "config_json contains null byte".to_string())?;

        let handle = unsafe { create_fn(kernel_handle as *const KernelHandle, config_c.as_ptr()) };
        if handle.is_null() {
            return Err(format!(
                "nexus_driver_create returned null for '{name}' \
                 — driver rejected config (check JSON: {config_json})"
            ));
        }

        Ok(DylibObjectStore {
            drv_name: name.to_string(),
            handle,
            read_fn,
            write_fn,
            destroy_fn,
        })
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
