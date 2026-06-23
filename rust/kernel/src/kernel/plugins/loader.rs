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
use std::ffi::{CStr, CString, OsString};
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use contracts::rust_service::{RustCallError, RustService};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nexus_plugin_abi::{
    signing::{PUBKEY_LENGTH, SIGNATURE_FILE_SUFFIX, SIGNATURE_LENGTH},
    DriverCreateFn, DriverDestroyFn, DriverReadFn, DriverReaddirFn, DriverWriteFn, KernelHandle,
    PluginGrpcServicesFn, PluginKind, PluginResult, ServiceCreateFn, ServiceDestroyFn,
    ServiceDispatchFn, PLUGIN_API_VERSION,
};

use crate::abc::object_store::{ObjectStore, StorageError, WriteResult};

// ── Trusted plugin signing keys ─────────────────────────────────────
//
// Embedded at compile time from `kernel/trusted_keys/*.pub`. Each file
// is base64(32-byte Ed25519 raw pubkey) with optional `#` comment
// lines. Adding a new trust root = add a `.pub` file + a line below +
// rebuild. Removing one = delete the file + the line below + rebuild
// (this is the revocation mechanism for 0→1).

const TRUSTED_KEY_FILES: &[&[u8]] = &[
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/trusted_keys/nexus-team.pub"
    )),
    // Sealed-keystore dogfood root — provisioned 2026-06-13 against the
    // nexi-lab/nexus VAULT_SIGNING_MASTER_KEY secret via
    // scripts/provision_dogfood_key.py. Signs every non-vault plugin
    // (local-connector, fuse-plugin, future drivers/services) so the
    // bootstrap nexus-team.pub stays scoped to vault only.
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/trusted_keys/kernel-dogfood-v1.pub"
    )),
];

fn trusted_keys() -> &'static [VerifyingKey] {
    static KEYS: OnceLock<Vec<VerifyingKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        TRUSTED_KEY_FILES
            .iter()
            .map(|raw| {
                let text = std::str::from_utf8(raw)
                    .expect("trusted_keys/*.pub must be UTF-8 (embedded at compile time)");
                parse_pubkey_file(text)
                    .expect("trusted_keys/*.pub must parse (embedded at compile time)")
            })
            .collect()
    })
}

/// Parse a `trusted_keys/*.pub` file: skip `#`-prefixed and blank lines,
/// take the first remaining line as base64 of `PUBKEY_LENGTH` raw bytes.
fn parse_pubkey_file(content: &str) -> Result<VerifyingKey, String> {
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| "no base64 pubkey line found".to_string())?;
    let bytes = BASE64
        .decode(line)
        .map_err(|e| format!("base64 decode: {e}"))?;
    if bytes.len() != PUBKEY_LENGTH {
        return Err(format!(
            "pubkey length {} != expected {PUBKEY_LENGTH}",
            bytes.len()
        ));
    }
    let arr: [u8; PUBKEY_LENGTH] = bytes
        .try_into()
        .map_err(|_| "pubkey slice to [u8; PUBKEY_LENGTH] failed".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("ed25519 pubkey: {e}"))
}

/// Read `<plugin>.sig` next to the plugin and Ed25519-verify against
/// the plugin's raw bytes using any embedded trusted key.
///
/// Fail-loud: a missing sig file, wrong-length sig, or sig that none of
/// the trusted keys verifies → `Err`. There is no `--allow-unsigned`
/// escape hatch — by design, every plugin loaded by the kernel must be
/// signed by a key the kernel was compiled to trust.
fn verify_signature(plugin_path: &Path) -> Result<(), String> {
    verify_signature_against(plugin_path, trusted_keys())
}

/// Verify the sibling `.sig` of `plugin_path` against a caller-supplied
/// keyring. Internal seam exposed so unit tests can run the full path
/// (read sig file → read plugin → verify) against a fresh test key
/// without going through the compile-time-embedded keys.
fn verify_signature_against(plugin_path: &Path, keys: &[VerifyingKey]) -> Result<(), String> {
    let mut sig_path: OsString = plugin_path.as_os_str().to_owned();
    sig_path.push(SIGNATURE_FILE_SUFFIX);
    let sig_path = PathBuf::from(sig_path);

    let sig_bytes = std::fs::read(&sig_path).map_err(|e| {
        format!(
            "plugin signature missing or unreadable ({}): {e}",
            sig_path.display()
        )
    })?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(format!(
            "signature length {} != expected {SIGNATURE_LENGTH} ({})",
            sig_bytes.len(),
            sig_path.display()
        ));
    }
    let sig_arr: [u8; SIGNATURE_LENGTH] = sig_bytes
        .try_into()
        .map_err(|_| "signature slice to [u8; SIGNATURE_LENGTH] failed".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);

    let plugin_bytes = std::fs::read(plugin_path)
        .map_err(|e| format!("read plugin for verify ({}): {e}", plugin_path.display()))?;

    let any_pass = keys.iter().any(|k| k.verify(&plugin_bytes, &sig).is_ok());
    if !any_pass {
        return Err(format!(
            "signature did not verify against any of {} trusted key(s) — {}",
            keys.len(),
            plugin_path.display()
        ));
    }
    tracing::debug!(plugin = %plugin_path.display(), "plugin signature verified");
    Ok(())
}

// ── gRPC services opt-in (optional symbol) ──────────────────────────

/// Invoke the optional `nexus_plugin_grpc_services` symbol and parse
/// its JSON-array return value into a `Vec<String>` of service names.
///
/// The contract (mirrored in plugin-abi's `symbols::SERVICE_GRPC_SERVICES`):
///
/// - Return is a `*const c_char` pointing at a null-terminated UTF-8
///   JSON document.  Pointer must outlive every load of the dylib
///   (static storage).  The kernel does not free it.
/// - JSON must be an array of strings, each a fully-qualified gRPC
///   service name (`<package>.<Service>`).  A null pointer or an
///   empty array → plugin is loaded but no external gRPC routing.
///
/// Returns `Err` only on hard contract violations (non-UTF-8, malformed
/// JSON, non-string element).  A plugin whose symbol returns null or
/// `[]` loads fine — gRPC routing is purely opt-in.
fn parse_grpc_services_symbol(
    sym: PluginGrpcServicesFn,
    plugin_name: &str,
) -> Result<Vec<String>, String> {
    let ptr = unsafe { sym() };
    if ptr.is_null() {
        return Ok(Vec::new());
    }
    let json = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| format!("{plugin_name}: grpc_services JSON not UTF-8: {e}"))?;
    let parsed: Vec<String> = serde_json::from_str(json).map_err(|e| {
        format!("{plugin_name}: grpc_services JSON parse failed (expected array of strings): {e}")
    })?;
    Ok(parsed)
}

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
    /// Fully-qualified gRPC service names this plugin opted into
    /// exposing via the optional `nexus_plugin_grpc_services` symbol.
    /// Empty for plugins (or driver kind) that did not export it.
    grpc_services: Vec<String>,
}

// SAFETY: The plugin C ABI contract requires all plugin instances to be
// thread-safe (`Send + Sync`). The `handle` pointer is only accessed
// through the C ABI functions which are themselves `Send + Sync`.
unsafe impl Send for LoadedPlugin {}
unsafe impl Sync for LoadedPlugin {}

// ── PluginGrpcEndpoint (public surface to cluster glue) ─────────────

/// One plugin-exposed gRPC service ready for cluster-side tonic
/// routing.  Returned by [`PluginLoader::collect_grpc_endpoints`].
///
/// The cluster builds one tower `Service` per endpoint, registered at
/// `/{service_name}/{{*method}}` in tonic's axum router.  Inbound
/// requests strip the gRPC frame header, pass the request bytes to
/// `service.dispatch(full_path, bytes)`, and re-frame the returned
/// response bytes.
///
/// Contract for the plugin's `RustService::dispatch`:
///
/// - `method` is the request URL path, e.g.
///   `"/nexus.secrets.v1.GenericSecretsService/PutSecret"`.  The
///   leading `/` distinguishes a gRPC-routed call from the legacy
///   short-method `Call` RPC convention (`"secret_put"`); plugins
///   that serve both branches simply match on the prefix.
/// - `payload` is the proto-encoded request body (gRPC framing
///   already stripped on the cluster side).
/// - Returned bytes are the proto-encoded response body; the cluster
///   re-frames and emits `grpc-status: 0` trailers on success.
/// - `RustCallError::NotFound` → gRPC `Unimplemented`;
///   `InvalidArgument` → `InvalidArgument`; `Internal(_)` → `Internal`.
pub struct PluginGrpcEndpoint {
    pub service_name: String,
    pub plugin_name: String,
    pub service: Arc<dyn RustService>,
}

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
    /// `nexus_driver_readdir` symbol.  `<Self as ObjectStore>::list_dir`
    /// delegates here so the kernel's `sys_readdir` surfaces
    /// driver-owned entries the same way it does for in-process
    /// backends like `PathLocalBackend`.  Drivers that cannot
    /// enumerate return `Ok([])`, which surfaces the same observable
    /// shape as `sys_readdir` on an empty directory.
    readdir_fn: DriverReaddirFn,
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
            (self.write_fn)(
                self.handle,
                path_c.as_ptr(),
                content.as_ptr(),
                content.len(),
            )
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
                    format!(
                        "driver '{}' rejected write to '{content_id}'",
                        self.drv_name
                    ),
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

        let rc =
            unsafe { (self.read_fn)(self.handle, path_c.as_ptr(), &mut out_buf, &mut out_len) };

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

    fn list_dir(&self, path: &str) -> Result<Vec<String>, StorageError> {
        let path_c = CString::new(path).map_err(|_| {
            StorageError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains null byte",
            ))
        })?;
        let mut out_buf: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let rc =
            unsafe { (self.readdir_fn)(self.handle, path_c.as_ptr(), &mut out_buf, &mut out_len) };

        match rc {
            0 => {
                let json = if out_buf.is_null() || out_len == 0 {
                    Vec::new()
                } else {
                    // SAFETY: plugin allocated this Vec and handed
                    // ownership over via ManuallyDrop in the
                    // `declare_driver_plugin!` readdir arm.
                    unsafe { Vec::from_raw_parts(out_buf, out_len, out_len) }
                };
                if json.is_empty() {
                    return Ok(Vec::new());
                }
                serde_json::from_slice::<Vec<String>>(&json).map_err(|e| {
                    StorageError::IOError(std::io::Error::other(format!(
                        "driver '{}' readdir returned non-array JSON: {e}",
                        self.drv_name
                    )))
                })
            }
            rc if rc == PluginResult::NotFound as i32 => {
                Err(StorageError::NotFound(path.to_string()))
            }
            rc => Err(StorageError::IOError(std::io::Error::other(format!(
                "driver '{}' readdir returned {rc}",
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
        // 0. Verify the detached Ed25519 signature next to the plugin
        // against the compile-time-embedded trusted public keys. Done
        // BEFORE `dlopen` so a tampered or unsigned plugin never gets a
        // chance to run constructor / `_init` code in the process.
        verify_signature(path)?;

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
        let mut grpc_services: Vec<String> = Vec::new();
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
                // Optional gRPC opt-in.  Plugin authors that want to be
                // routed as an external gRPC service export
                // `nexus_plugin_grpc_services` returning a JSON array
                // of fully-qualified service names — see plugin-abi
                // `symbols::SERVICE_GRPC_SERVICES` for the contract.
                // Plugins without the symbol load unchanged.
                if let Ok(sym) = unsafe {
                    lib.get::<PluginGrpcServicesFn>(
                        nexus_plugin_abi::symbols::SERVICE_GRPC_SERVICES.as_bytes(),
                    )
                } {
                    grpc_services = parse_grpc_services_symbol(*sym, &name)?;
                    if !grpc_services.is_empty() {
                        tracing::info!(
                            plugin = name,
                            services = ?grpc_services,
                            "plugin opted into external gRPC routing",
                        );
                    }
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
            grpc_services,
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
        let readdir_fn: DriverReaddirFn = unsafe {
            *plugin
                ._lib
                .get(nexus_plugin_abi::symbols::DRIVER_READDIR.as_bytes())
                .map_err(|e| format!("symbol {}: {e}", nexus_plugin_abi::symbols::DRIVER_READDIR))?
        };
        let destroy_fn: DriverDestroyFn = unsafe {
            *plugin
                ._lib
                .get(nexus_plugin_abi::symbols::DRIVER_DESTROY.as_bytes())
                .map_err(|e| format!("symbol {}: {e}", nexus_plugin_abi::symbols::DRIVER_DESTROY))?
        };

        let config_c =
            CString::new(config_json).map_err(|_| "config_json contains null byte".to_string())?;

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
            readdir_fn,
            destroy_fn,
        })
    }

    /// Enumerate every `(service_name, dispatcher)` pair declared by a
    /// loaded service plugin via the optional
    /// `nexus_plugin_grpc_services` symbol.
    ///
    /// One `PluginGrpcEndpoint` is returned per service-name × plugin.
    /// A single plugin exposing N services produces N endpoints sharing
    /// one underlying `RustService` dispatcher (one plugin instance);
    /// the cluster wires each as its own URL prefix in tonic Routes.
    ///
    /// Driver plugins are skipped (no service-dispatch surface).
    /// Plugins that did not export the optional symbol are skipped.
    pub fn collect_grpc_endpoints(&self) -> Vec<PluginGrpcEndpoint> {
        let map = self.loaded.lock().unwrap();
        let mut out = Vec::new();
        for (plugin_name, plugin) in map.iter() {
            if plugin.kind != PluginKind::Service || plugin.grpc_services.is_empty() {
                continue;
            }
            // Resolve dispatch_fn once per plugin; share the Arc across
            // every service-name the plugin claims.
            let dispatch_fn: ServiceDispatchFn = match unsafe {
                plugin
                    ._lib
                    .get(nexus_plugin_abi::symbols::SERVICE_DISPATCH.as_bytes())
            } {
                Ok(sym) => *sym,
                Err(e) => {
                    tracing::warn!(
                        plugin = plugin_name,
                        err = %e,
                        "skip plugin gRPC endpoints — dispatch symbol missing",
                    );
                    continue;
                }
            };
            let svc: Arc<dyn RustService> = Arc::new(DylibRustService {
                svc_name: plugin_name.clone(),
                handle: plugin.handle,
                dispatch_fn,
            });
            for service_name in &plugin.grpc_services {
                out.push(PluginGrpcEndpoint {
                    service_name: service_name.clone(),
                    plugin_name: plugin_name.clone(),
                    service: Arc::clone(&svc),
                });
            }
        }
        out
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

    // ── signing format tests ────────────────────────────────────────

    #[test]
    fn parse_pubkey_file_round_trip() {
        use ed25519_dalek::SigningKey;
        // Use a real Ed25519 pubkey (not arbitrary 32 bytes — those
        // rarely form a valid Edwards point so `from_bytes` rejects them).
        let pub_bytes = SigningKey::from_bytes(&[3u8; 32])
            .verifying_key()
            .to_bytes();
        let b64 = BASE64.encode(pub_bytes);
        let content = format!("# header comment\n#  another\n\n{b64}\n");
        let key = parse_pubkey_file(&content).expect("must parse");
        assert_eq!(key.to_bytes(), pub_bytes);
    }

    #[test]
    fn parse_pubkey_file_rejects_short_key() {
        let content = format!("{}\n", BASE64.encode([1u8; 16])); // wrong length
        assert!(parse_pubkey_file(&content)
            .unwrap_err()
            .contains("pubkey length"));
    }

    #[test]
    fn parse_pubkey_file_rejects_invalid_base64() {
        assert!(parse_pubkey_file("not-base64-at-all!@#")
            .unwrap_err()
            .contains("base64"));
    }

    #[test]
    fn parse_pubkey_file_rejects_all_comments() {
        let err = parse_pubkey_file("# only comments\n# more comments").unwrap_err();
        assert!(err.contains("no base64 pubkey line"));
    }

    #[test]
    fn embedded_trusted_keys_parse_at_runtime() {
        // The OnceLock initialiser asserts UTF-8 + parseable, so the
        // very act of getting trusted_keys() succeeds means every
        // `.pub` file in TRUSTED_KEY_FILES is well-formed.
        let keys = trusted_keys();
        assert!(
            !keys.is_empty(),
            "kernel must embed at least one trusted plugin signing key"
        );
    }

    #[test]
    fn verify_signature_against_round_trip() {
        use ed25519_dalek::{Signer, SigningKey};

        let tmp = tempfile::tempdir().unwrap();
        let plugin = tmp.path().join("fake.so");
        let plugin_bytes = b"pretend this is a dylib";
        std::fs::write(&plugin, plugin_bytes).unwrap();

        // Sign with a fresh test keypair, write .sig next to plugin.
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let sig: Signature = signing.sign(plugin_bytes);
        std::fs::write(
            tmp.path().join(format!("fake.so{SIGNATURE_FILE_SUFFIX}")),
            sig.to_bytes(),
        )
        .unwrap();

        // Verify with the test's own pubkey — fine.
        verify_signature_against(&plugin, &[signing.verifying_key()])
            .expect("real sig must verify");

        // Verify with an unrelated pubkey — must fail.
        let other = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let err = verify_signature_against(&plugin, &[other]).unwrap_err();
        assert!(
            err.contains("did not verify"),
            "wrong-key error must be loud: {err}"
        );
    }

    #[test]
    fn verify_signature_missing_sig_file_fails_loud() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin = tmp.path().join("solo.so");
        std::fs::write(&plugin, b"no sig file next to me").unwrap();

        let err = verify_signature_against(&plugin, trusted_keys()).unwrap_err();
        assert!(
            err.contains("signature missing"),
            "missing-sig error must be loud: {err}"
        );
    }

    // ── grpc_services symbol parsing ───────────────────────────────

    unsafe extern "C" fn stub_grpc_services_two() -> *const std::ffi::c_char {
        c"[\"foo.v1.Bar\",\"baz.v1.Qux\"]".as_ptr()
    }

    unsafe extern "C" fn stub_grpc_services_empty() -> *const std::ffi::c_char {
        c"[]".as_ptr()
    }

    unsafe extern "C" fn stub_grpc_services_null() -> *const std::ffi::c_char {
        std::ptr::null()
    }

    unsafe extern "C" fn stub_grpc_services_malformed() -> *const std::ffi::c_char {
        c"not a json array".as_ptr()
    }

    unsafe extern "C" fn stub_grpc_services_wrong_shape() -> *const std::ffi::c_char {
        c"[1, 2, 3]".as_ptr()
    }

    #[test]
    fn parse_grpc_services_happy_path() {
        let out = parse_grpc_services_symbol(stub_grpc_services_two, "test").unwrap();
        assert_eq!(
            out,
            vec!["foo.v1.Bar".to_string(), "baz.v1.Qux".to_string()]
        );
    }

    #[test]
    fn parse_grpc_services_empty_array_is_ok() {
        let out = parse_grpc_services_symbol(stub_grpc_services_empty, "test").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parse_grpc_services_null_ptr_is_ok() {
        let out = parse_grpc_services_symbol(stub_grpc_services_null, "test").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parse_grpc_services_malformed_fails_loud() {
        let err = parse_grpc_services_symbol(stub_grpc_services_malformed, "test").unwrap_err();
        assert!(err.contains("grpc_services JSON parse failed"));
        assert!(err.contains("test"));
    }

    #[test]
    fn parse_grpc_services_non_string_element_fails_loud() {
        let err = parse_grpc_services_symbol(stub_grpc_services_wrong_shape, "test").unwrap_err();
        assert!(err.contains("grpc_services JSON parse failed"));
    }

    #[test]
    fn verify_signature_wrong_length_sig_fails_loud() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin = tmp.path().join("trunc.so");
        std::fs::write(&plugin, b"payload").unwrap();
        // Write a too-short "sig" (real sig must be 64 bytes).
        std::fs::write(
            tmp.path().join(format!("trunc.so{SIGNATURE_FILE_SUFFIX}")),
            [0u8; 8],
        )
        .unwrap();

        let err = verify_signature_against(&plugin, trusted_keys()).unwrap_err();
        assert!(
            err.contains("signature length"),
            "short-sig error must be loud: {err}"
        );
    }
}
