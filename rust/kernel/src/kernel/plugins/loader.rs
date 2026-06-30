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
    DriverCreateFn, DriverDeleteFileFn, DriverDestroyFn, DriverReadFn, DriverReaddirFn,
    DriverRmdirFn, DriverStatFn, DriverWriteFn, KernelHandle, PluginGrpcServicesFn, PluginKind,
    PluginResult, ServiceCreateFn, ServiceDestroyFn, ServiceDispatchFn, PLUGIN_API_VERSION,
};

use crate::abc::object_store::{BackendStat, ObjectStore, StorageError, WriteResult};

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

/// Environment variable that, when set, points at a directory of
/// additional `*.pub` files to extend the runtime trust set with.
///
/// DEV ONLY — production daemons MUST NOT set this. The seam exists
/// so a local dev can sign plugins with their own key without editing
/// the kernel, bypassing the broken vault-dogfood signing pipeline.
/// When the env var is unset (the default) `trusted_keys()` returns
/// only the compile-time embedded set.
///
/// Contract: if set, the directory MUST exist and every `*.pub` inside
/// it MUST parse — the daemon panics at startup on either failure.
/// Fail-loud is intentional: a typoed path or malformed key file would
/// otherwise surface minutes later as a mysterious signature-verify
/// failure.
const LOCAL_TRUSTED_KEYS_ENV: &str = "NEXUS_LOCAL_TRUSTED_KEYS_DIR";

fn trusted_keys() -> &'static [VerifyingKey] {
    static KEYS: OnceLock<Vec<VerifyingKey>> = OnceLock::new();
    KEYS.get_or_init(|| compute_trusted_keys(local_trust_dir_from_env().as_deref()))
}

fn local_trust_dir_from_env() -> Option<PathBuf> {
    std::env::var_os(LOCAL_TRUSTED_KEYS_ENV).map(PathBuf::from)
}

/// Compose the compile-time trust roots with any runtime ones from
/// `local_dir`. Pure (no env, no `OnceLock`) so unit tests can drive
/// it without process-global state.
///
/// Panics if any compiled key fails to parse (kernel build is broken)
/// or if `local_dir` is set but unreadable / contains a malformed
/// `*.pub`.
fn compute_trusted_keys(local_dir: Option<&Path>) -> Vec<VerifyingKey> {
    let mut keys: Vec<VerifyingKey> = TRUSTED_KEY_FILES
        .iter()
        .map(|raw| {
            let text = std::str::from_utf8(raw)
                .expect("trusted_keys/*.pub must be UTF-8 (embedded at compile time)");
            parse_pubkey_file(text)
                .expect("trusted_keys/*.pub must parse (embedded at compile time)")
        })
        .collect();

    if let Some(dir) = local_dir {
        let extra = load_local_trust_dir(dir)
            .unwrap_or_else(|e| panic!("{LOCAL_TRUSTED_KEYS_ENV}={} unusable: {e}", dir.display()));
        if extra.is_empty() {
            tracing::warn!(
                target: "kernel.trust",
                dir = %dir.display(),
                "DEV-ONLY: {} set but no *.pub files found in directory",
                LOCAL_TRUSTED_KEYS_ENV,
            );
        } else {
            tracing::warn!(
                target: "kernel.trust",
                count = extra.len(),
                dir = %dir.display(),
                "DEV-ONLY: loaded {} additional trust root(s) from {}",
                extra.len(),
                LOCAL_TRUSTED_KEYS_ENV,
            );
            keys.extend(extra);
        }
    }

    keys
}

/// Read every `*.pub` file in `dir`, parse via `parse_pubkey_file`, and
/// return the resulting `VerifyingKey`s in lexicographic filename order.
/// Non-`*.pub` entries are ignored. Directory MUST exist (non-existent
/// dir → `Err`).
fn load_local_trust_dir(dir: &Path) -> Result<Vec<VerifyingKey>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read_dir entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("pub") {
            paths.push(path);
        }
    }
    // Stable order across platforms so signature-verify behavior is
    // reproducible regardless of filesystem listing order.
    paths.sort();
    let mut keys = Vec::with_capacity(paths.len());
    for path in paths {
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let key = parse_pubkey_file(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
        keys.push(key);
    }
    Ok(keys)
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
    /// backends like `PathLocalBackend`.
    readdir_fn: DriverReaddirFn,
    /// Optional `nexus_driver_delete_file` symbol — sister of
    /// `DRIVER_WRITE`.  Drivers that cannot meaningfully delete
    /// (CAS-only stores, read-only API connectors) omit it; the
    /// `ObjectStore::delete_file` impl below then returns
    /// `NotSupported`, the trait default.  Drivers that DO export
    /// it close the FUSE-`rm`-leaves-ghost-file gap (the
    /// metastore entry got removed but the host fs file persisted
    /// and the now-working `list_dir` re-surfaced it).
    delete_file_fn: Option<DriverDeleteFileFn>,
    /// Optional `nexus_driver_rmdir` symbol — sister of
    /// `DRIVER_DELETE_FILE` for directories.  When present, the
    /// `ObjectStore::rmdir` impl below delegates and `sys_rmdir`
    /// clears the metastore row plus the host fs directory in
    /// lockstep.  When absent, falls back to the trait default
    /// `NotSupported`, leaving the host fs directory in place
    /// (which then surfaces through the `sys_stat` backend
    /// fallback — closes the test_mkdir gap on cc-tasks-share).
    /// Carries the `recursive` flag through to the driver (v5);
    /// drivers that can only do single-dir removal must surface
    /// `NotSupported` for `recursive=true` so the kernel falls
    /// back to its walk + per-entry delete path.
    rmdir_fn: Option<DriverRmdirFn>,
    /// Optional `nexus_driver_stat` symbol — point-lookup
    /// `{size, is_dir}` for a single path.  When present, the
    /// kernel's `sys_stat` backend fallback uses it (O(1)); when
    /// absent, the fallback returns `None` for backend-owned
    /// paths and the FUSE layer gets ENOENT for entries that
    /// `readdir` would have listed.  LocalConnector and any
    /// driver wrapping a real filesystem should export it;
    /// virtual-namespace drivers may legitimately not.
    stat_fn: Option<DriverStatFn>,
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

    fn delete_file(&self, path: &str) -> Result<(), StorageError> {
        // Optional symbol — drivers that don't export it surface
        // the trait default of `NotSupported`, matching pre-v4
        // behaviour for any driver-backed mount.  Operators see
        // `sys_unlink` reach the metastore but not the host fs;
        // explicit cleanup is the operator's responsibility for
        // such drivers.
        let delete_fn = self.delete_file_fn.ok_or(StorageError::NotSupported(
            "driver plugin does not export nexus_driver_delete_file",
        ))?;
        let path_c = CString::new(path).map_err(|_| {
            StorageError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains null byte",
            ))
        })?;
        let rc = unsafe { delete_fn(self.handle, path_c.as_ptr()) };
        match rc {
            0 => Ok(()),
            rc if rc == PluginResult::NotFound as i32 => {
                Err(StorageError::NotFound(path.to_string()))
            }
            rc => Err(StorageError::IOError(std::io::Error::other(format!(
                "driver '{}' delete_file returned {rc}",
                self.drv_name
            )))),
        }
    }

    fn rmdir(&self, path: &str, recursive: bool) -> Result<(), StorageError> {
        // v5 ABI passes `recursive` through to the driver; backends
        // with a cheap bulk-remove primitive (`fs::remove_dir_all`,
        // future S3 bulk delete) satisfy `rm -rf` in a single FFI
        // call instead of the v4 walk + N+1 per-entry deletes that
        // `sys_rmdir` used to fall back to.  Drivers that can only
        // do single-dir removal surface `NotSupported` for
        // `recursive=true` and the kernel handles the walk itself.
        let rmdir_fn = self.rmdir_fn.ok_or(StorageError::NotSupported(
            "driver plugin does not export nexus_driver_rmdir",
        ))?;
        let path_c = CString::new(path).map_err(|_| {
            StorageError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains null byte",
            ))
        })?;
        let rc = unsafe { rmdir_fn(self.handle, path_c.as_ptr(), recursive) };
        match rc {
            0 => Ok(()),
            rc if rc == PluginResult::NotFound as i32 => {
                Err(StorageError::NotFound(path.to_string()))
            }
            rc => Err(StorageError::IOError(std::io::Error::other(format!(
                "driver '{}' rmdir(recursive={recursive}) returned {rc}",
                self.drv_name
            )))),
        }
    }

    fn stat(&self, path: &str) -> Result<BackendStat, StorageError> {
        // Optional symbol — same NotSupported fallback as
        // `delete_file` above.  When absent, the kernel's
        // `sys_stat` backend fallback returns `None` for paths
        // covered only by the driver's `list_dir` (no individual
        // metadata available), which the FUSE layer surfaces as
        // ENOENT.
        let stat_fn = self.stat_fn.ok_or(StorageError::NotSupported(
            "driver plugin does not export nexus_driver_stat",
        ))?;
        let path_c = CString::new(path).map_err(|_| {
            StorageError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains null byte",
            ))
        })?;
        let mut out_buf: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe { stat_fn(self.handle, path_c.as_ptr(), &mut out_buf, &mut out_len) };
        match rc {
            0 => {
                let json = if out_buf.is_null() || out_len == 0 {
                    Vec::new()
                } else {
                    // SAFETY: plugin allocated this Vec and handed
                    // ownership over via ManuallyDrop in the
                    // `declare_driver_plugin!` stat arm.
                    unsafe { Vec::from_raw_parts(out_buf, out_len, out_len) }
                };
                #[derive(serde::Deserialize)]
                struct StatWire {
                    size: u64,
                    is_dir: bool,
                }
                let parsed: StatWire = serde_json::from_slice(&json).map_err(|e| {
                    StorageError::IOError(std::io::Error::other(format!(
                        "driver '{}' stat returned non-stat JSON: {e}",
                        self.drv_name
                    )))
                })?;
                Ok(BackendStat {
                    size: parsed.size,
                    is_dir: parsed.is_dir,
                })
            }
            rc if rc == PluginResult::NotFound as i32 => {
                Err(StorageError::NotFound(path.to_string()))
            }
            rc => Err(StorageError::IOError(std::io::Error::other(format!(
                "driver '{}' stat returned {rc}",
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
        // Optional v4-additive symbols.  Missing symbol → fall back
        // to the `ObjectStore` trait defaults (`NotSupported`) so
        // drivers that legitimately don't have a delete or stat
        // primitive (CAS-only stores, read-only API connectors)
        // keep loading.
        let delete_file_fn: Option<DriverDeleteFileFn> = unsafe {
            plugin
                ._lib
                .get::<DriverDeleteFileFn>(nexus_plugin_abi::symbols::DRIVER_DELETE_FILE.as_bytes())
                .ok()
                .map(|sym| *sym)
        };
        let rmdir_fn: Option<DriverRmdirFn> = unsafe {
            plugin
                ._lib
                .get::<DriverRmdirFn>(nexus_plugin_abi::symbols::DRIVER_RMDIR.as_bytes())
                .ok()
                .map(|sym| *sym)
        };
        let stat_fn: Option<DriverStatFn> = unsafe {
            plugin
                ._lib
                .get::<DriverStatFn>(nexus_plugin_abi::symbols::DRIVER_STAT.as_bytes())
                .ok()
                .map(|sym| *sym)
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
            delete_file_fn,
            rmdir_fn,
            stat_fn,
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

    // ── runtime trust dir tests ────────────────────────────────────

    fn write_pubkey_file(dir: &Path, name: &str, seed: u8) -> [u8; 32] {
        use ed25519_dalek::SigningKey;
        let pub_bytes = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let b64 = BASE64.encode(pub_bytes);
        std::fs::write(dir.join(name), format!("{b64}\n")).unwrap();
        pub_bytes
    }

    #[test]
    fn load_local_trust_dir_reads_pub_files_in_sorted_order() {
        let tmp = tempfile::tempdir().unwrap();
        // Write in non-sorted creation order; loader must sort by name.
        let pub_b = write_pubkey_file(tmp.path(), "b.pub", 9);
        let pub_a = write_pubkey_file(tmp.path(), "a.pub", 11);
        let pub_c = write_pubkey_file(tmp.path(), "c.pub", 13);

        let keys = load_local_trust_dir(tmp.path()).expect("must load");
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].to_bytes(), pub_a);
        assert_eq!(keys[1].to_bytes(), pub_b);
        assert_eq!(keys[2].to_bytes(), pub_c);
    }

    #[test]
    fn load_local_trust_dir_ignores_non_pub_files() {
        let tmp = tempfile::tempdir().unwrap();
        write_pubkey_file(tmp.path(), "real.pub", 5);
        std::fs::write(tmp.path().join("notes.txt"), b"not a key").unwrap();
        std::fs::write(tmp.path().join("garbage"), b"no extension at all").unwrap();
        std::fs::write(tmp.path().join("foo.pubkey"), b"wrong suffix").unwrap();

        let keys = load_local_trust_dir(tmp.path()).expect("must load");
        assert_eq!(keys.len(), 1, "only real.pub should be loaded");
    }

    #[test]
    fn load_local_trust_dir_empty_dir_returns_empty_vec() {
        let tmp = tempfile::tempdir().unwrap();
        let keys = load_local_trust_dir(tmp.path()).expect("must load");
        assert!(keys.is_empty());
    }

    #[test]
    fn load_local_trust_dir_nonexistent_returns_err() {
        let bogus = Path::new("/this/path/should/not/exist/anywhere");
        let err = load_local_trust_dir(bogus).unwrap_err();
        assert!(
            err.contains("read_dir"),
            "non-existent dir error must mention read_dir: {err}"
        );
    }

    #[test]
    fn load_local_trust_dir_malformed_pub_returns_err() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("broken.pub"), b"not-base64-at-all!@#").unwrap();

        let err = load_local_trust_dir(tmp.path()).unwrap_err();
        assert!(
            err.contains("parse") && err.contains("broken.pub"),
            "malformed pub error must mention parse + filename: {err}"
        );
    }

    #[test]
    fn compute_trusted_keys_none_returns_only_compiled_keys() {
        let keys = compute_trusted_keys(None);
        assert_eq!(
            keys.len(),
            TRUSTED_KEY_FILES.len(),
            "no runtime dir means exactly the compiled set"
        );
    }

    #[test]
    fn compute_trusted_keys_some_appends_runtime_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let pub_x = write_pubkey_file(tmp.path(), "dev.pub", 19);
        write_pubkey_file(tmp.path(), "dev2.pub", 21);

        let keys = compute_trusted_keys(Some(tmp.path()));
        assert_eq!(keys.len(), TRUSTED_KEY_FILES.len() + 2);
        // The compiled keys come first; the dev keys are appended.
        let appended: Vec<[u8; 32]> = keys
            .iter()
            .skip(TRUSTED_KEY_FILES.len())
            .map(|k| k.to_bytes())
            .collect();
        assert!(
            appended.contains(&pub_x),
            "dev.pub must be present in the runtime-appended slice"
        );
    }

    #[test]
    fn compute_trusted_keys_empty_runtime_dir_returns_only_compiled() {
        let tmp = tempfile::tempdir().unwrap();
        let keys = compute_trusted_keys(Some(tmp.path()));
        assert_eq!(
            keys.len(),
            TRUSTED_KEY_FILES.len(),
            "empty runtime dir does not extend the trust set"
        );
    }

    #[test]
    #[should_panic(expected = "unusable")]
    fn compute_trusted_keys_panics_on_unreadable_dir() {
        let bogus = Path::new("/this/runtime/trust/dir/does/not/exist");
        // Should panic fail-loud — operator set the env to a typoed path.
        let _ = compute_trusted_keys(Some(bogus));
    }

    #[test]
    fn local_trust_dir_from_env_round_trip() {
        // SAFETY: temporarily setting then unsetting the env var. This is
        // the only test that touches the real process env var; running
        // serially under `cargo test` is fine.
        let saved = std::env::var(LOCAL_TRUSTED_KEYS_ENV).ok();
        std::env::set_var(LOCAL_TRUSTED_KEYS_ENV, "/some/dev/dir");
        assert_eq!(
            local_trust_dir_from_env(),
            Some(PathBuf::from("/some/dev/dir"))
        );
        std::env::remove_var(LOCAL_TRUSTED_KEYS_ENV);
        assert_eq!(local_trust_dir_from_env(), None);
        // Restore caller env if it had something set.
        if let Some(v) = saved {
            std::env::set_var(LOCAL_TRUSTED_KEYS_ENV, v);
        }
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

    // ── DylibObjectStore::rmdir wire-through ────────────────────────

    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Mutex;

    static RMDIR_LAST_RECURSIVE: AtomicU8 = AtomicU8::new(0xff);
    static RMDIR_LAST_PATH: Mutex<String> = Mutex::new(String::new());

    unsafe extern "C" fn stub_rmdir_record(
        _drv: *mut std::os::raw::c_void,
        path: *const std::ffi::c_char,
        recursive: bool,
    ) -> i32 {
        let p = std::ffi::CStr::from_ptr(path).to_str().unwrap().to_string();
        *RMDIR_LAST_PATH.lock().unwrap() = p;
        RMDIR_LAST_RECURSIVE.store(u8::from(recursive), Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn stub_read_noop(
        _drv: *mut std::os::raw::c_void,
        _path: *const std::ffi::c_char,
        _out_buf: *mut *mut u8,
        _out_len: *mut usize,
    ) -> i32 {
        -3
    }
    unsafe extern "C" fn stub_write_noop(
        _drv: *mut std::os::raw::c_void,
        _path: *const std::ffi::c_char,
        _data: *const u8,
        _data_len: usize,
    ) -> i32 {
        -3
    }
    unsafe extern "C" fn stub_readdir_noop(
        _drv: *mut std::os::raw::c_void,
        _path: *const std::ffi::c_char,
        _out_buf: *mut *mut u8,
        _out_len: *mut usize,
    ) -> i32 {
        -3
    }
    unsafe extern "C" fn stub_destroy_noop(_drv: *mut std::os::raw::c_void) {}

    fn build_stub_store_with_rmdir(rmdir_fn: Option<DriverRmdirFn>) -> DylibObjectStore {
        DylibObjectStore {
            drv_name: "stub".into(),
            // Null handle is fine — stubs ignore it.  Drop calls
            // destroy_fn(null) which is a no-op stub.
            handle: std::ptr::null_mut(),
            read_fn: stub_read_noop,
            write_fn: stub_write_noop,
            readdir_fn: stub_readdir_noop,
            delete_file_fn: None,
            rmdir_fn,
            stat_fn: None,
            destroy_fn: stub_destroy_noop,
        }
    }

    #[test]
    fn dylib_rmdir_passes_recursive_flag_through_to_driver() {
        // v5 ABI pin: when the driver exports nexus_driver_rmdir,
        // DylibObjectStore::rmdir(_, recursive=true) reaches the
        // symbol with recursive=true (no NotSupported short-circuit
        // like v4 used to apply).
        let store = build_stub_store_with_rmdir(Some(stub_rmdir_record));

        store
            .rmdir("/some/dir", true)
            .expect("recursive rmdir must reach stub");
        assert_eq!(RMDIR_LAST_RECURSIVE.load(Ordering::SeqCst), 1);
        assert_eq!(*RMDIR_LAST_PATH.lock().unwrap(), "/some/dir");

        store
            .rmdir("/other/dir", false)
            .expect("non-recursive rmdir must reach stub");
        assert_eq!(RMDIR_LAST_RECURSIVE.load(Ordering::SeqCst), 0);
        assert_eq!(*RMDIR_LAST_PATH.lock().unwrap(), "/other/dir");
    }

    #[test]
    fn dylib_rmdir_without_symbol_returns_not_supported() {
        // Sanity: drivers that omit the symbol still surface as
        // NotSupported regardless of the recursive flag.  Lets the
        // kernel fall back to its walk + per-entry delete path.
        let store = build_stub_store_with_rmdir(None);
        match store.rmdir("/x", false) {
            Err(StorageError::NotSupported(_)) => (),
            other => panic!("expected NotSupported, got {other:?}"),
        }
        match store.rmdir("/x", true) {
            Err(StorageError::NotSupported(_)) => (),
            other => panic!("expected NotSupported, got {other:?}"),
        }
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
