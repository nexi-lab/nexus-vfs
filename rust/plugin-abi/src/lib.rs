//! Stable C ABI contract between the Nexus kernel and dynamically-loaded
//! plugins (`.so` / `.dylib`).
//!
//! This crate is the **only** compile-time dependency a plugin needs.
//! It defines:
//!
//! - The ABI version constant (`PLUGIN_API_VERSION`)
//! - `#[repr(C)]` types shared across the dlopen boundary
//!   (`PluginKind`, `KernelHandle`, `PluginResult`)
//! - Symbol name constants for the manifest + lifecycle functions
//! - A `declare_service_plugin!` macro that generates the required
//!   `#[no_mangle] pub extern "C"` symbols from a Rust impl
//!
//! The kernel's `PluginLoader` (in `kernel::kernel::plugins::loader`) is the
//! consumer side — it `dlopen`s a `.so`, resolves these symbols, and
//! wraps the raw C handles as `Arc<dyn RustService>` or
//! `Arc<dyn ObjectStore>`.
//!
//! **Zero workspace deps** — this crate depends on nothing so plugins
//! can be compiled independently of the kernel workspace.

use std::ffi::c_char;
use std::os::raw::c_void;

// ── ABI version ─────────────────────────────────────────────────────

/// Bump when the C ABI changes in a backward-incompatible way.
/// The kernel rejects plugins whose `nexus_plugin_api_version()` does
/// not match this value.
///
/// History:
///   * v1 — initial: `sys_read` / `sys_write` / `sys_stat` only.
///   * v2 — added `sys_readdir` / `sys_unlink` / `sys_mkdir` /
///     `sys_rmdir` / `sys_rename` for the FUSE service plugin
///     (nexus#4375).  Existing plugins (vault, local-connector) need
///     a clean rebuild against v2; binaries that still report v1
///     are rejected with a clear ABI-mismatch error at load time.
pub const PLUGIN_API_VERSION: u32 = 2;

// ── Plugin kind ─────────────────────────────────────────────────────

/// Discriminant returned by `nexus_plugin_kind()`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginKind {
    /// Service plugin — registers as `Arc<dyn RustService>` via
    /// `ServiceRegistry.enlist_rust()`.
    Service = 1,
    /// Driver plugin — registers as `Arc<dyn ObjectStore>` for a
    /// mount point.
    Driver = 2,
}

impl PluginKind {
    /// Convert from the raw `u32` returned by `nexus_plugin_kind()`.
    pub fn from_raw(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Service),
            2 => Some(Self::Driver),
            _ => None,
        }
    }
}

// ── Plugin result codes ─────────────────────────────────────────────

/// Return codes for C ABI functions (`dispatch`, `read`, `write`, ...).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginResult {
    Ok = 0,
    NotFound = -1,
    InvalidArgument = -2,
    Internal = -3,
}

// ── KernelHandle — vtable of callbacks a plugin can use ─────────────

/// Opaque, ABI-stable handle the kernel passes to plugins at creation
/// time. Plugins call back into the kernel through these function
/// pointers — they never link against kernel symbols directly.
///
/// The `kernel_ptr` field is an opaque pointer the plugin passes back
/// as the first argument to every callback. The kernel sets it to a
/// pointer to `Arc<Kernel>` (or a thin wrapper).
///
/// # Safety
///
/// All function pointers must be valid for the lifetime of the plugin
/// instance. The kernel guarantees this by holding a strong reference
/// to itself while any plugin is loaded.
#[repr(C)]
pub struct KernelHandle {
    /// `sys_read(kernel, path, out_buf, out_len) -> i32`
    ///
    /// Reads the content of a regular file. On success (0), `*out_buf`
    /// points to a heap-allocated buffer and `*out_len` is its length.
    /// The plugin must call `nexus_free(out_buf, out_len)` when done.
    pub sys_read: unsafe extern "C" fn(
        kernel: *const c_void,
        path: *const c_char,
        out_buf: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,

    /// `sys_write(kernel, path, data, data_len) -> i32`
    pub sys_write: unsafe extern "C" fn(
        kernel: *const c_void,
        path: *const c_char,
        data: *const u8,
        data_len: usize,
    ) -> i32,

    /// `sys_stat(kernel, path, out_json, out_len) -> i32`
    ///
    /// Returns stat result as JSON. Caller frees with `nexus_free`.
    pub sys_stat: unsafe extern "C" fn(
        kernel: *const c_void,
        path: *const c_char,
        out_json: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,

    /// `sys_readdir(kernel, parent_path, out_json, out_len) -> i32`
    ///
    /// Lists directory entries.  On success (0), `*out_json` points to
    /// a heap-allocated UTF-8 JSON array of `{"name":<str>,"entry_type":<u8>}`
    /// objects (one per child).  The plugin must call
    /// `nexus_free(out_json, out_len)` when done.  Returns
    /// `PluginResult::NotFound` (-1) when the directory does not
    /// exist; an empty directory is `Ok(0)` with `[]` payload.
    ///
    /// `entry_type` values match `kernel::meta_store::DT_*`
    /// constants (DT_REG=0, DT_DIR=1, DT_MOUNT=2, ...).
    pub sys_readdir: unsafe extern "C" fn(
        kernel: *const c_void,
        parent_path: *const c_char,
        out_json: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,

    /// `sys_unlink(kernel, path) -> i32`
    ///
    /// Remove a single regular-file inode.  Non-recursive: returns
    /// `PluginResult::InvalidArgument` (-2) when `path` resolves to a
    /// directory.  Use `sys_rmdir` for directories.
    pub sys_unlink: unsafe extern "C" fn(kernel: *const c_void, path: *const c_char) -> i32,

    /// `sys_mkdir(kernel, path) -> i32`
    ///
    /// Create a directory inode at `path`.  Parent directory must
    /// already exist (no `mkdir -p` semantic — that lives one layer up
    /// in the kernel's tier-2 convenience method).  Returns
    /// `PluginResult::Internal` (-3) on EEXIST so the FUSE layer can
    /// translate to the right POSIX errno.
    pub sys_mkdir: unsafe extern "C" fn(kernel: *const c_void, path: *const c_char) -> i32,

    /// `sys_rmdir(kernel, path) -> i32`
    ///
    /// Remove an empty directory.  Non-recursive: returns
    /// `PluginResult::Internal` (-3) when the directory still has
    /// children, mirroring POSIX `ENOTEMPTY`.
    pub sys_rmdir: unsafe extern "C" fn(kernel: *const c_void, path: *const c_char) -> i32,

    /// `sys_rename(kernel, old_path, new_path) -> i32`
    ///
    /// Atomic rename, mirrors POSIX `rename(2)`.  Caller can move
    /// across directories within the same federation zone; cross-
    /// zone moves are rejected with `PluginResult::Internal` (-3).
    pub sys_rename: unsafe extern "C" fn(
        kernel: *const c_void,
        old_path: *const c_char,
        new_path: *const c_char,
    ) -> i32,

    /// Opaque kernel pointer — passed back as first arg to every callback.
    pub kernel_ptr: *const c_void,
}

// SAFETY: KernelHandle is a bag of function pointers + an opaque ptr.
// The kernel guarantees the pointers remain valid while any plugin
// referencing the handle is alive. Plugins are Send + Sync (required
// by the C ABI contract).
unsafe impl Send for KernelHandle {}
unsafe impl Sync for KernelHandle {}

// ── Signing format (cross-repo contract) ────────────────────────────

/// Detached-signature format for plugin binaries.
///
/// **Cross-repo contract.** The signer side (nexus repository's vault
/// release CI, `scripts/sign_plugin.py`) and the verifier side
/// (`kernel::plugins::loader::PluginLoader::load`) both reference the
/// constants in this module. Drift between the two means plugins fail
/// to verify — keep this the single source of truth.
///
/// File layout produced by the signer and expected by the verifier:
/// ```text
/// libnexus_vault.so          (the plugin binary; signed verbatim)
/// libnexus_vault.so.sig      (the detached signature, 64 raw bytes)
/// ```
///
/// Public keys live in `nexus-vfs/rust/kernel/trusted_keys/*.pub` as
/// base64-encoded text files (lines starting with `#` are comments).
pub mod signing {
    /// File suffix appended to the plugin binary name to locate its
    /// detached signature on disk.
    pub const SIGNATURE_FILE_SUFFIX: &str = ".sig";

    /// Raw Ed25519 signature length, bytes. The `.sig` file is exactly
    /// this many bytes — no encoding, no PEM header, no minisign frame.
    pub const SIGNATURE_LENGTH: usize = 64;

    /// Raw Ed25519 public key length, bytes. Trusted-key files in
    /// `rust/kernel/trusted_keys/*.pub` are base64 of exactly this many
    /// raw bytes (one key per file, with optional `#` comment lines).
    pub const PUBKEY_LENGTH: usize = 32;
}

// ── Symbol name constants ───────────────────────────────────────────

/// Expected symbol names in every plugin dylib.
pub mod symbols {
    /// `fn() -> u32` — must return `PLUGIN_API_VERSION`.
    pub const API_VERSION: &str = "nexus_plugin_api_version";
    /// `fn() -> u32` — returns `PluginKind` discriminant.
    pub const KIND: &str = "nexus_plugin_kind";
    /// `fn() -> *const c_char` — null-terminated UTF-8 plugin name.
    pub const NAME: &str = "nexus_plugin_name";

    // ── Service plugin symbols ──────────────────────────────────
    /// `fn(kernel: *const KernelHandle) -> *mut c_void`
    pub const SERVICE_CREATE: &str = "nexus_service_create";
    /// `fn(svc, method, payload, len, out_buf, out_len) -> i32`
    pub const SERVICE_DISPATCH: &str = "nexus_service_dispatch";
    /// `fn(svc: *mut c_void)`
    pub const SERVICE_DESTROY: &str = "nexus_service_destroy";

    // ── Driver plugin symbols ───────────────────────────────────
    /// `fn(kernel: *const KernelHandle, config: *const c_char) -> *mut c_void`
    pub const DRIVER_CREATE: &str = "nexus_driver_create";
    /// `fn(drv, path, out_buf, out_len) -> i32`
    pub const DRIVER_READ: &str = "nexus_driver_read";
    /// `fn(drv, path, data, data_len) -> i32`
    pub const DRIVER_WRITE: &str = "nexus_driver_write";
    /// `fn(drv: *mut c_void)`
    pub const DRIVER_DESTROY: &str = "nexus_driver_destroy";
}

// ── Free function for plugin-allocated buffers ──────────────────────

/// Free a buffer allocated by the kernel's callback functions
/// (`sys_read`, `sys_stat`). Plugins must call this instead of
/// `libc::free` because the kernel may use a custom allocator.
///
/// # Safety
///
/// `ptr` must have been returned by a KernelHandle callback, and
/// `len` must match the `out_len` value set by that callback.
#[no_mangle]
pub unsafe extern "C" fn nexus_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

// ── Service plugin type aliases ─────────────────────────────────────

/// Type of the `nexus_service_create` symbol.
pub type ServiceCreateFn = unsafe extern "C" fn(kernel: *const KernelHandle) -> *mut c_void;

/// Type of the `nexus_service_dispatch` symbol.
pub type ServiceDispatchFn = unsafe extern "C" fn(
    svc: *mut c_void,
    method: *const c_char,
    payload: *const u8,
    payload_len: usize,
    out_buf: *mut *mut u8,
    out_len: *mut usize,
) -> i32;

/// Type of the `nexus_service_destroy` symbol.
pub type ServiceDestroyFn = unsafe extern "C" fn(svc: *mut c_void);

// ── Driver plugin type aliases ──────────────────────────────────────

/// Type of the `nexus_driver_create` symbol.
pub type DriverCreateFn =
    unsafe extern "C" fn(kernel: *const KernelHandle, config_json: *const c_char) -> *mut c_void;

/// Type of the `nexus_driver_read` symbol.
pub type DriverReadFn = unsafe extern "C" fn(
    drv: *mut c_void,
    path: *const c_char,
    out_buf: *mut *mut u8,
    out_len: *mut usize,
) -> i32;

/// Type of the `nexus_driver_write` symbol.
pub type DriverWriteFn = unsafe extern "C" fn(
    drv: *mut c_void,
    path: *const c_char,
    data: *const u8,
    data_len: usize,
) -> i32;

/// Type of the `nexus_driver_destroy` symbol.
pub type DriverDestroyFn = unsafe extern "C" fn(drv: *mut c_void);

// ── Helper macro for service plugins ────────────────────────────────

/// Generate the required C ABI symbols for a service plugin.
///
/// The macro expects:
/// - `$name:expr` — plugin name (string literal)
/// - `$create:expr` — a closure `|kernel: &KernelHandle| -> Box<T>`
///   where `T` implements the service logic
/// - `$dispatch:expr` — a closure `|svc: &T, method: &str, payload: &[u8]|
///   -> Result<Vec<u8>, i32>` (0 = ok from PluginResult)
///
/// # Example
///
/// ```rust,ignore
/// use nexus_plugin_abi::{declare_service_plugin, KernelHandle};
///
/// struct MyService;
///
/// declare_service_plugin!("my-service", MyService, {
///     create: |_kernel| Box::new(MyService),
///     dispatch: |svc, method, payload| {
///         match method {
///             "ping" => Ok(b"pong".to_vec()),
///             _ => Err(-1), // NotFound
///         }
///     },
/// });
/// ```
#[macro_export]
macro_rules! declare_service_plugin {
    ($name:expr, $ty:ty, {
        create: $create:expr,
        dispatch: $dispatch:expr $(,)?
    }) => {
        #[no_mangle]
        pub extern "C" fn nexus_plugin_api_version() -> u32 {
            $crate::PLUGIN_API_VERSION
        }

        #[no_mangle]
        pub extern "C" fn nexus_plugin_kind() -> u32 {
            $crate::PluginKind::Service as u32
        }

        #[no_mangle]
        pub extern "C" fn nexus_plugin_name() -> *const std::ffi::c_char {
            // Static null-terminated string
            concat!($name, "\0").as_ptr() as *const std::ffi::c_char
        }

        #[no_mangle]
        pub unsafe extern "C" fn nexus_service_create(
            kernel: *const $crate::KernelHandle,
        ) -> *mut std::os::raw::c_void {
            let kernel_ref = &*kernel;
            let create_fn: fn(&$crate::KernelHandle) -> Box<$ty> = $create;
            let boxed = create_fn(kernel_ref);
            Box::into_raw(boxed) as *mut std::os::raw::c_void
        }

        #[no_mangle]
        pub unsafe extern "C" fn nexus_service_dispatch(
            svc: *mut std::os::raw::c_void,
            method: *const std::ffi::c_char,
            payload: *const u8,
            payload_len: usize,
            out_buf: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            let svc = &*(svc as *const $ty);
            let method = std::ffi::CStr::from_ptr(method).to_str().unwrap_or("");
            let payload = if payload.is_null() || payload_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(payload, payload_len)
            };
            let dispatch_fn: fn(&$ty, &str, &[u8]) -> Result<Vec<u8>, i32> = $dispatch;
            match dispatch_fn(svc, method, payload) {
                Ok(data) => {
                    let mut data = std::mem::ManuallyDrop::new(data);
                    *out_buf = data.as_mut_ptr();
                    *out_len = data.len();
                    0
                }
                Err(code) => code,
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn nexus_service_destroy(svc: *mut std::os::raw::c_void) {
            if !svc.is_null() {
                drop(Box::from_raw(svc as *mut $ty));
            }
        }
    };
}

// ── Helper macro for driver plugins ─────────────────────────────────

/// Generate the required C ABI symbols for a driver plugin.
///
/// Mirrors [`declare_service_plugin!`] but for the driver (object store)
/// dispatch shape. The kernel loader resolves the generated symbols and
/// wraps the driver instance behind an `Arc<dyn ObjectStore>` (see
/// `kernel::kernel::plugins::loader::DylibObjectStore`).
///
/// The macro expects:
/// - `$name:expr` — plugin name (string literal). Becomes the driver's
///   backend identifier.
/// - `$ty:ty` — the Rust type holding driver state.
/// - `create: $create:expr` — a closure
///   `|kernel: &KernelHandle, config_json: &str| -> Result<Box<T>, i32>`
///   that constructs the driver from its operator-supplied JSON config.
///   Return `Err(code)` to fail the load; the kernel logs the code and
///   skips the dylib.
/// - `read: $read:expr` — a closure
///   `|drv: &T, path: &str| -> Result<Vec<u8>, i32>`. The kernel calls
///   this on read syscalls routed to the driver's mount.
/// - `write: $write:expr` — a closure
///   `|drv: &T, path: &str, data: &[u8]| -> Result<(), i32>`. The
///   kernel calls this on write syscalls routed to the driver's mount.
///
/// # Example
///
/// ```rust,ignore
/// use nexus_plugin_abi::{declare_driver_plugin, KernelHandle};
///
/// struct LocalDriver { root: std::path::PathBuf }
///
/// declare_driver_plugin!("local-connector", LocalDriver, {
///     create: |_kernel, config_json| {
///         let cfg: serde_json::Value =
///             serde_json::from_str(config_json).map_err(|_| -2)?;
///         let root = cfg["local_root"].as_str().ok_or(-2)?;
///         Ok(Box::new(LocalDriver { root: root.into() }))
///     },
///     read: |drv, path| {
///         std::fs::read(drv.root.join(path.trim_start_matches('/')))
///             .map_err(|_| -3)
///     },
///     write: |drv, path, data| {
///         std::fs::write(drv.root.join(path.trim_start_matches('/')), data)
///             .map_err(|_| -3)
///     },
/// });
/// ```
#[macro_export]
macro_rules! declare_driver_plugin {
    ($name:expr, $ty:ty, {
        create: $create:expr,
        read: $read:expr,
        write: $write:expr $(,)?
    }) => {
        #[no_mangle]
        pub extern "C" fn nexus_plugin_api_version() -> u32 {
            $crate::PLUGIN_API_VERSION
        }

        #[no_mangle]
        pub extern "C" fn nexus_plugin_kind() -> u32 {
            $crate::PluginKind::Driver as u32
        }

        #[no_mangle]
        pub extern "C" fn nexus_plugin_name() -> *const std::ffi::c_char {
            concat!($name, "\0").as_ptr() as *const std::ffi::c_char
        }

        #[no_mangle]
        pub unsafe extern "C" fn nexus_driver_create(
            kernel: *const $crate::KernelHandle,
            config_json: *const std::ffi::c_char,
        ) -> *mut std::os::raw::c_void {
            let kernel_ref = &*kernel;
            let config_str = if config_json.is_null() {
                ""
            } else {
                match std::ffi::CStr::from_ptr(config_json).to_str() {
                    Ok(s) => s,
                    Err(_) => return std::ptr::null_mut(),
                }
            };
            let create_fn: fn(&$crate::KernelHandle, &str) -> Result<Box<$ty>, i32> = $create;
            match create_fn(kernel_ref, config_str) {
                Ok(boxed) => Box::into_raw(boxed) as *mut std::os::raw::c_void,
                Err(_) => std::ptr::null_mut(),
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn nexus_driver_read(
            drv: *mut std::os::raw::c_void,
            path: *const std::ffi::c_char,
            out_buf: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            let drv = &*(drv as *const $ty);
            let path = match std::ffi::CStr::from_ptr(path).to_str() {
                Ok(s) => s,
                Err(_) => return -2,
            };
            let read_fn: fn(&$ty, &str) -> Result<Vec<u8>, i32> = $read;
            match read_fn(drv, path) {
                Ok(data) => {
                    let mut data = std::mem::ManuallyDrop::new(data);
                    *out_buf = data.as_mut_ptr();
                    *out_len = data.len();
                    0
                }
                Err(code) => code,
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn nexus_driver_write(
            drv: *mut std::os::raw::c_void,
            path: *const std::ffi::c_char,
            data: *const u8,
            data_len: usize,
        ) -> i32 {
            let drv = &*(drv as *const $ty);
            let path = match std::ffi::CStr::from_ptr(path).to_str() {
                Ok(s) => s,
                Err(_) => return -2,
            };
            let bytes = if data.is_null() || data_len == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts(data, data_len)
            };
            let write_fn: fn(&$ty, &str, &[u8]) -> Result<(), i32> = $write;
            match write_fn(drv, path, bytes) {
                Ok(()) => 0,
                Err(code) => code,
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn nexus_driver_destroy(drv: *mut std::os::raw::c_void) {
            if !drv.is_null() {
                drop(Box::from_raw(drv as *mut $ty));
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_kind_round_trip() {
        assert_eq!(PluginKind::from_raw(1), Some(PluginKind::Service));
        assert_eq!(PluginKind::from_raw(2), Some(PluginKind::Driver));
        assert_eq!(PluginKind::from_raw(0), None);
        assert_eq!(PluginKind::from_raw(99), None);
    }

    #[test]
    fn plugin_result_values() {
        assert_eq!(PluginResult::Ok as i32, 0);
        assert_eq!(PluginResult::NotFound as i32, -1);
        assert_eq!(PluginResult::InvalidArgument as i32, -2);
        assert_eq!(PluginResult::Internal as i32, -3);
    }

    #[test]
    fn nexus_free_null_is_safe() {
        unsafe { nexus_free(std::ptr::null_mut(), 0) };
    }

    #[test]
    fn signing_format_constants() {
        // Pinned values — the signer (nexus repo CI) and the verifier
        // (kernel::plugins::loader) read this same module. Changing any
        // of these silently breaks every existing signed plugin, so the
        // test makes the values explicit rather than just "whatever the
        // constant says".
        assert_eq!(signing::SIGNATURE_FILE_SUFFIX, ".sig");
        assert_eq!(signing::SIGNATURE_LENGTH, 64);
        assert_eq!(signing::PUBKEY_LENGTH, 32);
    }
}
