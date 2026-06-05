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
//! The kernel's `PluginLoader` (in `kernel::core::plugin_loader`) is the
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
pub const PLUGIN_API_VERSION: u32 = 1;

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

    /// Opaque kernel pointer — passed back as first arg to every callback.
    pub kernel_ptr: *const c_void,
}

// SAFETY: KernelHandle is a bag of function pointers + an opaque ptr.
// The kernel guarantees the pointers remain valid while any plugin
// referencing the handle is alive. Plugins are Send + Sync (required
// by the C ABI contract).
unsafe impl Send for KernelHandle {}
unsafe impl Sync for KernelHandle {}

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
}
