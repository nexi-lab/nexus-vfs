//! Unary gRPC dispatch across the plugin boundary. Header values retain their
//! HTTP wire encoding (including base64 for `-bin` metadata). The host supplies
//! peer provenance separately; a client header can never manufacture it.

use std::ffi::{c_char, c_void};

/// Connection identity verified by the host against its cluster trust roots.
#[derive(Clone, Copy, Debug, Default)]
pub struct GrpcPeer {
    pub is_cluster_node: bool,
}

/// Per-request metadata and verified connection provenance.
#[derive(Clone, Debug, Default)]
pub struct GrpcContext {
    pub headers: Vec<(String, Vec<u8>)>,
    pub peer: GrpcPeer,
}

#[cfg(feature = "tonic")]
impl GrpcContext {
    /// Build the request inside a tonic-based plugin. Peer provenance is an
    /// extension; no client-supplied header is interpreted as authority.
    pub fn request<T>(&self, body: T) -> Result<tonic::Request<T>, tonic::Status> {
        let mut headers = http::HeaderMap::new();
        for (name, value) in &self.headers {
            let name = http::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| tonic::Status::invalid_argument("invalid metadata name"))?;
            let value = http::HeaderValue::from_bytes(value)
                .map_err(|_| tonic::Status::invalid_argument("invalid metadata value"))?;
            headers.append(name, value);
        }
        let mut request = tonic::Request::new(body);
        *request.metadata_mut() = tonic::metadata::MetadataMap::from_headers(headers);
        request.extensions_mut().insert(self.peer);
        Ok(request)
    }
}

/// A gRPC status. `code` uses the protocol's numeric codes 1 through 16.
#[derive(Debug)]
pub struct GrpcError {
    pub code: u32,
    pub message: String,
}

impl std::fmt::Display for GrpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gRPC {}: {}", self.code, self.message)
    }
}

impl std::error::Error for GrpcError {}

/// Host-side service surface. Only the C entry point below crosses the dylib
/// boundary; Rust trait objects and HTTP library types stay within each image.
pub trait GrpcService: Send + Sync {
    fn call(
        &self,
        method: &str,
        payload: &[u8],
        context: &GrpcContext,
    ) -> Result<Vec<u8>, GrpcError>;
}

/// Borrowed header entry. Both buffers remain valid for the dispatch call.
#[repr(C)]
pub struct Header {
    pub name: *const u8,
    pub name_len: usize,
    pub value: *const u8,
    pub value_len: usize,
}

impl Header {
    pub fn borrowed(name: &str, value: &[u8]) -> Self {
        Self {
            name: name.as_ptr(),
            name_len: name.len(),
            value: value.as_ptr(),
            value_len: value.len(),
        }
    }
}

/// Required for a plugin that advertises gRPC service names. Returns a gRPC
/// code (0 on success); the output is protobuf on success and a UTF-8 status
/// message on error. In both cases the host frees it through the plugin's
/// `nexus_free`. All input buffers are borrowed for the duration of the call.
pub type DispatchFn = unsafe extern "C" fn(
    service: *mut c_void,
    method: *const c_char,
    payload: *const u8,
    payload_len: usize,
    headers: *const Header,
    headers_len: usize,
    is_cluster_node: bool,
    out_buf: *mut *mut u8,
    out_len: *mut usize,
) -> u32;

/// Copy borrowed metadata into the plugin's allocator.
///
/// # Safety
/// Each pointer must address the indicated number of initialized bytes/entries
/// for this call. Zero-length buffers may use a null pointer.
pub unsafe fn read_headers(
    headers: *const Header,
    len: usize,
) -> Result<Vec<(String, Vec<u8>)>, GrpcError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    std::slice::from_raw_parts(headers, len)
        .iter()
        .map(|header| {
            let name = if header.name_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(header.name, header.name_len)
            };
            let name = std::str::from_utf8(name).map_err(|_| GrpcError {
                code: 3,
                message: "invalid metadata name".into(),
            })?;
            let value = if header.value_len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(header.value, header.value_len).to_vec()
            };
            Ok((name.to_owned(), value))
        })
        .collect()
}

/// Export unary gRPC dispatch for a service created by `declare_service_plugin!`.
/// The closure receives the plugin instance, full method path, protobuf body,
/// and request context. It returns protobuf bytes or an exact gRPC status.
#[macro_export]
macro_rules! declare_grpc_dispatch {
    ($ty:ty, $dispatch:expr) => {
        /// # Safety
        /// The service must be live and every input/output pointer valid for
        /// this call, following `nexus_plugin_abi::grpc::DispatchFn`.
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub unsafe extern "C" fn nexus_service_dispatch_grpc(
            svc: *mut std::ffi::c_void,
            method: *const std::ffi::c_char,
            payload: *const u8,
            payload_len: usize,
            headers: *const $crate::grpc::Header,
            headers_len: usize,
            is_cluster_node: bool,
            out_buf: *mut *mut u8,
            out_len: *mut usize,
        ) -> u32 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let svc = &*(svc as *const $ty);
                let method = std::ffi::CStr::from_ptr(method).to_str().map_err(|_| {
                    $crate::grpc::GrpcError {
                        code: 3,
                        message: "invalid method path".into(),
                    }
                })?;
                let payload = if payload_len == 0 {
                    &[]
                } else {
                    std::slice::from_raw_parts(payload, payload_len)
                };
                let context = $crate::grpc::GrpcContext {
                    headers: $crate::grpc::read_headers(headers, headers_len)?,
                    peer: $crate::grpc::GrpcPeer { is_cluster_node },
                };
                let dispatch: fn(
                    &$ty,
                    &str,
                    &[u8],
                    &$crate::grpc::GrpcContext,
                ) -> Result<Vec<u8>, $crate::grpc::GrpcError> = $dispatch;
                dispatch(svc, method, payload, &context)
            }))
            .unwrap_or_else(|_| {
                Err($crate::grpc::GrpcError {
                    code: 13,
                    message: "plugin gRPC handler panicked".into(),
                })
            });
            let (code, data) = match result {
                Ok(data) => (0, data),
                Err(error) => (error.code, error.message.into_bytes()),
            };
            let data = data.into_boxed_slice();
            *out_len = data.len();
            *out_buf = if data.is_empty() {
                std::ptr::null_mut()
            } else {
                Box::into_raw(data) as *mut u8
            };
            code
        }
    };
}
