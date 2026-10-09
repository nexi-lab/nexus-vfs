//! `nexus-search-plugin` — SearchService cdylib.
//!
//! Loaded by `nexusd-cluster` via `--plugin-dir`. Exposes indexed keyword,
//! semantic and hybrid search alongside VFS glob and regex grep. The plugin
//! declares `nexus.search.v1.SearchService` through `nexus_plugin_grpc_services`;
//! the host routes tonic traffic into `nexus_service_dispatch_grpc`.
//!
//! The host's SearchGrpcPolicy authenticates requests, checks readable zone
//! grants, and filters every returned path with the kernel's installed permission
//! provider. Index management and aggregate diagnostics require an administrator
//! or cluster node. A deployment must install a permission provider to enforce
//! file-level rules; the bare cluster profile only enforces identity and zones.
//! The plugin cache stores candidates and never stores authorization decisions.
//!
//! ## Why a plugin (and not a kernel primitive)
//!
//! Grep + glob are compositions over the kernel's `sys_readdir` +
//! `sys_read` primitives, not primitives themselves — putting the
//! walker + regex engine in the kernel tier would grow `kernel/`
//! with policy code that has no business next to the syscall ABI.
//! The cdylib boundary keeps the kernel small (kernel default:
//! zero search logic) and lets the plugin ship its own release
//! cadence with its own signed release chain.
//!
//! ## VFS discovery
//!
//! Recursive discovery uses `sys_readdir`; explicit working sets use `sys_stat`
//! on each authorized path. Glob matches with `globset`; grep reads UTF-8 file
//! content and scans with `regex`. The default result caps are 10,000 paths
//! for glob and 1,000 lines for grep. Recency sorting precedes the cap.
//! Cross-node paths resolve through the kernel's mounted filesystem backends.

use std::ffi::c_char;
use std::sync::Arc;

use nexus_plugin_abi::grpc::{GrpcContext, GrpcError};
use nexus_plugin_abi::{declare_grpc_dispatch, declare_service_plugin, KernelHandle};
use prost::Message;
use tonic::Status;

use crate::service::SearchServiceImpl;

// Generated tonic bindings for `nexus.search.v1`.  Include-path
// mirrors the vault crate — `OUT_DIR` gets the codegen output at
// build time from `build.rs`.
pub mod search_proto {
    #![allow(clippy::all)]
    #![allow(unused_qualifications)]
    tonic::include_proto!("nexus.search.v1");
}

pub mod ann_flush;
pub mod ann_index;
pub mod chunker;
pub mod contextual_chunker;
/// Servicer-side extract + validation of the `SearchDelegation` a
/// peer daemon stamps on `SearchService.Query` metadata.  See the
/// module docstring for the caller contract (used by
/// `SearchServiceImpl::query`).
pub mod delegation_gate;
mod discovery;
pub mod embed_cache;
pub mod embedder;
pub mod fts_index;
pub mod fusion;
pub mod http_client;
pub mod index_manager;
pub mod index_seq;
pub mod index_state;
pub mod indexed_dirs_state;
pub mod internal_call;
pub mod kernel_io;
pub mod llm_chat;
pub mod macro_expand;
mod markdown;
pub mod parked_state;
pub mod path_scope;
pub mod peer_fanout;
pub mod peer_registry;
pub mod query_cache;
pub mod query_expansion;
pub mod scoring;
pub mod service;
pub mod title_index;
pub mod zone_modes_state;

use search_proto::search_service_server::SearchService as SearchServiceTrait;
use search_proto::{
    AddIndexedDirectoryRequest, BatchQueryRequest, GlobRequest, GrepRequest, HealthRequest,
    IndexDocumentsRequest, IndexRequest, ListIndexedDirectoriesRequest,
    ListZoneIndexingModesRequest, LocateRequest, NotifyFileChangeRequest, ParkedDiscardRequest,
    ParkedListRequest, ParkedRetryRequest, QueryRequest, RefreshRequest,
    RemoveIndexedDirectoryRequest, SetZoneIndexingModeRequest, StatsRequest,
};

/// Plugin state held between `create` and `destroy`.
///
/// Owns the SearchService impl (which carries the compiled regex
/// cache and future indexing state) plus a small tokio runtime used
/// by `dispatch_grpc` to bridge the sync `nexus_service_dispatch`
/// ABI into the async tonic trait.
pub struct SearchPlugin {
    svc: Arc<SearchServiceImpl>,
    rt: tokio::runtime::Runtime,
}

/// Deep-clone a `KernelHandle` by copying every C-ABI field.  The
/// plugin ABI's `KernelHandle` is `#[repr(C)]` with fn-pointer +
/// `*const c_void` fields — all naturally `Copy` at the machine level
/// — but the type deliberately does NOT derive `Clone` so callers
/// think twice before duplicating it (each copy points at the same
/// kernel instance).  Search-plugin holds one copy inside an `Arc`
/// so the service impl + every `spawn_blocking` closure can share it
/// without cloning the underlying kernel.
fn dup_kernel_handle(h: &KernelHandle) -> KernelHandle {
    KernelHandle {
        sys_read: h.sys_read,
        sys_write: h.sys_write,
        sys_stat: h.sys_stat,
        sys_readdir: h.sys_readdir,
        sys_unlink: h.sys_unlink,
        sys_mkdir: h.sys_mkdir,
        sys_rmdir: h.sys_rmdir,
        sys_rename: h.sys_rename,
        sys_stat_batch: h.sys_stat_batch,
        free_buf: h.free_buf,
        kernel_ptr: h.kernel_ptr,
    }
}

fn create_search_plugin(kernel_handle: &KernelHandle) -> Box<SearchPlugin> {
    tracing::info!("nexus-search-plugin: create");
    let svc = Arc::new(SearchServiceImpl::new(Arc::new(dup_kernel_handle(
        kernel_handle,
    ))));
    Box::new(SearchPlugin {
        svc,
        rt: build_runtime(),
    })
}

/// Idle blocking-pool threads live this long before exiting (#4725).
/// tokio's default is 10 s, which under a steady request cadence means
/// a `pthread_create` per request — the churn that exhausted a cgroup
/// `pids.max` shared with the Python server.  It also means the pool is
/// usually EMPTY when a request arrives, and tokio turns a thread-spawn
/// `EAGAIN` into a panic only when the pool is empty (a non-empty pool
/// just queues the task for a busy thread).  Keeping threads for an
/// hour bounds the pool at the peak concurrency actually seen and makes
/// that panic unreachable while traffic flows.
const BLOCKING_THREAD_KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(3600);

/// The plugin's tokio runtime — bridges the sync plugin-ABI dispatch
/// into the async tonic trait via `block_on`.
///
/// Single-threaded, same posture as `nexus-vault`: search requests
/// are IO-bound (kernel-syscall walk) and heavy work runs on the
/// blocking pool, so parallelism gain does not justify pulling
/// `rt-multi-thread` into the plugin's dep tree.  Build errors are
/// effectively unreachable on healthy hosts (OS-level thread creation
/// failure); a panic here at load time is the same posture
/// `nexus-vault` takes — a broken plugin is worse than a loud failure.
fn build_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        // #4725: tokio's default thread name is "tokio-rt-worker",
        // which reads as a HOST thread in a panic line and sent the
        // investigation the wrong way.  Name ours.
        .thread_name("nexus-search-plugin")
        .thread_keep_alive(BLOCKING_THREAD_KEEP_ALIVE)
        .build()
        .expect("build search-plugin tokio runtime")
}

/// Plugin-ABI dispatch entry, wrapped in the last line of defence
/// (#4725).  A panic escaping a handler here would unwind into the
/// host's `extern "C"` `nexus_service_dispatch_grpc` and abort the WHOLE
/// nexusd-cluster process — kernel, raft, every plugin — for one
/// request's worth of trouble.  The realistic source is tokio
/// refusing a blocking thread (`OS can't spawn worker thread`), which
/// fires BEFORE any handler work runs, so nothing is left half-
/// mutated; the deeper stores are transactional regardless (FTS
/// commit probe, fail-closed dirty marks, `parking_lot` guards that
/// release on unwind).  tokio's current-thread scheduler hands its
/// core back from the `CoreGuard` drop when a `block_on` future
/// panics, so the runtime keeps serving afterwards.  Fail THIS RPC
/// with `Internal`, count it on Health, carry on.
fn dispatch_search(
    plugin: &SearchPlugin,
    method: &str,
    payload: &[u8],
    context: &GrpcContext,
) -> Result<Vec<u8>, GrpcError> {
    let guarded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatch_grpc(plugin, method, payload, context)
    }));
    match guarded {
        Ok(result) => result.map_err(|status| GrpcError {
            code: status.code() as u32,
            message: status.message().to_owned(),
        }),
        Err(payload) => {
            let reason = crate::http_client::panic_reason(payload.as_ref());
            tracing::error!(
                method = %method,
                reason = %reason,
                "nexus-search-plugin: handler panicked — failing this RPC instead of the host process",
            );
            plugin.svc.record_dispatch_panic(method, &reason);
            Err(GrpcError {
                code: 13,
                message: "search handler panicked".into(),
            })
        }
    }
}

fn dispatch_grpc(
    plugin: &SearchPlugin,
    method: &str,
    payload: &[u8],
    context: &GrpcContext,
) -> Result<Vec<u8>, Status> {
    let method = method
        .strip_prefix("/nexus.search.v1.SearchService/")
        .ok_or_else(|| Status::unimplemented("unknown search service"))?;
    // A search delegation cannot be used on any administrative or file RPC.
    // Query validates its target zone inside the servicer.
    if method != "Query" {
        crate::delegation_gate::extract_and_validate(&context.request(())?, method, "")?;
    }
    macro_rules! call {
        ($ty:ty, $handler:ident) => {{
            let body = <$ty>::decode(payload)
                .map_err(|e| Status::invalid_argument(format!("invalid {method} request: {e}")))?;
            let request = context.request(body)?;
            Ok(plugin
                .rt
                .block_on(plugin.svc.$handler(request))?
                .into_inner()
                .encode_to_vec())
        }};
    }
    match method {
        "Glob" => call!(GlobRequest, glob),
        "Grep" => call!(GrepRequest, grep),
        "Query" => call!(QueryRequest, query),
        "Index" => call!(IndexRequest, index),
        "Refresh" => call!(RefreshRequest, refresh),
        "BatchQuery" => call!(BatchQueryRequest, batch_query),
        "IndexDocuments" => call!(IndexDocumentsRequest, index_documents),
        "NotifyFileChange" => call!(NotifyFileChangeRequest, notify_file_change),
        "Locate" => call!(LocateRequest, locate),
        "ParkedList" => call!(ParkedListRequest, parked_list),
        "ParkedRetry" => call!(ParkedRetryRequest, parked_retry),
        "ParkedDiscard" => call!(ParkedDiscardRequest, parked_discard),
        "AddIndexedDirectory" => call!(AddIndexedDirectoryRequest, add_indexed_directory),
        "RemoveIndexedDirectory" => call!(RemoveIndexedDirectoryRequest, remove_indexed_directory),
        "ListIndexedDirectories" => call!(ListIndexedDirectoriesRequest, list_indexed_directories),
        "SetZoneIndexingMode" => call!(SetZoneIndexingModeRequest, set_zone_indexing_mode),
        "ListZoneIndexingModes" => call!(ListZoneIndexingModesRequest, list_zone_indexing_modes),
        "Health" => call!(HealthRequest, health),
        "Stats" => call!(StatsRequest, stats),
        #[cfg(test)]
        "__panic_for_test" => plugin
            .rt
            .block_on(async { panic!("injected dispatch panic") }),
        _ => Err(Status::unimplemented("unknown search method")),
    }
}

declare_service_plugin!("search", SearchPlugin, {
    create: create_search_plugin,
    dispatch: |_plugin, _method, _payload| Err(-1),
});

declare_grpc_dispatch!(SearchPlugin, dispatch_search);

/// Phase P opt-in: this cdylib exposes its gRPC service full name
/// hosted here, so `nexusd-cluster` can route external tonic traffic
/// at `/nexus.search.v1.SearchService/<method>` into our
/// `nexus_service_dispatch_grpc`. See `nexus-plugin-abi`'s
/// `symbols::SERVICE_GRPC_SERVICES` constant for the JSON contract.
///
/// # Safety
///
/// `SERVICES_JSON` is a static, null-terminated UTF-8 byte string with
/// `'static` lifetime; the pointer we hand back never dangles.  The
/// loader treats the return value as `*const c_char` and only reads
/// (never frees) it.
#[no_mangle]
pub unsafe extern "C" fn nexus_plugin_grpc_services() -> *const c_char {
    const SERVICES_JSON: &[u8] = b"[\"nexus.search.v1.SearchService\"]\0";
    SERVICES_JSON.as_ptr() as *const c_char
}

// Re-export the two proto message types for downstream integration
// tests that dial the plugin over a real tonic channel.  Kept in the
// crate root so callers write `use nexus_search_plugin::{GlobRequest,
// GrepRequest}` without going through the generated module tree.
pub use search_proto::{GlobResponse as ExportGlobResponse, GrepResponse as ExportGrepResponse};

#[cfg(test)]
mod tests {
    //! Dispatch-boundary guard (#4725).  A handler panic must fail its
    //! own RPC with `Internal`, be counted on Health, and leave the
    //! runtime serving — never unwind into the host's `extern "C"`
    //! dispatch (process abort).

    use std::ffi::c_void;
    use std::os::raw::c_char;

    use super::*;
    use crate::index_manager::IndexManager;
    use crate::search_proto::HealthResponse;

    // All-`-1` kernel: Health never touches the kernel; an accidental
    // touch fails loud instead of hitting a silent stub.
    unsafe extern "C" fn poison_buf(
        _: *const c_void,
        _: *const c_char,
        _: *mut *mut u8,
        _: *mut usize,
    ) -> i32 {
        -1
    }
    unsafe extern "C" fn poison_write(
        _: *const c_void,
        _: *const c_char,
        _: *const u8,
        _: usize,
        _: u64,
    ) -> i32 {
        -1
    }
    unsafe extern "C" fn poison_path(_: *const c_void, _: *const c_char) -> i32 {
        -1
    }
    unsafe extern "C" fn poison_rename(
        _: *const c_void,
        _: *const c_char,
        _: *const c_char,
    ) -> i32 {
        -1
    }

    fn poison_handle() -> KernelHandle {
        KernelHandle {
            sys_read: poison_buf,
            sys_write: poison_write,
            sys_stat: poison_buf,
            sys_readdir: poison_buf,
            sys_unlink: poison_path,
            sys_mkdir: poison_path,
            sys_rmdir: poison_path,
            sys_rename: poison_rename,
            sys_stat_batch: poison_buf,
            free_buf: nexus_plugin_abi::nexus_free,
            kernel_ptr: std::ptr::null(),
        }
    }

    fn plugin_for_test() -> SearchPlugin {
        let root = tempfile::tempdir().expect("tempdir").keep();
        let svc = SearchServiceImpl::builder(Arc::new(poison_handle()))
            .manager(Arc::new(IndexManager::with_root(root)))
            .no_expander()
            .no_peer_fanout()
            .no_context_generator()
            .build();
        SearchPlugin {
            svc: Arc::new(svc),
            rt: build_runtime(),
        }
    }

    fn health(plugin: &SearchPlugin) -> HealthResponse {
        let bytes = dispatch_search(
            plugin,
            "/nexus.search.v1.SearchService/Health",
            &HealthRequest::default().encode_to_vec(),
            &GrpcContext::default(),
        )
        .expect("health dispatch");
        HealthResponse::decode(bytes.as_slice()).expect("decode health")
    }

    #[test]
    fn handler_panic_fails_the_rpc_not_the_process_and_is_counted() {
        let plugin = plugin_for_test();
        assert_eq!(health(&plugin).dispatch_panics, 0);

        let code = dispatch_search(
            &plugin,
            "/nexus.search.v1.SearchService/__panic_for_test",
            &[],
            &GrpcContext::default(),
        )
        .expect_err("a panicking handler fails its RPC");
        assert_eq!(code.code, 13, "PluginResult::Internal");

        // The runtime survived the panic inside `block_on` and the
        // service still answers; the panic is on the record.
        let h = health(&plugin);
        assert_eq!(h.dispatch_panics, 1);
        assert!(h.detail.contains("injected dispatch panic"), "{}", h.detail);
        assert_eq!(
            h.status, "degraded",
            "no embedder ⇒ degraded; the caught panic itself does not move status"
        );
        assert_eq!(
            health(&plugin).dispatch_panics,
            1,
            "counted per panic, not per poll"
        );
    }
}
