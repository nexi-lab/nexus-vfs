use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use kernel::kernel::convenience::KernelConvenience;
use kernel::kernel::vfs_proto::{
    nexus_vfs_service_server::NexusVfsService, GetXattrBulkRequest, GetXattrRequest, IpcEmpty,
    IpcPathRequest, LockRequest, SetXattrRequest, SetattrRequest, UnlockRequest, WatchRequest,
};
use kernel::kernel::{KernelError, OperationContext};
use kernel::{Permission, PermissionProvider};
use tonic::Request;

use crate::grpc::VfsServiceImpl;
use crate::grpc_metadata_access_tests::fixture;

#[tokio::test]
async fn viewer_cannot_mutate_attributes_locks_or_close_ipc() {
    let (service, grants) = fixture();
    let path = "/docs/b-own.txt";
    grants.lock().unwrap().insert(path.into());
    let kernel = Arc::clone(&service.kernel);
    let admin = VfsServiceImpl::for_test(Arc::clone(&kernel));
    for (path, entry_type) in [("/docs/pipe", 3), ("/docs/stream", 4)] {
        let response = admin
            .setattr(Request::new(SetattrRequest {
                path: path.into(),
                entry_type,
                capacity: 16,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.is_error);
        grants.lock().unwrap().insert(path.into());
    }
    let response = service
        .set_xattr(Request::new(SetXattrRequest {
            path: path.into(),
            key: "label".into(),
            value: "bad".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.is_error);
    assert_eq!(kernel.get_xattr(path, "label", "root").unwrap(), None);
    let response = service
        .lock(Request::new(LockRequest {
            path: path.into(),
            timeout_ms: 100,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.is_error && !response.acquired);
    let response = service
        .unlock(Request::new(UnlockRequest {
            path: path.into(),
            force: true,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.is_error && !response.released);
    let ipc = |path: &str| {
        Request::new(IpcPathRequest {
            path: path.into(),
            ..Default::default()
        })
    };
    assert!(
        service
            .has_pipe(ipc("/docs/pipe"))
            .await
            .unwrap()
            .into_inner()
            .present
    );
    assert!(
        service
            .has_stream(ipc("/docs/stream"))
            .await
            .unwrap()
            .into_inner()
            .present
    );
    assert!(
        service
            .close_pipe(ipc("/docs/pipe"))
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
    assert!(
        service
            .close_stream(ipc("/docs/stream"))
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
    assert!(
        service
            .close_all_pipes(Request::new(IpcEmpty::default()))
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
    assert!(kernel.has_pipe("/docs/pipe") && kernel.has_stream("/docs/stream"));
    grants.lock().unwrap().clear();
    assert!(
        service
            .has_pipe(ipc("/docs/pipe"))
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
    assert!(
        service
            .has_stream(ipc("/docs/stream"))
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
}

struct Writer;
impl PermissionProvider for Writer {
    fn check(
        &self,
        path: &str,
        _: Option<&kernel::vfs_router::RouteResult>,
        _: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        assert_eq!(ctx.subject_id.as_deref(), Some("agent-a"));
        if matches!(path, "/docs/b-own.txt" | "/docs/pipe" | "/docs/stream") {
            Ok(())
        } else {
            Err(KernelError::PermissionDenied(path.into()))
        }
    }
}

#[tokio::test]
async fn writer_can_use_attributes_and_locks_while_bulk_reads_preflight_all_paths() {
    let (service, _) = fixture();
    let path = "/docs/b-own.txt";
    service
        .kernel
        .set_permission_provider(Arc::new(Box::new(Writer)));
    let response = service
        .set_xattr(Request::new(SetXattrRequest {
            path: path.into(),
            key: "label".into(),
            value: "owned".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!response.is_error, "{response:?}");
    let response = service
        .get_xattr(Request::new(GetXattrRequest {
            path: path.into(),
            key: "label".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.found && response.value == "owned");
    let response = service
        .get_xattr_bulk(Request::new(GetXattrBulkRequest {
            paths: vec![path.into(), "/docs/a-hidden.txt".into()],
            key: "label".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.is_error && response.items.is_empty());
    let response = service
        .lock(Request::new(LockRequest {
            path: path.into(),
            timeout_ms: 1000,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.acquired && !response.is_error);
    let response = service
        .unlock(Request::new(UnlockRequest {
            path: path.into(),
            lock_id: response.lock_id,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.released && !response.is_error);
    for (path, entry_type) in [("/docs/pipe", 3), ("/docs/stream", 4)] {
        let response = service
            .setattr(Request::new(SetattrRequest {
                path: path.into(),
                entry_type,
                capacity: 16,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.is_error, "{response:?}");
    }
    let ipc = |path: &str| {
        Request::new(IpcPathRequest {
            path: path.into(),
            ..Default::default()
        })
    };
    assert!(
        !service
            .close_pipe(ipc("/docs/pipe"))
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
    assert!(
        !service
            .close_stream(ipc("/docs/stream"))
            .await
            .unwrap()
            .into_inner()
            .is_error
    );
    let ctx = OperationContext::new("setup", "root", true, None, true);
    assert!(service
        .kernel
        .pipe_write_nowait("/docs/pipe", b"x", &ctx)
        .is_err());
    assert!(service
        .kernel
        .stream_write_nowait("/docs/stream", b"x", &ctx)
        .is_err());
}

struct WatchGrants {
    grants: Arc<Mutex<HashSet<String>>>,
    checks: Arc<AtomicUsize>,
}
impl PermissionProvider for WatchGrants {
    fn check(
        &self,
        path: &str,
        _: Option<&kernel::vfs_router::RouteResult>,
        _: Permission,
        _: &OperationContext,
    ) -> Result<(), KernelError> {
        let allowed = self.grants.lock().unwrap().contains(path);
        self.checks.fetch_add(1, Ordering::Release);
        if allowed {
            Ok(())
        } else {
            Err(KernelError::PermissionDenied(path.into()))
        }
    }
}

#[tokio::test]
async fn watches_require_scope_permission_and_recheck_events_after_revocation() {
    let (service, grants) = fixture();
    grants.lock().unwrap().insert("/docs/b-own.txt".into());
    let response = service
        .watch(Request::new(WatchRequest {
            path: "/docs/*".into(),
            timeout_ms: 0,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.is_error && !response.matched);
    grants.lock().unwrap().insert("/docs".into());
    for pattern in ["/docs/*", "/docs/b-own.txt"] {
        let response = service
            .watch(Request::new(WatchRequest {
                path: pattern.into(),
                timeout_ms: 0,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.is_error && !response.matched);
    }
    let kernel = Arc::clone(&service.kernel);
    let checks = Arc::new(AtomicUsize::new(0));
    kernel.set_permission_provider(Arc::new(Box::new(WatchGrants {
        grants: Arc::clone(&grants),
        checks: Arc::clone(&checks),
    })));
    let watch = tokio::spawn(async move {
        service
            .watch(Request::new(WatchRequest {
                path: "/docs/b-own.txt".into(),
                timeout_ms: 2000,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
    });
    // Notify repeatedly so scheduling cannot lose the event before watch registration.
    for _ in 0..100 {
        if checks.load(Ordering::Acquire) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(
        checks.load(Ordering::Acquire),
        1,
        "watch must have authorized its scope"
    );
    grants.lock().unwrap().remove("/docs/b-own.txt");
    for _ in 0..50 {
        kernel.wake_file_watch("/docs/b-own.txt");
        if watch.is_finished() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let response = watch.await.unwrap();
    assert_eq!(
        checks.load(Ordering::Acquire),
        2,
        "event must be checked after the wait"
    );
    assert!(response.is_error && !response.matched && response.path.is_empty());
}

#[test]
fn glob_watch_scope_is_the_fixed_parent() {
    for (pattern, scope) in [
        ("/docs/file.txt", "/docs/file.txt"),
        ("/docs/**/file", "/docs"),
        ("/docs/pre*.txt", "/docs"),
        ("/{docs,secrets}/x", "/"),
        ("*", "/"),
        ("/docs/../secret/*", "/docs/../secret"),
    ] {
        assert_eq!(VfsServiceImpl::watch_scope(pattern), scope);
    }
}
