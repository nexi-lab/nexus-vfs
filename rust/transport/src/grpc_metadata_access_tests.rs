use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::vfs_proto::{
    nexus_vfs_service_server::NexusVfsService, BatchStatRequest, ReaddirRequest, StatRequest,
};
use kernel::kernel::{KernelError, OperationContext};
use kernel::{Permission, PermissionProvider};
use tonic::{Code, Request, Status};

use crate::auth::{AuthCredentials, AuthProvider};
use crate::grpc::{tests::kernel_with_mem_backend, VfsServiceImpl};

struct AgentAuth;
impl AuthProvider for AgentAuth {
    fn resolve(&self, _: &AuthCredentials<'_>) -> Result<OperationContext, Status> {
        let mut ctx = OperationContext::new("owner", "root", false, Some("agent-a".into()), false);
        ctx.subject_type = "agent".into();
        ctx.subject_id = Some("agent-a".into());
        Ok(ctx)
    }
}

struct Grants(Arc<Mutex<HashSet<String>>>);
impl PermissionProvider for Grants {
    fn check(
        &self,
        path: &str,
        _: Option<&kernel::vfs_router::RouteResult>,
        permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        assert_eq!(ctx.subject_type, "agent");
        assert_eq!(ctx.subject_id.as_deref(), Some("agent-a"));
        if matches!(permission, Permission::Read) && self.0.lock().unwrap().contains(path) {
            Ok(())
        } else {
            Err(KernelError::PermissionDenied(format!("denied: {path}")))
        }
    }
}

pub(crate) fn fixture() -> (VfsServiceImpl, Arc<Mutex<HashSet<String>>>) {
    let kernel = Arc::new(kernel_with_mem_backend());
    let ctx = OperationContext::new("setup", "root", true, None, true);
    for path in [
        "/docs/a-hidden.txt",
        "/docs/b-own.txt",
        "/docs/nested/c-own.txt",
    ] {
        KernelSyscall::sys_write(&*kernel, path, &ctx, b"secret", 0).unwrap();
    }
    let grants = Arc::new(Mutex::new(HashSet::new()));
    kernel.set_permission_provider(Arc::new(Box::new(Grants(Arc::clone(&grants)))));
    let mut service = VfsServiceImpl::for_test(kernel);
    service.auth = Arc::new(AgentAuth);
    (service, grants)
}

#[tokio::test]
async fn file_grant_does_not_allow_directory_walk_or_peer_flag_bypass() {
    let (service, grants) = fixture();
    grants.lock().unwrap().insert("/docs/b-own.txt".into());
    for from_peer in [false, true] {
        let response = service
            .readdir(Request::new(ReaddirRequest {
                path: "/docs".into(),
                recursive: true,
                from_peer,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.is_error);
        assert!(response.entries.is_empty());
    }
}

#[tokio::test]
async fn directory_results_filter_children_before_limit_and_observe_revocation() {
    let (service, grants) = fixture();
    grants.lock().unwrap().extend([
        "/docs".into(),
        "/docs/b-own.txt".into(),
        "/docs/nested/c-own.txt".into(),
    ]);
    let request = || {
        Request::new(ReaddirRequest {
            path: "/docs".into(),
            recursive: true,
            limit: 1,
            ..Default::default()
        })
    };
    let response = service.readdir(request()).await.unwrap().into_inner();
    assert!(!response.is_error);
    assert_eq!(response.entries.len(), 1);
    assert_eq!(response.entries[0].name, "/docs/b-own.txt");
    grants.lock().unwrap().remove("/docs/b-own.txt");
    let response = service.readdir(request()).await.unwrap().into_inner();
    assert!(!response.is_error);
    assert_eq!(response.entries.len(), 1);
    assert_eq!(response.entries[0].name, "/docs/nested/c-own.txt");
    grants.lock().unwrap().remove("/docs");
    let response = service.readdir(request()).await.unwrap().into_inner();
    assert!(response.is_error && response.entries.is_empty());
}

#[tokio::test]
async fn stat_and_batch_stat_require_current_file_grants() {
    let (service, grants) = fixture();
    grants.lock().unwrap().insert("/docs/b-own.txt".into());
    for (path, allowed) in [("/docs/b-own.txt", true), ("/docs/a-hidden.txt", false)] {
        let response = service
            .stat(Request::new(StatRequest {
                path: path.into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.found, allowed);
        assert_eq!(response.is_error, !allowed);
        if !allowed {
            assert!(response.content_id.is_empty() && response.path.is_empty());
        }
    }
    let batch = |paths: &[&str]| {
        Request::new(BatchStatRequest {
            paths: paths.iter().map(|path| (*path).into()).collect(),
            ..Default::default()
        })
    };
    let response = service
        .batch_stat(batch(&["/docs/b-own.txt"]))
        .await
        .unwrap()
        .into_inner();
    assert!(response.results[0].found);
    let error = service
        .batch_stat(batch(&["/docs/b-own.txt", "/docs/a-hidden.txt"]))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    grants.lock().unwrap().clear();
    let error = service
        .batch_stat(batch(&["/docs/b-own.txt"]))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    // Synthetic primitives cannot bypass the installed gate by dropping identity.
    let response = service
        .stat(Request::new(StatRequest {
            path: "/__sys__/auth/keys".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.is_error && !response.found);
}
