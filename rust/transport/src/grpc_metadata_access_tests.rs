use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient,
    nexus_vfs_service_server::{NexusVfsService, NexusVfsServiceServer},
    BatchStatRequest, ReaddirRequest, StatRequest,
};
use kernel::kernel::{KernelError, OperationContext};
use kernel::{Permission, PermissionProvider};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Status};

use crate::auth::{AuthCredentials, AuthProvider};
use crate::grpc::{tests::kernel_with_mem_backend, VfsServiceImpl};

struct AgentAuth;
impl AuthProvider for AgentAuth {
    fn resolve(&self, _: &AuthCredentials<'_>) -> Result<OperationContext, Status> {
        let mut ctx = OperationContext::new("owner", "root", false, Some("agent-a"), false);
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

#[tokio::test]
async fn stat_follow_links_over_tcp_preserves_lstat_and_rechecks_target_grants() {
    let (service, grants) = fixture();
    let ctx = OperationContext::new("setup", "root", true, None, true);
    service
        .kernel
        .sys_setattr(
            "/alias",
            &ctx,
            i32::from(kernel::meta_store::DT_LINK),
            "",
            None,
            None,
            None,
            "memory",
            "root",
            false,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("/docs"),
            None,
            None,
        )
        .unwrap();
    let alias = "/alias/b-own.txt";
    let target = "/docs/b-own.txt";
    grants
        .lock()
        .unwrap()
        .extend(["/alias".into(), alias.into()]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(NexusVfsServiceServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let mut client = NexusVfsServiceClient::connect(endpoint).await.unwrap();
    let request = |path: &str| StatRequest {
        path: path.into(),
        ..Default::default()
    };
    let lstat = client.stat(request("/alias")).await.unwrap().into_inner();
    assert!(!lstat.is_error && lstat.found);
    assert_eq!(lstat.entry_type, i32::from(kernel::meta_store::DT_LINK));
    assert_eq!(lstat.link_target, "/docs");
    let denied = client
        .stat_follow(request(alias))
        .await
        .unwrap()
        .into_inner();
    assert!(denied.is_error && !denied.found && denied.content_id.is_empty());
    grants.lock().unwrap().insert(target.into());
    let found = client
        .stat_follow(request(alias))
        .await
        .unwrap()
        .into_inner();
    assert!(!found.is_error && found.found);
    assert_eq!(found.entry_type, i32::from(kernel::meta_store::DT_REG));
    assert_eq!(found.path, target);
    assert_eq!(found.size, 6);
    grants.lock().unwrap().remove(target);
    let revoked = client
        .stat_follow(request(alias))
        .await
        .unwrap()
        .into_inner();
    assert!(revoked.is_error && !revoked.found && revoked.path.is_empty());
    drop(client);
    stop.send(()).unwrap();
    server.await.unwrap();
}
