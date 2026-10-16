#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use backends::storage::path_local::PathLocalBackend;
use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient,
    nexus_vfs_service_server::NexusVfsServiceServer, ChmodRequest, StatRequest, WriteRequest,
};
use kernel::kernel::{Kernel, KernelError, OperationContext};
use kernel::{Permission, PermissionProvider};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Status;

use crate::auth::{AuthCredentials, AuthProvider};
use crate::grpc::VfsServiceImpl;

struct TokenIdentity;

impl AuthProvider for TokenIdentity {
    fn resolve(&self, credentials: &AuthCredentials<'_>) -> Result<OperationContext, Status> {
        match credentials.token {
            "owner" | "other" => Ok(OperationContext::new(
                credentials.token,
                "root",
                false,
                Some("agent"),
                false,
            )),
            _ => Err(Status::unauthenticated("unknown test identity")),
        }
    }
}

struct OwnerOnly;

impl PermissionProvider for OwnerOnly {
    fn check(
        &self,
        path: &str,
        _: Option<&kernel::vfs_router::RouteResult>,
        _: Permission,
        context: &OperationContext,
    ) -> Result<(), KernelError> {
        if context.user_id == "owner" {
            Ok(())
        } else {
            Err(KernelError::PermissionDenied(format!(
                "foreign owner: {path}"
            )))
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_permissions_cross_the_wire_and_keep_file_identity_and_authorization() {
    let directory = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Kernel::new());
    kernel.vfs_router_arc().add_mount(
        "/",
        "root",
        Some(Arc::new(
            PathLocalBackend::new(directory.path(), false).unwrap(),
        )),
        false,
    );
    kernel.set_permission_provider(Arc::new(Box::new(OwnerOnly)));
    let mut service = VfsServiceImpl::for_test(Arc::clone(&kernel));
    service.auth = Arc::new(TokenIdentity);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
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
    let content = b"#!/bin/sh\nprintf ready".to_vec();
    let written = client
        .write(WriteRequest {
            path: "/run.sh".into(),
            content: content.clone(),
            auth_token: "owner".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!written.is_error);
    let before = kernel.sys_stat("/run.sh", "root").unwrap();
    for mode in [0o700, 0, 0o600] {
        let response = client
            .chmod(ChmodRequest {
                path: "/run.sh".into(),
                mode,
                auth_token: "owner".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert!(!response.is_error);
        let stat = client
            .stat(StatRequest {
                path: "/run.sh".into(),
                auth_token: "owner".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert!(stat.found && !stat.is_error);
        assert_eq!(stat.mode, mode);
        assert_eq!(
            std::fs::metadata(directory.path().join("run.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            mode
        );
    }
    for (path, identity, mode) in [
        ("/run.sh", "other", 0o700),
        ("/run.sh", "invalid", 0o700),
        ("/run.sh", "owner", 0o4700),
        ("/missing", "owner", 0o700),
    ] {
        let response = client
            .chmod(ChmodRequest {
                path: path.into(),
                mode,
                auth_token: identity.into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert!(response.is_error && !response.error_payload.is_empty());
    }
    let after = kernel.sys_stat("/run.sh", "root").unwrap();
    assert_eq!(after.mode, 0o600);
    assert_eq!(
        (after.gen, after.version, after.content_id),
        (before.gen, before.version, before.content_id)
    );
    assert_eq!(
        std::fs::read(directory.path().join("run.sh")).unwrap(),
        content
    );
    assert!(!directory.path().join("missing").exists());
    drop(client);
    shutdown.send(()).unwrap();
    server.await.unwrap();
}
