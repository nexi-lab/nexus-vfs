//! Managed workspace aliases must address their descendants, with the
//! original and target permission checks intact. Real kernel/backend calls.

use std::sync::Arc;

use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, KernelError, OperationContext};
use kernel::{Permission, PermissionProvider};

mod common;

fn link(kernel: &Kernel, ctx: &OperationContext, path: &str, target: &str) {
    KernelSyscall::sys_setattr(
        kernel,
        path,
        ctx,
        6,
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
        Some(target),
        None,
        None,
    )
    .expect("register workspace link");
}

fn boot() -> (Kernel, OperationContext) {
    let kernel = Kernel::new();
    common::mount_mem_root(&kernel);
    let ctx = OperationContext::new("alice", "root", false, Some("alice"), false);
    link(
        &kernel,
        &ctx,
        "/proc/p1/workspace/repo",
        "/agents/alice/workspaces/s1",
    );
    (kernel, ctx)
}

#[test]
fn a_new_relative_file_round_trips_through_a_workspace_directory_link() {
    let (kernel, ctx) = boot();
    let alias = "/proc/p1/workspace/repo/nested/proof.txt";
    let target = "/agents/alice/workspaces/s1/nested/proof.txt";
    let written = KernelSyscall::sys_write(&kernel, alias, &ctx, b"actual bytes", 0).unwrap();
    assert!(written.hit);
    for path in [alias, target] {
        let read = KernelSyscall::sys_read(&kernel, path, &ctx, 0, 0).unwrap();
        assert_eq!(read.data.as_deref(), Some(b"actual bytes".as_slice()));
    }
    assert!(KernelSyscall::sys_stat(&kernel, target, "root").is_some());
    assert_eq!(
        KernelSyscall::sys_stat(&kernel, "/proc/p1/workspace/repo", "root")
            .unwrap()
            .entry_type,
        6
    );
}

struct DenyPath(&'static str);

impl PermissionProvider for DenyPath {
    fn check(
        &self,
        path: &str,
        _route: Option<&kernel::vfs_router::RouteResult>,
        _permission: Permission,
        _ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        if path.starts_with(self.0) {
            Err(KernelError::PermissionDenied(path.to_string()))
        } else {
            Ok(())
        }
    }
}

#[test]
fn both_the_workspace_alias_and_the_target_must_be_authorized() {
    for denied in ["/proc/p1/workspace", "/agents/alice/workspaces"] {
        let (kernel, ctx) = boot();
        KernelSyscall::sys_write(
            &kernel,
            "/agents/alice/workspaces/s1/proof",
            &ctx,
            b"private",
            0,
        )
        .unwrap();
        kernel.set_permission_provider(Arc::new(Box::new(DenyPath(denied))));
        let alias = "/proc/p1/workspace/repo/proof";
        assert!(matches!(
            KernelSyscall::sys_read(&kernel, alias, &ctx, 0, 0),
            Err(KernelError::PermissionDenied(_))
        ));
        assert!(matches!(
            KernelSyscall::sys_write(&kernel, alias, &ctx, b"overwrite", 0),
            Err(KernelError::PermissionDenied(_))
        ));
        assert!(matches!(
            kernel.stat_follow(alias, Permission::Read, &ctx),
            Err(KernelError::PermissionDenied(_))
        ));
    }
}

#[test]
fn directory_aliases_do_not_allow_an_extra_link_hop_or_parent_escape() {
    let (kernel, ctx) = boot();
    link(
        &kernel,
        &ctx,
        "/agents/alice/workspaces/s1/again",
        "/secrets",
    );
    link(&kernel, &ctx, "/escape", "/agents/../secrets");
    for path in ["/proc/p1/workspace/repo/again/key", "/escape/key"] {
        assert!(KernelSyscall::sys_write(&kernel, path, &ctx, b"no", 0).is_err());
        assert!(KernelSyscall::sys_read(&kernel, path, &ctx, 0, 0).is_err());
        assert!(kernel.stat_follow(path, Permission::Read, &ctx).is_err());
    }
}

#[test]
fn a_root_proc_alias_preserves_the_non_root_sessions_zone() {
    let kernel = Kernel::new();
    kernel.vfs_router_arc().add_mount(
        "/agents",
        "edge",
        Some(Arc::new(common::MemBackend::default())),
        false,
    );
    let ctx = OperationContext::new("alice", "edge", false, Some("alice"), false);
    link(
        &kernel,
        &ctx,
        "/proc/p1/workspace/repo",
        "/agents/alice/workspaces/s1",
    );
    let alias = "/proc/p1/workspace/repo/proof.txt";
    let target = "/agents/alice/workspaces/s1/proof.txt";
    assert!(
        KernelSyscall::sys_write(&kernel, alias, &ctx, b"edge bytes", 0)
            .unwrap()
            .hit
    );
    assert_eq!(
        KernelSyscall::sys_read(&kernel, alias, &ctx, 0, 0)
            .unwrap()
            .data
            .as_deref(),
        Some(b"edge bytes".as_slice())
    );
    assert_eq!(
        KernelSyscall::sys_stat(&kernel, target, "edge")
            .unwrap()
            .zone_id
            .as_deref(),
        Some("edge")
    );
    assert_eq!(
        kernel
            .stat_follow(alias, Permission::Read, &ctx)
            .unwrap()
            .unwrap()
            .zone_id
            .as_deref(),
        Some("edge")
    );
}

#[test]
fn target_metadata_follows_leaf_and_directory_links_without_reading_a_frame() {
    let (kernel, ctx) = boot();
    let target = "/agents/alice/workspaces/s1/transcript";
    kernel.create_stream(target, 4096).unwrap();
    KernelSyscall::sys_write(&kernel, target, &ctx, b"first frame", 0).unwrap();
    link(&kernel, &ctx, "/transcript-alias", target);
    for path in ["/transcript-alias", "/proc/p1/workspace/repo/transcript"] {
        let metadata = kernel
            .stat_follow(path, Permission::Read, &ctx)
            .unwrap()
            .unwrap();
        assert_eq!(metadata.entry_type, kernel::meta_store::DT_STREAM);
        assert_eq!(metadata.path, target);
        let first = KernelSyscall::sys_read(&kernel, path, &ctx, 0, 0).unwrap();
        assert_eq!(first.data.as_deref(), Some(b"first frame".as_slice()));
    }
    assert_eq!(
        kernel
            .sys_stat("/transcript-alias", "root")
            .unwrap()
            .entry_type,
        6
    );
    assert!(kernel
        .stat_follow("/proc/p1/workspace/repo/missing", Permission::Read, &ctx)
        .unwrap()
        .is_none());
}

struct WriteOnly;

impl PermissionProvider for WriteOnly {
    fn check(
        &self,
        _path: &str,
        _route: Option<&kernel::vfs_router::RouteResult>,
        permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        assert_eq!(ctx.agent_id.as_deref(), Some("alice"));
        if matches!(permission, Permission::Write) {
            Ok(())
        } else {
            Err(KernelError::PermissionDenied("write only".into()))
        }
    }
}

#[test]
fn append_classification_uses_write_permission_and_preserves_identity() {
    let (kernel, ctx) = boot();
    let target = "/agents/alice/workspaces/s1/transcript";
    kernel.create_stream(target, 4096).unwrap();
    kernel.set_permission_provider(Arc::new(Box::new(WriteOnly)));
    let alias = "/proc/p1/workspace/repo/transcript";
    assert_eq!(
        kernel
            .stat_follow(alias, Permission::Write, &ctx)
            .unwrap()
            .unwrap()
            .entry_type,
        kernel::meta_store::DT_STREAM
    );
    assert!(matches!(
        kernel.stat_follow(alias, Permission::Read, &ctx),
        Err(KernelError::PermissionDenied(_))
    ));
}

#[test]
fn target_metadata_does_not_consume_pipe_contents() {
    let (kernel, ctx) = boot();
    kernel.create_pipe("/queued-message", 4096).unwrap();
    KernelSyscall::sys_write(&kernel, "/queued-message", &ctx, b"pending", 0).unwrap();
    link(&kernel, &ctx, "/inbox-alias", "/queued-message");
    assert_eq!(
        kernel
            .stat_follow("/inbox-alias", Permission::Read, &ctx)
            .unwrap()
            .unwrap()
            .entry_type,
        kernel::meta_store::DT_PIPE
    );
    let received = KernelSyscall::sys_read(&kernel, "/inbox-alias", &ctx, 0, 0).unwrap();
    assert_eq!(received.data.as_deref(), Some(b"pending".as_slice()));
}

#[test]
fn a_batch_write_cannot_materialize_an_alias_descendant_as_a_different_file() {
    let (kernel, ctx) = boot();
    let reqs = [
        kernel::kernel::WriteRequest {
            path: "/proc/p1/workspace/repo/proof".into(),
            content: b"batch bytes".to_vec(),
            offset: 0,
        },
        kernel::kernel::WriteRequest {
            path: "/direct".into(),
            content: b"direct bytes".to_vec(),
            offset: 0,
        },
    ];
    assert!(kernel
        .sys_write(&reqs, &ctx)
        .iter()
        .all(|result| result.as_ref().is_ok_and(|written| written.hit)));
    assert_eq!(
        KernelSyscall::sys_read(&kernel, "/agents/alice/workspaces/s1/proof", &ctx, 0, 0)
            .unwrap()
            .data
            .as_deref(),
        Some(b"batch bytes".as_slice())
    );
}
