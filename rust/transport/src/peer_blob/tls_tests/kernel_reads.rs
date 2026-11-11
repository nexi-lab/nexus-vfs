//! Kernel mount routing through the production peer adapter and real mTLS.
use super::*;
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, OperationContext};
use kernel::meta_store::{FileMetadata, LocalMetaStore, MetaStore, DT_REG};

fn mount_remote_file(
    kernel: &Kernel,
    directory: &std::path::Path,
    alias: &str,
    zone: &str,
    origin: &str,
) {
    let metadata = Arc::new(LocalMetaStore::open(&directory.join(format!("{zone}.redb"))).unwrap());
    let path = format!("{alias}/shared");
    metadata
        .put(
            &path,
            FileMetadata {
                path: path.clone(),
                entry_type: DT_REG,
                content_id: Some("missing-local-object".into()),
                last_writer_address: Some(origin.into()),
                ..Default::default()
            },
        )
        .unwrap();
    kernel
        .vfs_router_arc()
        .add_federation_mount(alias, "root", None, zone, "/sessions", false);
    kernel.install_mount_metastore(Kernel::canonical_mount_key(alias, "root"), metadata);
}

#[test]
fn kernel_file_reads_keep_scope_and_backing_path_across_aliases() {
    let runtime = build_kernel_runtime();
    let fixture = runtime.block_on(Fixture::start_with_scoped(true, true));
    let directory = tempfile::tempdir().unwrap();
    let kernel = Kernel::new();
    let client = Arc::new(PeerBlobClient::new(runtime.handle().clone()));
    client.install_tls_config(fixture.tls(2));
    kernel.set_peer_client(client);
    let ctx = OperationContext::new("reader", "root", true, None, true);
    mount_remote_file(
        &kernel,
        directory.path(),
        "/visible-a",
        "agent-alice",
        &fixture.address,
    );
    mount_remote_file(
        &kernel,
        directory.path(),
        "/visible-b",
        "agent-bob",
        &fixture.address,
    );
    assert_eq!(
        KernelSyscall::sys_read(&kernel, "/visible-a/shared", &ctx, 0, 0)
            .unwrap()
            .data,
        Some(BODY.to_vec())
    );
    let error = KernelSyscall::sys_read(&kernel, "/visible-b/shared", &ctx, 0, 0).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&tonic::Code::PermissionDenied.to_string()),
        "{error}"
    );
    assert!(fixture.calls.lock().unwrap().is_empty());
    assert_eq!(
        *fixture.scoped_calls.lock().unwrap(),
        vec![
            (Some(2), "agent-alice".into(), "/sessions/shared".into()),
            (Some(2), "agent-bob".into(), "/sessions/shared".into()),
        ]
    );
    drop(kernel);
    runtime.block_on(fixture.shutdown());
}

#[test]
fn kernel_file_reads_refuse_peers_without_scoped_content() {
    let runtime = build_kernel_runtime();
    let fixture = runtime.block_on(Fixture::start(true));
    let directory = tempfile::tempdir().unwrap();
    let kernel = Kernel::new();
    let client = Arc::new(PeerBlobClient::new(runtime.handle().clone()));
    client.install_tls_config(fixture.tls(2));
    kernel.set_peer_client(client);
    mount_remote_file(
        &kernel,
        directory.path(),
        "/visible",
        "agent-alice",
        &fixture.address,
    );
    let ctx = OperationContext::new("reader", "root", true, None, true);
    let error = KernelSyscall::sys_read(&kernel, "/visible/shared", &ctx, 0, 0).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&tonic::Code::Unimplemented.to_string()),
        "{error}"
    );
    assert!(fixture.calls.lock().unwrap().is_empty());
    assert!(fixture.scoped_calls.lock().unwrap().is_empty());
    drop(kernel);
    runtime.block_on(fixture.shutdown());
}
