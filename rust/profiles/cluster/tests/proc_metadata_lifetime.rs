//! Process namespace lifetime across a durable metastore reopen.

use std::path::Path;
use std::sync::Arc;

use backends::storage::path_local::PathLocalBackend;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, OperationContext};
use kernel::meta_store::{FileMetadata, LocalMetaStore, MetaStore, DT_DIR};

fn boot(metadata: &Path, files: &Path) -> Arc<Kernel> {
    let kernel = Arc::new(Kernel::new());
    kernel
        .set_metastore_path(metadata.to_str().unwrap())
        .unwrap();
    kernel
        .mount(
            "/",
            MountOptions::new("local")
                .with_backend(Arc::new(PathLocalBackend::new(files, false).unwrap())),
        )
        .unwrap();
    kernel
}

#[test]
fn process_cleanup_does_not_remove_durable_history_or_workspace_bytes() {
    let root = tempfile::tempdir().unwrap();
    let metadata = root.path().join("metadata.redb");
    let files = root.path().join("files");
    std::fs::create_dir_all(&files).unwrap();
    {
        let store = LocalMetaStore::open(&metadata).unwrap();
        for path in ["/proc", "/proc/pid-legacy", "/proc/pid-legacy/workspace"] {
            store
                .put(
                    path,
                    FileMetadata {
                        path: path.into(),
                        entry_type: DT_DIR,
                        zone_id: Some("root".into()),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
    }
    let kernel = boot(&metadata, &files);
    let caller = OperationContext::new("operator", "root", true, None, true);
    let durable_files = [
        (
            "/sessions/original/transcript.jsonl",
            b"original history".as_slice(),
        ),
        (
            "/agents/original/memory/MEMORY.md",
            b"original memory".as_slice(),
        ),
        (
            "/agents/original/workspaces/repository/file.txt",
            b"original file".as_slice(),
        ),
    ];
    for (path, bytes) in durable_files {
        KernelSyscall::sys_write(&*kernel, path, &caller, bytes, 0).unwrap();
    }
    managed_agent::install_managed_agent(&kernel).unwrap();
    assert!(KernelSyscall::sys_stat(&*kernel, "/proc/pid-legacy", "root").is_none());
    for (path, bytes) in durable_files {
        assert_eq!(
            KernelSyscall::sys_read(&*kernel, path, &caller, 0, 0)
                .unwrap()
                .data
                .unwrap(),
            bytes
        );
    }
    kernel.release_metastores();
    let store = LocalMetaStore::open(&metadata).unwrap();
    assert!(store.get("/proc/pid-legacy").unwrap().is_none());
}

#[test]
fn a_live_process_namespace_survives_service_reinstall_but_not_kernel_reopen() {
    let root = tempfile::tempdir().unwrap();
    let metadata = root.path().join("metadata.redb");
    let files = root.path().join("files");
    std::fs::create_dir_all(&files).unwrap();
    let kernel = boot(&metadata, &files);
    managed_agent::install_managed_agent(&kernel).unwrap();
    let caller = OperationContext::new("operator", "root", true, None, true);
    let reply = transport::call_dispatch::dispatch(
        &kernel,
        &caller,
        "managed_agent.start_session_v1",
        br#"{"agent_id":"process-lifetime","owner_id":"alice"}"#,
    )
    .unwrap()
    .into_inner();
    assert!(
        !reply.is_error,
        "{}",
        String::from_utf8_lossy(&reply.payload)
    );
    let started: serde_json::Value = serde_json::from_slice(&reply.payload).unwrap();
    let pid = started["session_id"].as_str().unwrap();
    let process_path = format!("/proc/{pid}");
    assert!(KernelSyscall::sys_stat(&*kernel, &process_path, "root").is_some());
    assert!(kernel.unregister_service(managed_agent::SERVICE_NAME));
    managed_agent::install_managed_agent(&kernel).unwrap();
    assert!(kernel.agent_registry().get(pid).is_some());
    assert!(KernelSyscall::sys_stat(&*kernel, &process_path, "root").is_some());
    kernel.release_metastores();

    let reopened = boot(&metadata, &files);
    assert!(reopened.agent_registry().get(pid).is_none());
    assert!(
        KernelSyscall::sys_stat(&*reopened, &process_path, "root").is_none(),
        "a process inode must not outlive its kernel-owned PCB"
    );
}
