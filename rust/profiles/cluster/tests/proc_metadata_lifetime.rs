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
    // Harness boot mount uses the system/admin boot context every
    // boot-tier mount uses.
    let boot_ctx = OperationContext::new("system", "root", true, None, true);
    kernel
        .mount(
            "/",
            MountOptions::new(&boot_ctx, "local")
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

#[test]
fn independent_nexus_namespaces_do_not_share_process_views_or_workspace_bytes() {
    for is_natural_exit in [false, true] {
        let first_root = tempfile::tempdir().unwrap();
        let second_root = tempfile::tempdir().unwrap();
        for root in [&first_root, &second_root] {
            std::fs::create_dir_all(root.path().join("files")).unwrap();
        }
        let first = boot(
            &first_root.path().join("metadata.redb"),
            &first_root.path().join("files"),
        );
        let second = boot(
            &second_root.path().join("metadata.redb"),
            &second_root.path().join("files"),
        );
        managed_agent::install_managed_agent(&first).unwrap();
        managed_agent::install_managed_agent(&second).unwrap();
        let caller = OperationContext::new("operator", "root", true, Some("operator"), true);
        let repository = "/agents/isolated/workspaces/repository";
        let file = format!("{repository}/retained.txt");
        KernelSyscall::sys_write(&*first, &file, &caller, b"persistent repository", 0).unwrap();
        let started = transport::call_dispatch::dispatch(&first, &caller, "managed_agent.start_session_v1",
        serde_json::json!({"agent_id":"isolated", "repos":[{"alias":"workspace", "host_path":repository}]}).to_string().as_bytes()).unwrap().into_inner();
        assert!(
            !started.is_error,
            "{}",
            String::from_utf8_lossy(&started.payload)
        );
        let started: serde_json::Value = serde_json::from_slice(&started.payload).unwrap();
        let pid = started["session_id"].as_str().unwrap();
        let process = format!("/proc/{pid}");
        let view = format!("{process}/workspace/workspace/retained.txt");
        let dynamic_paths = [
            format!("{process}/workspace/generated/nested"),
            format!("{process}/sessions/active"),
            format!("{process}/tasks/running"),
        ];
        for dynamic in &dynamic_paths {
            first.mkdir(dynamic, &caller, true, true).unwrap();
            assert!(KernelSyscall::sys_stat(&*first, dynamic, "root").is_some());
        }

        assert_eq!(
            KernelSyscall::sys_read(&*first, &view, &caller, 0, 0)
                .unwrap()
                .data
                .unwrap(),
            b"persistent repository"
        );
        assert!(KernelSyscall::sys_stat(&*second, &process, "root").is_none());
        assert!(KernelSyscall::sys_read(&*second, &file, &caller, 0, 0).is_err());
        if is_natural_exit {
            first
                .agent_registry()
                .update_state(pid, kernel::core::agents::registry::AgentState::Terminated)
                .unwrap();
        } else {
            let cancelled = transport::call_dispatch::dispatch(
                &first,
                &caller,
                "managed_agent.cancel_v1",
                serde_json::json!({"session_id":pid,"mode":"session"})
                    .to_string()
                    .as_bytes(),
            )
            .unwrap()
            .into_inner();
            assert!(!cancelled.is_error);
        }
        assert!(KernelSyscall::sys_stat(&*first, &process, "root").is_none());
        for dynamic in &dynamic_paths {
            assert!(KernelSyscall::sys_stat(&*first, dynamic, "root").is_none());
        }

        assert_eq!(
            KernelSyscall::sys_read(&*first, &file, &caller, 0, 0)
                .unwrap()
                .data
                .unwrap(),
            b"persistent repository"
        );
    }
}
