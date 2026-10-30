//! Actual Kernel boot, metadata operations and explicit persistent reopen.

use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, OperationContext};

fn create_directory(kernel: &Kernel) {
    let context = OperationContext::new("owner", "root", true, Some("owner"), true);
    KernelSyscall::sys_setattr(
        kernel,
        "/boot-metadata-proof",
        &context,
        1,
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
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        KernelSyscall::sys_stat(kernel, "/boot-metadata-proof", "root")
            .unwrap()
            .entry_type,
        1
    );
}

#[test]
fn temporary_kernel_metadata_uses_no_host_files() {
    const CHILD: &str = "NEXUS_BOOT_METADATA_ACCEPTANCE_SCRATCH";
    if let Some(scratch) = std::env::var_os(CHILD) {
        let kernel = Kernel::new();
        create_directory(&kernel);
        assert!(
            std::fs::read_dir(&scratch).unwrap().next().is_none(),
            "temporary Kernel metadata must not create host files"
        );
        drop(kernel);
        let fresh = Kernel::new();
        assert!(KernelSyscall::sys_stat(&fresh, "/boot-metadata-proof", "root").is_none());
        assert!(std::fs::read_dir(&scratch).unwrap().next().is_none());
        return;
    }
    // A fresh process reads the test's temporary-directory settings before any
    // platform tempfile cache is initialized. Other tests keep their own env.
    let sandbox = tempfile::tempdir().unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "temporary_kernel_metadata_uses_no_host_files",
            "--nocapture",
        ])
        .env(CHILD, sandbox.path())
        .env("TMPDIR", sandbox.path())
        .env("TMP", sandbox.path())
        .env("TEMP", sandbox.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn an_explicit_metadata_path_remains_durable_across_kernel_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("persistent/meta.redb");
    {
        let kernel = Kernel::new();
        kernel.set_metastore_path(path.to_str().unwrap()).unwrap();
        create_directory(&kernel);
        assert!(path.is_file());
        kernel.release_metastores();
    }
    let restored = Kernel::new();
    restored.set_metastore_path(path.to_str().unwrap()).unwrap();
    assert_eq!(
        KernelSyscall::sys_stat(&restored, "/boot-metadata-proof", "root")
            .unwrap()
            .entry_type,
        1
    );
}
