//! Qualify the ObjectStore composition using the shared native CAS fault fixture.
#![cfg(feature = "driver-cas-local")]

use std::{collections::HashMap, path::Path, sync::Arc};

use backends::provider::DefaultObjectStoreProvider;
use kernel::abc::object_store::ObjectStore;
use kernel::hal::object_store_provider::{ObjectStoreProvider, ObjectStoreProviderArgs};

fn from_provider(root: &Path, fsync: Option<&str>) -> Result<Arc<dyn ObjectStore>, String> {
    let peer = kernel::hal::peer::NoopPeerBlobClient::arc();
    let runtime = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap(),
    );
    let mut parameters = HashMap::from([("local_root".into(), root.to_str().unwrap().into())]);
    if let Some(fsync) = fsync {
        parameters.insert("fsync".into(), fsync.into());
    }
    DefaultObjectStoreProvider
        .build(&ObjectStoreProviderArgs {
            backend_type: "cas-local-durable",
            backend_name: "durable-fixture",
            mount_path: Some("/managed"),
            backend_params: &parameters,
            peer_client: &peer,
            self_address: None,
            runtime: &runtime,
        })?
        .backend
        .ok_or_else(|| "provider returned no backend".into())
}

#[test]
fn durable_factory_refuses_a_second_publication_policy_before_creating_storage() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("new-storage");
    assert!(DefaultObjectStoreProvider.can_build("cas-local-durable"));
    for fsync in ["false", "true", ""] {
        let error = from_provider(&root, Some(fsync)).err().unwrap();
        assert!(error.contains("fsync"), "{error}");
        assert!(!root.exists());
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use backends::storage::cas_local::CasLocalBackend;
    use kernel::abc::object_store::{ObjectStore, StorageError};
    use lib::file_durability::PublishedButNotDurable;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const CONTENT: &[u8] = b"complete immutable backend object";

    fn backend(root: &Path, source: &str) -> std::sync::Arc<dyn ObjectStore> {
        match source {
            "constructor" => std::sync::Arc::new(CasLocalBackend::new_durable(root).unwrap()),
            "provider" => super::from_provider(root, None).unwrap(),
            _ => panic!("unknown fixture source: {source}"),
        }
    }

    fn context() -> kernel::kernel::OperationContext {
        kernel::kernel::OperationContext::new("test", "root", false, None, false)
    }

    struct Worker(Child);

    impl Drop for Worker {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn durable_backend_worker() {
        let Ok(root) = std::env::var("NEXUS_CAS_BACKEND_ROOT") else {
            return;
        };
        let source = std::env::var("NEXUS_CAS_BACKEND_SOURCE").unwrap();
        let backend = backend(Path::new(&root), &source);
        let result = backend.write_content(CONTENT, "", &context(), 0);
        let fault = std::env::var("NEXUS_CAS_SYNC_FAULT").unwrap();
        if fault.is_empty() {
            let written = result.unwrap();
            assert_eq!(
                backend
                    .read_content(&written.content_id, &context())
                    .unwrap(),
                CONTENT
            );
            return;
        }
        let StorageError::IOError(error) = result.unwrap_err() else {
            panic!("ObjectStore must preserve the native publication error");
        };
        if fault == "staged-file" {
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
            assert!(!Path::new(&std::env::var("NEXUS_CAS_SYNC_TARGET").unwrap()).exists());
        } else {
            let publication = error
                .get_ref()
                .unwrap()
                .downcast_ref::<PublishedButNotDurable>()
                .unwrap();
            assert_eq!(publication.io_error().raw_os_error(), Some(libc::EIO));
            assert_eq!(
                backend
                    .read_content(&lib::hash::hash_content(CONTENT), &context())
                    .unwrap(),
                CONTENT
            );
        }
    }

    #[test]
    fn durable_backend_returns_barrier_failures_and_preserves_complete_objects() {
        let fixture = tempfile::tempdir().unwrap();
        let source = fixture.path().join("fault.c");
        std::fs::write(
            &source,
            include_str!("../../kernel/tests/fixtures/cas_fsync_fault.c"),
        )
        .unwrap();
        let library = fixture.path().join("fault.so");
        let compile = Command::new("cc")
            .args(["-shared", "-fPIC", "-O0", "-Wall", "-Wextra", "-Werror"])
            .arg(source)
            .arg("-o")
            .arg(&library)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let hash = lib::hash::hash_content(CONTENT);
        for (source, fault) in ["constructor", "provider"].into_iter().flat_map(|source| {
            ["", "staged-file", "published-dir", "existing-file"]
                .into_iter()
                .map(move |fault| (source, fault))
        }) {
            let root = fixture.path().join(format!(
                "{source}-{}",
                if fault.is_empty() { "success" } else { fault }
            ));
            let target = root.join(format!("cas/{}/{}/{hash}", &hash[..2], &hash[2..4]));
            let trace = fixture.path().join(format!("{source}-{fault}-trace"));
            let original_inode = if fault == "existing-file" {
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::write(&target, CONTENT).unwrap();
                Some(std::fs::metadata(&target).unwrap().ino())
            } else {
                None
            };
            let child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "linux::durable_backend_worker", "--nocapture"])
                .env("NEXUS_CAS_BACKEND_ROOT", &root)
                .env("NEXUS_CAS_BACKEND_SOURCE", source)
                .env("LD_PRELOAD", &library)
                .env("NEXUS_CAS_SYNC_ROOT", &root)
                .env("NEXUS_CAS_SYNC_TARGET", &target)
                .env("NEXUS_CAS_SYNC_TRACE", &trace)
                .env("NEXUS_CAS_SYNC_FAULT", fault)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut child = Worker(child);
            let deadline = Instant::now() + Duration::from_secs(30);
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(
                    Instant::now() < deadline,
                    "backend worker exceeded its deadline: {fault}"
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            let mut diagnostics = String::new();
            use std::io::Read;
            child
                .0
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut diagnostics)
                .unwrap();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut diagnostics)
                .unwrap();
            assert!(status.success(), "{fault}: {diagnostics}");
            let events = std::fs::read_to_string(&trace).unwrap();
            if fault.is_empty() {
                assert!(
                    events.lines().any(|line| line.starts_with("D|1|0|")),
                    "namespace publication barrier is required"
                );
            } else {
                assert!(
                    events
                        .lines()
                        .any(|line| line.split('|').nth(2) == Some("1")),
                    "native injected failure must be observed"
                );
            }
            let backend = backend(&root, source);
            assert_eq!(
                backend
                    .write_content(CONTENT, "", &context(), 0)
                    .unwrap()
                    .content_id,
                hash
            );
            assert_eq!(backend.read_content(&hash, &context()).unwrap(), CONTENT);
            if let Some(inode) = original_inode {
                assert_eq!(std::fs::metadata(&target).unwrap().ino(), inode);
            }
        }
    }

    #[test]
    fn durable_backend_preserves_each_immutable_version_after_reopen() {
        let root = tempfile::tempdir().unwrap();
        let backend = CasLocalBackend::new_durable(root.path()).unwrap();
        let previous = backend.write_content(CONTENT, "", &context(), 0).unwrap();
        let next_bytes = vec![42; 4 * 1024 * 1024];
        let next = backend
            .write_content(&next_bytes, "", &context(), 0)
            .unwrap();
        drop(backend);
        let reopened = CasLocalBackend::new_durable(root.path()).unwrap();
        assert_ne!(previous.content_id, next.content_id);
        assert_eq!(
            reopened
                .read_content(&previous.content_id, &context())
                .unwrap(),
            CONTENT
        );
        assert_eq!(
            reopened.read_content(&next.content_id, &context()).unwrap(),
            next_bytes
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unqualified_platform_refuses_before_creating_storage() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("new-storage");
    let error = backends::storage::cas_local::CasLocalBackend::new_durable(&root)
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(!root.exists());
    assert!(from_provider(&root, None).is_err());
    assert!(!root.exists());
}
