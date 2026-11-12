use super::*;
use crate::abc::object_store::{ObjectStore, StorageError, WriteResult};
use crate::kernel::OperationContext;
use crate::meta_store::{LocalMetaStore, MetaStore};
use crate::vfs_router::RouteResult;
use std::sync::Barrier;

struct RoutingBackend;

impl ObjectStore for RoutingBackend {
    fn name(&self) -> &str {
        "routing-fixture"
    }

    fn read_content(&self, _: &str, _: &OperationContext) -> Result<Vec<u8>, StorageError> {
        Err(StorageError::NotSupported("routing-only fixture"))
    }

    fn write_content(
        &self,
        _: &[u8],
        _: &str,
        _: &OperationContext,
        _: u64,
    ) -> Result<WriteResult, StorageError> {
        Err(StorageError::NotSupported("routing-only fixture"))
    }
}

struct StoragePair {
    backend: Arc<dyn ObjectStore>,
    metastore: Arc<dyn MetaStore>,
}

impl StoragePair {
    fn new(path: &std::path::Path) -> Self {
        Self {
            backend: Arc::new(RoutingBackend),
            metastore: Arc::new(LocalMetaStore::open(path).unwrap()),
        }
    }

    fn matches(&self, route: &RouteResult) -> bool {
        route
            .backend
            .as_ref()
            .is_some_and(|backend| Arc::ptr_eq(backend, &self.backend))
            && route
                .metastore
                .as_ref()
                .is_some_and(|metastore| Arc::ptr_eq(metastore, &self.metastore))
    }

    fn mount(&self, kernel: &Kernel) {
        kernel
            .add_mount(
                "/owned",
                "root",
                Some(self.backend.clone()),
                Some(self.metastore.clone()),
                None,
                false,
            )
            .unwrap();
    }
}

#[test]
fn mount_pair_preserves_bootstrap_and_captured_routes() {
    let directory = tempfile::tempdir().unwrap();
    let first = StoragePair::new(&directory.path().join("first.redb"));
    let second = StoragePair::new(&directory.path().join("second.redb"));
    let kernel = Kernel::new();
    kernel.install_mount_metastore(
        Kernel::canonical_mount_key("/owned", "root"),
        first.metastore.clone(),
    );
    kernel
        .add_mount(
            "/owned",
            "root",
            Some(first.backend.clone()),
            None,
            None,
            false,
        )
        .unwrap();
    let captured = kernel.vfs_router.route("/owned/history", "root").unwrap();
    assert!(first.matches(&captured));
    second.mount(&kernel);
    assert!(second.matches(&kernel.vfs_router.route("/owned/history", "root").unwrap()));
    assert!(first.matches(&captured));

    let backend_first = Kernel::new();
    backend_first
        .add_mount(
            "/owned",
            "root",
            Some(first.backend.clone()),
            None,
            None,
            false,
        )
        .unwrap();
    backend_first.install_mount_metastore(
        Kernel::canonical_mount_key("/owned", "root"),
        first.metastore.clone(),
    );
    assert!(first.matches(
        &backend_first
            .vfs_router
            .route("/owned/history", "root")
            .unwrap()
    ));
}

#[test]
fn concurrent_mount_replacement_exposes_complete_storage_pairs() {
    let directory = tempfile::tempdir().unwrap();
    let first = StoragePair::new(&directory.path().join("first.redb"));
    let second = StoragePair::new(&directory.path().join("second.redb"));
    let kernel = Kernel::new();
    first.mount(&kernel);
    let start = Barrier::new(3);
    std::thread::scope(|scope| {
        for pair in [&first, &second] {
            let kernel = &kernel;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                for _ in 0..4096 {
                    pair.mount(kernel);
                    std::thread::yield_now();
                }
            });
        }
        start.wait();
        for _ in 0..8192 {
            let route = kernel.vfs_router.route("/owned/history", "root").unwrap();
            assert!(
                first.matches(&route) || second.matches(&route),
                "mount replacement exposed metadata and content from different stores"
            );
            std::thread::yield_now();
        }
    });
}
