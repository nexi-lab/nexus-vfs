//! Ordinary regular-file operations retain their storage ownership boundary.

use super::unscoped_reads::scoped_refusal;
use super::{service, Fixture, OWNER};
use backends::storage::cas_local::CasLocalBackend;
use backends::storage::path_local::PathLocalBackend;
use kernel::abc::object_store::{ObjectStore, StorageError, WriteResult};
use kernel::cas_engine::CASEngine;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::OperationContext;
use kernel::meta_store::MetaStore;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub(super) struct CountedStorage<B> {
    inner: B,
    reads: AtomicUsize,
    writes: AtomicUsize,
    copies: AtomicUsize,
    after_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

pub(super) type CountedCas = CountedStorage<CasLocalBackend>;
type CountedPath = CountedStorage<PathLocalBackend>;

impl<B> CountedStorage<B> {
    fn from_backend(inner: B) -> Self {
        Self {
            inner,
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            copies: AtomicUsize::new(0),
            after_read: Mutex::new(None),
        }
    }

    pub(super) fn counts(&self) -> [usize; 3] {
        [&self.reads, &self.writes, &self.copies].map(|count| count.load(Ordering::SeqCst))
    }
}

impl CountedStorage<CasLocalBackend> {
    pub(super) fn new(path: &std::path::Path) -> Self {
        Self::from_backend(CasLocalBackend::new_durable(path).unwrap())
    }
}

impl CountedStorage<PathLocalBackend> {
    fn new(path: &std::path::Path) -> Self {
        Self::from_backend(PathLocalBackend::new(path, true).unwrap())
    }
}

impl<B: ObjectStore> ObjectStore for CountedStorage<B> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    #[allow(private_interfaces)]
    fn as_cas(&self) -> Option<&CASEngine> {
        self.inner.as_cas()
    }

    fn write_content(
        &self,
        content: &[u8],
        content_id: &str,
        ctx: &OperationContext,
        offset: u64,
    ) -> Result<WriteResult, StorageError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.write_content(content, content_id, ctx, offset)
    }

    fn read_content(
        &self,
        content_id: &str,
        ctx: &OperationContext,
    ) -> Result<Vec<u8>, StorageError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let data = self.inner.read_content(content_id, ctx)?;
        let callback = self.after_read.lock().unwrap().take();
        if let Some(callback) = callback {
            callback();
        }
        Ok(data)
    }

    fn copy_file(&self, src: &str, dst: &str) -> Result<WriteResult, StorageError> {
        self.copies.fetch_add(1, Ordering::SeqCst);
        self.inner.copy_file(src, dst)
    }
}

#[test]
fn kernel_owned_content_copy_refuses_before_alias_or_backend_effects() {
    const CONTENT: &str = "/sessions/service-session/completion";
    let directory = tempfile::tempdir().unwrap();
    let backend = Arc::new(CountedCas::new(&directory.path().join("cas")));
    let fixture = Fixture::open_with_components(directory.path(), |store| store, backend.clone()).0;
    let other = Arc::new(CountedCas::new(&directory.path().join("other-cas")));
    let other_store = Arc::new(fixture._runtime.store("/other", "/other"));
    fixture
        .kernel
        .mount(
            "/other",
            MountOptions::new(&service(), "local")
                .with_backend(other.clone())
                .with_metastore(other_store.clone()),
        )
        .unwrap();
    let owner = fixture.enroll();
    let bytes = b"independent immutable content";
    for path in [CONTENT, "/ordinary"] {
        KernelSyscall::sys_write(fixture.kernel.as_ref(), path, &service(), bytes, 0).unwrap();
    }
    fixture
        .kernel
        .protect_record_content(CONTENT, &service())
        .unwrap();
    fixture
        .kernel
        .bind_record_content_owner(CONTENT, OWNER, &service(), &owner)
        .unwrap();

    // Exercise both real strategies before checking that refusal reaches neither.
    assert!(
        fixture
            .kernel
            .sys_copy("/ordinary", "/local-copy", &service())
            .unwrap()
            .hit
    );
    assert!(backend.copies.load(Ordering::SeqCst) > 0);
    assert!(
        fixture
            .kernel
            .sys_copy("/ordinary", "/other/copy", &service())
            .unwrap()
            .hit
    );
    assert!(other.writes.load(Ordering::SeqCst) > 0);
    let local = fixture.store.get("/local-copy").unwrap().unwrap();
    let remote = other_store.get("/other/copy").unwrap().unwrap();
    let counts = (backend.counts(), other.counts());
    for destination in ["/fresh-alias", "/local-copy", "/other/fresh", "/other/copy"] {
        scoped_refusal(fixture.kernel.sys_copy(CONTENT, destination, &service()));
        assert_eq!(
            (backend.counts(), other.counts()),
            counts,
            "refused copy performed backend I/O"
        );
    }
    assert!(fixture.store.get("/fresh-alias").unwrap().is_none());
    assert!(other_store.get("/other/fresh").unwrap().is_none());
    for (actual, expected) in [
        (fixture.store.get("/local-copy").unwrap().unwrap(), local),
        (other_store.get("/other/copy").unwrap().unwrap(), remote),
    ] {
        assert_eq!(actual, expected);
    }
    for path in ["/ordinary", "/local-copy", "/other/copy"] {
        assert_eq!(
            KernelSyscall::sys_read(fixture.kernel.as_ref(), path, &service(), 0, 0)
                .unwrap()
                .data,
            Some(bytes.to_vec())
        );
    }
}

#[test]
fn kernel_owned_content_refuses_metadata_miss_before_backend_fallback() {
    let directory = tempfile::tempdir().unwrap();
    // Only path-addressed storage discovers files without a namespace row.
    // CAS hashes do not grant namespace access to otherwise unpublished data.
    let backend = Arc::new(CountedPath::new(&directory.path().join("content")));
    let fixture = Fixture::open(directory.path(), true);
    let owner = fixture.enroll();
    let ordinary = backend
        .write_content(b"ordinary raw blob", "ordinary", &service(), 0)
        .unwrap();
    let owned = backend
        .write_content(b"owned raw blob", "owned", &service(), 0)
        .unwrap();
    let ordinary_path = format!("/{}", ordinary.content_id);
    let owned_path = format!("/{}", owned.content_id);
    assert!(fixture.store.get(&owned_path).unwrap().is_none());
    // The service admits and reserves through the durable CAS control plane.
    // Its existing ownership policy also governs the later native path view.
    fixture
        .kernel
        .bind_record_content_owner(&owned_path, OWNER, &service(), &owner)
        .unwrap();
    fixture
        .kernel
        .mount(
            "/",
            MountOptions::new(&service(), "local")
                .with_backend(backend.clone())
                .with_metastore(fixture.store.clone()),
        )
        .unwrap();
    assert!(fixture.store.get(&ordinary_path).unwrap().is_none());
    assert_eq!(
        KernelSyscall::sys_read(fixture.kernel.as_ref(), &ordinary_path, &service(), 0, 0)
            .unwrap()
            .data,
        Some(b"ordinary raw blob".to_vec())
    );
    assert!(fixture.store.get(&owned_path).unwrap().is_none());
    let counts = backend.counts();
    scoped_refusal(KernelSyscall::sys_read(
        fixture.kernel.as_ref(),
        &owned_path,
        &service(),
        0,
        0,
    ));
    assert_eq!(
        backend.counts(),
        counts,
        "refused metadata miss reached the backend"
    );
    assert!(fixture.store.get(&owned_path).unwrap().is_none());
}

#[test]
fn kernel_batch_read_rechecks_consumer_enrollment_after_ordinary_lead_io() {
    use kernel::kernel::{Kernel, ReadRequest};

    const CONTENT: &str = "/sessions/service-session/completion";
    let directory = tempfile::tempdir().unwrap();
    let backend = Arc::new(CountedCas::new(&directory.path().join("cas")));
    let fixture = Fixture::open_with_components(directory.path(), |store| store, backend.clone()).0;
    let owner = fixture.enroll();
    for path in ["/ordinary", CONTENT] {
        KernelSyscall::sys_write(
            fixture.kernel.as_ref(),
            path,
            &service(),
            b"shared bytes",
            0,
        )
        .unwrap();
    }
    fixture
        .kernel
        .protect_record_content(CONTENT, &service())
        .unwrap();
    let image = fixture.store.get(CONTENT).unwrap().unwrap();
    assert_eq!(
        fixture.store.get("/ordinary").unwrap().unwrap().content_id,
        image.content_id
    );
    assert_eq!(
        KernelSyscall::sys_read(fixture.kernel.as_ref(), CONTENT, &service(), 0, 0)
            .unwrap()
            .data,
        Some(b"shared bytes".to_vec())
    );
    let store = fixture.store.clone();
    *backend.after_read.lock().unwrap() = Some(Box::new(move || {
        // Only the independent ordinary file has I/O in flight at this cut;
        // the protected consumer has not started and is quiescent.
        store
            .bind_record_guard(CONTENT, Some(&image), OWNER, &owner)
            .unwrap();
    }));
    let requests = ["/ordinary", CONTENT].map(|path| ReadRequest {
        path: path.into(),
        offset: 0,
        len: None,
        timeout_ms: 0,
    });
    let mut results = Kernel::sys_read(fixture.kernel.as_ref(), &requests, &service()).into_iter();
    assert!(
        backend.after_read.lock().unwrap().is_none(),
        "enrollment cut was not reached"
    );
    assert_eq!(
        results.next().unwrap().unwrap().data,
        Some(b"shared bytes".to_vec())
    );
    scoped_refusal(results.next().unwrap());
}

#[test]
fn kernel_peer_read_observes_only_the_captured_store_after_mount_replacement() {
    captured_peer_read(false);
}

#[test]
fn kernel_scoped_peer_read_observes_only_the_captured_store_after_mount_replacement() {
    captured_peer_read(true);
}

fn captured_peer_read(scoped: bool) {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a_backend = Arc::new(CountedPath::new(&a_dir.path().join("content")));
    let b_backend = Arc::new(CountedPath::new(&b_dir.path().join("content")));
    let a = Fixture::open_with_components(a_dir.path(), |store| store, a_backend.clone()).0;
    let b = Fixture::open_with_components(b_dir.path(), |store| store, b_backend.clone()).0;
    let raw = a_backend
        .write_content(b"untracked original A bytes", "raw", &service(), 0)
        .unwrap();
    let path = format!("/{}", raw.content_id);
    assert!(a.store.get(&path).unwrap().is_none());
    assert!(b.store.get(&path).unwrap().is_none());
    KernelSyscall::sys_write(
        b.kernel.as_ref(),
        "/ordinary",
        &service(),
        b"independent B bytes",
        0,
    )
    .unwrap();
    assert_eq!(
        KernelSyscall::sys_read(b.kernel.as_ref(), "/ordinary", &service(), 0, 0)
            .unwrap()
            .data,
        Some(b"independent B bytes".to_vec())
    );
    let b_image = b.store.get("/ordinary").unwrap().unwrap();
    let b_counts = b_backend.counts();
    let weak = Arc::downgrade(&a.kernel);
    let store = b.store.clone();
    let backend = b_backend.clone();
    *a_backend.after_read.lock().unwrap() = Some(Box::new(move || {
        weak.upgrade()
            .unwrap()
            .mount(
                "/",
                MountOptions::new(&service(), "local")
                    .with_backend(backend)
                    .with_metastore(store),
            )
            .unwrap();
    }));
    // Use the actual peer-served duality flag; local reads skip observation.
    let mut peer = service();
    peer.propagates_cross_node = true;
    let bytes = if scoped {
        a.kernel.read_local_zone_content("root", &path).unwrap()
    } else {
        KernelSyscall::sys_read(a.kernel.as_ref(), &path, &peer, 0, 0)
            .unwrap()
            .data
            .unwrap()
    };
    assert_eq!(bytes, b"untracked original A bytes");
    assert!(
        a_backend.after_read.lock().unwrap().is_none(),
        "backend-read replacement cut was not reached"
    );
    assert!(
        b.store.get(&path).unwrap().is_none(),
        "peer read published A observation into replacement store B"
    );
    assert_eq!(b.store.get("/ordinary").unwrap().unwrap(), b_image);
    assert_eq!(
        b_backend.counts(),
        b_counts,
        "peer read touched the replacement backend"
    );
    let observed = a
        .store
        .get(&path)
        .unwrap()
        .expect("peer read did not observe its captured store A");
    assert_eq!(observed.size, b"untracked original A bytes".len() as u64);
    assert_eq!(
        a_backend
            .read_content(observed.content_id.as_deref().unwrap(), &service())
            .unwrap(),
        b"untracked original A bytes"
    );
    drop(a);
}
