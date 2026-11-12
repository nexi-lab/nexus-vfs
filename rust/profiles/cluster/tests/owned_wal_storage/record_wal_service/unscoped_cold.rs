//! Retained legacy caches lose admission when the store enrolls their owner.
//! This tests the mechanism; the trusted Kernel still refuses occupied-log
//! conversion and requires fresh or quiescent consumers before enrollment.

use super::{service, Fixture, HISTORY, OWNER};
use backends::storage::cas_local::CasLocalBackend;
use kernel::abc::object_store::ObjectStore;
use kernel::core::stream::wal::{wal_stream_prefix, ColdSegmentStore, SealPolicy, WalStreamCore};
use kernel::meta_store::MetaStore;
use kernel::stream::StreamBackend;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct NativeCold {
    backend: CasLocalBackend,
    reads: AtomicUsize,
}

impl ColdSegmentStore for NativeCold {
    fn self_origin(&self) -> Option<String> {
        None
    }

    fn write_segment(&self, stream: &str, base: u64, bytes: &[u8]) -> Result<String, String> {
        self.backend
            .write_content(bytes, &format!("{stream}/{base}"), &service(), 0)
            .map(|result| result.content_id)
            .map_err(|error| format!("{error:?}"))
    }

    fn read_segment(&self, _: &str, _: u64, content_id: &str, _: &str) -> Result<Vec<u8>, String> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.backend
            .read_content(content_id, &service())
            .map_err(|error| format!("{error:?}"))
    }
}

#[test]
fn kernel_owned_wal_refuses_retained_unowned_cold_cache_before_any_content_io() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(directory.path(), true);
    let cold = Arc::new(NativeCold {
        backend: CasLocalBackend::new_durable(&directory.path().join("cold-cas")).unwrap(),
        reads: AtomicUsize::new(0),
    });
    let core = |path: &str| {
        WalStreamCore::with_cold_tier(
            fixture.store.clone(),
            path.into(),
            cold.clone(),
            SealPolicy {
                hot_window: 2,
                seal_batch: 2,
            },
            0,
        )
    };
    let legacy = core(HISTORY);
    for index in 0..4 {
        assert_eq!(
            StreamBackend::push(&legacy, format!("r{index}").as_bytes()).unwrap(),
            index
        );
    }
    let prefix = wal_stream_prefix(HISTORY);
    let deadline = Instant::now() + Duration::from_secs(10);
    while fixture.store.stream_floor(&prefix).unwrap() != 2 {
        assert!(Instant::now() < deadline, "real cold seal did not finish");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(fixture
        .store
        .get_stream_entry(&format!("{prefix}0"))
        .unwrap()
        .is_none());
    let before = cold.reads.load(Ordering::SeqCst);
    assert_eq!(legacy.read_at(0).unwrap(), Some(b"r0".to_vec()));
    assert_eq!(cold.reads.load(Ordering::SeqCst), before + 1);
    assert_eq!(legacy.read_at(1).unwrap(), Some(b"r1".to_vec()));
    assert_eq!(
        cold.reads.load(Ordering::SeqCst),
        before + 1,
        "positive cache hit"
    );
    let fresh = core(HISTORY);
    let ordinary = core("/ordinary-cold-control");
    ordinary.write_sync(b"ordinary").unwrap();

    let owner = fixture.enroll();
    // No legacy request is active here. Exercise durable policy with the
    // existing lower-level binding contract, without claiming service adoption.
    fixture
        .store
        .bind_record_guard(HISTORY, None, OWNER, &owner)
        .unwrap();
    let counts = cold.reads.load(Ordering::SeqCst);
    for handle in [&legacy, &fresh] {
        for offset in [0, 1, 3] {
            let error = handle.read_at(offset).unwrap_err();
            assert!(error.contains("requires the scoped owner handle"));
        }
    }
    assert_eq!(cold.reads.load(Ordering::SeqCst), counts);
    assert_eq!(ordinary.read_at(0).unwrap(), Some(b"ordinary".to_vec()));
    let scoped = core(HISTORY)
        .with_record_owner(HISTORY, owner.clone())
        .unwrap();
    assert_eq!(scoped.read_at(0).unwrap(), Some(b"r0".to_vec()));
    fixture
        .kernel
        .retire_record_content_owner(OWNER, &service(), &owner)
        .unwrap();
    assert!(scoped.read_at(0).is_err());
    assert!(legacy.read_at(0).is_err());
}
