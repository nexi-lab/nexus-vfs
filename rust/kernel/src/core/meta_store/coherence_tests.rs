use super::*;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Hold a real redb writer open while a delete and an uncached read race.
/// A read of the old snapshot must never survive in the cache after deletion.
fn deletion_does_not_resurrect_cached_metadata(batch_delete: bool, batch_read: bool) {
    let store = Arc::new(LocalMetaStore::in_memory().unwrap());
    let path = "/proc/123.1";
    store
        .put(
            path,
            FileMetadata {
                path: path.into(),
                entry_type: DT_DIR,
                ..Default::default()
            },
        )
        .unwrap();
    let blocker = store.db.begin_write().unwrap();
    let deleting = Arc::clone(&store);
    let deletion = std::thread::spawn(move || {
        if batch_delete {
            assert_eq!(deleting.delete_batch(&[path.into()]).unwrap(), 1);
        } else {
            assert!(deleting.delete(path).unwrap());
        }
    });
    // The old implementation invalidates before waiting for redb. The fixed
    // one takes the coherence guard before it can touch either store or cache.
    let deadline = Instant::now() + Duration::from_secs(5);
    while store.cache.contains_key(path) && !store.cache_coherence.is_locked_exclusive() {
        assert!(
            Instant::now() < deadline,
            "delete did not reach the blocked writer"
        );
        std::thread::yield_now();
    }
    let (sent, received) = mpsc::channel();
    let reading = Arc::clone(&store);
    let reader = std::thread::spawn(move || {
        if batch_read {
            reading.get_batch(&[path.into()]).unwrap();
        } else {
            reading.get(path).unwrap();
        }
        sent.send(()).unwrap();
    });
    // Old readers complete against the pre-delete snapshot; coherent readers
    // wait for the writer. Release it in either case, then check the public API.
    let _ = received.recv_timeout(Duration::from_millis(100));
    drop(blocker);
    deletion.join().unwrap();
    reader.join().unwrap();
    assert!(!store.exists(path).unwrap());
    assert_eq!(
        store.get(path).unwrap(),
        None,
        "deleted metadata remained cached"
    );
}

#[test]
fn delete_cannot_be_undone_by_a_concurrent_cache_fill() {
    deletion_does_not_resurrect_cached_metadata(false, false);
}

#[test]
fn delete_cannot_be_undone_by_a_concurrent_batch_read() {
    deletion_does_not_resurrect_cached_metadata(false, true);
}

#[test]
fn batch_delete_cannot_be_undone_by_a_concurrent_cache_fill() {
    deletion_does_not_resurrect_cached_metadata(true, false);
}

#[test]
fn batch_delete_cannot_be_undone_by_a_concurrent_batch_read() {
    deletion_does_not_resurrect_cached_metadata(true, true);
}

#[test]
fn committed_mutations_remain_visible_with_concurrent_single_and_batch_reads() {
    let store = Arc::new(LocalMetaStore::in_memory().unwrap());
    let start = Arc::new(std::sync::Barrier::new(2));
    let reading = Arc::clone(&store);
    let read_start = Arc::clone(&start);
    let reader = std::thread::spawn(move || {
        read_start.wait();
        for _ in 0..10_000 {
            reading.get("/a").unwrap();
            reading.get_batch(&["/a".into(), "/b".into()]).unwrap();
        }
    });
    start.wait();
    for version in 1..=64 {
        let mut row = FileMetadata {
            path: "/a".into(),
            version,
            entry_type: DT_REG,
            ..Default::default()
        };
        store.put("/a", row.clone()).unwrap();
        assert_eq!(store.get("/a").unwrap(), Some(row.clone()));
        row.size = 42;
        store.put_batch(&[("/a".into(), row.clone())]).unwrap();
        assert_eq!(store.get("/a").unwrap(), Some(row.clone()));
        let mut next = row.clone();
        next.version += 1;
        assert!(
            !store
                .put_if_version(next.clone(), version + 10)
                .unwrap()
                .success
        );
        assert_eq!(store.get("/a").unwrap(), Some(row));
        assert!(store.put_if_version(next.clone(), version).unwrap().success);
        assert_eq!(store.get("/a").unwrap(), Some(next.clone()));
        store.rename_path("/a", "/b", false).unwrap();
        next.path = "/b".into();
        assert_eq!(store.get("/a").unwrap(), None);
        assert_eq!(store.get("/b").unwrap(), Some(next));
        assert_eq!(store.delete_batch(&["/b".into()]).unwrap(), 1);
        assert_eq!(store.get("/b").unwrap(), None);
    }
    reader.join().unwrap();
}
