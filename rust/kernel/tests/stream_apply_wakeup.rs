//! A stream reader must let an apply observer finish while its backend is busy.
//! WAL reads need the Raft state-machine lock, while apply holds that lock and
//! wakes stream readers. Holding the notification lock across a backend read
//! reverses those locks and permanently stops both replication and the reader.

use kernel::core::stream::manager::StreamManager;
use kernel::stream::{StreamBackend, StreamError};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

struct ApplyingBackend {
    reads: AtomicUsize,
    apply: mpsc::Sender<()>,
    applied: Mutex<mpsc::Receiver<()>>,
}

impl StreamBackend for ApplyingBackend {
    fn read_at(&self, offset: usize) -> Result<(Vec<u8>, usize), StreamError> {
        let read = self.reads.fetch_add(1, Ordering::SeqCst);
        self.apply.send(()).unwrap();
        self.applied
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| StreamError::Closed("apply observer blocked behind reader"))?;
        if read == 0 {
            // The initial empty read overlaps a notification. The next read
            // must run immediately and must also allow apply to finish.
            Err(StreamError::Empty)
        } else {
            let data = b"replicated reply".to_vec();
            let next = offset + 4 + data.len();
            Ok((data, next))
        }
    }

    fn push(&self, _: &[u8]) -> Result<usize, StreamError> {
        unreachable!("this backend is populated by the apply observer")
    }
    fn read_batch(&self, _: usize, _: usize) -> Result<(Vec<Vec<u8>>, usize), StreamError> {
        unreachable!("the blocking reader reads one frame")
    }
    fn close(&self) {}
    fn is_closed(&self) -> bool {
        false
    }
    fn tail_offset(&self) -> usize {
        4 + b"replicated reply".len()
    }
    fn msg_count(&self) -> usize {
        1
    }
}

#[test]
fn apply_wakeup_can_finish_during_a_backend_read() {
    let (apply, requests) = mpsc::channel();
    let (finished, applied) = mpsc::channel();
    let backend = Arc::new(ApplyingBackend {
        reads: AtomicUsize::new(0),
        apply,
        applied: Mutex::new(applied),
    });
    let manager = Arc::new(StreamManager::new());
    let path = "/conversations/apply-lock-order/transcript";
    manager.register(path, backend).unwrap();

    let observer = {
        let manager = Arc::clone(&manager);
        std::thread::spawn(move || {
            for _ in 0..2 {
                requests.recv_timeout(Duration::from_secs(3)).unwrap();
                assert!(manager.wake_waiters(path));
                let _ = finished.send(());
            }
        })
    };
    let result = manager.read_at_blocking(path, 0, 1_000);
    observer.join().unwrap();
    let (data, next) = result.expect("backend read must not hold the notification lock");
    assert_eq!(data, b"replicated reply");
    assert_eq!(next, 4 + data.len());
}
