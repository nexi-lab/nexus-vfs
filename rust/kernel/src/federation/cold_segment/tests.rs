use super::*;
use crate::hal::peer::{PeerBlobClient, PeerBlobResult};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Default)]
struct ScopedPeer {
    legacy_calls: AtomicUsize,
    calls: Mutex<Vec<(String, String, String)>>,
}

impl PeerBlobClient for ScopedPeer {
    fn fetch(&self, _: &str, _: &str) -> PeerBlobResult<Vec<u8>> {
        self.legacy_calls.fetch_add(1, Ordering::SeqCst);
        Ok(b"unscoped bytes".to_vec())
    }

    fn fetch_in_zone(&self, addr: &str, zone: &str, content: &str) -> PeerBlobResult<Vec<u8>> {
        self.calls
            .lock()
            .unwrap()
            .push((addr.into(), zone.into(), content.into()));
        if zone == "agent-alice" {
            Ok(b"cold segment".to_vec())
        } else {
            Err("zone denied".into())
        }
    }
}

#[test]
fn cold_peer_reads_preserve_owning_zone() {
    let kernel = Kernel::new();
    let peer = Arc::new(ScopedPeer::default());
    kernel.set_peer_client(peer.clone());
    assert_eq!(
        kernel
            .read_cold_segment("/history", "agent-alice", "same-hash", "writer:2028")
            .unwrap(),
        b"cold segment"
    );
    assert!(kernel
        .read_cold_segment("/history", "agent-bob", "same-hash", "writer:2028")
        .is_err());
    assert_eq!(peer.legacy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        *peer.calls.lock().unwrap(),
        vec![
            (
                "writer:2028".into(),
                "agent-alice".into(),
                "same-hash".into()
            ),
            ("writer:2028".into(), "agent-bob".into(), "same-hash".into()),
        ]
    );
}

#[test]
fn cold_peer_reads_refuse_an_unscoped_client() {
    struct LegacyPeer(AtomicUsize);
    impl PeerBlobClient for LegacyPeer {
        fn fetch(&self, _: &str, _: &str) -> PeerBlobResult<Vec<u8>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(b"legacy private bytes".to_vec())
        }
    }
    let kernel = Kernel::new();
    let peer = Arc::new(LegacyPeer(AtomicUsize::new(0)));
    kernel.set_peer_client(peer.clone());
    let error = kernel
        .read_cold_segment("/history", "agent-alice", "same-hash", "writer:2028")
        .unwrap_err();
    assert!(error.contains("zone-scoped peer content is unavailable"));
    assert_eq!(peer.0.load(Ordering::SeqCst), 0);
}
