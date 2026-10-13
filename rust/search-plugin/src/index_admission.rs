//! Shared, non-blocking admission for index builds and document batches.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tonic::Status;

const MAX_INFLIGHT_ENV: &str = "NEXUS_SEARCH_INDEX_MAX_INFLIGHT";
const DEFAULT_MAX_INFLIGHT: u32 = 8;

pub(crate) struct IndexAdmission {
    inflight: AtomicU32,
    max_inflight: u32,
}

impl IndexAdmission {
    pub(crate) fn new(max_inflight: u32) -> Self {
        Self {
            inflight: AtomicU32::new(0),
            max_inflight,
        }
    }

    pub(crate) fn from_env() -> Self {
        Self::new(parse_limit(std::env::var(MAX_INFLIGHT_ENV).ok().as_deref()))
    }

    pub(crate) fn inflight(&self) -> u32 {
        self.inflight.load(Ordering::Relaxed)
    }

    pub(crate) fn admit(self: &Arc<Self>) -> Result<IndexPermit, Status> {
        let mut current = self.inflight();
        loop {
            if (self.max_inflight != 0 && current >= self.max_inflight) || current == u32::MAX {
                return Err(Status::resource_exhausted(format!(
                    "search indexing backlog: {current} operations in flight (limit {}); back off and retry",
                    self.max_inflight
                )));
            }
            match self.inflight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(IndexPermit(Arc::clone(self))),
                Err(observed) => current = observed,
            }
        }
    }
}

/// Move into the blocking task: cancelling its caller cannot free capacity
/// while the accepted work continues to hold index locks or embed documents.
pub(crate) struct IndexPermit(Arc<IndexAdmission>);

impl Drop for IndexPermit {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

fn parse_limit(raw: Option<&str>) -> u32 {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return DEFAULT_MAX_INFLIGHT;
    };
    raw.parse().unwrap_or_else(|_| {
        tracing::warn!(
            variable = MAX_INFLIGHT_ENV,
            value = raw,
            default = DEFAULT_MAX_INFLIGHT,
            "invalid indexing admission limit; using default"
        );
        DEFAULT_MAX_INFLIGHT
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn configuration_defaults_and_zero_disables_cap() {
        for raw in [
            None,
            Some(""),
            Some("  "),
            Some("bad"),
            Some("-4"),
            Some("4294967296"),
        ] {
            assert_eq!(parse_limit(raw), 8);
        }
        assert_eq!(parse_limit(Some(" 3 ")), 3);
        assert_eq!(parse_limit(Some("0")), 0);
        let gate = Arc::new(IndexAdmission::new(0));
        let permits: Vec<_> = (0..64).map(|_| gate.admit().unwrap()).collect();
        assert_eq!(gate.inflight(), 64);
        drop(permits);
        assert_eq!(gate.inflight(), 0);
    }

    #[test]
    fn concurrent_reservations_never_exceed_capacity() {
        let gate = Arc::new(IndexAdmission::new(8));
        let start = Arc::new(Barrier::new(65));
        let reserved = Arc::new(Barrier::new(65));
        let release = Arc::new(Barrier::new(65));
        let workers: Vec<_> = (0..64)
            .map(|_| {
                let (gate, start, reserved, release) = (
                    Arc::clone(&gate),
                    Arc::clone(&start),
                    Arc::clone(&reserved),
                    Arc::clone(&release),
                );
                std::thread::spawn(move || {
                    start.wait();
                    let permit = gate.admit();
                    reserved.wait();
                    release.wait();
                    permit.is_ok()
                })
            })
            .collect();
        start.wait();
        reserved.wait();
        let inflight = gate.inflight();
        release.wait();
        assert_eq!(inflight, 8);
        assert_eq!(
            workers
                .into_iter()
                .map(|w| w.join().unwrap())
                .filter(|ok| *ok)
                .count(),
            8
        );
        assert_eq!(gate.inflight(), 0);
        assert!(gate.admit().is_ok());
    }
}
