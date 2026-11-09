//! Original-host retirement latch. This is a native capability, not a wire token.
//!
//! Only the runtime which owns the writer and receiver may complete this latch,
//! after driving all of its existing joins. Requesting stop is not completion.

use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostCleanupOutcome {
    Pending,
    Joined,
    Unconfirmed(String),
}

type StopHandler = Arc<dyn Fn() + Send + Sync>;

struct State {
    outcome: HostCleanupOutcome,
    stop_requested: bool,
    stop_handler: Option<StopHandler>,
}

/// Issued once for one registry incarnation before its host is started.
/// Clones share the first completion outcome. A later empty cleanup cannot
/// overwrite an unconfirmed join with success.
#[derive(Clone)]
pub struct ManagedHostCleanup(Arc<Mutex<State>>);

impl std::fmt::Debug for ManagedHostCleanup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.0.lock();
        f.debug_struct("ManagedHostCleanup")
            .field("outcome", &state.outcome)
            .field("stop_requested", &state.stop_requested)
            .finish_non_exhaustive()
    }
}

impl ManagedHostCleanup {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            outcome: HostCleanupOutcome::Pending,
            stop_requested: false,
            stop_handler: None,
        })))
    }

    pub fn outcome(&self) -> HostCleanupOutcome {
        self.0.lock().outcome.clone()
    }

    pub fn is_joined(&self) -> bool {
        self.0.lock().outcome == HostCleanupOutcome::Joined
    }

    pub fn stop_requested(&self) -> bool {
        self.0.lock().stop_requested
    }

    /// All writer, receiver and completion-retirement joins must have run
    /// before calling this. Return true only for an accepted joined outcome.
    /// An error is retained even if another caller later reports Ok.
    pub fn complete(&self, result: Result<(), String>) -> bool {
        let mut state = self.0.lock();
        if state.outcome == HostCleanupOutcome::Pending {
            state.outcome = match result {
                Ok(()) => HostCleanupOutcome::Joined,
                Err(error) => {
                    // A runtime may report failed joins without publishing a
                    // terminal observer event. Withdraw readiness immediately.
                    state.stop_requested = true;
                    HostCleanupOutcome::Unconfirmed(error)
                }
            };
        }
        state.outcome == HostCleanupOutcome::Joined
    }

    /// Signal only. The handler must not block on joins; completion comes back
    /// through complete(). Invoke outside all registry/map/latch guards.
    pub fn request_stop(&self) {
        let handler = {
            let mut state = self.0.lock();
            if state.stop_requested {
                return;
            }
            state.stop_requested = true;
            state.stop_handler.clone()
        };
        if let Some(handler) = handler {
            handler();
        }
    }

    /// Attach the original handle's signal once. A stop requested during spawn
    /// is delivered immediately on attachment. The handler should hold a weak
    /// reference so it cannot create a handle/latch ownership cycle.
    pub fn set_stop_handler(&self, handler: StopHandler) -> Result<(), &'static str> {
        let requested = {
            let mut state = self.0.lock();
            if state.stop_handler.is_some() {
                return Err("original host stop handler already attached");
            }
            state.stop_handler = Some(Arc::clone(&handler));
            state.stop_requested
        };
        if requested {
            handler();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn unconfirmed_join_cannot_be_erased_by_a_second_empty_cleanup() {
        let cleanup = ManagedHostCleanup::new();
        assert!(!cleanup.complete(Err("writer join timed out".into())));
        assert!(!cleanup.clone().complete(Ok(())));
        assert_eq!(
            cleanup.outcome(),
            HostCleanupOutcome::Unconfirmed("writer join timed out".into())
        );
    }

    #[test]
    fn early_stop_is_delivered_once_without_holding_the_latch() {
        let cleanup = ManagedHostCleanup::new();
        cleanup.request_stop();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let completing = cleanup.clone();
        cleanup
            .set_stop_handler(Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                assert!(completing.complete(Ok(())));
            }))
            .unwrap();
        cleanup.request_stop();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(cleanup.is_joined());
    }
}
