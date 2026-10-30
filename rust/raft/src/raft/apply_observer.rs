//! Runtime ownership of post-commit observer registrations.

use std::sync::{Arc, Weak};

use super::state_machine::{AppliedEntry, ApplyObserver};

type Callback = Arc<dyn Fn(&AppliedEntry) + Send + Sync>;
type ObserverSlot = parking_lot::RwLock<Vec<ApplyObserver>>;

/// Keeps one observer registered until its owning runtime surface is dropped.
pub struct ApplySubscription {
    slot: Weak<ObserverSlot>,
    callback: Callback,
}

impl ApplySubscription {
    pub(super) fn new(slot: &Arc<ObserverSlot>, callback: Callback) -> Self {
        Self {
            slot: Arc::downgrade(slot),
            callback,
        }
    }
}

impl Drop for ApplySubscription {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.upgrade() {
            let mut observers = slot.write();
            if let Some(index) = observers
                .iter()
                .position(|(key, callback)| key.is_none() && Arc::ptr_eq(callback, &self.callback))
            {
                observers.remove(index);
            }
        }
    }
}
