//! Boot-time stash for the raft-tier blob-fetcher slot.

use crate::kernel::Kernel;

impl Kernel {
    /// Stash the raft-tier blob-fetcher slot. Drained by
    /// `nexus_raft::blob_fetcher_handler::install` during boot.
    /// Typed as `Box<dyn Any>` so kernel does not name the raft-side
    /// `BlobFetcherSlot` concrete type.
    pub fn stash_blob_fetcher_slot(&self, slot: Box<dyn std::any::Any + Send + Sync>) {
        *self.pending_blob_fetcher_slot.lock() = Some(slot);
    }

    /// Drain the previously stashed blob-fetcher slot. Returns `None`
    /// after the first drain so repeat-boot scenarios stay safe.
    pub fn take_pending_blob_fetcher_slot(&self) -> Option<Box<dyn std::any::Any + Send + Sync>> {
        self.pending_blob_fetcher_slot.lock().take()
    }
}
