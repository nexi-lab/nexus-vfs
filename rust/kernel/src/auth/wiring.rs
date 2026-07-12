//! Kernel-side accessors for the §3.B.3 `AuthKeyStore` slot.

use std::sync::Arc;

use crate::hal::auth_key_store::AuthKeyStore;
use crate::kernel::Kernel;

impl Kernel {
    /// Replace the kernel's `auth_key_store` slot with a concrete
    /// implementation. Kernel boots with `NoopAuthKeyStore`; the host
    /// binary calls this with `nexus_raft::auth_key_store::RaftAuthKeyStore`
    /// bound to the ROOT zone's consensus, so the whole cluster shares one
    /// credential namespace. Mirrors `set_distributed_coordinator`.
    pub fn set_auth_key_store(&self, store: Arc<dyn AuthKeyStore>) {
        *self.auth_key_store.write() = store;
    }

    /// Borrow the current auth-key store — read-locked snapshot, so
    /// callers never hold the lock across a consensus round-trip. Before
    /// the host binary wires a real store this returns `NoopAuthKeyStore`,
    /// which resolves no credential and lists no key.
    pub fn auth_key_store(&self) -> Arc<dyn AuthKeyStore> {
        Arc::clone(&self.auth_key_store.read())
    }
}
