//! Compose the real CAS backend, Raft metadata and owning Kernel WAL service.
#![cfg(feature = "driver-cas-local")]

#[path = "owned_wal_storage/record_wal_service.rs"]
mod record_wal_service;
