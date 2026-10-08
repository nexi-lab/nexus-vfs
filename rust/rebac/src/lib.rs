//! Relationship-based authorization for kernel operations and search results.
//!
//! Durable tuples live in the credential consensus under `CONTROL_NS_REBAC`.
//! Permission graphs are derived in memory and refreshed when applied state
//! changes. The management API and kernel provider share one tuple store.

pub mod graph_cache;
pub mod inmem;
pub mod list_zones;
pub mod permission_provider;
pub mod raft_store;
pub mod store;
pub mod tuple_key;

// Re-export the trait + error at the crate root so callers reach
// them at one path (`nexus_rebac::ReBACTupleStore`) instead of
// remembering the module layout — same convention as
// `nexus_http_api::AppState`.
pub use graph_cache::ReBACGraphCache;
pub use inmem::InMemoryReBACTupleStore;
pub use permission_provider::RebacPermissionProvider;
pub use raft_store::{RaftReBACTupleStore, CONTROL_NS_REBAC};
pub use store::{NoopReBACTupleStore, ReBACTupleStore, ReBACTupleStoreError};
