//! Shared contracts (traits + types) for Nexus Rust crates.
//! Aligned with Python ``src/nexus/contracts/``.
//!
//! Submodules mirror Python's file layout so a reader jumping between
//! the two trees sees the same names in the same places. Re-exports at
//! the crate root keep consumers' ``use contracts::X`` paths stable.

pub mod agent_pid;
pub mod constants;
pub mod lock_state;
pub mod operation_context;
pub mod rust_service;
pub use agent_pid::{decode_agent_pid, encode_agent_pid};
pub use constants::{
    env, is_system_path, recommended_worker_threads, AUTH_KEYS_PATH_PREFIX, BLAKE3_EMPTY,
    CONTROL_NS_AUTH, CONTROL_NS_FOREIGN_CA, CONTROL_ZONE_ID, LOCKS_PATH_PREFIX,
    MAX_GRPC_MESSAGE_BYTES, MIN_SERVER_RUNTIME_WORKERS, ROOT_ZONE_ID, SHARE_REGISTRY_PREFIX,
    SYSTEM_PATH_PREFIX, VFS_ROOT, ZONES_PATH_PREFIX,
};
pub use lock_state::{HolderInfo, LockAcquireResult, LockEntry, LockInfo, LockState, Locks};
pub use operation_context::OperationContext;
pub use rust_service::{RustCallError, RustService};
