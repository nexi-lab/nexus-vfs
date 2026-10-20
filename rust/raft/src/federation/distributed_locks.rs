//! Distributed advisory-lock backend.
//!
//! Implements the ``contracts::Locks`` trait on top of a
//! ``ZoneConsensus<FullStateMachine>``. Write operations propose a
//! ``Command::{Acquire,Release,Force,Extend}Lock`` through raft; the
//! apply path mutates the shared ``Arc<Mutex<LockState>>`` on every
//! peer. Reads hit that same shared map directly (no round-trip) —
//! same post-R14 consistency model as the previous in-kernel
//! implementation.
//!
//! The kernel resolves a zone via its mount table and requests this backend
//! through `DistributedCoordinator::locks_for_zone`. Each zone's committed
//! state remains separate; local or other-zone holders are never copied in.

use std::sync::Arc;

use parking_lot::Mutex;

use contracts::lock_state::{LockInfo, LockState, Locks};

use crate::raft::{Command, CommandResult, FullStateMachine, ZoneConsensus};

fn now_secs() -> u64 {
    FullStateMachine::now()
}

/// Distributed ``Locks`` backend — raft-replicated advisory locks.
///
/// Wraps a ``ZoneConsensus<FullStateMachine>`` + its tokio runtime +
/// the state machine's shared advisory ``Arc<Mutex<LockState>>``.
///
/// ``shared_state`` is the same Arc the state machine's apply path
/// mutates — owning a handle here lets ``get_lock`` / ``list_locks``
/// read without a raft round-trip.
pub struct DistributedLocks {
    node: ZoneConsensus<FullStateMachine>,
    runtime: tokio::runtime::Handle,
    shared_state: Arc<Mutex<LockState>>,
}

impl DistributedLocks {
    /// Bind to the zone's existing apply-owned state. This is a handle, not
    /// another lock table, so reads observe that same local replica.
    pub fn new(node: ZoneConsensus<FullStateMachine>, runtime: tokio::runtime::Handle) -> Self {
        // This accessor clones the apply-owned handle cached by ZoneConsensus;
        // it neither reenters the runtime nor waits on the state machine.
        // Snapshot restore replaces the contents under this same shared Arc.
        let shared_state: Arc<Mutex<LockState>> = node.advisory_state_blocking();
        Self {
            node,
            runtime,
            shared_state,
        }
    }
}

impl Locks for DistributedLocks {
    fn acquire(
        &self,
        path: &str,
        lock_id: &str,
        max_holders: u32,
        ttl_secs: u32,
        holder_info: &str,
    ) -> Result<bool, String> {
        let cmd = Command::AcquireLock {
            path: path.to_string(),
            lock_id: lock_id.to_string(),
            max_holders,
            ttl_secs,
            holder_info: holder_info.to_string(),
            now_secs: now_secs(),
        };
        let result = self
            .runtime
            .block_on(self.node.propose(cmd))
            .map_err(|e| format!("DistributedLocks.acquire({path}): {e}"))?;
        match result {
            CommandResult::LockResult(state) => {
                if state.acquired {
                    // Read-your-writes on follower: poll local state
                    // machine until the exact lock_id we just wrote
                    // appears. SSOT = `shared_state` (the same
                    // `Arc<Mutex<LockState>>` the apply path mutates).
                    // Using a raft-index barrier instead would fail on
                    // followers — `commit_index()` immediately after
                    // propose is stale until AppendEntries arrives.
                    let shared = Arc::clone(&self.shared_state);
                    let lock_id_owned = lock_id.to_string();
                    let path_owned = path.to_string();
                    let _ = self.node.wait_until(
                        || {
                            shared
                                .lock()
                                .get_lock(&path_owned)
                                .map(|info| info.holders.iter().any(|h| h.lock_id == lock_id_owned))
                                .unwrap_or(false)
                        },
                        500,
                    );
                }
                Ok(state.acquired)
            }
            CommandResult::Error(e) => {
                Err(format!("DistributedLocks.acquire({path}) rejected: {e}"))
            }
            _ => Err("DistributedLocks.acquire: unexpected result type".into()),
        }
    }

    fn release(&self, path: &str, lock_id: &str) -> Result<bool, String> {
        let cmd = Command::ReleaseLock {
            path: path.to_string(),
            lock_id: lock_id.to_string(),
        };
        let result = self
            .runtime
            .block_on(self.node.propose(cmd))
            .map_err(|e| format!("DistributedLocks.release({path}): {e}"))?;
        Ok(matches!(result, CommandResult::Success))
    }

    fn force_release(&self, path: &str) -> Result<bool, String> {
        let cmd = Command::ForceReleaseLock {
            path: path.to_string(),
        };
        let result = self
            .runtime
            .block_on(self.node.propose(cmd))
            .map_err(|e| format!("DistributedLocks.force_release({path}): {e}"))?;
        Ok(matches!(result, CommandResult::Success))
    }

    fn extend(&self, path: &str, lock_id: &str, ttl_secs: u32) -> Result<bool, String> {
        let cmd = Command::ExtendLock {
            path: path.to_string(),
            lock_id: lock_id.to_string(),
            new_ttl_secs: ttl_secs,
            now_secs: now_secs(),
        };
        let result = self
            .runtime
            .block_on(self.node.propose(cmd))
            .map_err(|e| format!("DistributedLocks.extend({path}): {e}"))?;
        Ok(matches!(result, CommandResult::Success))
    }

    fn get_lock(&self, path: &str) -> Option<LockInfo> {
        // Reads share semantics with ``LocalLocks`` post-fix: no
        // read-side GC. ``apply_*`` paths prune expired holders on
        // every write, so unmutated rows that survive are by
        // definition cold and never block live decisions.
        self.shared_state.lock().get_lock(path)
    }

    fn list_locks(&self, prefix: &str, limit: usize) -> Vec<LockInfo> {
        self.shared_state.lock().list_locks(prefix, limit)
    }

    fn shared_state_arc(&self) -> Arc<Mutex<LockState>> {
        self.shared_state.clone()
    }
}
