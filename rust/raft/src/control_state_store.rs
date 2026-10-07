//! Generic replicated cluster-control store over a Raft `ZoneConsensus`, scoped
//! to one namespace of the [`crate::prelude::Command::PutControlState`] key
//! space.
//!
//! This is the one place the propose + read-your-writes + local read boilerplate
//! lives. Typed stores are thin wrappers that pick a namespace and map the error:
//! [`crate::auth_key_store::RaftAuthKeyStore`] (`contracts::CONTROL_NS_AUTH`) and
//! the cross-org foreign-CA anchor registry (`contracts::CONTROL_NS_FOREIGN_CA`).
//!
//! Same shape as [`crate::zone_meta_store::ZoneMetaStore`]: writes go through
//! `propose` (Raft consensus, majority ACK) so they reach every replica; reads
//! hit the locally-applied state machine directly, no consensus round-trip.

use crate::prelude::{Command, CommandResult, FullStateMachine, ZoneConsensus};
use lib::rt::block_on_via as bridge_block_on;

/// A namespace-scoped view of the replicated cluster-control store.
///
/// Clone-cheap in spirit but not `Clone` (holds a `ZoneConsensus`); construct one
/// per typed store at the composition root.
pub struct ControlStateStore {
    node: ZoneConsensus<FullStateMachine>,
    runtime: tokio::runtime::Handle,
    /// The `contracts::CONTROL_NS_*` this view reads and writes under. Every key
    /// is stored as `namespace\0key`, so views never see each other's records.
    namespace: &'static str,
}

impl ControlStateStore {
    /// Construct against a running `ZoneConsensus` (the control zone) + its
    /// runtime, scoped to `namespace` (a `contracts::CONTROL_NS_*`).
    pub fn new(
        node: ZoneConsensus<FullStateMachine>,
        runtime: tokio::runtime::Handle,
        namespace: &'static str,
    ) -> Self {
        Self {
            node,
            runtime,
            namespace,
        }
    }

    /// Read one value off the locally-applied state machine (no consensus).
    ///
    /// `#[inline]` (like the rest of this thin layer) so the typed-wrapper
    /// delegation — hit per auth lookup on a provider cache miss — costs no extra
    /// call.
    #[inline]
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let ns = self.namespace;
        let k = key.to_string();
        let fut = self
            .node
            .with_state_machine(move |sm: &FullStateMachine| sm.get_control_state(ns, &k));
        bridge_block_on(&self.runtime, fut).map_err(|e| format!("get({ns}/{key}): {e}"))
    }

    /// Enumerate this namespace as `(key, value)` — a prefix scan.
    #[inline]
    pub fn list(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        let ns = self.namespace;
        let fut = self
            .node
            .with_state_machine(move |sm: &FullStateMachine| sm.list_control_state(ns));
        bridge_block_on(&self.runtime, fut).map_err(|e| format!("list({ns}): {e}"))
    }

    /// Upsert (rotation-friendly): replaces any existing value at `key`.
    #[inline]
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), String> {
        self.put_inner(key, value, /* if_absent */ false)
            .map(|_| ())
    }

    /// CAS put-if-absent — a log-ordered uniqueness gate. `Ok(true)` = inserted;
    /// `Ok(false)` = `(namespace, key)` already existed, so nothing was written
    /// (NOT an error — the caller decides: refuse an agent-name mint, skip an
    /// anchor re-pin). Storage errors are still `Err`.
    #[inline]
    pub fn put_if_absent(&self, key: &str, value: &[u8]) -> Result<bool, String> {
        self.put_inner(key, value, /* if_absent */ true)
    }

    fn put_inner(&self, key: &str, value: &[u8], if_absent: bool) -> Result<bool, String> {
        let ns = self.namespace;
        let result = bridge_block_on(
            &self.runtime,
            self.node.propose(Command::PutControlState {
                namespace: ns.to_string(),
                key: key.to_string(),
                value: value.to_vec(),
                if_absent,
            }),
        )
        .map_err(|e| format!("put({ns}/{key}): {e}"))?;
        if let CommandResult::Error(msg) = result {
            // The only expected rejection is the CAS conflict; surface anything
            // else (an upsert must never be refused).
            if if_absent {
                // The winner's insert is committed, but on a follower the
                // local apply lags the returned leader result — barrier
                // before reporting the loss so a caller that reads the
                // record back right away (the journal's begin does) sees
                // the winner instead of a stale miss.
                self.read_barrier()?;
                return Ok(false);
            }
            return Err(format!("put({ns}/{key}) rejected: {msg}"));
        }
        self.read_barrier()?;
        Ok(true)
    }

    /// Remove `key` (revocation / un-pin). Returns whether a record was present
    /// in the local view before proposing — advisory (the delete is idempotent, the log is
    /// authoritative), for an operator "removed something" vs "nothing there".
    #[inline]
    pub fn delete(&self, key: &str) -> Result<bool, String> {
        let ns = self.namespace;
        let existed = self.get(key)?.is_some();
        let result = bridge_block_on(
            &self.runtime,
            self.node.propose(Command::DeleteControlState {
                namespace: ns.to_string(),
                key: key.to_string(),
            }),
        )
        .map_err(|e| format!("delete({ns}/{key}): {e}"))?;
        if let CommandResult::Error(msg) = result {
            return Err(format!("delete({ns}/{key}) rejected: {msg}"));
        }
        self.read_barrier()?;
        Ok(existed)
    }

    /// Wait for the local replica to apply all preceding commits through Raft
    /// ReadIndex. Applies equally to grants and revocations, including writes
    /// forwarded by followers. Errors are returned to the management caller.
    pub(crate) fn read_barrier(&self) -> Result<(), String> {
        bridge_block_on(&self.runtime, async {
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                self.node.read_linearizable(|_| ()),
            )
            .await
            .map_err(|_| format!("apply barrier({}) timed out", self.namespace))?
            .map_err(|e| format!("apply barrier({}): {e}", self.namespace))
        })
    }
}
