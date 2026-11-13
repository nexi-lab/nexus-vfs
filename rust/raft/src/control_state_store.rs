//! Generic replicated cluster-control store over a Raft `ZoneConsensus`, scoped
//! to one namespace of the [`crate::prelude::Command::PutControlState`] key
//! space.
//!
//! This is the one place the propose + local read boilerplate lives. Typed
//! stores are thin wrappers that pick a namespace and map the error:
//! [`crate::auth_key_store::RaftAuthKeyStore`] (`contracts::CONTROL_NS_AUTH`) and
//! the cross-org foreign-CA anchor registry (`contracts::CONTROL_NS_FOREIGN_CA`).
//!
//! Same shape as [`crate::zone_meta_store::ZoneMetaStore`]: writes go through
//! `propose` (Raft consensus, majority ACK) so they reach every replica, and
//! succeed only once this replica has applied them; reads hit the
//! locally-applied state machine directly, no consensus round-trip, after
//! this node's own writes are applied here
//! ([`ZoneConsensus::own_writes_visible`]).

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
        self.own_writes_visible()
            .map_err(|e| format!("get({ns}/{key}): {e}"))?;
        let k = key.to_string();
        let fut = self
            .node
            .with_state_machine(move |sm: &FullStateMachine| sm.get_control_state(ns, &k));
        bridge_block_on(&self.runtime, fut).map_err(|e| format!("get({ns}/{key}): {e}"))
    }

    /// Read-your-writes for a local read: two atomic loads when this
    /// replica has applied every write this node submitted, else a bounded
    /// wait that reports the replica's lag.
    fn own_writes_visible(&self) -> Result<(), crate::raft::RaftError> {
        if self.node.own_writes_applied() {
            return Ok(());
        }
        bridge_block_on(&self.runtime, self.node.own_writes_visible())
    }

    /// Read related control records at one consensus read point. Unlike a
    /// sequence of cached/local gets, a grant and its revocation cannot come
    /// from different state-machine snapshots. This orders admission, not a
    /// later data-plane append in another zone.
    pub fn get_many_linearizable(&self, keys: &[String]) -> Result<Vec<Option<Vec<u8>>>, String> {
        let ns = self.namespace;
        let keys = keys.to_vec();
        self.read_linearizable(move |sm| {
            keys.iter()
                .map(|key| sm.get_control_state(ns, key).map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, String>>()
        })?
    }

    /// Typed native stores can inspect related namespaces at ONE ReadIndex.
    /// No caller-controlled namespace, mutation or public RPC is exposed here.
    pub(crate) fn read_linearizable<T: Send + 'static>(
        &self,
        read: impl FnOnce(&FullStateMachine) -> T + Send + 'static,
    ) -> Result<T, String> {
        let ns = self.namespace;
        bridge_block_on(&self.runtime, async {
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                self.node.read_linearizable(read),
            )
            .await
            .map_err(|_| format!("control snapshot({ns}) timed out"))?
            .map_err(|e| format!("control snapshot({ns}): {e}"))
        })
    }

    /// Enumerate this namespace as `(key, value)` — a prefix scan.
    #[inline]
    pub fn list(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        let ns = self.namespace;
        self.own_writes_visible()
            .map_err(|e| format!("list({ns}): {e}"))?;
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

    /// Typed stores submit their owning command through the same consensus
    /// handle. A proposal error may follow a commit and remains unknown.
    pub(crate) fn propose(&self, command: Command) -> Result<CommandResult, String> {
        bridge_block_on(&self.runtime, self.node.propose(command))
            .map_err(|e| format!("control proposal({}): {e}", self.namespace))
    }

    pub(crate) fn supports_replica_binding(&self) -> Result<bool, String> {
        bridge_block_on(&self.runtime, self.node.supports_replica_binding())
            .map_err(|error| format!("replica activation observation: {error}"))
    }

    pub(crate) fn commit_replica_control(&self, command: Command) -> Result<CommandResult, String> {
        bridge_block_on(&self.runtime, self.node.commit_replica_control(command))
            .map_err(|e| format!("replica binding proposal: {e}"))
    }

    fn put_inner(&self, key: &str, value: &[u8], if_absent: bool) -> Result<bool, String> {
        let ns = self.namespace;
        let result = self.propose(Command::PutControlState {
            namespace: ns.to_string(),
            key: key.to_string(),
            value: value.to_vec(),
            if_absent,
        })?;
        if let CommandResult::Error(msg) = result {
            // The only expected rejection is the CAS conflict; surface anything
            // else (an upsert must never be refused). The losing CAS was
            // applied here, so the winner's earlier insert is visible to a
            // caller that reads the record back right away (the journal's
            // begin does).
            if if_absent {
                return Ok(false);
            }
            return Err(format!("put({ns}/{key}) rejected: {msg}"));
        }
        Ok(true)
    }

    /// Remove `key` (revocation / un-pin). Returns whether a record was present
    /// in the local view before proposing — advisory (the delete is idempotent, the log is
    /// authoritative), for an operator "removed something" vs "nothing there".
    #[inline]
    pub fn delete(&self, key: &str) -> Result<bool, String> {
        let ns = self.namespace;
        let existed = self.get(key)?.is_some();
        let result = self.propose(Command::DeleteControlState {
            namespace: ns.to_string(),
            key: key.to_string(),
        })?;
        if let CommandResult::Error(msg) = result {
            return Err(format!("delete({ns}/{key}) rejected: {msg}"));
        }
        Ok(existed)
    }

    /// Wait for the local replica to apply everything committed cluster-wide
    /// before this call, through Raft ReadIndex — for a read that must observe
    /// OTHER nodes' writes too. Errors are returned to the management caller.
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
