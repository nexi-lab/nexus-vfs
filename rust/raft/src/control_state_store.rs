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
use crate::runtime_bridge::bridge_block_on;

/// How long a write waits for its own effect to become visible in the local
/// state machine before returning (read-your-writes). Admin tooling that writes
/// then immediately lists must not see its own write missing; control-plane
/// writes are never a hot path, so paying this is free in practice.
const READ_YOUR_WRITES_POLL_MS: u64 = 500;

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
        let expected = value.to_vec();
        let result = bridge_block_on(
            &self.runtime,
            self.node.propose(Command::PutControlState {
                namespace: ns.to_string(),
                key: key.to_string(),
                value: expected.clone(),
                if_absent,
            }),
        )
        .map_err(|e| format!("put({ns}/{key}): {e}"))?;
        if let CommandResult::Error(msg) = result {
            // The only expected rejection is the CAS conflict; surface anything
            // else (an upsert must never be refused).
            if if_absent {
                return Ok(false);
            }
            return Err(format!("put({ns}/{key}) rejected: {msg}"));
        }
        self.wait_visible(key, &expected);
        Ok(true)
    }

    /// Remove `key` (revocation / un-pin). Returns whether a record was present
    /// at propose time — advisory (the delete is idempotent, the log is
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
        Ok(existed)
    }

    /// Read-your-writes: `propose` returns on commit, but the local apply can lag
    /// it by a raft tick (always on a follower whose proposal was forwarded). Wait
    /// until this node's state machine shows the committed value. SSOT stays the
    /// state machine — we only wait for it.
    fn wait_visible(&self, key: &str, expected: &[u8]) {
        let runtime = self.runtime.clone();
        let node = self.node.clone();
        let ns = self.namespace;
        let key = key.to_string();
        let expected = expected.to_vec();
        let _ = self.node.wait_until(
            || {
                let poll_key = key.clone();
                let observed = bridge_block_on(
                    &runtime,
                    node.with_state_machine(move |sm: &FullStateMachine| {
                        sm.get_control_state(ns, &poll_key)
                    }),
                );
                matches!(&observed, Ok(Some(bytes)) if *bytes == expected)
            },
            READ_YOUR_WRITES_POLL_MS,
        );
    }
}
