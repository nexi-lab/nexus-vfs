//! Storage admission follows durable namespace contents after log compaction.

use super::{control_key, FullStateMachine, Result, Snapshot, OWNED_CONTROL_NAMESPACES};
use crate::raft::{MembershipPolicy, RaftError};

fn validate_owned_namespaces(
    policy: MembershipPolicy,
    mut contains: impl FnMut(&[u8]) -> Result<bool>,
) -> Result<()> {
    if policy == MembershipPolicy::FixedLocal {
        return Ok(());
    }
    for namespace in OWNED_CONTROL_NAMESPACES {
        if contains(&control_key(namespace, ""))? {
            return Err(RaftError::Config(format!(
                "{namespace} records require qualified fixed-local storage"
            )));
        }
    }
    Ok(())
}

impl FullStateMachine {
    pub(super) fn validate_owned_storage_policy(&self, policy: MembershipPolicy) -> Result<()> {
        validate_owned_namespaces(policy, |prefix| {
            // One bounded lookup per namespace, independent of its record count.
            let mut found = false;
            self.control_state.for_each_prefix(prefix, |_, _| {
                found = true;
                Ok(false)
            })?;
            Ok(found)
        })
    }

    pub(super) fn validate_owned_snapshot_policy(
        snapshot: &Snapshot,
        policy: MembershipPolicy,
    ) -> Result<()> {
        validate_owned_namespaces(policy, |prefix| {
            Ok(snapshot
                .control_state
                .keys()
                .any(|key| key.as_bytes().starts_with(prefix)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        raft::{Command, StateMachine},
        storage::RedbStore,
    };

    #[test]
    fn ordinary_control_namespaces_and_similar_names_remain_managed() {
        let directory = tempfile::tempdir().unwrap();
        let store = RedbStore::open(directory.path().join("state")).unwrap();
        let mut state = FullStateMachine::new(&store).unwrap();
        for (index, namespace) in [
            contracts::CONTROL_NS_AUTH.to_owned(),
            format!("{}-other", OWNED_CONTROL_NAMESPACES[0]),
            format!("{}-other", OWNED_CONTROL_NAMESPACES[1]),
        ]
        .into_iter()
        .enumerate()
        {
            state
                .apply(
                    index as u64 + 1,
                    &Command::PutControlState {
                        namespace,
                        key: "ordinary".into(),
                        value: b"preserved".to_vec(),
                        if_absent: false,
                    },
                )
                .unwrap();
        }
        state
            .validate_membership_policy(MembershipPolicy::Managed)
            .unwrap();
        state
            .validate_snapshot_membership(&state.snapshot().unwrap(), MembershipPolicy::Managed)
            .unwrap();
    }
}
