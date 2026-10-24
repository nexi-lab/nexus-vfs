//! Experimental typed view of the EXISTING replicated control state. No second
//! database, daemon, issuer or mutable transcript-membership journal. Management
//! methods are trusted composition-root primitives; they must not be exposed as
//! Agent RPCs. The native Node/operator authorization door is not installed yet.

use crate::{
    control_state_store::ControlStateStore,
    prelude::{FullStateMachine, ZoneConsensus},
};
use a2a::collaboration_policy::{validated_space_key, PolicyError, SpacePolicy, SpacePolicyStore};

const REVOKED: &[u8] = b"collaboration-space-revoked-v1";

pub struct RaftSpacePolicyStore {
    inner: ControlStateStore,
}

impl RaftSpacePolicyStore {
    pub fn new(node: ZoneConsensus<FullStateMachine>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            inner: ControlStateStore::new(
                node,
                runtime,
                contracts::constants::CONTROL_NS_COLLABORATION,
            ),
        }
    }
}

impl SpacePolicyStore for RaftSpacePolicyStore {
    fn create(&self, policy: &SpacePolicy) -> Result<(), PolicyError> {
        let key = validated_space_key(policy.space())?;
        let bytes = policy.encode()?;
        // One proposal only. A lost proposal/barrier reply remains Unknown;
        // querying current state is a separate operation, never a remint/retry.
        self.inner
            .put_if_absent(&key, &bytes)
            .map_err(PolicyError::Unknown)?;
        let winner = self.current(policy.space())?;
        if winner != *policy {
            return Err(PolicyError::Conflict);
        }
        Ok(())
    }

    fn current(&self, space: &str) -> Result<SpacePolicy, PolicyError> {
        let key = validated_space_key(space)?;
        let values = self
            .inner
            .get_many_linearizable(&[key.clone(), format!("revoked:{space}")])
            .map_err(PolicyError::Unavailable)?;
        match values.as_slice() {
            [_, Some(value)] if value == REVOKED => Err(PolicyError::Revoked),
            [_, Some(_)] => Err(PolicyError::Unavailable("invalid revocation record".into())),
            [Some(record), None] => {
                let policy = SpacePolicy::decode(record)?;
                if policy.space() != space {
                    return Err(PolicyError::Unavailable("space key/record mismatch".into()));
                }
                Ok(policy)
            }
            [None, None] => Err(PolicyError::NotFound),
            _ => Err(PolicyError::Unavailable(
                "incomplete control snapshot".into(),
            )),
        }
    }

    fn revoke(&self, space: &str) -> Result<(), PolicyError> {
        validated_space_key(space)?;
        // Tombstone before creation is intentional: an in-flight create cannot
        // resurrect this space. New authority/membership needs a new space ID.
        self.inner
            .put_if_absent(&format!("revoked:{space}"), REVOKED)
            .map_err(PolicyError::Unknown)?;
        match self.current(space) {
            Err(PolicyError::Revoked) => Ok(()),
            _ => Err(PolicyError::Unknown("revocation was not confirmed".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::ZoneRaftRegistry;
    use a2a::domain_address::AgentAddress;
    use std::sync::{Arc, Barrier};
    const SPACE: &str = "0123456789abcdef0123456789abcdef";
    async fn ready(node: &ZoneConsensus<FullStateMachine>) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if node.is_leader() && node.applied_index() >= node.last_index() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("singleton must apply its current-term leader entry before ReadIndex");
    }
    fn policy(host: u8) -> SpacePolicy {
        SpacePolicy::new(
            SPACE.into(),
            [host; 32],
            "collab-one".into(),
            vec![
                AgentAddress::new([1; 32], "worker".into()).unwrap(),
                AgentAddress::new([2; 32], "worker".into()).unwrap(),
            ],
            100,
            200,
        )
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn immutable_host_race_and_irreversible_revocation_use_real_consensus() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Handle::current();
        let registry = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
        let node = registry
            .create_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
            .unwrap();
        node.campaign().await.unwrap();
        ready(&node).await;
        let store = Arc::new(RaftSpacePolicyStore::new(node, runtime.clone()));
        assert_eq!(store.current(SPACE), Err(PolicyError::NotFound));
        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = (1..=2)
            .map(|host| {
                let store = store.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.create(&policy(host))
                })
            })
            .collect();
        let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == Err(PolicyError::Conflict))
                .count(),
            1
        );
        let winner = store.current(SPACE).unwrap();
        store.create(&winner).unwrap();
        store.revoke(SPACE).unwrap();
        assert_eq!(store.current(SPACE), Err(PolicyError::Revoked));
        assert_eq!(store.create(&winner), Err(PolicyError::Revoked));
        store.revoke(SPACE).unwrap();
        drop(store);
        registry.shutdown_all();
        drop(registry);
        // Like the existing native restart fixtures: driver/transport cleanup
        // is asynchronous. This is not a production handoff/lease guarantee.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let registry = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
        let node = registry
            .open_persisted_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
            .unwrap();
        node.campaign().await.unwrap();
        ready(&node).await;
        let store = RaftSpacePolicyStore::new(node, runtime);
        assert_eq!(store.current(SPACE), Err(PolicyError::Revoked));
        assert_eq!(store.create(&winner), Err(PolicyError::Revoked));
        drop(store);
        registry.shutdown_all();
    }
}
