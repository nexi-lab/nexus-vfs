use super::*;
use crate::transport::{observe_sender, NodeAddress, PeerMap, SharedPeerMap};

fn bind_routes<S: StateMachine + 'static>(driver: &mut ZoneConsensusDriver<S>) -> SharedPeerMap {
    let routes = Arc::new(std::sync::RwLock::new(PeerMap::new(1)));
    driver.set_peer_map(routes.clone(), false);
    routes
}

async fn remove_then_observe(address: &[u8]) {
    let (_handle, mut driver, _directory) = leader_1voter().await;
    let routes = bind_routes(&mut driver);
    assert!(observe_sender(&routes, 2, "node-2:9100", false));

    let add = ConfChange {
        change_type: ConfChangeType::AddLearnerNode,
        node_id: 2,
        context: address.to_vec().into(),
        ..Default::default()
    };
    driver.raw_node.propose_conf_change(vec![], add).unwrap();
    advance_until_membership(&mut driver, |m| m.learners == vec![2]).await;
    assert!(routes.read().unwrap().route(2).is_some());
    assert_eq!(routes.read().unwrap().len(), 1);
    assert!(observe_sender(&routes, 2, "node-2:9200", false));

    let remove = ConfChange {
        change_type: ConfChangeType::RemoveNode,
        node_id: 2,
        ..Default::default()
    };
    driver.raw_node.propose_conf_change(vec![], remove).unwrap();
    advance_until_membership(&mut driver, |m| m.learners.is_empty()).await;
    assert!(applied_member_addresses(&driver).await.0.is_empty());

    // Deliver the authenticated sender observation strictly after removal.
    // It is an address hint, never a new membership decision.
    assert!(observe_sender(&routes, 2, "node-2:9300", false));
    {
        let routes = routes.read().unwrap();
        assert!(
            routes.route(2).is_none(),
            "a delayed sender observation must not restore a removed member route"
        );
        assert!(
            routes.snapshot().is_empty(),
            "route enumeration must exclude a removed member after a late observation"
        );
        assert_eq!(routes.len(), 0);
        assert!(routes.is_empty());
    }

    // A subsequent committed rejoin uses the new registered address.
    let rejoin = ConfChange {
        change_type: ConfChangeType::AddLearnerNode,
        node_id: 2,
        context: b"node-2:9400".to_vec().into(),
        ..Default::default()
    };
    driver.raw_node.propose_conf_change(vec![], rejoin).unwrap();
    advance_until_membership(&mut driver, |m| m.learners == vec![2]).await;
    assert_eq!(
        routes.read().unwrap().route(2),
        Some(&NodeAddress::new(2, "http://node-2:9400"))
    );
}

#[tokio::test]
async fn removed_registered_member_rejects_delayed_sender_route() {
    remove_then_observe(b"node-2:9000").await;
}

#[tokio::test]
async fn removed_observation_only_member_rejects_delayed_sender_route() {
    remove_then_observe(b"").await;
}

fn witness_with_membership(
    membership: ConfState,
) -> (
    ZoneConsensus<WitnessStateMachine>,
    ZoneConsensusDriver<WitnessStateMachine>,
    TempDir,
) {
    let directory = TempDir::new().unwrap();
    {
        let storage = RaftStorage::open(directory.path()).unwrap();
        storage.set_conf_state(&membership).unwrap();
    }
    let storage = RaftStorage::open(directory.path()).unwrap();
    let store = RedbStore::open(directory.path().join("witness")).unwrap();
    let config = RaftConfig {
        id: 1,
        skip_bootstrap: true,
        ..Default::default()
    };
    let (handle, driver) = ZoneConsensus::new(
        config,
        storage,
        WitnessStateMachine::new(&store).unwrap(),
        None,
    )
    .unwrap();
    (handle, driver, directory)
}

#[test]
fn restored_joint_membership_routes_outgoing_voters_and_next_learners() {
    let (_handle, mut driver, _directory) = witness_with_membership(ConfState {
        voters: vec![1, 2],
        voters_outgoing: vec![1, 3],
        learners: vec![4],
        learners_next: vec![3],
        ..Default::default()
    });
    let routes = bind_routes(&mut driver);
    for id in 2..=5 {
        assert!(observe_sender(
            &routes,
            id,
            &format!("node-{id}:9000"),
            false
        ));
    }
    let mut routed: Vec<_> = routes.read().unwrap().snapshot().into_keys().collect();
    routed.sort_unstable();
    assert_eq!(routed, vec![2, 3, 4]);
    assert!(routes.read().unwrap().route(5).is_none());
}

#[test]
fn unconfigured_witness_can_reply_before_receiving_membership() {
    let (_handle, mut driver, _directory) = witness_with_membership(ConfState::default());
    let routes = bind_routes(&mut driver);
    assert!(observe_sender(&routes, 2, "node-2:9000", false));
    assert_eq!(
        routes.read().unwrap().route(2),
        Some(&NodeAddress::new(2, "http://node-2:9000"))
    );
    assert_eq!(routes.read().unwrap().len(), 1);
}

#[test]
fn restored_membership_filters_observations_without_address_records() {
    let (_handle, mut driver, _directory) = witness_with_membership(ConfState {
        voters: vec![1, 2],
        ..Default::default()
    });
    let routes = bind_routes(&mut driver);
    assert!(observe_sender(&routes, 2, "node-2:9000", false));
    assert!(observe_sender(&routes, 3, "node-3:9000", false));
    assert!(routes.read().unwrap().route(2).is_some());
    assert!(routes.read().unwrap().route(3).is_none());
    assert_eq!(routes.read().unwrap().len(), 1);
}
