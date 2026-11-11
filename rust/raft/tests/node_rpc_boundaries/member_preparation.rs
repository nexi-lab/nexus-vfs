//! Complete configured membership is qualified over the original mTLS channels.

use super::reader_preparation::{node_tls, pool};
use super::replica_transport::RunningNode;
use super::*;
use nexus_raft::{
    raft::{FullStateMachine, ReplicaPreparationError, StateMachine, ZoneConsensus},
    transport::{NodeAddress, PeerMap, SharedPeerMap},
};

fn routes(id: u64, members: &[(u64, u64, &str)]) -> SharedPeerMap {
    let mut peers = PeerMap::new(id);
    for (member, address_id, address) in members {
        peers.observe(
            *member,
            NodeAddress::new(*address_id, format!("http://{address}")),
        );
    }
    Arc::new(std::sync::RwLock::new(peers))
}

async fn leader(
    first: &RunningNode,
    zone: &str,
    members: &[u64],
) -> ZoneConsensus<FullStateMachine> {
    let node = first
        .registry
        .create_zone(zone, &tokio::runtime::Handle::current())
        .unwrap();
    node.campaign().await.unwrap();
    for id in members {
        node.propose_conf_change(
            raft::eraftpb::ConfChangeType::AddLearnerNode,
            *id,
            Vec::new(),
        )
        .await
        .unwrap();
    }
    node
}

async fn no_activation(node: &ZoneConsensus<FullStateMachine>) {
    assert!(node
        .with_state_machine(|state| state.replica_control_activation().unwrap())
        .await
        .is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_configured_learners_prepare_but_unconfigured_routes_do_not() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let first = RunningNode::start(1, node_tls(&ca, &key, 1)).await;
    let second = RunningNode::start(2, node_tls(&ca, &key, 2)).await;
    let third = RunningNode::start(3, node_tls(&ca, &key, 3)).await;
    let zone = "member-preparation";
    let mut node = leader(&first, zone, &[2, 3]).await;
    let second_node = second
        .registry
        .create_zone(zone, &tokio::runtime::Handle::current())
        .unwrap();
    let third_node = third
        .registry
        .create_zone(zone, &tokio::runtime::Handle::current())
        .unwrap();
    let pool = pool(node_tls(&ca, &key, 1));
    // A stale nonmember route is deliberately unreachable. Qualifying the
    // routing table instead of the actual Raft configuration would fail here.
    node.set_forward_ctx(
        pool.clone(),
        routes(
            1,
            &[
                (2, 2, &second.address),
                (3, 3, &third.address),
                (99, 99, "127.0.0.1:1"),
            ],
        ),
        zone.into(),
    );
    let before = node.last_index();
    let prepared = node.prepare_replica_control_members().await.unwrap();
    assert_eq!(prepared.member_ids(), vec![1, 2, 3]);
    assert_eq!(pool.connection_count().await, 2);
    assert_eq!(node.last_index(), before);
    for current in [&node, &second_node, &third_node] {
        no_activation(current).await;
    }
    drop((node, second_node, third_node, pool));
    for server in [first, second, third] {
        let directory = server.stop().await;
        let storage = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match nexus_raft::raft::RaftStorage::open(directory.path().join(zone).join("raft"))
                {
                    Ok(storage) => break storage,
                    Err(error) => {
                        assert!(error.to_string().contains("already open"), "{error}");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert!(storage.replica_control_reader_required().unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_identity_controls_dial_even_when_route_carries_another_node_id() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let first = RunningNode::start(1, node_tls(&ca, &key, 1)).await;
    let second = RunningNode::start(2, node_tls(&ca, &key, 2)).await;
    let third = RunningNode::start(3, node_tls(&ca, &key, 3)).await;
    let zone = "identity-preparation";
    let mut node = leader(&first, zone, &[2]).await;
    second
        .registry
        .create_zone(zone, &tokio::runtime::Handle::current())
        .unwrap();
    third
        .registry
        .create_zone(zone, &tokio::runtime::Handle::current())
        .unwrap();
    let pool = pool(node_tls(&ca, &key, 1));
    let peers = routes(1, &[(2, 3, &third.address)]);
    node.set_forward_ctx(pool.clone(), peers.clone(), zone.into());
    let error = node.prepare_replica_control_members().await.unwrap_err();
    // The actual TLS refusal must retain the Node identity cause; a timeout
    // cannot qualify this identity counterexample.
    let ReplicaPreparationError::Member { member, error } = error else {
        panic!("expected the original authenticated member refusal: {error:?}");
    };
    assert_eq!(member, 2);
    assert_peer_refusal(
        &error,
        PeerRefusal::Identity("server certificate does not name the expected replication peer"),
    );
    peers
        .write()
        .unwrap()
        .observe(2, NodeAddress::new(2, format!("http://{}", second.address)));
    assert_eq!(
        node.prepare_replica_control_members()
            .await
            .unwrap()
            .member_ids(),
        vec![1, 2]
    );
    no_activation(&node).await;
    drop((node, pool, peers));
    first.stop().await;
    second.stop().await;
    third.stop().await;
}
