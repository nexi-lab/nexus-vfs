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
    quiescent(&node).await;
    node
}

/// What the zone has written on its own: term, last index and member-address records.
async fn log_state(node: &ZoneConsensus<FullStateMachine>) -> String {
    let records = node
        .with_state_machine(|state| state.member_addresses().unwrap())
        .await;
    format!(
        "term {}, last index {}, applied {}, member addresses {records:?}",
        node.term(),
        node.last_index(),
        node.applied_index()
    )
}

/// Wait until the zone has stopped writing on its own. A zone created after
/// `set_self_address` registers this node's address in the background
/// (`register_member_address`), and its self-election can race the explicit
/// campaign; either can append an entry after a caller starts measuring the
/// log. Quiescent: leader, own address record applied, nothing unapplied, and
/// the term unchanged for longer than the election timeout (10 ticks of 10 ms,
/// randomized up to twice that).
async fn quiescent(node: &ZoneConsensus<FullStateMachine>) {
    let id = node.id();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut stable_since: Option<(u64, std::time::Instant)> = None;
    loop {
        let registered = node
            .with_state_machine(move |state| {
                state
                    .member_addresses()
                    .unwrap()
                    .is_some_and(|records| records.iter().any(|(member, _)| *member == id))
            })
            .await;
        let settled = node.is_leader() && registered && node.applied_index() >= node.last_index();
        let term = node.term();
        match stable_since {
            Some((seen, since)) if settled && seen == term => {
                if since.elapsed() >= std::time::Duration::from_millis(300) {
                    return;
                }
            }
            _ => stable_since = settled.then(|| (term, std::time::Instant::now())),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the zone did not settle: {}",
            log_state(node).await
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
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
    let state_before = log_state(&node).await;
    let prepared = node.prepare_replica_control_members().await.unwrap();
    assert_eq!(prepared.member_ids(), vec![1, 2, 3]);
    assert_eq!(pool.connection_count().await, 2);
    assert_eq!(
        node.last_index(),
        before,
        "preparation appended to the log: before {state_before}; after {}",
        log_state(&node).await
    );
    for current in [&node, &second_node, &third_node] {
        no_activation(current).await;
    }
    drop((node, second_node, third_node, pool));
    for server in [first, second, third] {
        let directory = server.stop().await;
        let storage =
            nexus_raft::raft::RaftStorage::open(directory.path().join(zone).join("raft")).unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn qualified_members_activate_and_replicate_native_identity_before_voter_promotion() {
    use contracts::node_identity::{NodeIdentity, NodeIdentityRequest};
    use nexus_raft::replica_binding_store::RaftReplicaBindingStore;

    let (ca, key) = generate_zone_ca("root").unwrap();
    let first = RunningNode::start(1, node_tls(&ca, &key, 1)).await;
    let second = RunningNode::start(2, node_tls(&ca, &key, 2)).await;
    let zone = "activated-members";
    let runtime = tokio::runtime::Handle::current();
    let peer = second.registry.join_zone(zone, false, &runtime).unwrap();
    let mut node = leader(&first, zone, &[2]).await;
    assert!(first.registry.learn_peer_address(zone, 2, &second.address));
    node.set_forward_ctx(
        pool(node_tls(&ca, &key, 1)),
        routes(1, &[(2, 2, &second.address)]),
        zone.into(),
    );
    let prepared = node.prepare_replica_control_members().await.unwrap();
    assert_eq!(prepared.member_ids(), vec![1, 2]);
    let active = node
        .activate_replica_control(prepared, "native-original".into())
        .await
        .unwrap();
    assert_eq!(active.operation_id, "native-original");

    let store = RaftReplicaBindingStore::new(node.clone(), runtime);
    tokio::task::spawn_blocking(move || {
        store
            .reserve_node(&NodeIdentityRequest {
                operation_id: "native-node".into(),
                identity: NodeIdentity {
                    node_id: 42,
                    subject_public_key_sha256: [7; 32],
                },
            })
            .unwrap();
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if node.membership().await.unwrap().is_caught_up_learner(2) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    node.propose_conf_change(raft::eraftpb::ConfChangeType::AddNode, 2, Vec::new())
        .await
        .unwrap();
    assert!(node.membership().await.unwrap().is_voter(2));
    let observed = tokio::time::timeout(
        Duration::from_secs(5),
        peer.read_linearizable(|state| state.replica_control_activation().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(observed, Some(active));
    let store = RaftReplicaBindingStore::new(peer.clone(), tokio::runtime::Handle::current());
    let identity = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || store.node_identity(42).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(identity.unwrap().subject_public_key_sha256, [7; 32]);
    drop((node, peer));
    first.stop().await;
    second.stop().await;
}
