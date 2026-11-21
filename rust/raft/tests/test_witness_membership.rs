//! A witness never founds a zone and joins each of its boot zones on its own
//! (`WitnessZoneRegistry`): real witnesses and founders over gRPC.

#![cfg(all(feature = "grpc", has_protos))]

mod common;
#[path = "common/zone_cluster.rs"]
mod zone_cluster;

use std::time::Duration;

use raft::eraftpb::ConfChangeType;
use zone_cluster::*;

/// A zone no founder serves: its JoinZone never succeeds.
const UNSERVED: &str = "unserved";

fn sorted(mut ids: Vec<u64>) -> Vec<u64> {
    ids.sort_unstable();
    ids
}

/// A witness that opens a zone it does not hold — its seeds known, the case
/// that once bootstrapped a 1-voter ConfState of the witness alone — forms
/// no cluster of its own: no bootstrap entry, no ConfState, no leader. Once a
/// founder admits it, it holds the founder's ConfState (a self-bootstrapped
/// log would have kept its own index-1 entry and never named the founder)
/// and the two-voter zone commits with its ack.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_witness_never_founds_a_zone_and_joins_once_admitted() {
    let founder = Node::new();
    let witness = Witness::new();
    let running = witness.boot(&[&founder], &[]).await;
    let replica = running
        .registry
        .auto_join_zone(ZONE, &tokio::runtime::Handle::current())
        .expect("the witness opens a replica of a zone it does not hold");
    // Ten election timeouts: a witness that formed its own cluster would show it.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(replica.voters().is_empty(), "no ConfState of its own");
    assert_eq!(replica.last_index(), 0, "no bootstrap entry");
    assert_eq!(replica.leader_id(), None, "no leader");

    let founder_zm = found(&founder, Vec::new()).await;
    // The witness auto-invite: AddNode carrying the witness's address.
    consensus(&founder_zm)
        .propose_conf_change(
            ConfChangeType::AddNode,
            witness.id,
            witness.bind.clone().into_bytes(),
        )
        .await
        .expect("AddNode(witness) commits");
    eventually("the witness to hold the founder's ConfState", || async {
        sorted(replica.voters()) == sorted(vec![founder.id, witness.id])
            && replica.leader_id() == Some(founder.id)
    })
    .await;
    write(&founder_zm, "/after-admission").await;

    running.stop().await;
    stop(founder_zm).await;
}

/// Boot zones join independently: a witness holding `ZONE` on disk boots
/// with a zone no leader serves listed first, and still resumes `ZONE` at
/// once — voting and acking in its founder's two-voter zone — while the
/// unserved zone's join keeps retrying on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_boot_zone_without_a_leader_does_not_delay_another() {
    let founder = Node::new();
    let witness = Witness::new();
    let founder_zm = found(&founder, Vec::new()).await;
    let first = witness.boot(&[&founder], &[ZONE]).await;
    eventually("the witness to join as a voter", || async {
        sorted(consensus(&founder_zm).voters()) == sorted(vec![founder.id, witness.id])
            && first.follows(founder.id)
    })
    .await;
    first.stop().await;

    let booted = witness.boot(&[&founder], &[UNSERVED, ZONE]).await;
    eventually("the held zone to resume", || async {
        booted.follows(founder.id)
    })
    .await;
    write(&founder_zm, "/after-resume").await;
    assert!(
        booted.zone(UNSERVED).is_none(),
        "no leader admitted the unserved zone"
    );
    assert!(
        !booted.boot[0].is_finished(),
        "the unserved zone's join is still retrying"
    );

    booted.stop().await;
    stop(founder_zm).await;
}

/// Upgrade the existing single voter and learner, then exercise each of the
/// three two-member quorums with real writes. Finally restore the original
/// membership through the same JoinZone and RemoveVoter endpoints.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_data_nodes_and_a_witness_survive_each_single_loss_and_roll_back() {
    use nexus_raft::transport::{call_join_zone_rpc, call_remove_voter_rpc};

    let founder = Node::new();
    let peer = Node::new();
    let witness = Witness::new();
    let founder_manager = found(&founder, Vec::new()).await;
    let peer_manager = peer.start(vec![founder.endpoint()]).await;
    join_as_learner(&peer_manager, &peer, &founder, &peer.bind).await;
    write(&founder_manager, "/before-promotion").await;
    eventually("the learner to apply the first write", || {
        has_key(&peer_manager, "/before-promotion")
    })
    .await;

    let running_witness = witness.boot(&[&founder, &peer], &[ZONE]).await;
    eventually("the witness to join the original voter", || async {
        sorted(consensus(&founder_manager).voters()) == sorted(vec![founder.id, witness.id])
            && running_witness.follows(founder.id)
    })
    .await;
    eventually("the caught-up learner to promote via JoinZone", || async {
        let join = call_join_zone_rpc(
            &founder.endpoint(),
            ZONE,
            peer.id,
            &peer.bind,
            false,
            None,
            5,
        )
        .await
        .expect("call JoinZone");
        assert!(
            join.success || join.catching_up,
            "JoinZone: {:?}",
            join.error
        );
        join.success
    })
    .await;
    let voters = sorted(vec![founder.id, peer.id, witness.id]);
    eventually("all three to agree on the voting membership", || async {
        sorted(consensus(&founder_manager).voters()) == voters
            && sorted(consensus(&peer_manager).voters()) == voters
            && running_witness
                .zone(ZONE)
                .is_some_and(|z| sorted(z.voters()) == voters)
    })
    .await;

    running_witness.stop().await;
    write(&founder_manager, "/without-witness").await;
    eventually("both data nodes to apply without the witness", || {
        has_key(&peer_manager, "/without-witness")
    })
    .await;
    let running_witness = witness.boot(&[&founder, &peer], &[ZONE]).await;
    eventually("the witness to rejoin", || async {
        running_witness.follows(founder.id)
    })
    .await;

    stop(founder_manager).await;
    await_leader(&peer_manager, peer.id).await;
    write(&peer_manager, "/without-founder").await;
    let founder_manager = restart_member(&founder, vec![peer.endpoint()]).await;
    eventually("the founder to recover the peer's write", || {
        has_key(&founder_manager, "/without-founder")
    })
    .await;

    stop(peer_manager).await;
    await_leader(&founder_manager, founder.id).await;
    write(&founder_manager, "/without-peer").await;
    let peer_manager = restart_member(&peer, vec![founder.endpoint()]).await;
    eventually("the peer to recover the founder's write", || {
        has_key(&peer_manager, "/without-peer")
    })
    .await;

    // Roll back one member at a time while both data nodes can acknowledge.
    running_witness.stop().await;
    for id in [witness.id, peer.id] {
        let removed = call_remove_voter_rpc(&founder.endpoint(), ZONE, id, None, 5)
            .await
            .expect("call RemoveVoter");
        assert!(removed.success, "RemoveVoter({id}): {:?}", removed.error);
    }
    let joined = call_join_zone_rpc(
        &founder.endpoint(),
        ZONE,
        peer.id,
        &peer.bind,
        true,
        None,
        5,
    )
    .await
    .expect("restore learner");
    assert!(joined.success, "JoinZone(learner): {:?}", joined.error);
    write(&founder_manager, "/after-rollback").await;
    eventually("the original learner to apply after rollback", || {
        has_key(&peer_manager, "/after-rollback")
    })
    .await;
    let config = cluster_info(&founder.endpoint())
        .await
        .config
        .expect("founder membership");
    assert_eq!(
        config.voters.iter().map(|n| n.id).collect::<Vec<_>>(),
        vec![founder.id]
    );
    assert_eq!(
        config.learners.iter().map(|n| n.id).collect::<Vec<_>>(),
        vec![peer.id]
    );
    stop(peer_manager).await;
    stop(founder_manager).await;
}

/// A named-zone witness can restart an existing root store, but does not
/// request a vote in any seed's node-local root, even if listed at boot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_witness_only_resumes_root_from_its_own_disk() {
    let root = contracts::ROOT_ZONE_ID;
    let founder = Node::new();
    let witness = Witness::new();
    let manager = found(&founder, Vec::new()).await;
    let private_root = manager
        .create_zone(root)
        .expect("create private root")
        .consensus_node();

    let fresh = witness.boot(&[&founder], &[root, ZONE]).await;
    assert_eq!(fresh.boot.len(), 1);
    eventually("the named zone to have both voters", || async {
        sorted(consensus(&manager).voters()) == sorted(vec![founder.id, witness.id])
            && fresh.follows(founder.id)
    })
    .await;
    assert!(fresh.zone(root).is_none());
    assert_eq!(private_root.voters(), vec![founder.id]);

    // Represent an installation with root storage already on disk. Opening
    // that store on restart must not request membership from a seed.
    fresh
        .registry
        .auto_join_zone(root, &tokio::runtime::Handle::current())
        .expect("initialize the local legacy store");
    fresh.stop().await;
    let resumed = witness.boot(&[&founder], &[ZONE]).await;
    assert_eq!(resumed.boot.len(), 1);
    assert!(resumed.zone(root).is_some());
    eventually("named zone to resume after restart", || async {
        resumed.follows(founder.id)
    })
    .await;
    assert_eq!(private_root.voters(), vec![founder.id]);

    resumed.stop().await;
    stop(manager).await;
}
