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
