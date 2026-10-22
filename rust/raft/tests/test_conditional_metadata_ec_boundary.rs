//! Exercise the EC boundaries above the state machine: local WAL admission
//! and the real replication RPC must agree on the fixed managed-key policy.
#![cfg(all(feature = "grpc", has_protos))]

mod common;

use nexus_raft::prelude::Command;
use nexus_raft::transport::proto::EcReplicationEntry;
use nexus_raft::transport::{ClientConfig, RaftClient};
use nexus_raft::ZoneManager;
use std::time::Duration;
use tempfile::TempDir;

const ZONE: &str = "conditional-ec-boundary";
const MANAGED: &str = "/__managed_content_v1__/reader";

fn protected_commands() -> Vec<Command> {
    vec![
        Command::SetMetadata {
            key: MANAGED.into(),
            value: b"uncommitted image".to_vec(),
        },
        Command::PutControlState {
            namespace: "content-version-v1".into(),
            key: "allocator".into(),
            value: vec![0; 24],
            if_absent: false,
        },
        Command::AdjustCounter {
            key: MANAGED.into(),
            delta: 1,
        },
    ]
}

fn entry(seq: u64, command: Command) -> EcReplicationEntry {
    EcReplicationEntry {
        seq,
        command: bincode::serialize(&command).unwrap(),
        timestamp: 1,
        node_id: 2,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_ec_is_refused_before_wal_and_acknowledged_without_blocking_replication() {
    let dir = TempDir::new().unwrap();
    let bind = common::node_bind_addr();
    let manager = ZoneManager::with_node_id(
        "conditional-ec-fixture",
        1,
        dir.path().to_str().unwrap(),
        vec![],
        &bind,
        None,
        Some(format!("http://{bind}")),
        None,
    )
    .unwrap();
    let zone = manager
        .create_zone(ZONE, vec![format!("1@{bind}")])
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !zone.is_leader() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("isolated one-voter fixture must elect itself");
    let node = zone.consensus_node();
    let before = node.ec_wal_bounds().expect("full node has an EC WAL").1;
    for command in protected_commands() {
        assert!(node.propose_ec_local(command).await.is_err());
        assert_eq!(
            node.ec_wal_bounds().unwrap().1,
            before,
            "refusal must precede WAL append"
        );
    }

    let mut client = RaftClient::connect(&format!("http://{bind}"), ClientConfig::default())
        .await
        .unwrap();
    let mut entries: Vec<_> = protected_commands()
        .into_iter()
        .enumerate()
        .map(|(i, command)| entry(100 + i as u64, command))
        .collect();
    entries.push(entry(
        103,
        Command::SetMetadata {
            key: "/ordinary/ec-after-skips".into(),
            value: b"replicated".to_vec(),
        },
    ));
    entries.push(entry(104, protected_commands().remove(0)));
    assert_eq!(
        client
            .replicate_entries(ZONE.into(), entries, 2)
            .await
            .unwrap(),
        104
    );

    // Anti-entropy uses the same receiver boundary. It must also acknowledge
    // protected images while retaining unrelated entries in the snapshot.
    let snapshot = vec![
        entry(0, protected_commands().remove(0)),
        entry(
            0,
            Command::SetMetadata {
                key: "/ordinary/snapshot-after-skip".into(),
                value: b"snapshot".to_vec(),
            },
        ),
    ];
    assert_eq!(
        client
            .snapshot_ec_state(ZONE.into(), snapshot, 105, 2)
            .await
            .unwrap(),
        105
    );
    node.with_state_machine(|sm| {
        assert_eq!(sm.get_metadata(MANAGED).unwrap(), None);
        assert_eq!(
            sm.get_control_state("content-version-v1", "allocator")
                .unwrap(),
            None
        );
        assert_eq!(
            sm.get_metadata("/ordinary/ec-after-skips").unwrap(),
            Some(b"replicated".to_vec())
        );
        assert_eq!(
            sm.get_metadata("/ordinary/snapshot-after-skip").unwrap(),
            Some(b"snapshot".to_vec())
        );
    })
    .await;
    drop(client);
    manager.shutdown();
}
