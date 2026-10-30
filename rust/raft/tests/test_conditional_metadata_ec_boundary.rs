//! Exercise the EC boundaries above the state machine: local WAL admission
//! and the real replication RPC must agree on the fixed managed-key policy.
#![cfg(all(feature = "grpc", has_protos))]

mod common;

use nexus_raft::prelude::Command;
use nexus_raft::transport::proto::{
    zone_api_service_client::ZoneApiServiceClient, EcReplicationEntry, ProposeRequest,
};
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
    node.read_linearizable(|_| ()).await.unwrap();
    let log_before = node.last_index();
    // Deferred lookup offers the operation without materializing a zone. Each
    // first operation must still reject an unqualified managed node itself.
    for protect in [false, true] {
        let store = nexus_raft::zone_meta_store::ZoneMetaStore::deferred_arc(
            manager.registry(),
            ZONE,
            manager.runtime_handle(),
            "/state".into(),
            "/".into(),
        );
        let result = if protect {
            store
                .as_record_protection()
                .unwrap()
                .protect_record("/state/reader", &|_| {
                    panic!("unqualified managed node cannot qualify content")
                })
                .map(|_| ())
        } else {
            store
                .as_conditional_metadata()
                .unwrap()
                .read_versioned("/state/reader")
                .map(|_| ())
        };
        assert!(matches!(
            result,
            Err(kernel::meta_store::ConditionalMetadataError::Unsupported)
        ));
        assert!(store.as_conditional_metadata().is_none());
        assert!(store.as_record_protection().is_none());
    }
    assert_eq!(node.last_index(), log_before);
    let experimental = [
        Command::WriteVersionedMetadata {
            key: MANAGED.into(),
            value: b"not activated".to_vec(),
            expected: None,
            incarnation: [7; 16],
        },
        Command::AdoptProtectedMetadata {
            key: "/conversations/private/readers/owner".into(),
            expected_image: None,
            incarnation: [7; 16],
        },
        Command::RenameMetadata {
            old_key: "/conversations/private/readers/owner".into(),
            new_key: "/conversations/private/readers/other".into(),
            is_pas: false,
        },
    ];
    let mut api = ZoneApiServiceClient::connect(format!("http://{bind}"))
        .await
        .unwrap();
    for command in experimental {
        for forwarded in [false, true] {
            let refusal = api
                .propose(ProposeRequest {
                    command: None,
                    request_id: "unactivated-conditional-fixture".into(),
                    zone_id: ZONE.into(),
                    raw_command: bincode::serialize(&command).unwrap(),
                    forwarded,
                })
                .await
                .expect_err("raw RPC must refuse the experimental command before proposal");
            assert_eq!(refusal.code(), tonic::Code::Unimplemented);
        }
        assert!(
            node.propose(command).await.is_err(),
            "the local submission path must also reject unactivated commands"
        );
    }
    assert_eq!(
        node.last_index(),
        log_before,
        "no refused proposal may enter Raft"
    );
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
    drop(api);
    drop(client);
    manager.shutdown();
}
