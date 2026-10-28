//! Real mTLS control-plane refusal, not an Agent/VFS mock. All CA keys and
//! consensus data are isolated; no fleet endpoint or model is used.
#![cfg(all(feature = "grpc", has_protos))]
mod common;

use lib::transport_primitives::{FederatedClientCertVerifier, ForeignCaAnchor};
use nexus_raft::transport::proto::{
    zone_api_service_client::ZoneApiServiceClient,
    zone_transport_service_client::ZoneTransportServiceClient, EcReplicationEntry,
    MintSessionAgentRequest, ProposeRequest, ReplicateEntriesRequest, SnapshotEcStateRequest,
    StepMessageRequest,
};
use nexus_raft::{
    prelude::Command,
    raft::ZoneRaftRegistry,
    transport::{
        generate_agent_cert, generate_node_cert, generate_zone_ca, RaftGrpcServer,
        RaftWitnessServer, ServerConfig, TlsConfig, WitnessZoneRegistry,
    },
};
use protobuf::Message as _;
use std::{sync::Arc, time::Duration};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

async fn connect(address: &str, ca: &[u8], cert: Vec<u8>, key: Vec<u8>) -> Channel {
    Endpoint::from_shared(format!("https://{address}"))
        .unwrap()
        .timeout(Duration::from_secs(5))
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(Certificate::from_pem(ca))
                .identity(Identity::from_pem(cert, key)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap()
}

async fn listener_ready(address: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("isolated listener must bind");
}
fn put(key: &str) -> ProposeRequest {
    ProposeRequest {
        zone_id: "root".into(),
        request_id: format!("isolated-{key}"),
        command: None,
        forwarded: false,
        raw_command: bincode::serialize(&Command::PutControlState {
            namespace: "node-boundary-fixture".into(),
            key: key.into(),
            value: b"private fixture value".to_vec(),
            if_absent: true,
        })
        .unwrap(),
    }
}

fn metadata_entry(path: &str) -> EcReplicationEntry {
    EcReplicationEntry {
        seq: 1,
        command: bincode::serialize(&Command::SetMetadata {
            key: path.into(),
            value: br#"{"fixture":"node sender boundary"}"#.to_vec(),
        })
        .unwrap(),
        timestamp: 1,
        node_id: 2,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agents_and_foreign_nodes_cannot_propose_or_step_but_local_nodes_can() {
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (foreign, foreign_key) = generate_zone_ca("root").unwrap();
    let (server_cert, server_key) = generate_node_cert(1, "root", &ca, &ca_key, &[], None).unwrap();
    let verifier = FederatedClientCertVerifier::new(&ca).unwrap();
    verifier
        .set_foreign_cas(&[ForeignCaAnchor::from_pem("edge", &foreign).unwrap()])
        .unwrap();
    let private = tempfile::tempdir().unwrap();
    let registry = Arc::new(ZoneRaftRegistry::new(private.path().to_path_buf(), 1));
    let node = registry
        .create_zone("root", vec![], &tokio::runtime::Handle::current())
        .unwrap();
    node.campaign().await.unwrap();
    let address = common::node_bind_addr();
    let server = RaftGrpcServer::new(
        registry.clone(),
        ServerConfig {
            bind_address: address.parse().unwrap(),
            tls: Some(TlsConfig {
                ca_pem: ca.clone(),
                cert_pem: server_cert,
                key_pem: server_key,
            }),
            ..ServerConfig::default()
        },
    )
    .with_foreign_ca_verifier(Some(verifier));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        server
            .serve_with_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap()
    });
    // Readiness only, before any data submission. No RPC/write is retried.
    listener_ready(&address).await;

    let (node_cert, node_key) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let channel = connect(&address, &ca, node_cert, node_key).await;
    let mut local = ZoneApiServiceClient::new(channel.clone());
    assert!(
        local
            .propose(put("local-node"))
            .await
            .unwrap()
            .into_inner()
            .success
    );
    let stored = node
        .read_linearizable(|sm| sm.get_control_state("node-boundary-fixture", "local-node"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored, Some(b"private fixture value".to_vec()));
    drop(local);

    let mut transport = ZoneTransportServiceClient::new(channel);
    let mut message = raft::eraftpb::Message::default();
    message.set_msg_type(raft::eraftpb::MessageType::MsgHeartbeatResponse);
    message.set_from(7);
    message.set_to(1);
    message.set_term(1);
    let step = transport
        .step_message(StepMessageRequest {
            message: message.write_to_bytes().unwrap(),
            zone_id: "root".into(),
            sender_address: "127.0.0.1:19999".into(),
        })
        .await;
    let incremental = transport
        .replicate_entries(ReplicateEntriesRequest {
            zone_id: "root".into(),
            entries: vec![metadata_entry("/forged-incremental")],
            sender_node_id: 7,
        })
        .await;
    let snapshot = transport
        .snapshot_ec_state(SnapshotEcStateRequest {
            zone_id: "root".into(),
            entries: vec![metadata_entry("/forged-snapshot")],
            covering_seq: 73,
            sender_node_id: 7,
        })
        .await;
    let outcomes = [
        step.map(|_| ()),
        incremental.map(|_| ()),
        snapshot.map(|_| ()),
    ];
    assert!(
        outcomes.iter().all(
            |result| matches!(result, Err(status) if status.code() == tonic::Code::PermissionDenied)
        ),
        "Node 2 must not submit Raft or EC as Node 7: {outcomes:?}"
    );
    assert!(
        !registry.get_peers("root").unwrap().contains_key(&7),
        "refusal must precede learning the forged sender address"
    );
    for path in ["/forged-incremental", "/forged-snapshot"] {
        assert_eq!(
            node.read_linearizable(|sm| sm.get_metadata(path))
                .await
                .unwrap()
                .unwrap(),
            None,
            "refusal must precede applying metadata"
        );
    }

    let unopened_zone = "forged-unopened-zone";
    assert!(registry.get_node(unopened_zone).is_none());
    let refusal = transport
        .step_message(StepMessageRequest {
            message: message.write_to_bytes().unwrap(),
            zone_id: unopened_zone.into(),
            sender_address: "127.0.0.1:19999".into(),
        })
        .await
        .expect_err("sender refusal must precede zone auto-join");
    assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
    assert!(registry.get_node(unopened_zone).is_none());
    assert!(!private.path().join(unopened_zone).exists());

    message.set_from(2);
    transport
        .step_message(StepMessageRequest {
            message: message.write_to_bytes().unwrap(),
            zone_id: "root".into(),
            sender_address: "127.0.0.1:19998".into(),
        })
        .await
        .unwrap();
    assert!(registry.get_peers("root").unwrap().contains_key(&2));
    assert!(
        transport
            .replicate_entries(ReplicateEntriesRequest {
                zone_id: "root".into(),
                entries: vec![metadata_entry("/accepted-incremental")],
                sender_node_id: 2,
            })
            .await
            .unwrap()
            .into_inner()
            .success
    );
    assert_eq!(
        transport
            .snapshot_ec_state(SnapshotEcStateRequest {
                zone_id: "root".into(),
                entries: vec![metadata_entry("/accepted-snapshot")],
                covering_seq: 74,
                sender_node_id: 2,
            })
            .await
            .unwrap()
            .into_inner()
            .acked_up_to,
        74
    );
    for path in ["/accepted-incremental", "/accepted-snapshot"] {
        assert_eq!(
            node.read_linearizable(|sm| sm.get_metadata(path))
                .await
                .unwrap()
                .unwrap(),
            Some(br#"{"fixture":"node sender boundary"}"#.to_vec())
        );
    }

    // Exercise raft-rs itself: a follower relays these requests with the
    // original caller's `from`, rather than its own connection identity.
    for message_type in [
        raft::eraftpb::MessageType::MsgPropose,
        raft::eraftpb::MessageType::MsgReadIndex,
        raft::eraftpb::MessageType::MsgTransferLeader,
    ] {
        let storage = raft::storage::MemStorage::new_with_conf_state((vec![1, 2, 3], vec![]));
        let mut follower = raft::RawNode::new(
            &raft::Config {
                id: 2,
                ..raft::Config::default()
            },
            storage,
            &slog::Logger::root(slog::Discard, slog::o!()),
        )
        .unwrap();
        follower.raft.become_follower(1, 1);
        let mut request = raft::eraftpb::Message::default();
        request.set_msg_type(message_type);
        request.set_from(3);
        request.set_to(2);
        let mut entry = raft::eraftpb::Entry::default();
        let mut data = (u64::MAX - 1).to_be_bytes().to_vec();
        data.extend(put("relayed-proposal").raw_command);
        entry.set_data(data.into());
        request.mut_entries().push(entry);
        follower.step(request).unwrap();
        let forwarded = follower
            .raft
            .msgs
            .iter()
            .find(|m| m.get_msg_type() == message_type)
            .expect("the actual follower must forward this request");
        assert_eq!((forwarded.from, forwarded.to), (3, 1));
        transport
            .step_message(StepMessageRequest {
                message: forwarded.write_to_bytes().unwrap(),
                zone_id: "root".into(),
                sender_address: "127.0.0.1:19998".into(),
            })
            .await
            .expect("a follower must preserve the original request sender");
        assert!(
            !registry.get_peers("root").unwrap().contains_key(&3),
            "the forwarder's address must not be assigned to the logical origin"
        );
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let stored = node
            .read_linearizable(|sm| {
                sm.get_control_state("node-boundary-fixture", "relayed-proposal")
            })
            .await
            .unwrap()
            .unwrap();
        if stored == Some(b"private fixture value".to_vec()) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the relayed proposal must commit"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let domestic = generate_agent_cert("domestic-agent", &ca, &ca_key).unwrap();
    let foreign_agent = generate_agent_cert("foreign-agent", &foreign, &foreign_key).unwrap();
    let foreign_node = generate_node_cert(2, "root", &foreign, &foreign_key, &[], None).unwrap();
    for (label, (cert, key)) in [
        ("domestic-agent", domestic),
        ("foreign-agent", foreign_agent),
        ("foreign-node", foreign_node),
    ] {
        let channel = connect(&address, &ca, cert, key).await;
        let mut api = ZoneApiServiceClient::new(channel.clone());
        let refusal = api
            .propose(put(label))
            .await
            .expect_err("Agent or foreign Node reached the Node-only Propose RPC");
        assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
        let stored = node
            .read_linearizable(|sm| sm.get_control_state("node-boundary-fixture", label))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, None, "refusal must precede control-state mutation");
        let mut transport = ZoneTransportServiceClient::new(channel);
        let refusal = transport
            .step_message(StepMessageRequest {
                message: vec![0xff],
                zone_id: "root".into(),
                sender_address: String::new(),
            })
            .await
            .expect_err("unprivileged peer reached Raft message parsing");
        assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
        if label != "foreign-node" {
            // This allowed door still reaches its own issuer gate. An empty
            // minter slot refuses minting; RPC acceptance confers no credential.
            let reply = api
                .mint_session_agent(MintSessionAgentRequest {
                    owner_id: "owner".into(),
                    validity_secs: 300,
                })
                .await
                .unwrap()
                .into_inner();
            assert!(!reply.success);
        }
    }
    stop.send(()).unwrap();
    running.await.unwrap();
    drop(node);
    registry.shutdown_all();
    drop(registry);
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn witness_checks_the_authenticated_sender_before_auto_join() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let (cert_pem, key_pem) = generate_node_cert(1, "root", &ca, &key, &[], None).unwrap();
    let tls = TlsConfig {
        ca_pem: ca.clone(),
        cert_pem,
        key_pem,
    };
    let private = tempfile::tempdir().unwrap();
    let registry = Arc::new(WitnessZoneRegistry::new(
        private.path().to_path_buf(),
        1,
        Some(tls.clone()),
    ));
    let address = common::node_bind_addr();
    let server = RaftWitnessServer::new(
        registry.clone(),
        ServerConfig {
            bind_address: address.parse().unwrap(),
            tls: Some(tls),
            ..ServerConfig::default()
        },
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        server
            .serve_with_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    listener_ready(&address).await;
    let (cert, key) = generate_node_cert(2, "root", &ca, &key, &[], None).unwrap();
    let mut transport = ZoneTransportServiceClient::new(connect(&address, &ca, cert, key).await);
    let mut message = raft::eraftpb::Message::default();
    message.set_msg_type(raft::eraftpb::MessageType::MsgHeartbeatResponse);
    message.set_from(7);
    message.set_to(1);
    message.set_term(1);
    let refused_zone = "forged-witness-zone";
    let refusal = transport
        .step_message(StepMessageRequest {
            message: message.write_to_bytes().unwrap(),
            zone_id: refused_zone.into(),
            sender_address: "127.0.0.1:19999".into(),
        })
        .await
        .expect_err("Node 2 must not auto-join a witness as Node 7");
    assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
    assert!(registry.get_node(refused_zone).is_none());
    assert!(!private.path().join(refused_zone).exists());
    message.set_from(2);
    let accepted_zone = "accepted-witness-zone";
    transport
        .step_message(StepMessageRequest {
            message: message.write_to_bytes().unwrap(),
            zone_id: accepted_zone.into(),
            sender_address: "127.0.0.1:19998".into(),
        })
        .await
        .unwrap();
    assert!(registry.get_node(accepted_zone).is_some());
    stop.send(()).unwrap();
    running.await.unwrap();
    registry.shutdown_all();
    drop(registry);
    tokio::time::sleep(Duration::from_millis(500)).await;
}
