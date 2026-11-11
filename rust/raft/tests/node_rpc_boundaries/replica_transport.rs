//! Real transport exchanges bind the required dialect to durable reader state.

use super::reader_preparation::{node_tls, pool, reopened};
use super::*;
use nexus_raft::transport::{NodeAddress, TransportError};

fn heartbeat(from: u64, to: u64) -> Vec<u8> {
    let mut message = raft::eraftpb::Message::default();
    message.set_msg_type(raft::eraftpb::MessageType::MsgHeartbeat);
    message.from = from;
    message.to = to;
    message.term = 1;
    message.write_to_bytes().unwrap()
}

fn assert_legacy_refusal(error: TransportError) {
    assert!(
        matches!(error, TransportError::Rpc(ref reason)
        if reason.contains("prepared reader requires replica-control transport")),
        "{error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn required_wire_prepares_full_node_and_refuses_both_legacy_methods() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let server = PeerServer::start(node_tls(&ca, &key, 7)).await;
    let clients = pool(node_tls(&ca, &key, 2));
    let address = NodeAddress::new(7, server.endpoint.clone());
    let mut general = clients.get(&address).await.unwrap();
    general
        .step_message(heartbeat(2, 7), "root".into(), String::new())
        .await
        .unwrap();
    let error = general
        .step_replica_control_v1(heartbeat(2, 7), "root".into(), String::new())
        .await
        .unwrap_err();
    assert!(matches!(error, TransportError::Connection(ref reason)
        if reason.contains("exact cluster Node channel")));
    let mut control = clients.get_node(&address).await.unwrap();
    control
        .step_replica_control_v1(heartbeat(2, 7), "root".into(), String::new())
        .await
        .unwrap();
    assert_legacy_refusal(
        general
            .step_message(heartbeat(2, 7), "root".into(), String::new())
            .await
            .unwrap_err(),
    );
    assert_legacy_refusal(
        general
            .step_storage_v1(heartbeat(2, 7), "root".into(), String::new())
            .await
            .unwrap_err(),
    );
    control
        .step_replica_control_v1(heartbeat(2, 7), "root".into(), String::new())
        .await
        .unwrap();
    assert!(server
        .registry
        .get_node("root")
        .unwrap()
        .with_state_machine(
            |state| nexus_raft::raft::StateMachine::replica_control_activation(state).unwrap()
        )
        .await
        .is_none());
    drop(general);
    drop(control);
    drop(clients);
    let directory = server.shutdown_preserving_storage().await;
    assert!(reopened(directory.path())
        .await
        .replica_control_reader_required()
        .unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn required_wire_refuses_replica_and_agent_before_unknown_zone_creation() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let server = PeerServer::start(node_tls(&ca, &key, 7)).await;
    let address = server.endpoint.strip_prefix("http://").unwrap();
    for (cert, key) in [
        generate_agent_cert("ordinary", &ca, &key).unwrap(),
        generate_user_replica_cert("replica", "alice", 2, 300, &ca, &key).unwrap(),
    ] {
        let mut client = ZoneTransportServiceClient::new(connect(address, &ca, cert, key).await);
        for zone in ["root", "unopened"] {
            let error = client
                .step_replica_control_v1(StepMessageRequest {
                    zone_id: zone.into(),
                    message: heartbeat(2, 7),
                    sender_address: String::new(),
                })
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::PermissionDenied);
        }
    }
    assert!(server.registry.get_node("unopened").is_none());
    let directory = server.shutdown_preserving_storage().await;
    assert!(!reopened(directory.path())
        .await
        .replica_control_reader_required()
        .unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn required_wire_prepares_witness_and_refuses_legacy_traffic() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let tls = node_tls(&ca, &key, 7);
    let directory = tempfile::tempdir().unwrap();
    let registry = Arc::new(WitnessZoneRegistry::new(
        directory.path().to_path_buf(),
        7,
        Some(tls.clone()),
    ));
    let node = registry
        .create_zone("root", Vec::new(), &tokio::runtime::Handle::current())
        .unwrap();
    let address = common::node_bind_addr();
    let server = RaftWitnessServer::new(
        registry.clone(),
        ServerConfig {
            bind_address: address.parse().unwrap(),
            tls: Some(tls),
            ..Default::default()
        },
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        server
            .serve_with_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    listener_ready(&address).await;
    let clients = pool(node_tls(&ca, &key, 2));
    let mut control = clients
        .get_node(&NodeAddress::new(7, format!("http://{address}")))
        .await
        .unwrap();
    control
        .step_replica_control_v1(heartbeat(2, 7), "root".into(), String::new())
        .await
        .unwrap();
    assert_legacy_refusal(
        control
            .step_message(heartbeat(2, 7), "root".into(), String::new())
            .await
            .unwrap_err(),
    );
    assert!(!node.is_leader());
    drop(control);
    drop(clients);
    stop.send(()).unwrap();
    task.await.unwrap();
    registry.shutdown_all();
    drop(node);
    drop(registry);
    assert!(reopened(directory.path())
        .await
        .replica_control_reader_required()
        .unwrap());
}

struct RunningNode {
    directory: tempfile::TempDir,
    registry: Arc<ZoneRaftRegistry>,
    address: String,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl RunningNode {
    async fn start(id: u64, tls: TlsConfig) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let registry = Arc::new(ZoneRaftRegistry::with_tls(
            directory.path().to_path_buf(),
            id,
            Some(tls.clone()),
        ));
        registry
            .create_zone("root", &tokio::runtime::Handle::current())
            .unwrap()
            .campaign()
            .await
            .unwrap();
        let address = common::node_bind_addr();
        registry.set_self_address(address.clone());
        let server = RaftGrpcServer::new(
            registry.clone(),
            ServerConfig {
                bind_address: address.parse().unwrap(),
                tls: Some(tls),
                ..Default::default()
            },
        );
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .serve_with_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        listener_ready(&address).await;
        Self {
            directory,
            registry,
            address,
            stop,
            task,
        }
    }

    async fn stop(self) -> tempfile::TempDir {
        self.stop.send(()).unwrap();
        self.task.await.unwrap();
        self.registry.shutdown_all();
        drop(self.registry);
        self.directory
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_transport_loop_uses_required_wire_for_new_learner_and_replication() {
    let (ca, key) = generate_zone_ca("root").unwrap();
    let first = RunningNode::start(1, node_tls(&ca, &key, 1)).await;
    let second = RunningNode::start(2, node_tls(&ca, &key, 2)).await;
    let zone = "required-wire";
    let leader = first
        .registry
        .create_zone(zone, &tokio::runtime::Handle::current())
        .unwrap();
    leader.campaign().await.unwrap();
    leader.prepare_replica_control_reader().await.unwrap();
    // Only the original leader has prepared. The actual production send loop
    // must select the new RPC and its receiver must prepare the new learner.
    leader
        .propose_conf_change(raft::eraftpb::ConfChangeType::AddLearnerNode, 2, Vec::new())
        .await
        .unwrap();
    assert!(first.registry.learn_peer_address(zone, 2, &second.address));
    let value = b"replicated through required transport".to_vec();
    leader
        .propose(Command::SetMetadata {
            key: "/wire-control".into(),
            value: value.clone(),
        })
        .await
        .unwrap();
    let learner = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(node) = second.registry.get_node(zone) {
                if node
                    .with_state_machine(|state| state.get_metadata("/wire-control"))
                    .await
                    .unwrap()
                    == Some(value.clone())
                {
                    break node;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("real transport must replicate ordinary data through the required method");
    // A genuine same-zone ReadIndex roundtrip requires the follower's outgoing
    // transport to use the required method as well.
    assert_eq!(
        learner
            .read_linearizable(|state| state.get_metadata("/wire-control"))
            .await
            .unwrap()
            .unwrap(),
        Some(value)
    );
    let clients = pool(node_tls(&ca, &key, 1));
    let mut legacy = clients
        .get(&NodeAddress::new(2, format!("http://{}", second.address)))
        .await
        .unwrap();
    assert_legacy_refusal(
        legacy
            .step_message(heartbeat(1, 2), zone.into(), String::new())
            .await
            .unwrap_err(),
    );
    assert!(learner
        .with_state_machine(
            |state| nexus_raft::raft::StateMachine::replica_control_activation(state).unwrap()
        )
        .await
        .is_none());
    drop(legacy);
    drop(clients);
    drop(learner);
    drop(leader);
    let first_directory = first.stop().await;
    let second_directory = second.stop().await;
    for directory in [first_directory, second_directory] {
        let store = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match nexus_raft::raft::RaftStorage::open(directory.path().join(zone).join("raft"))
                {
                    Ok(store) => break store,
                    Err(error) => {
                        assert!(error.to_string().contains("already open"), "{error}");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert!(store.replica_control_reader_required().unwrap());
        assert!(store
            .initial_state_impl()
            .unwrap()
            .conf_state
            .learners
            .contains(&2));
    }
}
