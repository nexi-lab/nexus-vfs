//! Real zone members over gRPC for the raft integration tests: data nodes
//! (`ZoneManager`) and witnesses (`WitnessZoneRegistry` + `RaftWitnessServer`,
//! booted the way `nexus-witness` boots), sharing one zone.
//!
//! Included with `#[path]` by the binaries that run members, so the cheap
//! `common` module stays cheap for the rest.

#![allow(dead_code)] // each test binary uses a different subset

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nexus_raft::prelude::Command;
use nexus_raft::raft::{RaftStorage, StateMachine, WitnessStateMachine, ZoneConsensus};
use nexus_raft::transport::{
    call_join_zone_rpc, ClientConfig, NodeAddress, RaftApiClient, RaftWitnessServer, ServerConfig,
    WitnessZoneRegistry,
};
use nexus_raft::ZoneManager;
use raft::Storage;
use tempfile::TempDir;

pub const ZONE: &str = "sharedzone";
pub const BUDGET: Duration = Duration::from_secs(30);

fn random_node_id() -> u64 {
    loop {
        let id = rand::random::<u64>();
        if id != 0 {
            return id;
        }
    }
}

/// One node's durable identity: its id, data directory and advertise/bind
/// address. A restart reuses all three unless the test moves it on purpose.
pub struct Node {
    pub id: u64,
    pub dir: TempDir,
    pub bind: String,
}

impl Node {
    pub fn new() -> Self {
        let dir = TempDir::new().expect("node dir");
        let id = random_node_id();
        std::fs::write(dir.path().join(".node_id"), id.to_be_bytes()).expect("write .node_id");
        Self {
            id,
            dir,
            bind: crate::common::node_bind_addr(),
        }
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.bind)
    }

    pub fn raft_dir(&self) -> PathBuf {
        self.dir.path().join(ZONE).join("raft")
    }

    /// Start (or restart) this node. `seeds` are the operator `--peers`. A
    /// previous run released the data dir when its `shutdown` returned.
    pub async fn start(&self, seeds: Vec<String>) -> Arc<ZoneManager> {
        wait_until_bindable(&self.bind).await;
        ZoneManager::with_node_id(
            "zone-cluster",
            self.id,
            self.dir.path().to_str().expect("utf-8 dir"),
            seeds,
            &self.bind,
            None,
            Some(self.bind.clone()),
            None,
        )
        .unwrap_or_else(|error| panic!("start node {}: {error}", self.id))
    }
}

/// A witness voter's durable identity: its id, data directory and address.
pub struct Witness {
    pub id: u64,
    pub dir: TempDir,
    pub bind: String,
}

/// A running witness: its zone registry, gRPC server and boot joins.
pub struct RunningWitness {
    pub registry: Arc<WitnessZoneRegistry>,
    stop: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<()>,
    pub boot: Vec<tokio::task::JoinHandle<()>>,
}

impl Witness {
    pub fn new() -> Self {
        Self {
            id: random_node_id(),
            dir: TempDir::new().expect("witness dir"),
            bind: crate::common::node_bind_addr(),
        }
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.bind)
    }

    /// Boot the witness as `nexus-witness` does: advertising its address,
    /// with `seeds` as `NEXUS_PEERS`, joining `zones` at boot.
    pub async fn boot(&self, seeds: &[&Node], zones: &[&str]) -> RunningWitness {
        let mut registry = WitnessZoneRegistry::new(self.dir.path().to_path_buf(), self.id, None);
        registry.set_peers(
            seeds
                .iter()
                .map(|seed| NodeAddress::parse(&seed.bind, false).expect("seed address"))
                .collect(),
        );
        registry.set_self_address(self.endpoint());
        let mut running = self.serve(registry).await;
        running.boot = running.registry.join_at_boot(
            zones.iter().map(|zone| zone.to_string()).collect(),
            Duration::from_millis(200),
        );
        running
    }

    /// Serve the witness the way witnesses ran before they registered: no
    /// advertise address and no seeds. It joins `ZONE` when the leader's
    /// first message arrives and never registers its address.
    pub async fn start_unregistered(&self) -> RunningWitness {
        self.serve(WitnessZoneRegistry::new(
            self.dir.path().to_path_buf(),
            self.id,
            None,
        ))
        .await
    }

    async fn serve(&self, registry: WitnessZoneRegistry) -> RunningWitness {
        wait_until_bindable(&self.bind).await;
        let registry = Arc::new(registry);
        let server = RaftWitnessServer::new(
            registry.clone(),
            ServerConfig {
                bind_address: self.bind.parse().expect("witness bind"),
                ..Default::default()
            },
        );
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            server
                .serve_with_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .expect("witness server");
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while tokio::net::TcpStream::connect(&self.bind).await.is_err() {
            assert!(Instant::now() < deadline, "witness never listened");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        RunningWitness {
            registry,
            stop,
            server,
            boot: Vec::new(),
        }
    }
}

impl RunningWitness {
    /// This witness's open replica of `zone_id`.
    pub fn zone(&self, zone_id: &str) -> Option<ZoneConsensus<WitnessStateMachine>> {
        self.registry.get_node(zone_id)
    }

    pub fn follows(&self, leader: u64) -> bool {
        self.zone(ZONE)
            .is_some_and(|node| node.leader_id() == Some(leader))
    }

    /// Stop the witness. Its zones' stores are released when this returns.
    pub async fn stop(self) {
        let _ = self.stop.send(());
        self.server.await.expect("witness server task");
        self.registry.shutdown().released().await;
        for boot in self.boot {
            boot.await
                .expect("a boot join ends when the witness shuts down");
        }
    }
}

/// A restarted node binds the same address; the previous listener must be
/// gone first (a failed bind ends the process).
pub async fn wait_until_bindable(bind: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpListener::bind(bind).is_err() {
        assert!(Instant::now() < deadline, "{bind} still bound");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Shut `manager` down; its data dir is released when this returns.
pub async fn stop(manager: Arc<ZoneManager>) {
    tokio::task::spawn_blocking(move || manager.shutdown())
        .await
        .expect("shutdown");
}

pub async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + BUDGET;
    while !check().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

pub fn consensus(manager: &ZoneManager) -> ZoneConsensus<nexus_raft::raft::FullStateMachine> {
    manager
        .get_zone(ZONE)
        .expect("zone hosted here")
        .consensus_node()
}

pub async fn records(manager: &ZoneManager) -> Vec<(u64, String)> {
    let mut records = consensus(manager)
        .with_state_machine(|sm| sm.member_addresses().unwrap().unwrap())
        .await;
    records.sort();
    records
}

pub async fn has_key(manager: &ZoneManager, key: &str) -> bool {
    consensus(manager)
        .with_state_machine(|sm| sm.get_metadata(key).unwrap().is_some())
        .await
}

pub async fn write(manager: &ZoneManager, key: &str) {
    consensus(manager)
        .propose(Command::SetMetadata {
            key: key.to_string(),
            value: key.as_bytes().to_vec(),
        })
        .await
        .unwrap_or_else(|e| panic!("write {key}: {e}"));
}

pub async fn found(node: &Node, seeds: Vec<String>) -> Arc<ZoneManager> {
    let manager = node.start(seeds).await;
    manager.create_zone(ZONE).expect("create zone");
    await_leader(&manager, node.id).await;
    manager
}

pub async fn await_leader(manager: &ZoneManager, id: u64) {
    eventually("the node to lead", || async {
        consensus(manager).leader_id() == Some(id)
    })
    .await;
}

/// Join `learner` to the zone led by `leader`, advertising `advertised` in
/// the JoinZone request (the AddLearnerNode context).
pub async fn join_as_learner(
    manager: &ZoneManager,
    learner: &Node,
    leader: &Node,
    advertised: &str,
) {
    manager.join_zone(ZONE, true).expect("local join_zone");
    let joined = call_join_zone_rpc(
        &leader.endpoint(),
        ZONE,
        learner.id,
        advertised,
        true,
        None,
        30,
    )
    .await
    .expect("JoinZone RPC");
    assert!(joined.success, "JoinZone: {:?}", joined.error);
}

pub async fn wait_for_records(manager: &ZoneManager, expected: &[(u64, &str)], whose: &str) {
    let mut expected: Vec<(u64, String)> = expected
        .iter()
        .map(|(id, address)| (*id, address.to_string()))
        .collect();
    expected.sort();
    eventually(whose, || {
        let expected = expected.clone();
        async move { records(manager).await == expected }
    })
    .await;
}

/// The stopped node's first retained log index.
pub fn first_retained_index(raft_dir: &Path) -> u64 {
    RaftStorage::open(raft_dir)
        .expect("a stopped node releases its raft storage")
        .first_index()
        .expect("first index")
}

/// Restart `node` and make its zone resident, as a daemon does when it
/// serves the zone's mount.
pub async fn restart_member(node: &Node, seeds: Vec<String>) -> Arc<ZoneManager> {
    let manager = node.start(seeds).await;
    assert!(
        manager.get_zone(ZONE).is_some(),
        "the restarted zone materializes"
    );
    manager
}

pub async fn cluster_info(endpoint: &str) -> nexus_raft::transport::ClusterInfoResult {
    RaftApiClient::connect(endpoint, ClientConfig::default())
        .await
        .expect("connect")
        .with_zone_id(ZONE.into())
        .get_cluster_info()
        .await
        .expect("GetClusterInfo")
}
