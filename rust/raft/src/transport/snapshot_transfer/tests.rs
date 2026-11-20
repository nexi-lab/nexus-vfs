//! Snapshot transfers between the real transport client and server, through
//! a [`ThrottledLink`]: a TCP forwarder that caps the rate toward the
//! receiver and cuts connections on demand.
//!
//! The receiver is a real node — a zone it joined, served by
//! `RaftGrpcServer` — so "delivered" here means the snapshot was verified,
//! stepped through the node's driver and installed in its state machine.
//! Sizes, rates and deadlines are scaled down together ([`SCALED`]) so a
//! test takes seconds and still exercises the property at production ratios.

use std::net::SocketAddr;
use std::sync::Arc;

use raft::eraftpb::MessageType;
use tokio::task::JoinHandle;

use super::*;
use crate::raft::message_bound::MAX_RAFT_MESSAGE_BYTES;
use crate::raft::{Command, FullStateMachine, StateMachine, ZoneConsensus, ZoneRaftRegistry};
use crate::storage::RedbStore;
use crate::transport::proto::nexus::raft as wire;
use crate::transport::transport_loop::client_config;
use crate::transport::{
    generate_node_cert, generate_zone_ca, ClientConfig, RaftGrpcServer, ServerConfig, TlsConfig,
};

#[path = "../../../tests/common/throttled_link.rs"]
mod throttled_link;

use throttled_link::ThrottledLink;

const ZONE: &str = "sharedzone";
const SENDER: u64 = 1;
const RECEIVER: u64 = 2;
const BUDGET: Duration = Duration::from_secs(60);

/// `send_deadline`'s shape at test scale: a base plus the payload at a
/// floor rate.
fn scaled_deadline(bytes: usize) -> Duration {
    Duration::from_secs(1) + Duration::from_secs_f64(bytes as f64 / (256.0 * 1024.0))
}

/// The scaled deadline with room for a loaded test machine: a test that
/// counts the bytes a transfer sends must not have a slice time out and be
/// sent twice because five hundred other tests were running.
fn unhurried_deadline(bytes: usize) -> Duration {
    5 * scaled_deadline(bytes)
}

/// Production pacing with every size and time divided down.
const SCALED: Pacing = Pacing {
    chunk_bytes: 16 * 1024,
    call_deadline: unhurried_deadline,
    stall_window: Duration::from_secs(3),
    retry_first: Duration::from_millis(20),
    retry_max: Duration::from_millis(200),
};

/// The scaled link: a quarter of the scaled deadline's floor rate.
const SLOW: u64 = 64 * 1024;

/// A real node hosting [`ZONE`] as a member that has received nothing yet.
struct Receiver {
    _directory: tempfile::TempDir,
    registry: Arc<ZoneRaftRegistry>,
    bind: SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    server: JoinHandle<()>,
}

impl Receiver {
    async fn start() -> Self {
        Self::hosting_zone(None).await
    }

    /// A member of the zone serving `tls`, or plaintext without it.
    async fn hosting_zone(tls: Option<TlsConfig>) -> Self {
        let receiver = Self::serving(tls).await;
        receiver
            .registry
            .join_zone(ZONE, true, &tokio::runtime::Handle::current())
            .expect("join zone");
        receiver
    }

    /// A node that does not host the zone, and refuses it.
    async fn without_zone() -> Self {
        Self::serving(None).await
    }

    /// A node serving its raft transport on a loopback port the OS chose,
    /// bound here and handed to the server.
    async fn serving(tls: Option<TlsConfig>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let registry = Arc::new(ZoneRaftRegistry::with_tls(
            directory.path().to_path_buf(),
            RECEIVER,
            tls.clone(),
        ));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind receiver");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let bind = listener.local_addr().expect("receiver address");
        let prepared = RaftGrpcServer::prepare_listener(registry.shared_tls(), tls.as_ref(), None)
            .expect("listener");
        let server = RaftGrpcServer::new(
            registry.clone(),
            ServerConfig {
                bind_address: bind,
                tls,
                ..Default::default()
            },
        );
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            server
                .serve_prepared(prepared, listener, async move {
                    let _ = stopped.await;
                })
                .await
                .expect("receiver server");
        });
        Self {
            _directory: directory,
            registry,
            bind,
            stop,
            server,
        }
    }

    fn node(&self) -> ZoneConsensus<FullStateMachine> {
        self.registry.get_node(ZONE).expect("zone hosted")
    }

    async fn has(&self, key: &str) -> bool {
        let key = key.to_owned();
        self.node()
            .with_state_machine(move |sm| sm.get_metadata(&key))
            .await
            .expect("read")
            .is_some()
    }

    /// The snapshot is installed: applied at its index, its last key readable.
    async fn installed(&self, snapshot: &ZoneSnapshot) {
        eventually("the receiver installs the snapshot", || async {
            self.node().applied_index() == snapshot.index
        })
        .await;
        assert!(self.has(&snapshot.last_key).await);
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        self.server.await.expect("server task");
        self.registry.shutdown().released().await;
    }
}

async fn eventually<Fut: std::future::Future<Output = bool>>(
    what: &str,
    mut done: impl FnMut() -> Fut,
) {
    let deadline = Instant::now() + BUDGET;
    while !done().await {
        assert!(Instant::now() < deadline, "{what} within {BUDGET:?}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A zone's state as a leader would snapshot it.
struct ZoneSnapshot {
    index: u64,
    data: Vec<u8>,
    last_key: String,
}

impl ZoneSnapshot {
    /// `values` keys of `value_bytes` each, applied at indices `1..=values`.
    fn of(values: u64, value_bytes: usize) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = RedbStore::open(directory.path().join("sm")).unwrap();
        let mut machine = FullStateMachine::new(&store).unwrap();
        for index in 1..=values {
            let value = (0..value_bytes)
                .map(|byte| (byte as u64).wrapping_mul(index + 31) as u8)
                .collect();
            machine
                .apply(
                    index,
                    &Command::SetMetadata {
                        key: format!("/k/{index}"),
                        value,
                    },
                )
                .unwrap();
        }
        Self {
            index: values,
            data: machine.snapshot().unwrap(),
            last_key: format!("/k/{values}"),
        }
    }

    /// The `MsgSnapshot` raft-rs would send [`RECEIVER`] for it.
    fn message(&self) -> Message {
        let mut message = Message::default();
        message.set_msg_type(MessageType::MsgSnapshot);
        message.from = SENDER;
        message.to = RECEIVER;
        message.term = 1;
        let snapshot = message.mut_snapshot();
        snapshot.data = self.data.clone().into();
        let metadata = snapshot.mut_metadata();
        metadata.index = self.index;
        metadata.term = 1;
        metadata.mut_conf_state().voters = vec![SENDER];
        metadata.mut_conf_state().learners = vec![RECEIVER];
        message
    }
}

/// The sender's side: the pool the transport loop builds, routed at `endpoint`.
fn route(endpoint: String) -> Route {
    Route {
        pool: RaftClientPool::with_config(client_config(Default::default())),
        peer: NodeAddress::new(RECEIVER, endpoint),
        zone_id: ZONE.to_owned(),
        self_address: String::new(),
        protocol: RaftMessageProtocol::Legacy,
    }
}

/// Wait for the one report a transfer owes.
async fn outcome(transfers: &mut SnapshotTransfers) -> SendReport {
    let deadline = Instant::now() + BUDGET;
    loop {
        if let Some(report) = transfers.next_outcome() {
            return report;
        }
        assert!(Instant::now() < deadline, "a report within {BUDGET:?}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Nothing further is reported: a transfer reports once.
async fn no_further_outcome(transfers: &mut SnapshotTransfers) {
    let until = Instant::now() + Duration::from_millis(500);
    while Instant::now() < until {
        assert!(
            transfers.next_outcome().is_none(),
            "a transfer reports exactly once"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn heartbeat() -> Message {
    let mut message = Message::default();
    message.set_msg_type(MessageType::MsgHeartbeat);
    message.from = SENDER;
    message.to = RECEIVER;
    message.term = 1;
    message
}

/// An append the receiver answers and rejects: its previous entry is far
/// beyond the receiver's log, so its state is untouched.
fn append() -> Message {
    let mut message = heartbeat();
    message.set_msg_type(MessageType::MsgAppend);
    message.index = 1_000_000;
    message.log_term = 1;
    message.set_entries(
        vec![raft::eraftpb::Entry {
            index: 1_000_001,
            term: 1,
            ..Default::default()
        }]
        .into(),
    );
    message
}

/// The production failure: the whole snapshot in one call needs longer than
/// that call's deadline allows, at any deadline of this shape, because the
/// link is slower than the deadline's floor rate. Sent in slices, each call
/// fits its own deadline and the snapshot installs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_installs_over_a_link_too_slow_for_one_message() {
    let receiver = Receiver::start().await;
    let link = ThrottledLink::start(&receiver.bind.to_string(), SLOW).await;
    let snapshot = ZoneSnapshot::of(16, 16 * 1024);
    let route = route(link.endpoint());
    let whole = snapshot.message().write_to_bytes().unwrap();
    let one_call = scaled_deadline(whole.len());
    assert!(
        Duration::from_secs_f64(whole.len() as f64 / SLOW as f64) > one_call,
        "the link cannot carry the whole snapshot within one call's deadline"
    );

    // Control: the snapshot as one StepMessage does not arrive in time.
    let mut client = route.pool.get(&route.peer).await.unwrap();
    let single = client.step_message(whole, ZONE.to_owned(), String::new());
    assert!(
        tokio::time::timeout(one_call, single).await.is_err(),
        "one message outlasts its deadline on this link"
    );
    link.drop_connections();
    route.pool.remove(RECEIVER).await;
    assert_eq!(receiver.node().applied_index(), 0);

    let mut transfers = SnapshotTransfers::new(Pacing {
        call_deadline: scaled_deadline,
        ..SCALED
    });
    let started = Instant::now();
    let message = snapshot.message();
    transfers.start(route, message.clone());
    let report = outcome(&mut transfers).await;
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "delivered: {:?}",
        report.outcome
    );
    assert_eq!(report.peer_id, RECEIVER);
    assert_eq!(report.payload, Payload::of(&message));
    assert!(
        started.elapsed() > one_call,
        "the transfer took longer than any single call was allowed"
    );
    receiver.installed(&snapshot).await;
    no_further_outcome(&mut transfers).await;
    receiver.shutdown().await;
}

/// A sender whose build delivers a snapshot whole, inside one `StepMessage`,
/// is still served: the receiver installs it. A zone is upgraded receiver
/// first, so its leader may be such a build.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_whole_snapshot_in_one_step_message_installs() {
    let receiver = Receiver::start().await;
    let snapshot = ZoneSnapshot::of(16, 16 * 1024);
    let route = route(format!("http://{}", receiver.bind));
    let mut client = route.pool.get(&route.peer).await.unwrap();
    client
        .step_message(
            snapshot.message().write_to_bytes().unwrap(),
            ZONE.to_owned(),
            String::new(),
        )
        .await
        .expect("the whole snapshot is admitted");
    receiver.installed(&snapshot).await;
    receiver.shutdown().await;
}

/// A connection cut mid-transfer costs the call in flight, not the bytes
/// already received: the transfer asks the receiver where it stands and
/// continues there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_connection_resumes_from_the_receivers_offset() {
    let receiver = Receiver::start().await;
    let link = ThrottledLink::start(&receiver.bind.to_string(), 2 * SLOW).await;
    let snapshot = ZoneSnapshot::of(32, 16 * 1024);
    let total = snapshot.data.len() as u64;
    let mut transfers = SnapshotTransfers::new(SCALED);
    transfers.start(route(link.endpoint()), snapshot.message());

    // Cut the connection twice, each time with a good part delivered.
    for fraction in [3, 6] {
        eventually("part of the snapshot crosses the link", || async {
            link.bytes_toward_target() >= total * fraction / 10
        })
        .await;
        link.drop_connections();
    }
    let report = outcome(&mut transfers).await;
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "delivered: {:?}",
        report.outcome
    );
    receiver.installed(&snapshot).await;
    assert!(
        link.connections() >= 3,
        "the transfer re-dialed after each cut"
    );
    let crossed = link.bytes_toward_target();
    assert!(
        crossed < total + total / 4,
        "{crossed} bytes crossed the link for a {total}-byte snapshot: a transfer restarted \
         from its first byte after a cut at 30% and at 60% sends at least {}",
        total + total * 9 / 10
    );
    no_further_outcome(&mut transfers).await;
    receiver.shutdown().await;
}

/// Production pacing on the measured 8 KiB/s link, including a connection
/// loss halfway through. The real receiver installs every value while its
/// independent heartbeat connection remains responsive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_pacing_resumes_at_eight_kib_per_second() {
    let receiver = Receiver::start().await;
    let rate = 8 * 1024;
    let link = ThrottledLink::start(&receiver.bind.to_string(), rate).await;
    let snapshot = ZoneSnapshot::of(32, 16 * 1024);
    let total = snapshot.data.len() as u64;
    assert!(
        Duration::from_secs_f64(total as f64 / rate as f64)
            > send_deadline(snapshot.message().write_to_bytes().unwrap().len()),
        "one whole message cannot cross this link inside its deadline"
    );
    let route = route(link.endpoint());
    let messages = RaftClientPool::with_config(client_config(Default::default()));
    let mut transfers = SnapshotTransfers::new(Pacing::default());
    transfers.start(route.clone(), snapshot.message());
    let started = Instant::now();
    let mut cut = false;
    let mut answered = 0;
    let report = loop {
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "transfer finishes"
        );
        if let Some(report) = transfers.next_outcome() {
            break report;
        }
        if !cut && link.bytes_toward_target() >= total / 2 {
            link.drop_connections();
            messages.remove(RECEIVER).await;
            cut = true;
        }
        let reply = async {
            let mut client = messages.get(&route.peer).await.unwrap();
            client
                .step_message(
                    heartbeat().write_to_bytes().unwrap(),
                    ZONE.to_owned(),
                    String::new(),
                )
                .await
        };
        tokio::time::timeout(Duration::from_secs(3), reply)
            .await
            .expect("a heartbeat does not wait behind an eight-second slice")
            .expect("heartbeat answered");
        answered += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "{:?}",
        report.outcome
    );
    assert!(cut, "the connection was cut during the transfer");
    assert!(answered >= 20, "heartbeats answered throughout: {answered}");
    assert!(
        link.bytes_toward_target() < total + 2 * CALL_PAYLOAD_BYTES as u64,
        "resuming costs at most one slice plus protocol traffic, not half the snapshot"
    );
    receiver.installed(&snapshot).await;
    for index in 1..=snapshot.index {
        let actual = receiver
            .node()
            .with_state_machine(move |sm| sm.get_metadata(&format!("/k/{index}")))
            .await
            .expect("read installed state")
            .expect("every key restored");
        let expected: Vec<u8> = (0..16 * 1024)
            .map(|byte| (byte as u64).wrapping_mul(index + 31) as u8)
            .collect();
        assert_eq!(actual, expected, "all bytes of key {index} restored");
    }
    no_further_outcome(&mut transfers).await;
    receiver.shutdown().await;
}

/// Heartbeats and appends to the peer cross the same link as the transfer
/// on their own connection, as the transport loop sends them, and are
/// answered throughout it without queueing behind a slice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn heartbeats_and_appends_are_answered_while_a_snapshot_is_in_flight() {
    let receiver = Receiver::start().await;
    // Half a second of link per slice: long enough to tell a message that
    // waited behind one from a message that did not.
    let rate = SLOW / 2;
    let link = ThrottledLink::start(&receiver.bind.to_string(), rate).await;
    let snapshot = ZoneSnapshot::of(16, 16 * 1024);
    let route = route(link.endpoint());
    let messages = RaftClientPool::with_config(client_config(Default::default()));
    let whole_transfer = Duration::from_secs_f64(snapshot.data.len() as f64 / rate as f64);
    let one_slice = Duration::from_secs_f64(SCALED.chunk_bytes as f64 / rate as f64);
    let mut transfers = SnapshotTransfers::new(SCALED);
    transfers.start(route.clone(), snapshot.message());
    eventually("the transfer is under way", || async {
        link.bytes_toward_target() > 4 * SCALED.chunk_bytes as u64
    })
    .await;

    let mut answered = Vec::new();
    let report = loop {
        if let Some(report) = transfers.next_outcome() {
            break report;
        }
        for message in [heartbeat(), append()] {
            let sent = Instant::now();
            let mut client = messages.get(&route.peer).await.unwrap();
            client
                .step_message(
                    message.write_to_bytes().unwrap(),
                    ZONE.to_owned(),
                    String::new(),
                )
                .await
                .expect("answered during the transfer");
            answered.push(sent.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "delivered: {:?}",
        report.outcome
    );
    assert_eq!(
        link.connections(),
        2,
        "the transfer and the messages each have their connection"
    );
    assert!(
        answered.len() >= 10,
        "only {} messages were answered during a {whole_transfer:?} transfer",
        answered.len()
    );
    // A message behind the whole snapshot would wait for all of it; one
    // sharing the transfer's stream would wait half a slice on average.
    answered.sort_unstable();
    let (median, slowest) = (answered[answered.len() / 2], answered[answered.len() - 1]);
    assert!(
        median < one_slice / 4,
        "messages typically waited {median:?} beside slices taking {one_slice:?}"
    );
    assert!(
        slowest < whole_transfer / 4,
        "a message waited {slowest:?} of a {whole_transfer:?} transfer"
    );
    receiver.installed(&snapshot).await;
    receiver.shutdown().await;
}

/// A snapshot larger than the largest gRPC message any endpoint accepts
/// installs, at production pacing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_larger_than_the_message_bound_installs() {
    let receiver = Receiver::start().await;
    let snapshot = ZoneSnapshot::of(66, 1024 * 1024);
    assert!(snapshot.data.len() > MAX_RAFT_MESSAGE_BYTES);
    let mut transfers = SnapshotTransfers::new(Pacing::default());
    transfers.start(
        route(format!("http://{}", receiver.bind)),
        snapshot.message(),
    );
    let report = outcome(&mut transfers).await;
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "delivered: {:?}",
        report.outcome
    );
    receiver.installed(&snapshot).await;
    no_further_outcome(&mut transfers).await;
    receiver.shutdown().await;
}

/// The measured production link carries about 8 KiB/s. One 64 KiB slice
/// needs longer there than the 10 s a default client channel allows any
/// request; the transport loop's pool leaves each call to its own deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slice_may_take_longer_than_a_default_channel_allows() {
    let default_ceiling = ClientConfig::default().request_timeout;
    assert!(client_config(Default::default()).request_timeout >= send_deadline(CALL_PAYLOAD_BYTES));
    assert!(
        client_config(Default::default()).request_timeout >= send_deadline(MAX_RAFT_MESSAGE_BYTES)
    );

    let receiver = Receiver::start().await;
    let rate = 5 * 1024;
    let link = ThrottledLink::start(&receiver.bind.to_string(), rate).await;
    // One slice of state: 60 KiB of values.
    let snapshot = ZoneSnapshot::of(4, 15 * 1024);
    assert!(snapshot.data.len() <= CALL_PAYLOAD_BYTES);
    assert!(Duration::from_secs_f64(snapshot.data.len() as f64 / rate as f64) > default_ceiling);
    let mut transfers = SnapshotTransfers::new(Pacing::default());
    let started = Instant::now();
    transfers.start(route(link.endpoint()), snapshot.message());
    let report = outcome(&mut transfers).await;
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "delivered: {:?}",
        report.outcome
    );
    assert!(started.elapsed() > default_ceiling);
    assert_eq!(link.connections(), 1, "no call was cut short and re-dialed");
    receiver.installed(&snapshot).await;
    receiver.shutdown().await;
}

fn chunk(snapshot: &ZoneSnapshot, sha256: &[u8], offset: u64, data: &[u8]) -> SnapshotChunkRequest {
    SnapshotChunkRequest {
        zone_id: ZONE.to_owned(),
        sender_address: String::new(),
        sender_node_id: SENDER,
        boundary: StepBoundary::Legacy as i32,
        snapshot_index: snapshot.index,
        snapshot_term: 1,
        total_bytes: snapshot.data.len() as u64,
        sha256: sha256.to_vec(),
        offset,
        data: data.to_vec(),
        message: Vec::new(),
    }
}

/// Bytes that do not hash to the snapshot's digest are never stepped: the
/// slice that completes them is refused and the receiver starts over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_corrupt_snapshot_is_refused_and_its_bytes_dropped() {
    let receiver = Receiver::start().await;
    let snapshot = ZoneSnapshot::of(8, 4 * 1024);
    let sha256 = Sha256::digest(&snapshot.data).to_vec();
    let total = snapshot.data.len() as u64;
    let mut wrapper = snapshot.message();
    wrapper.mut_snapshot().take_data();
    let wrapper = wrapper.write_to_bytes().unwrap();
    let route = route(format!("http://{}", receiver.bind));
    let mut client = route.pool.get(&route.peer).await.unwrap();

    let mut corrupt = snapshot.data.clone();
    corrupt[total as usize / 2] ^= 0x01;
    let half = corrupt.len() / 2;
    let first = chunk(&snapshot, &sha256, 0, &corrupt[..half]);
    assert_eq!(client.snapshot_chunk(first).await.unwrap(), half as u64);
    let second = chunk(&snapshot, &sha256, half as u64, &corrupt[half..]);
    let completing = SnapshotChunkRequest {
        message: wrapper.clone(),
        ..chunk(&snapshot, &sha256, total, &[])
    };
    // The last byte verifies the data.
    match client.snapshot_chunk(second).await {
        Err(TransportError::Status(status)) => {
            assert_eq!(status.code(), tonic::Code::DataLoss, "{status}");
        }
        other => panic!("corrupt data must be refused, got {other:?}"),
    }
    assert!(matches!(
        failure_of(TransportError::Status(tonic::Status::data_loss("digest"))),
        SendFailure::Refused(_)
    ));
    let resume = chunk(&snapshot, &sha256, 0, &[]);
    assert_eq!(
        client.snapshot_chunk(resume).await.unwrap(),
        0,
        "the corrupt bytes were dropped"
    );
    assert_eq!(receiver.node().applied_index(), 0, "nothing was stepped");

    // The same snapshot, intact, installs.
    let intact = chunk(&snapshot, &sha256, 0, &snapshot.data);
    assert_eq!(client.snapshot_chunk(intact).await.unwrap(), total);
    assert_eq!(client.snapshot_chunk(completing).await.unwrap(), total);
    receiver.installed(&snapshot).await;
    receiver.shutdown().await;
}

fn node_tls(id: u64, ca: &[u8], ca_key: &[u8]) -> TlsConfig {
    let (cert_pem, key_pem) = generate_node_cert(id, "root", ca, ca_key, &[], None).unwrap();
    TlsConfig {
        cert_pem,
        key_pem,
        ca_pem: ca.to_vec(),
    }
}

/// Over mTLS a transfer is bound to the Node its connection authenticated:
/// another Node cannot send a snapshot in the leader's name, and the
/// leader's own transfer installs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authenticated_transfer_is_bound_to_its_sender() {
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let receiver = Receiver::hosting_zone(Some(node_tls(RECEIVER, &ca, &ca_key))).await;
    let snapshot = ZoneSnapshot::of(8, 16 * 1024);
    let route_as = |node: u64| Route {
        pool: RaftClientPool::with_config(client_config(
            lib::transport_primitives::SharedTlsConfig::new(Some(node_tls(node, &ca, &ca_key))),
        )),
        ..route(format!("http://{}", receiver.bind))
    };
    let mut transfers = SnapshotTransfers::new(SCALED);

    // Node 3 holds a valid Node certificate and sends the leader's snapshot.
    transfers.start(route_as(3), snapshot.message());
    let report = outcome(&mut transfers).await;
    match &report.outcome {
        Some(Err(failure @ SendFailure::Refused(_))) => {
            assert!(
                failure
                    .to_string()
                    .contains("does not match the authenticated Node"),
                "{failure}"
            );
        }
        other => panic!("another Node's transfer is refused, got {other:?}"),
    }
    no_further_outcome(&mut transfers).await;
    assert_eq!(receiver.node().applied_index(), 0);

    transfers.start(route_as(SENDER), snapshot.message());
    let report = outcome(&mut transfers).await;
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "delivered: {:?}",
        report.outcome
    );
    receiver.installed(&snapshot).await;
    no_further_outcome(&mut transfers).await;
    receiver.shutdown().await;
}

/// A receiver that keeps what it is sent, as the real one does, and once —
/// when `forget_at` bytes have arrived — loses all of it without the
/// connection noticing, as a receiver does that dropped an idle snapshot.
struct Forgetful {
    /// While set, the receiver answers as a build without the RPC does.
    without_the_rpc: std::sync::atomic::AtomicBool,
    calls_refused: std::sync::atomic::AtomicUsize,
    forget_at: usize,
    held: std::sync::Mutex<Vec<u8>>,
    forgot: std::sync::atomic::AtomicBool,
    /// The data in hand when the completing call arrived.
    completed: std::sync::Mutex<Option<Vec<u8>>>,
    slices_refused: std::sync::atomic::AtomicUsize,
}

impl Forgetful {
    /// A receiver that loses what it holds once `forget_at` bytes arrived.
    fn forgetting_at(forget_at: usize) -> Arc<Self> {
        Arc::new(Self {
            without_the_rpc: Default::default(),
            calls_refused: Default::default(),
            forget_at,
            held: Default::default(),
            forgot: Default::default(),
            completed: Default::default(),
            slices_refused: Default::default(),
        })
    }

    /// Serve on a loopback port the OS chose; returns the endpoint.
    async fn serve(self: Arc<Self>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(
                    wire::zone_transport_service_server::ZoneTransportServiceServer::from_arc(self),
                )
                .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener)),
        );
        endpoint
    }
}

#[tonic::async_trait]
impl wire::zone_transport_service_server::ZoneTransportService for Forgetful {
    async fn snapshot_chunk(
        &self,
        request: tonic::Request<SnapshotChunkRequest>,
    ) -> Result<tonic::Response<wire::SnapshotChunkResponse>, tonic::Status> {
        use std::sync::atomic::Ordering;
        if self.without_the_rpc.load(Ordering::SeqCst) {
            self.calls_refused.fetch_add(1, Ordering::SeqCst);
            return Err(tonic::Status::unimplemented(""));
        }
        let call = request.into_inner();
        let mut held = self.held.lock().unwrap();
        if held.len() >= self.forget_at && !self.forgot.swap(true, Ordering::SeqCst) {
            held.clear();
        }
        if call.offset == held.len() as u64 {
            held.extend_from_slice(&call.data);
        } else if !call.data.is_empty() {
            self.slices_refused.fetch_add(1, Ordering::SeqCst);
        }
        if !call.message.is_empty() && held.len() as u64 == call.total_bytes {
            *self.completed.lock().unwrap() = Some(std::mem::take(&mut *held));
            return Ok(tonic::Response::new(wire::SnapshotChunkResponse {
                next_offset: call.total_bytes,
            }));
        }
        Ok(tonic::Response::new(wire::SnapshotChunkResponse {
            next_offset: held.len() as u64,
        }))
    }

    async fn step_message(
        &self,
        _: tonic::Request<wire::StepMessageRequest>,
    ) -> Result<tonic::Response<wire::StepMessageResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not part of this receiver"))
    }

    async fn step_storage_v1(
        &self,
        _: tonic::Request<wire::StepMessageRequest>,
    ) -> Result<tonic::Response<wire::StepMessageResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not part of this receiver"))
    }

    async fn step_replica_control_v1(
        &self,
        _: tonic::Request<wire::StepMessageRequest>,
    ) -> Result<tonic::Response<wire::StepMessageResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not part of this receiver"))
    }

    async fn prepare_replica_control_reader_v1(
        &self,
        _: tonic::Request<wire::PrepareReplicaControlReaderRequest>,
    ) -> Result<tonic::Response<wire::PrepareReplicaControlReaderResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not part of this receiver"))
    }

    async fn replicate_entries(
        &self,
        _: tonic::Request<wire::ReplicateEntriesRequest>,
    ) -> Result<tonic::Response<wire::ReplicateEntriesResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not part of this receiver"))
    }

    async fn snapshot_ec_state(
        &self,
        _: tonic::Request<wire::SnapshotEcStateRequest>,
    ) -> Result<tonic::Response<wire::SnapshotEcStateResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not part of this receiver"))
    }
}

/// A receiver that answers a slice with another offset than the one it gave
/// — it lost what it held in between — is not refusing: the transfer
/// continues from its answer and still delivers every byte, reported once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_that_lost_its_bytes_is_sent_them_again() {
    use std::sync::atomic::Ordering;

    let snapshot = ZoneSnapshot::of(16, 16 * 1024);
    let receiver = Forgetful::forgetting_at(snapshot.data.len() / 2);
    let endpoint = receiver.clone().serve().await;

    let mut transfers = SnapshotTransfers::new(SCALED);
    transfers.start(route(endpoint), snapshot.message());
    let report = outcome(&mut transfers).await;
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "delivered: {:?}",
        report.outcome
    );
    assert!(receiver.forgot.load(Ordering::SeqCst));
    assert_eq!(
        receiver.slices_refused.load(Ordering::SeqCst),
        1,
        "one slice met the emptied receiver, and the transfer went back to its answer"
    );
    assert_eq!(
        receiver.completed.lock().unwrap().as_deref(),
        Some(snapshot.data.as_slice()),
        "every byte arrived, in order, after the loss"
    );
    no_further_outcome(&mut transfers).await;
}

/// A `ZoneTransportService` as a build without `SnapshotChunk` serves it:
/// the method is not in its table.
#[derive(Clone)]
struct WithoutSnapshotChunk;

impl tonic::server::NamedService for WithoutSnapshotChunk {
    const NAME: &'static str = "nexus.raft.ZoneTransportService";
}

impl tonic::codegen::Service<tonic::codegen::http::Request<tonic::body::Body>>
    for WithoutSnapshotChunk
{
    type Response = tonic::codegen::http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: tonic::codegen::http::Request<tonic::body::Body>) -> Self::Future {
        Box::pin(async { Ok(tonic::Status::unimplemented("").into_http()) })
    }
}

/// Serve a receiver that predates `SnapshotChunk` on a loopback port the OS
/// chose; returns its endpoint.
pub(in crate::transport) async fn receiver_without_snapshot_chunk() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(WithoutSnapshotChunk)
            .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener)),
    );
    endpoint
}

/// A receiver without the RPC cannot be sent a snapshot at all. The transfer
/// keeps asking for the stall window — a refusal is retried like any failed
/// call, so the peer's `Progress` rests in `Snapshot` meanwhile — and then
/// fails once, saying the peer must be upgraded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_without_the_rpc_fails_the_transfer_after_the_window_naming_the_upgrade() {
    let endpoint = receiver_without_snapshot_chunk().await;
    let snapshot = ZoneSnapshot::of(8, 4 * 1024);
    let mut transfers = SnapshotTransfers::new(SCALED);
    let started = Instant::now();
    transfers.start(route(endpoint), snapshot.message());
    let report = outcome(&mut transfers).await;
    match &report.outcome {
        Some(Err(failure @ SendFailure::Refused(_))) => {
            let said = failure.to_string();
            assert!(said.contains("SnapshotChunk"), "{said}");
            assert!(said.contains("must be upgraded"), "{said}");
        }
        other => panic!("an old receiver refuses, got {other:?}"),
    }
    assert!(
        started.elapsed() >= SCALED.stall_window,
        "a refusal is retried for the whole stall window"
    );
    no_further_outcome(&mut transfers).await;
}

/// A receiver that refuses every call at first — a build without the RPC —
/// and is then upgraded is delivered to by the transfer that was already
/// waiting on it: no second snapshot is needed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_gains_the_rpc_is_delivered_to_by_the_same_transfer() {
    use std::sync::atomic::Ordering;

    let snapshot = ZoneSnapshot::of(16, 16 * 1024);
    let receiver = Forgetful::forgetting_at(usize::MAX);
    receiver.without_the_rpc.store(true, Ordering::SeqCst);
    let endpoint = receiver.clone().serve().await;
    let mut transfers = SnapshotTransfers::new(SCALED);
    transfers.start(route(endpoint), snapshot.message());
    eventually("the transfer is refused and asks again", || async {
        receiver.calls_refused.load(Ordering::SeqCst) >= 3
    })
    .await;
    assert!(transfers.next_outcome().is_none(), "a refusal ends nothing");

    receiver.without_the_rpc.store(false, Ordering::SeqCst);
    let report = outcome(&mut transfers).await;
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "delivered: {:?}",
        report.outcome
    );
    assert_eq!(
        receiver.completed.lock().unwrap().as_deref(),
        Some(snapshot.data.as_slice())
    );
    no_further_outcome(&mut transfers).await;
}

/// A receiver that answers and refuses — here, a node that does not host the
/// zone — fails the transfer once, when the stall window ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusing_receiver_fails_the_transfer_once() {
    let receiver = Receiver::without_zone().await;
    let snapshot = ZoneSnapshot::of(8, 4 * 1024);
    let mut transfers = SnapshotTransfers::new(SCALED);
    let started = Instant::now();
    transfers.start(
        route(format!("http://{}", receiver.bind)),
        snapshot.message(),
    );
    let report = outcome(&mut transfers).await;
    match &report.outcome {
        Some(Err(failure @ SendFailure::Refused(_))) => {
            assert!(failure.to_string().contains("not found"), "{failure}");
        }
        other => panic!("a node without the zone refuses, got {other:?}"),
    }
    assert!(started.elapsed() >= SCALED.stall_window);
    no_further_outcome(&mut transfers).await;
    receiver.shutdown().await;
}

/// A snapshot larger than the bound is not started: nothing is sent, and
/// the failure names the bound.
#[tokio::test]
async fn a_snapshot_beyond_the_bound_is_not_sent() {
    let mut message = ZoneSnapshot::of(1, 16).message();
    // Zeroed pages the test never touches.
    message.mut_snapshot().data = vec![0u8; MAX_SNAPSHOT_BYTES + 1].into();
    let unsendable = match prepare(&route("http://127.0.0.1:1".to_owned()), message).await {
        Err(unsendable) => unsendable,
        Ok(_) => panic!("a snapshot beyond the bound must not be prepared"),
    };
    assert!(unsendable.contains("snapshot bound"), "{unsendable}");
}

/// A peer that cannot be reached fails the transfer once, after the stall
/// window and not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_peer_fails_the_transfer_once_after_the_stall_window() {
    let receiver = Receiver::start().await;
    let link = ThrottledLink::start(&receiver.bind.to_string(), 0).await;
    link.set_down(true);
    let snapshot = ZoneSnapshot::of(8, 4 * 1024);
    let mut transfers = SnapshotTransfers::new(SCALED);
    let started = Instant::now();
    transfers.start(route(link.endpoint()), snapshot.message());
    let report = outcome(&mut transfers).await;
    match &report.outcome {
        Some(Err(failure @ SendFailure::Connection(_))) => {
            assert!(
                failure.to_string().contains("acknowledged no byte"),
                "{failure}"
            );
        }
        other => panic!("an unreachable peer stalls the transfer, got {other:?}"),
    }
    assert!(started.elapsed() >= SCALED.stall_window);
    assert!(link.connections() == 0, "nothing got through");
    no_further_outcome(&mut transfers).await;
    assert_eq!(receiver.node().applied_index(), 0);
    receiver.shutdown().await;
}

/// A transfer that stalled half way is reported failed once. The receiver
/// keeps what it has, so the next `MsgSnapshot` for the same snapshot
/// finishes the job instead of starting it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_transfer_is_resumed_by_the_next_snapshot_message() {
    let receiver = Receiver::start().await;
    let link = ThrottledLink::start(&receiver.bind.to_string(), 2 * SLOW).await;
    let snapshot = ZoneSnapshot::of(32, 16 * 1024);
    let total = snapshot.data.len() as u64;
    let route = route(link.endpoint());
    let mut transfers = SnapshotTransfers::new(SCALED);
    transfers.start(route.clone(), snapshot.message());
    eventually("half the snapshot crosses the link", || async {
        link.bytes_toward_target() >= total / 2
    })
    .await;
    link.set_down(true);
    let report = outcome(&mut transfers).await;
    assert!(
        matches!(report.outcome, Some(Err(SendFailure::Connection(_)))),
        "stalled: {:?}",
        report.outcome
    );
    no_further_outcome(&mut transfers).await;
    assert_eq!(
        receiver.node().applied_index(),
        0,
        "nothing incomplete was stepped"
    );

    link.set_down(false);
    let before = link.bytes_toward_target();
    transfers.start(route, snapshot.message());
    let report = outcome(&mut transfers).await;
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "delivered: {:?}",
        report.outcome
    );
    receiver.installed(&snapshot).await;
    let crossed = link.bytes_toward_target() - before;
    assert!(
        crossed < total * 3 / 4,
        "the second transfer sent {crossed} of {total} bytes: it resumed"
    );
    no_further_outcome(&mut transfers).await;
    receiver.shutdown().await;
}

/// raft-rs generating another `MsgSnapshot` for a peer means the first is
/// not awaited: its transfer ends unreported and the newer one alone
/// reports.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newer_snapshot_replaces_the_running_transfer() {
    let receiver = Receiver::start().await;
    let link = ThrottledLink::start(&receiver.bind.to_string(), 2 * SLOW).await;
    let older = ZoneSnapshot::of(32, 16 * 1024);
    let newer = ZoneSnapshot::of(34, 4 * 1024);
    let route = route(link.endpoint());
    let mut transfers = SnapshotTransfers::new(SCALED);
    transfers.start(route.clone(), older.message());
    eventually("the older transfer is under way", || async {
        link.bytes_toward_target() > 4 * SCALED.chunk_bytes as u64
    })
    .await;
    transfers.start(route, newer.message());
    let report = outcome(&mut transfers).await;
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "delivered: {:?}",
        report.outcome
    );
    assert_eq!(report.payload, Payload::of(&newer.message()));
    receiver.installed(&newer).await;
    no_further_outcome(&mut transfers).await;
    receiver.shutdown().await;
}

/// A running transfer raft-rs stopped awaiting is ended without a report
/// and sends nothing more; one that already finished keeps its report.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_raft_no_longer_awaits_ends_unreported() {
    let receiver = Receiver::start().await;
    let link = ThrottledLink::start(&receiver.bind.to_string(), SLOW).await;
    let snapshot = ZoneSnapshot::of(32, 16 * 1024);
    let mut transfers = SnapshotTransfers::new(SCALED);
    transfers.start(route(link.endpoint()), snapshot.message());
    eventually("the transfer is under way", || async {
        link.bytes_toward_target() > 4 * SCALED.chunk_bytes as u64
    })
    .await;

    transfers.retain_awaited(|peer, index| {
        assert_eq!((peer, index), (RECEIVER, snapshot.index));
        true
    });
    assert_eq!(transfers.running.len(), 1, "an awaited transfer continues");
    transfers.retain_awaited(|_, _| false);
    assert!(transfers.running.is_empty());
    no_further_outcome(&mut transfers).await;
    let settled = link.bytes_toward_target();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        link.bytes_toward_target(),
        settled,
        "the transfer stopped sending"
    );
    assert_eq!(receiver.node().applied_index(), 0);

    // Finished before raft-rs moved on: the report is still delivered.
    link.set_rate(0);
    transfers.start(route(link.endpoint()), snapshot.message());
    eventually("the transfer finishes", || async {
        transfers.running[&RECEIVER].task.is_finished()
    })
    .await;
    transfers.retain_awaited(|_, _| false);
    let report = outcome(&mut transfers).await;
    assert!(
        matches!(report.outcome, Some(Ok(()))),
        "delivered: {:?}",
        report.outcome
    );
    no_further_outcome(&mut transfers).await;
    receiver.shutdown().await;
}
