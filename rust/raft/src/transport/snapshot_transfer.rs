//! Sending side of `SnapshotChunk`: deliver a `MsgSnapshot` as sequential
//! slices of its data, resumed from wherever the receiver says it stands.
//!
//! A snapshot is the whole zone state. One call carrying all of it has to
//! finish inside one deadline on one connection, so a slow or lossy link
//! restarts it from the first byte forever. Here every call carries at most
//! [`CALL_PAYLOAD_BYTES`] under its own deadline, the receiver keeps what arrived,
//! and a failed call costs that call alone. Each transfer is its own task
//! on a connection of its own, so the peer's appends and heartbeats never
//! queue behind a slice.
//!
//! The raft-rs contract is the transport loop's (see [`SendReport`]): one
//! report per `MsgSnapshot` that raft-rs still awaits. A transfer reports
//! delivered once the receiver verified the data and admitted the message,
//! and failed once the receiver acknowledged nothing for [`PROGRESS_WINDOW`].
//! Calls that fail in between — a broken channel or a refusal alike — are
//! retried here and reported to nobody. A transfer raft-rs stopped awaiting
//! — a newer `MsgSnapshot` went to the same peer, the peer's own response
//! settled the snapshot, the peer left, or this node stopped leading
//! ([`SnapshotTransfers::retain_awaited`]) — ends without a report: the
//! `Progress` it was owed to has left that snapshot, and a report then
//! would be applied to whatever the peer is sent next.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::Bytes;
use protobuf::Message as _;
use raft::eraftpb::Message;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};

use super::client::RaftClientPool;
use super::proto::nexus::raft::{SnapshotChunkRequest, StepBoundary};
use super::transport_loop::{protocol_client, send_deadline, Payload, SendFailure, SendReport};
use super::{NodeAddress, TransportError};
use crate::raft::message_bound::{CALL_PAYLOAD_BYTES, MAX_SNAPSHOT_BYTES};
use crate::raft::{RaftMessageProtocol, PROGRESS_WINDOW};

/// Delay before retrying a failed call; doubles per consecutive failure.
const RETRY_FIRST: Duration = Duration::from_millis(200);
const RETRY_MAX: Duration = Duration::from_secs(10);

/// How a transfer is paced.
#[derive(Clone, Copy)]
pub(super) struct Pacing {
    /// Snapshot data bytes per call.
    pub(super) chunk_bytes: usize,
    /// Deadline of one call carrying this many payload bytes.
    pub(super) call_deadline: fn(usize) -> Duration,
    /// How long a transfer goes without the receiver acknowledging a byte
    /// before it is reported failed. Until then raft-rs holds the peer in
    /// `Snapshot` and the leader keeps its log from the snapshot onward for
    /// it. Within the window nothing received is sent again: every retry
    /// continues from the receiver's offset. A transfer given up is
    /// continued by the next one only if raft-rs then sends the same
    /// snapshot — the leader stores another every compaction threshold —
    /// and the receiver still holds its bytes.
    pub(super) stall_window: Duration,
    pub(super) retry_first: Duration,
    pub(super) retry_max: Duration,
}

impl Default for Pacing {
    fn default() -> Self {
        Self {
            chunk_bytes: CALL_PAYLOAD_BYTES,
            call_deadline: send_deadline,
            stall_window: PROGRESS_WINDOW,
            retry_first: RETRY_FIRST,
            retry_max: RETRY_MAX,
        }
    }
}

/// Where a transfer goes, and through which step boundary.
#[derive(Clone)]
pub(super) struct Route {
    /// The transfers' own pool, apart from the one raft messages use.
    pub(super) pool: RaftClientPool,
    pub(super) peer: NodeAddress,
    pub(super) zone_id: String,
    pub(super) self_address: String,
    pub(super) protocol: RaftMessageProtocol,
}

/// The transfer running for one peer.
struct Running {
    id: u64,
    /// The snapshot's raft index: what the peer's `Progress` is pending on.
    index: u64,
    task: AbortHandle,
}

/// The snapshot transfers of one transport loop: at most one per peer.
pub(super) struct SnapshotTransfers {
    pacing: Pacing,
    running: HashMap<u64, Running>,
    tasks: JoinSet<()>,
    next_id: u64,
    /// Each transfer's report, tagged with its id so that one replaced or
    /// ended in the meantime is recognised and dropped.
    outcome_tx: mpsc::UnboundedSender<(u64, SendReport)>,
    outcome_rx: mpsc::UnboundedReceiver<(u64, SendReport)>,
}

impl SnapshotTransfers {
    pub(super) fn new(pacing: Pacing) -> Self {
        let (outcome_tx, outcome_rx) = mpsc::unbounded_channel();
        Self {
            pacing,
            running: HashMap::new(),
            tasks: JoinSet::new(),
            next_id: 0,
            outcome_tx,
            outcome_rx,
        }
    }

    /// Start transferring `message`, a `MsgSnapshot`, to its peer. raft-rs
    /// generates a second one for a peer only after that peer's `Progress`
    /// left the snapshot the first put it in, so a transfer still running
    /// for the peer is ended unreported and this one takes its place.
    pub(super) fn start(&mut self, route: Route, message: Message) {
        let peer_id = message.to;
        let payload = Payload::of(&message);
        let id = self.next_id;
        self.next_id += 1;
        let pacing = self.pacing;
        let report = ReportOnce {
            id,
            peer_id,
            payload,
            outcome: None,
            tx: self.outcome_tx.clone(),
        };
        let task = self.tasks.spawn(async move {
            let outcome = transfer(&route, message, &pacing).await;
            // The connection was this transfer's alone.
            route.pool.remove(route.peer.id).await;
            report.settle(outcome);
        });
        let running = Running {
            id,
            index: payload.last,
            task,
        };
        if let Some(replaced) = self.running.insert(peer_id, running) {
            replaced.task.abort();
        }
    }

    /// The next finished transfer's report, if one is waiting.
    pub(super) fn next_outcome(&mut self) -> Option<SendReport> {
        while self.tasks.try_join_next().is_some() {}
        while let Ok((id, report)) = self.outcome_rx.try_recv() {
            if self
                .running
                .get(&report.peer_id)
                .is_some_and(|running| running.id == id)
            {
                self.running.remove(&report.peer_id);
                return Some(report);
            }
        }
        None
    }

    /// End every running transfer whose snapshot raft-rs stopped awaiting:
    /// `awaited(peer, snapshot index)` is the peer's `Progress`. The peer
    /// answered for itself, was removed, or this node stopped leading; no
    /// report is owed and nobody wants the bytes. A transfer that
    /// already finished keeps its report.
    pub(super) fn retain_awaited(&mut self, awaited: impl Fn(u64, u64) -> bool) {
        self.running.retain(|peer_id, running| {
            let keep = running.task.is_finished() || awaited(*peer_id, running.index);
            if !keep {
                tracing::info!(
                    peer_node_id = *peer_id,
                    snapshot_index = running.index,
                    "snapshot transfer ended: raft stopped awaiting it",
                );
                running.task.abort();
            }
            keep
        });
    }
}

/// Sends a transfer's report when its task ends, however it ends, so a
/// transfer raft-rs awaits is never left unreported. A task that was aborted
/// reports too; its id is not the current one and the report is dropped.
struct ReportOnce {
    id: u64,
    peer_id: u64,
    payload: Payload,
    outcome: Option<Result<(), SendFailure>>,
    tx: mpsc::UnboundedSender<(u64, SendReport)>,
}

impl ReportOnce {
    fn settle(mut self, outcome: Result<(), SendFailure>) {
        self.outcome = Some(outcome);
    }
}

impl Drop for ReportOnce {
    fn drop(&mut self) {
        let outcome = self.outcome.take().unwrap_or_else(|| {
            Err(SendFailure::Connection(
                "snapshot transfer ended without an outcome".into(),
            ))
        });
        // A closed receiver means the loop is gone, and the driver with it.
        let _ = self.tx.send((
            self.id,
            SendReport {
                peer_id: self.peer_id,
                payload: self.payload,
                outcome: Some(outcome),
            },
        ));
    }
}

/// A `MsgSnapshot` ready to be transferred: the call every slice is cut
/// from, the data, and the message without it.
struct Prepared {
    /// Names the snapshot; only the slice and, at the end, the message
    /// differ from call to call.
    call: SnapshotChunkRequest,
    data: Bytes,
    message: Vec<u8>,
}

async fn prepare(route: &Route, mut message: Message) -> Result<Prepared, String> {
    let data: Bytes = message.mut_snapshot().take_data();
    if data.len() > MAX_SNAPSHOT_BYTES {
        return Err(format!(
            "snapshot of {} bytes exceeds the {MAX_SNAPSHOT_BYTES}-byte snapshot bound",
            data.len()
        ));
    }
    let metadata = message.get_snapshot().get_metadata();
    let (snapshot_index, snapshot_term) = (metadata.index, metadata.term);
    let sha256 = {
        let data = data.clone();
        tokio::task::spawn_blocking(move || Sha256::digest(&data).to_vec())
            .await
            .map_err(|error| format!("digest snapshot: {error}"))?
    };
    Ok(Prepared {
        call: SnapshotChunkRequest {
            zone_id: route.zone_id.clone(),
            sender_address: route.self_address.clone(),
            sender_node_id: message.from,
            boundary: StepBoundary::from(route.protocol) as i32,
            snapshot_index,
            snapshot_term,
            total_bytes: data.len() as u64,
            sha256,
            offset: 0,
            data: Vec::new(),
            message: Vec::new(),
        },
        message: message
            .write_to_bytes()
            .map_err(|error| format!("serialize: {error}"))?,
        data,
    })
}

/// Deliver one `MsgSnapshot`: ask the receiver where it stands, send the
/// data from there in slices, and complete with the message itself.
///
/// It ends when the receiver admitted the message, or when the receiver
/// acknowledged no byte for the stall window. A call that fails — the
/// channel broke, or the receiver answered and refused — is made again
/// after a delay, from wherever the receiver then says it stands; a peer
/// that refuses every call (one whose build has no `SnapshotChunk`, say)
/// thus holds its `Progress` in `Snapshot`, where raft-rs generates nothing
/// for it, for one stall window per snapshot, and is delivered to by the
/// same transfer if it stops refusing meanwhile. The failure reported at
/// the end carries the last call's.
async fn transfer(route: &Route, message: Message, pacing: &Pacing) -> Result<(), SendFailure> {
    let started = Instant::now();
    let Prepared {
        call,
        data,
        message,
    } = match prepare(route, message).await {
        Ok(prepared) => prepared,
        Err(unsendable) => {
            // Nothing a retry changes; reported no sooner than a snapshot
            // the peer never takes, so raft-rs does not generate the next
            // one at once.
            tracing::warn!(
                zone = %route.zone_id,
                peer_node_id = route.peer.id,
                "snapshot cannot be transferred: {unsendable}",
            );
            tokio::time::sleep(pacing.stall_window).await;
            return Err(SendFailure::Refused(unsendable));
        }
    };
    let (index, total) = (call.snapshot_index, call.total_bytes);
    tracing::info!(
        zone = %route.zone_id,
        peer_node_id = route.peer.id,
        snapshot_index = index,
        bytes = total,
        "snapshot transfer started",
    );

    // The offset the receiver expects, once it has said so. Its answer is
    // the only position: after any failed call it is asked again.
    let mut expected: Option<u64> = None;
    let mut resumed_at = None;
    let mut acknowledged_at = Instant::now();
    let mut retry_in = pacing.retry_first;
    let mut failures = 0u64;
    loop {
        let (offset, slice, completing) = match expected {
            None => (0, Bytes::new(), false),
            Some(at) if at < total => {
                let end = total.min(at + pacing.chunk_bytes as u64);
                (at, data.slice(at as usize..end as usize), false)
            }
            Some(_) => (total, Bytes::new(), true),
        };
        let sent = slice.len() as u64;
        let request = SnapshotChunkRequest {
            offset,
            data: slice.into(),
            message: if completing {
                message.clone()
            } else {
                Vec::new()
            },
            ..call.clone()
        };
        let failure = match send(route, request, pacing).await {
            Ok(next) if completing && next == total => {
                tracing::info!(
                    zone = %route.zone_id,
                    peer_node_id = route.peer.id,
                    snapshot_index = index,
                    bytes = total,
                    resumed_at = resumed_at.unwrap_or(0),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "snapshot transfer delivered",
                );
                return Ok(());
            }
            Ok(next) if next <= total => {
                resumed_at.get_or_insert(next);
                expected = Some(next);
                if sent == 0 || next == offset + sent {
                    if sent > 0 {
                        acknowledged_at = Instant::now();
                    }
                    retry_in = pacing.retry_first;
                    failures = 0;
                    continue;
                }
                // The receiver stands elsewhere than it said: it lost or
                // replaced what it held. Continue from its answer, at the
                // pace of a retry.
                SendFailure::Refused(format!(
                    "peer expects offset {next}, not the slice sent at {offset}"
                ))
            }
            Ok(next) => {
                expected = None;
                SendFailure::Refused(format!(
                    "peer expects offset {next} of a {total}-byte snapshot"
                ))
            }
            Err(failure) => {
                if matches!(failure, SendFailure::Connection(_)) {
                    // A broken channel is retried on a fresh connection.
                    route.pool.remove(route.peer.id).await;
                }
                expected = None;
                failure
            }
        };
        failures += 1;
        let stalled_for = acknowledged_at.elapsed();
        if stalled_for >= pacing.stall_window {
            let stalled = format!("snapshot transfer acknowledged no byte for {stalled_for:?}");
            return Err(match failure {
                SendFailure::Connection(why) => {
                    SendFailure::Connection(format!("{stalled}: {why}"))
                }
                SendFailure::Refused(why) | SendFailure::Oversized(why) => {
                    SendFailure::Refused(format!("{stalled}: {why}"))
                }
            });
        }
        if failures.is_power_of_two() {
            tracing::warn!(
                zone = %route.zone_id,
                peer_node_id = route.peer.id,
                snapshot_index = index,
                consecutive_failures = failures,
                "snapshot transfer call did not advance, resuming from the receiver's offset: \
                 {failure}",
            );
        }
        tokio::time::sleep(retry_in).await;
        retry_in = (retry_in * 2).min(pacing.retry_max);
    }
}

/// One `SnapshotChunk` call under its deadline; the receiver's next offset.
async fn send(
    route: &Route,
    request: SnapshotChunkRequest,
    pacing: &Pacing,
) -> Result<u64, SendFailure> {
    let deadline = (pacing.call_deadline)(request.data.len() + request.message.len());
    let call = async {
        let mut client = protocol_client(&route.pool, &route.peer, route.protocol).await?;
        client.snapshot_chunk(request).await.map_err(failure_of)
    };
    match tokio::time::timeout(deadline, call).await {
        Ok(outcome) => outcome,
        Err(_elapsed) => Err(SendFailure::Connection(format!(
            "no answer within {deadline:?}"
        ))),
    }
}

/// Classify a failed call. A receiver without the RPC has no other way to
/// be sent a snapshot, and says only that the method is unknown: name what
/// has to happen.
fn failure_of(error: TransportError) -> SendFailure {
    match error {
        TransportError::Status(status) if status.code() == tonic::Code::Unimplemented => {
            SendFailure::Refused(format!(
                "peer does not implement SnapshotChunk and must be upgraded before it can \
                 receive a snapshot: {status}"
            ))
        }
        other => SendFailure::of(other),
    }
}

#[cfg(test)]
pub(super) mod tests;
