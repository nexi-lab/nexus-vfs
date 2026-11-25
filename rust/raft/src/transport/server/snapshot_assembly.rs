//! Receiving side of `SnapshotChunk`: assemble a raft snapshot's data from
//! sequential slices, verify it, and hand the complete `MsgSnapshot` to the
//! step path of the boundary the sender named.
//!
//! The bytes live in memory only, one snapshot per zone: a zone has one
//! leader, so another sender, or another snapshot from the same one,
//! replaces what is held. A restart loses them and the sender, told to
//! resume at offset zero, sends them again.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use protobuf::Message as _;
use raft::eraftpb::{Message, MessageType};
use sha2::{Digest, Sha256};
use tonic::{Response, Status};

use crate::raft::message_bound::MAX_SNAPSHOT_BYTES;
use crate::raft::{RaftMessageProtocol, PROGRESS_WINDOW};
use crate::transport::proto::nexus::raft::{
    SnapshotChunkRequest, SnapshotChunkResponse, StepBoundary, StepMessageResponse,
};

/// How long a held snapshot may go without a call before it is dropped.
///
/// A transfer rides out a link that is away for up to [`PROGRESS_WINDOW`],
/// so its bytes are kept at least that long. A transfer given up after that
/// window can be continued by the next one raft-rs starts for the peer, but
/// only if that one carries the same snapshot — the leader stores another
/// every compaction threshold, so in a zone that is being written the next
/// transfer usually starts from the first byte. Twice the window covers the
/// quiet zone and bounds how long an abandoned snapshot stays in memory;
/// the raft messages the service keeps receiving release it
/// ([`SnapshotAssembly::release_idle`]).
const PARTIAL_IDLE_LIMIT: Duration = PROGRESS_WINDOW.saturating_mul(2);

/// What makes two calls slices of the same snapshot: its raft metadata index
/// and term, and the length and SHA-256 of its data.
#[derive(Clone, PartialEq, Eq)]
struct Identity {
    index: u64,
    term: u64,
    total_bytes: u64,
    sha256: [u8; 32],
}

impl Identity {
    #[allow(clippy::result_large_err)]
    fn of(request: &SnapshotChunkRequest) -> Result<Self, Status> {
        let sha256 = request.sha256.as_slice().try_into().map_err(|_| {
            Status::invalid_argument("snapshot digest is not a 32-byte SHA-256 value")
        })?;
        Ok(Self {
            index: request.snapshot_index,
            term: request.snapshot_term,
            total_bytes: request.total_bytes,
            sha256,
        })
    }
}

/// A snapshot's data in this node's hands.
enum Data {
    /// Slices received so far, and the SHA-256 over them.
    Receiving { bytes: Vec<u8>, digest: Sha256 },
    /// Every byte, matching the snapshot's digest. Kept until a step of the
    /// `MsgSnapshot` carrying it has been admitted.
    Verified(Bytes),
}

/// Where a snapshot's data stands after one call.
enum Position {
    /// Incomplete: the next byte expected.
    At(u64),
    /// Complete and verified.
    Complete(Bytes),
}

impl Data {
    /// Append `slice` if it starts at the expected offset, and verify the
    /// data against the digest once the last byte is in.
    #[allow(clippy::result_large_err)]
    fn take(&mut self, identity: &Identity, slice: &Slice<'_>) -> Result<Position, Status> {
        let total = identity.total_bytes;
        let (bytes, digest) = match self {
            Self::Verified(complete) => return Ok(Position::Complete(complete.clone())),
            Self::Receiving { bytes, digest } => (bytes, digest),
        };
        if slice.offset == bytes.len() as u64 && !slice.bytes.is_empty() {
            if slice.offset + slice.bytes.len() as u64 > total {
                return Err(Status::invalid_argument(format!(
                    "snapshot slice ends beyond its declared {total} bytes"
                )));
            }
            bytes.extend_from_slice(slice.bytes);
            digest.update(slice.bytes);
        }
        if (bytes.len() as u64) < total {
            return Ok(Position::At(bytes.len() as u64));
        }
        if <[u8; 32]>::from(digest.clone().finalize()) != identity.sha256 {
            return Err(Status::data_loss(format!(
                "snapshot {}@{} does not match its SHA-256 digest; the received bytes were dropped",
                identity.index, identity.term
            )));
        }
        let complete = Bytes::from(std::mem::take(bytes));
        *self = Self::Verified(complete.clone());
        Ok(Position::Complete(complete))
    }
}

/// The snapshot held for one zone.
struct Held {
    sender: u64,
    identity: Identity,
    /// The last call that named this snapshot.
    touched: Instant,
    /// Locked on its own while a slice is appended and hashed, so that work
    /// holds up no other zone and no raft message.
    data: Arc<parking_lot::Mutex<Data>>,
}

impl Held {
    fn new(sender: u64, identity: Identity, now: Instant) -> Self {
        Self {
            sender,
            identity,
            touched: now,
            data: Arc::new(parking_lot::Mutex::new(Data::Receiving {
                bytes: Vec::new(),
                digest: Sha256::new(),
            })),
        }
    }
}

/// One call's slice of a snapshot.
struct Slice<'a> {
    offset: u64,
    bytes: &'a [u8],
    /// Whether the call carries the `MsgSnapshot` to step.
    completing: bool,
}

/// What one call left the receiver holding.
enum Received {
    /// The snapshot is incomplete, or the call does not complete it: the
    /// sender continues at this offset.
    Expecting(u64),
    /// Every byte is present and verified, and the call completes the
    /// transfer. `held` names what to release once the step is admitted.
    Verified {
        data: Bytes,
        held: Arc<parking_lot::Mutex<Data>>,
    },
}

/// The snapshots one transport service is receiving, one per zone.
#[derive(Default)]
pub(super) struct SnapshotAssembly {
    held: parking_lot::Mutex<HashMap<String, Held>>,
}

impl SnapshotAssembly {
    /// Take one call's slice — see [`Data::take`]. A refused slice or a
    /// digest mismatch drops what is held; verified data stays for the
    /// completing call, however often that call has to be made.
    #[allow(clippy::result_large_err)]
    fn receive(
        &self,
        zone_id: &str,
        sender: u64,
        identity: &Identity,
        slice: Slice<'_>,
        now: Instant,
    ) -> Result<Received, Status> {
        let held = {
            let mut zones = self.held.lock();
            Self::retain_active(&mut zones, now);
            let held = zones
                .entry(zone_id.to_owned())
                .and_modify(|held| {
                    if held.sender != sender || held.identity != *identity {
                        *held = Held::new(sender, identity.clone(), now);
                    }
                })
                .or_insert_with(|| Held::new(sender, identity.clone(), now));
            held.touched = now;
            Arc::clone(&held.data)
        };
        let position = held.lock().take(identity, &slice);
        match position {
            Ok(Position::At(offset)) => Ok(Received::Expecting(offset)),
            Ok(Position::Complete(data)) if slice.completing => {
                Ok(Received::Verified { data, held })
            }
            Ok(Position::Complete(_)) => Ok(Received::Expecting(identity.total_bytes)),
            Err(refused) => {
                self.release(zone_id, &held);
                Err(refused)
            }
        }
    }

    /// Stop holding `data` for the zone, unless another snapshot has taken
    /// its place.
    fn release(&self, zone_id: &str, data: &Arc<parking_lot::Mutex<Data>>) {
        let mut zones = self.held.lock();
        if zones
            .get(zone_id)
            .is_some_and(|held| Arc::ptr_eq(&held.data, data))
        {
            zones.remove(zone_id);
        }
    }

    /// Drop every snapshot idle for [`PARTIAL_IDLE_LIMIT`]. Called for each
    /// raft message the service steps — heartbeats arrive many times a
    /// second — so an abandoned snapshot goes on time whether or not another
    /// transfer ever calls. A call looking up its zone at this moment holds
    /// the lock and shows the map is in use; the next message looks again.
    pub(super) fn release_idle(&self, now: Instant) {
        if let Some(mut zones) = self.held.try_lock() {
            Self::retain_active(&mut zones, now);
        }
    }

    fn retain_active(zones: &mut HashMap<String, Held>, now: Instant) {
        if !zones.is_empty() {
            zones
                .retain(|_, held| now.saturating_duration_since(held.touched) < PARTIAL_IDLE_LIMIT);
        }
    }

    /// Bytes held for the zone and who sent them, if any.
    #[cfg(test)]
    fn held_bytes(&self, zone_id: &str) -> Option<(u64, usize)> {
        let zones = self.held.lock();
        let held = zones.get(zone_id)?;
        let bytes = match &*held.data.lock() {
            Data::Receiving { bytes, .. } => bytes.len(),
            Data::Verified(bytes) => bytes.len(),
        };
        Some((held.sender, bytes))
    }
}

/// The step protocol a transfer's boundary admits its message through.
#[allow(clippy::result_large_err)]
pub(super) fn boundary_protocol(
    request: &SnapshotChunkRequest,
) -> Result<RaftMessageProtocol, Status> {
    match StepBoundary::try_from(request.boundary) {
        Ok(StepBoundary::Legacy) => Ok(RaftMessageProtocol::Legacy),
        Ok(StepBoundary::AtomicNamespaceV1) => Ok(RaftMessageProtocol::AtomicNamespaceV1),
        Ok(StepBoundary::ReplicaControlV1) => Ok(RaftMessageProtocol::ReplicaControlV1),
        Ok(StepBoundary::Unspecified) | Err(_) => Err(Status::invalid_argument(
            "snapshot transfer names no step boundary",
        )),
    }
}

/// The transfer's raft message, checked to be the `MsgSnapshot` the request
/// names with its data left out, and completed with the verified `data`.
#[allow(clippy::result_large_err)]
fn complete_message(
    request: &SnapshotChunkRequest,
    identity: &Identity,
    data: Bytes,
) -> Result<Message, Status> {
    let mut message = Message::parse_from_bytes(&request.message).map_err(|error| {
        Status::invalid_argument(format!(
            "snapshot transfer message does not decode: {error}"
        ))
    })?;
    let metadata = message.get_snapshot().get_metadata();
    if message.get_msg_type() != MessageType::MsgSnapshot
        || message.from != request.sender_node_id
        || metadata.index != identity.index
        || metadata.term != identity.term
        || !message.get_snapshot().data.is_empty()
    {
        return Err(Status::invalid_argument(
            "snapshot transfer message is not the data-less MsgSnapshot the transfer names",
        ));
    }
    message.mut_snapshot().data = data;
    Ok(message)
}

/// Handle one `SnapshotChunk` call already admitted at its boundary.
/// `host_zone` and `step` are the service's own step path for that boundary:
/// the first refuses a zone a raft message would be refused for (and joins
/// one a raft message would join), before any byte is kept; the second
/// receives the complete `MsgSnapshot` on the completing call. The verified
/// data is released once a step has been admitted: a completing call that
/// is refused, or abandoned by its caller before the step answered, is
/// simply made again.
pub(super) async fn receive_chunk<Step>(
    assembly: &SnapshotAssembly,
    extensions: &tonic::codegen::http::Extensions,
    request: &SnapshotChunkRequest,
    host_zone: impl FnOnce() -> Result<(), Status>,
    step: impl FnOnce(Message) -> Step,
) -> Result<Response<SnapshotChunkResponse>, Status>
where
    Step: std::future::Future<Output = Result<Response<StepMessageResponse>, Status>>,
{
    if request.sender_node_id == 0 {
        return Err(Status::invalid_argument(
            "snapshot transfer names no sender",
        ));
    }
    crate::transport::node_authority::authorize_declared_sender(
        extensions,
        request.sender_node_id,
    )?;
    let identity = Identity::of(request)?;
    if identity.total_bytes > MAX_SNAPSHOT_BYTES as u64 {
        return Err(Status::invalid_argument(format!(
            "snapshot of {} bytes exceeds the {MAX_SNAPSHOT_BYTES}-byte snapshot bound",
            identity.total_bytes
        )));
    }
    host_zone()?;
    let received = assembly.receive(
        &request.zone_id,
        request.sender_node_id,
        &identity,
        Slice {
            offset: request.offset,
            bytes: &request.data,
            completing: !request.message.is_empty(),
        },
        Instant::now(),
    )?;
    let (data, held) = match received {
        Received::Expecting(next_offset) => {
            return Ok(Response::new(SnapshotChunkResponse { next_offset }))
        }
        Received::Verified { data, held } => (data, held),
    };
    let message = complete_message(request, &identity, data)?;
    let stepped = step(message).await?.into_inner();
    if !stepped.success {
        return Err(Status::failed_precondition(
            stepped
                .error
                .unwrap_or_else(|| "snapshot was not admitted".to_owned()),
        ));
    }
    assembly.release(&request.zone_id, &held);
    Ok(Response::new(SnapshotChunkResponse {
        next_offset: identity.total_bytes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = b"0123456789";

    fn identity(data: &[u8]) -> Identity {
        Identity {
            index: 9,
            term: 2,
            total_bytes: data.len() as u64,
            sha256: Sha256::digest(data).into(),
        }
    }

    /// One call from `sender` for zone `z`.
    fn call(
        assembly: &SnapshotAssembly,
        sender: u64,
        identity: &Identity,
        offset: u64,
        bytes: &[u8],
        completing: bool,
    ) -> Result<Received, Status> {
        assembly.receive(
            "z",
            sender,
            identity,
            Slice {
                offset,
                bytes,
                completing,
            },
            Instant::now(),
        )
    }

    fn expecting(received: Result<Received, Status>) -> u64 {
        match received.expect("accepted") {
            Received::Expecting(offset) => offset,
            Received::Verified { .. } => panic!("the call did not complete the snapshot"),
        }
    }

    fn verified(received: Result<Received, Status>) -> Bytes {
        match received.expect("accepted") {
            Received::Verified { data, .. } => data,
            Received::Expecting(offset) => panic!("incomplete: expecting {offset}"),
        }
    }

    /// Only a slice at the expected offset is appended; a repeated or
    /// premature one is answered with the expected offset and changes
    /// nothing, and an empty one asks where to resume.
    #[test]
    fn slices_are_idempotent_and_ordered() {
        let assembly = SnapshotAssembly::default();
        let id = identity(DATA);
        let put =
            |offset: u64, slice: &[u8]| expecting(call(&assembly, 1, &id, offset, slice, false));
        assert_eq!(put(0, b""), 0, "nothing held: resume at zero");
        assert_eq!(put(0, &DATA[..4]), 4);
        assert_eq!(put(0, &DATA[..4]), 4, "a repeated slice is not appended");
        assert_eq!(put(8, &DATA[8..]), 4, "a slice ahead is not appended");
        assert_eq!(
            put(2, &DATA[2..6]),
            4,
            "an overlapping slice is not appended"
        );
        assert_eq!(put(4, &DATA[4..]), 10);
        assert_eq!(put(0, b""), 10);
        assert_eq!(put(0, &DATA[..4]), 10, "verified data takes no more slices");
        assert_eq!(assembly.held_bytes("z"), Some((1, 10)));
        assert_eq!(verified(call(&assembly, 1, &id, 10, b"", true)), DATA);
        assert_eq!(
            verified(call(&assembly, 1, &id, 10, b"", true)),
            DATA,
            "the completing call can be made again"
        );
    }

    /// A completing call before every byte arrived completes nothing.
    #[test]
    fn a_completing_call_on_an_incomplete_snapshot_reports_the_expected_offset() {
        let assembly = SnapshotAssembly::default();
        let id = identity(DATA);
        expecting(call(&assembly, 1, &id, 0, &DATA[..6], false));
        assert_eq!(expecting(call(&assembly, 1, &id, 10, b"", true)), 6);
        assert_eq!(assembly.held_bytes("z"), Some((1, 6)));
    }

    /// A zone holds one snapshot: another snapshot from its sender, or the
    /// same snapshot from another sender, replaces what is held. Other
    /// zones keep theirs.
    #[test]
    fn another_snapshot_or_sender_replaces_what_the_zone_holds() {
        let assembly = SnapshotAssembly::default();
        let now = Instant::now();
        let old = identity(b"old snapshot");
        let slice = |bytes: &'static [u8]| Slice {
            offset: 0,
            bytes,
            completing: false,
        };
        for zone in ["z", "y"] {
            expecting(assembly.receive(zone, 1, &old, slice(b"old"), now));
        }
        let new = Identity {
            index: old.index + 1,
            ..identity(b"new snapshot")
        };
        assert_eq!(
            expecting(call(&assembly, 1, &new, 0, b"", false)),
            0,
            "the newer snapshot starts from its first byte"
        );
        assert_eq!(assembly.held_bytes("z"), Some((1, 0)));
        assert_eq!(
            expecting(call(&assembly, 1, &old, 0, b"", false)),
            0,
            "the replaced snapshot's bytes are gone"
        );

        // Another leader sends the zone its snapshot.
        expecting(call(&assembly, 1, &old, 0, b"old", false));
        assert_eq!(assembly.held_bytes("z"), Some((1, 3)));
        assert_eq!(expecting(call(&assembly, 2, &old, 0, b"ol", false)), 2);
        assert_eq!(
            assembly.held_bytes("z"),
            Some((2, 2)),
            "the first sender's bytes were replaced"
        );
        assert_eq!(assembly.held.lock().len(), 2, "one snapshot per zone");
        assert_eq!(assembly.held_bytes("y"), Some((1, 3)));
    }

    /// Data that does not hash to the declared digest is refused when its
    /// last byte arrives and dropped, so the transfer starts over.
    #[test]
    fn a_digest_mismatch_is_refused_and_the_bytes_dropped() {
        let assembly = SnapshotAssembly::default();
        let id = identity(DATA);
        expecting(call(&assembly, 1, &id, 0, b"01234", false));
        let refused = match call(&assembly, 1, &id, 5, b"56780", false) {
            Err(status) => status,
            Ok(_) => panic!("corrupt data must not verify"),
        };
        assert_eq!(refused.code(), tonic::Code::DataLoss);
        assert_eq!(assembly.held_bytes("z"), None);
        assert_eq!(expecting(call(&assembly, 1, &id, 0, b"", false)), 0);
    }

    /// More bytes than the snapshot declares are refused and dropped.
    #[test]
    fn a_slice_beyond_the_declared_length_is_refused() {
        let assembly = SnapshotAssembly::default();
        let id = identity(b"0123");
        let refused = match call(&assembly, 1, &id, 0, b"01234", false) {
            Err(status) => status,
            Ok(_) => panic!("an overlong slice must be refused"),
        };
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        assert_eq!(assembly.held_bytes("z"), None);
    }

    /// An empty snapshot (a witness's) completes in its one call.
    #[test]
    fn an_empty_snapshot_completes_without_a_slice() {
        let assembly = SnapshotAssembly::default();
        let data = verified(call(&assembly, 1, &identity(b""), 0, b"", true));
        assert!(data.is_empty());
    }

    /// An abandoned snapshot is released by the raft messages the service
    /// steps, with no further transfer call from anyone, and by the next
    /// transfer call for any zone.
    #[test]
    fn an_abandoned_snapshot_is_released_after_the_idle_limit() {
        let assembly = SnapshotAssembly::default();
        let id = identity(DATA);
        let start = Instant::now();
        let slice = || Slice {
            offset: 0,
            bytes: &DATA[..4],
            completing: false,
        };
        expecting(assembly.receive("z", 1, &id, slice(), start));
        assembly.release_idle(start + PARTIAL_IDLE_LIMIT - Duration::from_secs(1));
        assert_eq!(assembly.held_bytes("z"), Some((1, 4)), "within the limit");
        assembly.release_idle(start + PARTIAL_IDLE_LIMIT);
        assert_eq!(assembly.held_bytes("z"), None);

        expecting(assembly.receive("z", 1, &id, slice(), start));
        expecting(assembly.receive("y", 1, &id, slice(), start + PARTIAL_IDLE_LIMIT));
        assert_eq!(assembly.held_bytes("z"), None);
        assert_eq!(assembly.held_bytes("y"), Some((1, 4)));
    }

    const SNAPSHOT: &[u8] = b"snapshot data";

    fn request(message: &Message) -> SnapshotChunkRequest {
        SnapshotChunkRequest {
            zone_id: "z".into(),
            sender_node_id: 1,
            boundary: StepBoundary::Legacy as i32,
            snapshot_index: 9,
            snapshot_term: 2,
            total_bytes: SNAPSHOT.len() as u64,
            sha256: Sha256::digest(SNAPSHOT).to_vec(),
            offset: 0,
            data: SNAPSHOT.to_vec(),
            message: message.write_to_bytes().unwrap(),
            ..Default::default()
        }
    }

    fn snapshot_message() -> Message {
        let mut message = Message::default();
        message.set_msg_type(MessageType::MsgSnapshot);
        message.from = 1;
        message.to = 2;
        let metadata = message.mut_snapshot().mut_metadata();
        metadata.index = 9;
        metadata.term = 2;
        message
    }

    /// One call whose step answers `admit`, recording what was stepped.
    async fn receive(
        assembly: &SnapshotAssembly,
        request: &SnapshotChunkRequest,
        stepped: &std::sync::Mutex<Vec<Message>>,
        admit: bool,
    ) -> Result<u64, Status> {
        receive_chunk(
            assembly,
            &Default::default(),
            request,
            || Ok(()),
            |message| async move {
                stepped.lock().unwrap().push(message);
                Ok(Response::new(StepMessageResponse {
                    success: admit,
                    error: (!admit).then(|| "reader refused".to_owned()),
                }))
            },
        )
        .await
        .map(|response| response.into_inner().next_offset)
    }

    /// The completing call steps the message with the verified data in
    /// place, and releases the data once the step is admitted.
    #[tokio::test]
    async fn the_completing_call_steps_the_whole_snapshot_and_releases_it() {
        let assembly = SnapshotAssembly::default();
        let stepped = std::sync::Mutex::new(Vec::new());
        let request = request(&snapshot_message());
        assert_eq!(
            receive(&assembly, &request, &stepped, true).await.unwrap(),
            13
        );
        let messages = std::mem::take(&mut *stepped.lock().unwrap());
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].get_snapshot().get_data(), SNAPSHOT);
        assert_eq!(messages[0].get_msg_type(), MessageType::MsgSnapshot);
        assert_eq!(assembly.held_bytes("z"), None);
    }

    /// A completing call whose step is refused, or whose caller gave up
    /// before the step answered, leaves the verified data in place: the
    /// call made again steps it without a byte being sent twice.
    #[tokio::test]
    async fn a_snapshot_is_kept_until_its_step_is_admitted() {
        let assembly = SnapshotAssembly::default();
        let stepped = std::sync::Mutex::new(Vec::new());
        let with_data = request(&snapshot_message());
        let completing = SnapshotChunkRequest {
            offset: SNAPSHOT.len() as u64,
            data: Vec::new(),
            ..with_data.clone()
        };
        let probe = SnapshotChunkRequest {
            message: Vec::new(),
            ..completing.clone()
        };

        let refused = receive(&assembly, &with_data, &stepped, false)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(refused.message().contains("reader refused"));
        assert_eq!(assembly.held_bytes("z"), Some((1, SNAPSHOT.len())));
        assert_eq!(
            receive(&assembly, &probe, &stepped, true).await.unwrap(),
            13,
            "nothing is asked for again"
        );

        // The caller's deadline ends while the step is still being admitted.
        let extensions = Default::default();
        let abandoned = receive_chunk(
            &assembly,
            &extensions,
            &completing,
            || Ok(()),
            |_| std::future::pending(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), abandoned)
                .await
                .is_err(),
            "the call was dropped mid-step"
        );
        assert_eq!(assembly.held_bytes("z"), Some((1, SNAPSHOT.len())));

        assert_eq!(
            receive(&assembly, &completing, &stepped, true)
                .await
                .unwrap(),
            13
        );
        let messages = stepped.lock().unwrap();
        assert_eq!(messages.len(), 2, "the refused step and the admitted one");
        assert_eq!(messages[1].get_snapshot().get_data(), SNAPSHOT);
        assert_eq!(assembly.held_bytes("z"), None, "released once admitted");
    }

    /// A snapshot declared larger than the bound is refused before a byte
    /// of it is kept.
    #[tokio::test]
    async fn a_snapshot_beyond_the_bound_is_refused_with_nothing_held() {
        let assembly = SnapshotAssembly::default();
        let stepped = std::sync::Mutex::new(Vec::new());
        let oversized = SnapshotChunkRequest {
            total_bytes: MAX_SNAPSHOT_BYTES as u64 + 1,
            message: Vec::new(),
            ..request(&snapshot_message())
        };
        let refused = receive(&assembly, &oversized, &stepped, true)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        assert!(refused.message().contains("snapshot bound"), "{refused}");
        assert!(assembly.held.lock().is_empty());
        assert!(stepped.lock().unwrap().is_empty());
    }

    /// Only the data-less `MsgSnapshot` the transfer names is completed:
    /// another message type, sender or snapshot, or one carrying data of its
    /// own, is refused without being stepped.
    #[tokio::test]
    async fn a_message_that_is_not_the_named_snapshot_is_not_stepped() {
        let stepped = std::sync::Mutex::new(Vec::new());
        let mut append = snapshot_message();
        append.set_msg_type(MessageType::MsgAppend);
        let mut other_sender = snapshot_message();
        other_sender.from = 3;
        let mut other_snapshot = snapshot_message();
        other_snapshot.mut_snapshot().mut_metadata().index = 10;
        let mut with_data = snapshot_message();
        with_data.mut_snapshot().data = b"smuggled".to_vec().into();
        for message in [append, other_sender, other_snapshot, with_data] {
            let assembly = SnapshotAssembly::default();
            let refused = receive(&assembly, &request(&message), &stepped, true)
                .await
                .unwrap_err();
            assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        }
        assert!(stepped.lock().unwrap().is_empty());

        let assembly = SnapshotAssembly::default();
        let mut unbound = request(&snapshot_message());
        unbound.sender_node_id = 0;
        assert_eq!(
            receive(&assembly, &unbound, &stepped, true)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let mut short_digest = request(&snapshot_message());
        short_digest.sha256.truncate(8);
        assert_eq!(
            receive(&assembly, &short_digest, &stepped, true)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        assert!(stepped.lock().unwrap().is_empty());
        assert!(assembly.held.lock().is_empty());
    }

    #[test]
    fn each_boundary_maps_to_its_step_protocol() {
        let with = |boundary: i32| SnapshotChunkRequest {
            boundary,
            ..Default::default()
        };
        let protocol = |boundary: StepBoundary| boundary_protocol(&with(boundary as i32));
        assert_eq!(
            protocol(StepBoundary::Legacy).unwrap(),
            RaftMessageProtocol::Legacy
        );
        assert_eq!(
            protocol(StepBoundary::ReplicaControlV1).unwrap(),
            RaftMessageProtocol::ReplicaControlV1
        );
        assert_eq!(
            protocol(StepBoundary::AtomicNamespaceV1).unwrap(),
            RaftMessageProtocol::AtomicNamespaceV1
        );
        assert!(protocol(StepBoundary::Unspecified).is_err());
        assert!(boundary_protocol(&with(99)).is_err());
    }
}
