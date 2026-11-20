//! How large a raft message may be, derived from the one bound every
//! endpoint on the port applies.
//!
//! A message one node may build but another must reject wedges replication
//! for good: raft-rs regenerates the same append on every retry, so the
//! receiver never advances. Every size below is therefore derived from
//! [`MAX_RAFT_MESSAGE_BYTES`], which the raft transport applies to every
//! server and client it builds, in both directions:
//!
//! * the transport refuses to send an encoded raft message larger than
//!   [`MAX_RAFT_PAYLOAD_BYTES`];
//! * a proposal whose entry would exceed [`MAX_ENTRY_BYTES`] is refused
//!   before it enters the log, so no append can ever need more.
//!
//! Far below that bound, [`CALL_PAYLOAD_BYTES`] is what one call normally
//! carries, so that replication crosses a slow link as many short calls:
//!
//! * raft-rs batches at most that many bytes of entries per append, a soft
//!   cap it exceeds only to send one entry alone. Such an entry is the one
//!   payload that cannot be split: its call's deadline grows with it at the
//!   transport's floor rate (`transport_loop::SEND_FLOOR_BYTES_PER_SEC`),
//!   and a link slower than that floor cannot deliver it;
//! * a snapshot is as large as the zone's state, not as any message.
//!   Its data never travels inside a raft message: the transport sends it in
//!   slices of that size (`transport::snapshot_transfer`), up to
//!   [`MAX_SNAPSHOT_BYTES`] in all, and the `MsgSnapshot` that follows them
//!   carries none of it.

use super::{RaftError, Result};

/// The largest gRPC message a raft-transport endpoint encodes or accepts:
/// the port-wide bound the co-hosted VFS service applies too.
pub const MAX_RAFT_MESSAGE_BYTES: usize = contracts::MAX_GRPC_MESSAGE_BYTES;

/// Room the transport request needs around the encoded raft message: the
/// zone id, the sender's address and the field framing.
const REQUEST_ENVELOPE_BYTES: usize = 16 * 1024;

/// The largest encoded raft-rs message the transport sends.
pub const MAX_RAFT_PAYLOAD_BYTES: usize = MAX_RAFT_MESSAGE_BYTES - REQUEST_ENVELOPE_BYTES;

/// Room an append needs around one entry's data: the message header and the
/// entry's own fields and framing.
const ENTRY_ENVELOPE_BYTES: usize = 16 * 1024;

/// The largest entry a proposal may write: an append carrying it alone fits
/// [`MAX_RAFT_PAYLOAD_BYTES`].
pub const MAX_ENTRY_BYTES: usize = MAX_RAFT_PAYLOAD_BYTES - ENTRY_ENVELOPE_BYTES;

/// The payload one replication call carries: raft-rs's per-append entry
/// budget (`max_size_per_msg`) and the size of one snapshot slice. Small
/// enough to cross a link of a few KiB/s inside one call's base deadline, so
/// a backlog or a snapshot advances call by call instead of outlasting a
/// deadline as a whole; large enough that a fast link is not paced by round
/// trips. The floor is a link that carries this much within the base
/// deadline of 30 s, about 2 KiB/s: below it no call completes and
/// replication to the peer stands still. The field framing of many tiny
/// entries can at most double an append, which still fits.
pub const CALL_PAYLOAD_BYTES: usize = 64 * 1024;

const _: () = assert!(2 * CALL_PAYLOAD_BYTES + ENTRY_ENVELOPE_BYTES <= MAX_RAFT_PAYLOAD_BYTES);

/// The largest snapshot the transport transfers. A snapshot is assembled in
/// the receiver's memory and restored from there, and a transfer names its
/// size before a byte is sent: a receiver keeps nothing of one declared
/// larger, and a sender does not start one.
pub const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024 * 1024;

/// Refuse an entry of `bytes` that no append could carry. Called before the
/// data reaches raft-rs, and before a follower forwards it.
pub(crate) fn admit_entry(bytes: usize) -> Result<()> {
    if bytes > MAX_ENTRY_BYTES {
        return Err(RaftError::EntryTooLarge {
            bytes,
            limit: MAX_ENTRY_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_at_the_bound_is_admitted_and_one_byte_more_is_refused() {
        admit_entry(MAX_ENTRY_BYTES).unwrap();
        match admit_entry(MAX_ENTRY_BYTES + 1) {
            Err(error @ RaftError::EntryTooLarge { .. }) => {
                assert!(!error.proposal_outcome_unknown(), "nothing was submitted");
            }
            other => panic!("expected EntryTooLarge, got {other:?}"),
        }
    }

    /// The largest append raft-rs can build — one entry at the bound —
    /// encodes within what the transport sends.
    #[test]
    fn an_append_carrying_the_largest_entry_fits_the_transport_bound() {
        use protobuf::Message as _;
        use raft::eraftpb::{Entry, Message, MessageType};

        let mut message = Message::default();
        message.set_msg_type(MessageType::MsgAppend);
        message.to = u64::MAX;
        message.from = u64::MAX;
        message.term = u64::MAX;
        message.log_term = u64::MAX;
        message.index = u64::MAX;
        message.commit = u64::MAX;
        message.set_entries(
            vec![Entry {
                term: u64::MAX,
                index: u64::MAX,
                data: vec![0; MAX_ENTRY_BYTES].into(),
                ..Default::default()
            }]
            .into(),
        );
        assert!(message.compute_size() as usize <= MAX_RAFT_PAYLOAD_BYTES);
    }
}
