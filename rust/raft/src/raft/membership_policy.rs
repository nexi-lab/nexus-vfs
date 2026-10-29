//! Construction and ingress policy for a fixed local consensus group.

use protobuf::Message;
use raft::eraftpb::{ConfChange, ConfChangeType, ConfState, EntryType};
use raft::{GetEntriesContext, Storage};

use super::{RaftConfig, RaftError, RaftStorage, Result};

/// The membership authority selected by the owning runtime at construction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MembershipPolicy {
    #[default]
    Managed,
    FixedLocal,
}

impl MembershipPolicy {
    pub(crate) fn require_managed(self) -> Result<()> {
        if self == Self::FixedLocal {
            return Err(RaftError::Config(
                "isolated root has fixed local membership".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_storage(self, config: &RaftConfig, storage: &RaftStorage) -> Result<()> {
        if self == Self::Managed {
            return Ok(());
        }
        if config.id == 0 || config.is_witness || !config.peers.is_empty() {
            return Err(invalid("requires one local voter and local bootstrap"));
        }
        let state = storage.initial_state_impl()?;
        let first = storage.first_index_impl()?;
        let last = storage.last_index_impl()?;
        if state.conf_state == ConfState::default() {
            if config.skip_bootstrap
                || state.hard_state != Default::default()
                || first != 1
                || last != 0
            {
                return Err(invalid("stored history has no membership"));
            }
        } else {
            require_local(&state.conf_state, config.id)?;
        }
        let snapshot = storage
            .snapshot(0, config.id)
            .map_err(|error| invalid(&format!("read stored snapshot: {error}")))?;
        if snapshot.get_metadata().index > 0 {
            require_local(snapshot.get_metadata().get_conf_state(), config.id)?;
        }
        // Admission also covers retained entries that a restart can replay or
        // commit later. Read bounded batches once, before a driver owns storage.
        let end = last
            .checked_add(1)
            .ok_or_else(|| invalid("stored log index is exhausted"))?;
        let mut next = first;
        while next < end {
            let entries = storage
                .entries(
                    next,
                    end,
                    Some(1024 * 1024),
                    GetEntriesContext::empty(false),
                )
                .map_err(|error| invalid(&format!("read stored log: {error}")))?;
            if entries.is_empty() {
                return Err(invalid("stored log is incomplete"));
            }
            for entry in entries {
                match entry.get_entry_type() {
                    EntryType::EntryNormal => {}
                    EntryType::EntryConfChange => {
                        let change =
                            ConfChange::parse_from_bytes(&entry.data).map_err(|error| {
                                invalid(&format!("decode stored membership: {error}"))
                            })?;
                        if change.get_change_type() != ConfChangeType::AddNode
                            || change.node_id != config.id
                        {
                            return Err(invalid("stored log changes local membership"));
                        }
                    }
                    EntryType::EntryConfChangeV2 => {
                        return Err(invalid("stored log contains a membership transition"));
                    }
                }
                next = entry.index + 1;
            }
        }
        Ok(())
    }
}

fn require_local(state: &ConfState, node_id: u64) -> Result<()> {
    if state.voters != [node_id]
        || !state.learners.is_empty()
        || !state.voters_outgoing.is_empty()
        || !state.learners_next.is_empty()
        || state.auto_leave
    {
        return Err(invalid(
            "stored membership must contain exactly its local voter",
        ));
    }
    Ok(())
}

fn invalid(reason: &str) -> RaftError {
    RaftError::Config(format!("isolated root: {reason}"))
}
