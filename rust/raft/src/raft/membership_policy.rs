//! Construction and ingress policy for a fixed local consensus group.

#[cfg(feature = "consensus")]
use {
    super::{Command, RaftConfig, RaftError, RaftStorage, Result, StateMachine},
    protobuf::Message,
    raft::{
        eraftpb::{ConfChange, ConfChangeType, ConfState, Entry, EntryType},
        GetEntriesContext, Storage,
    },
};

/// The membership authority selected by the owning runtime at construction.
/// Storage requirements remain inspectable independently of the consensus driver.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MembershipPolicy {
    #[default]
    Managed,
    FixedLocal,
}

#[cfg(feature = "consensus")]
impl MembershipPolicy {
    pub(crate) fn require_managed(self) -> Result<()> {
        if self == Self::FixedLocal {
            return Err(RaftError::Config(
                "isolated root has fixed local membership".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_entry(self, entry: &Entry) -> Result<()> {
        if self == Self::Managed
            && entry.get_entry_type() == EntryType::EntryNormal
            && !entry.data.is_empty()
        {
            let (_, command) = Command::from_log_data(&entry.data)?;
            if command.requires_fixed_local_storage() {
                return Err(RaftError::Config(
                    "conditional metadata log requires qualified fixed-local storage".into(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_storage(
        self,
        config: &RaftConfig,
        storage: &RaftStorage,
        state_machine: &dyn StateMachine,
    ) -> Result<()> {
        state_machine.validate_membership_policy(self)?;
        if self == Self::Managed {
            let first = storage.first_index_impl()?;
            let last = storage.last_index_impl()?;
            // Only the unapplied suffix can introduce a requirement not already
            // reflected by the state machine's durable format marker.
            let next = first.max(state_machine.last_applied_index().saturating_add(1));
            return self.validate_retained_entries(storage, next, last, None);
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
        self.validate_retained_entries(storage, first, last, Some(config.id))
    }

    // Admission covers retained entries that can be replayed or committed later.
    // Bounded batches keep startup memory independent of retained log size.
    fn validate_retained_entries(
        self,
        storage: &RaftStorage,
        mut next: u64,
        last: u64,
        local_id: Option<u64>,
    ) -> Result<()> {
        let end = last
            .checked_add(1)
            .ok_or_else(|| invalid("stored log index is exhausted"))?;
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
                self.validate_entry(&entry)?;
                match entry.get_entry_type() {
                    EntryType::EntryNormal => {}
                    EntryType::EntryConfChange if local_id.is_some() => {
                        let change =
                            ConfChange::parse_from_bytes(&entry.data).map_err(|error| {
                                invalid(&format!("decode stored membership: {error}"))
                            })?;
                        if change.get_change_type() != ConfChangeType::AddNode
                            || local_id != Some(change.node_id)
                        {
                            return Err(invalid("stored log changes local membership"));
                        }
                    }
                    EntryType::EntryConfChangeV2 if local_id.is_some() => {
                        return Err(invalid("stored log contains a membership transition"));
                    }
                    _ => {}
                }
                next = entry.index + 1;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "consensus")]
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

#[cfg(feature = "consensus")]
fn invalid(reason: &str) -> RaftError {
    RaftError::Config(format!("isolated root: {reason}"))
}
