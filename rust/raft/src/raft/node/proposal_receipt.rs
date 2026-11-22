//! Local callers awaiting the exact Raft entries their leader appended.
use super::{CommandResult, ConfState, RaftError, Result};
use std::collections::HashMap;
use tokio::sync::oneshot;

pub(super) enum Reply {
    Command(oneshot::Sender<Result<CommandResult>>),
    Membership(oneshot::Sender<Result<ConfState>>),
}

impl Reply {
    pub(super) fn fail(self, error: RaftError) {
        match self {
            Self::Command(tx) => {
                let _ = tx.send(Err(error));
            }
            Self::Membership(tx) => {
                let _ = tx.send(Err(error));
            }
        }
    }

    fn closed(&self) -> bool {
        match self {
            Self::Command(tx) => tx.is_closed(),
            Self::Membership(tx) => tx.is_closed(),
        }
    }
}

struct Pending {
    term: u64,
    reply: Reply,
}

#[derive(Default)]
pub(super) struct ProposalReceipts(HashMap<u64, Pending>);

impl ProposalReceipts {
    pub(super) fn insert(&mut self, index: u64, term: u64, reply: Reply) {
        if let Some(previous) = self.0.insert(index, Pending { term, reply }) {
            previous
                .reply
                .fail(RaftError::ProposalOutcomeUnknown(format!(
                    "proposal at index {index} term {} lost its local log slot",
                    previous.term
                )));
        }
    }

    pub(super) fn committed(&mut self, index: u64, committed_term: u64) -> Option<Reply> {
        let pending = self.0.remove(&index)?;
        if pending.term == committed_term {
            return Some(pending.reply);
        }
        pending.reply.fail(RaftError::ProposalSuperseded {
            index,
            proposed_term: pending.term,
            committed_term,
        });
        None
    }

    pub(super) fn installed_snapshot(&mut self, through: u64) {
        for (index, pending) in self.0.extract_if(|index, _| *index <= through) {
            pending
                .reply
                .fail(RaftError::ProposalOutcomeUnknown(format!(
                    "snapshot covered proposal at index {index} term {}",
                    pending.term
                )));
        }
    }

    pub(super) fn discard_closed(&mut self) {
        self.0.retain(|_, pending| !pending.reply.closed());
    }
}
