//! Driver-owned configuration observations for storage protocol activation.

use super::{RaftError, Result, StateMachine, ZoneConsensusDriver};
use crate::raft::storage_protocol::StorageProtocol;
use crate::raft::{Command, MembershipPolicy};
use raft::eraftpb::ConfState;
use std::sync::Arc;

/// An in-process observation of one leader's complete Raft configuration.
///
/// The transport inspects member IDs for authenticated capability probes. The
/// owning driver rechecks the original observation at submission. An observation
/// grants no storage or membership authority and is never persisted.
#[derive(Clone, Debug)]
pub struct StorageActivationView {
    incarnation: Arc<()>,
    epoch: u64,
    term: u64,
    configuration: ConfState,
}

impl StorageActivationView {
    /// Include every configured member, including learners and witnesses.
    pub fn member_ids(&self) -> Vec<u64> {
        let mut ids = self.configuration.voters.clone();
        ids.extend(&self.configuration.learners);
        ids.extend(&self.configuration.voters_outgoing);
        ids.extend(&self.configuration.learners_next);
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

/// The transport dialect attached to one inbound Raft exchange.
/// The owning driver checks it against its durable local reader requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaftMessageProtocol {
    Legacy,
    ReplicaControlV1,
}

/// A typed proposal constructed by its native storage authority.
/// Admission metadata remains separate from the durable command encoding.
pub struct StorageSubmission {
    pub(super) command: Command,
    pub(super) protocol: StorageProtocol,
    pub(super) configuration: Option<StorageActivationView>,
}

impl<S: StateMachine + 'static> ZoneConsensusDriver<S> {
    pub(super) fn prepare_replica_control_reader(&mut self) -> Result<()> {
        self.config.membership_policy.require_managed()?;
        if self.failed {
            return Err(RaftError::InvalidState("Raft driver has failed".into()));
        }
        if !self.replica_control_reader_prepared {
            self.raw_node.store().prepare_replica_control_reader()?;
            self.replica_control_reader_prepared = true;
        }
        Ok(())
    }

    /// The outbound dialect follows the original durable reader floor.
    /// This derived driver cache is initialized from storage on every boot.
    pub fn raft_message_protocol(&self) -> RaftMessageProtocol {
        if self.replica_control_reader_prepared {
            RaftMessageProtocol::ReplicaControlV1
        } else {
            RaftMessageProtocol::Legacy
        }
    }

    pub(super) fn admit_raft_protocol(&mut self, protocol: RaftMessageProtocol) -> Result<()> {
        self.config.membership_policy.require_managed()?;
        if self.failed {
            return Err(RaftError::InvalidState("Raft driver has failed".into()));
        }
        match protocol {
            RaftMessageProtocol::ReplicaControlV1 => self.prepare_replica_control_reader(),
            RaftMessageProtocol::Legacy if self.replica_control_reader_prepared => {
                Err(RaftError::UnsupportedOperation(
                    "prepared reader requires replica-control transport",
                ))
            }
            RaftMessageProtocol::Legacy => Ok(()),
        }
    }

    pub(super) fn storage_activation_view(&self) -> Result<StorageActivationView> {
        self.config.membership_policy.require_managed()?;
        if self.failed {
            return Err(RaftError::InvalidState("Raft driver has failed".into()));
        }
        if !self.is_leader() || self.config.is_witness {
            return Err(RaftError::NotLeader { leader_hint: None });
        }
        if self.raw_node.raft.pending_conf_index > self.raw_node.raft.raft_log.applied {
            return Err(RaftError::Config(
                "storage activation waits for the pending configuration".into(),
            ));
        }
        let configuration = self.raw_node.raft.prs().conf().to_conf_state();
        if !configuration.voters_outgoing.is_empty()
            || !configuration.learners_next.is_empty()
            || configuration.auto_leave
        {
            return Err(RaftError::Config(
                "storage activation waits for stable membership".into(),
            ));
        }
        let epoch = self.membership_epoch.ok_or_else(|| {
            RaftError::Config("storage configuration observation space exhausted".into())
        })?;
        Ok(StorageActivationView {
            incarnation: Arc::clone(&self.incarnation),
            epoch,
            term: self.raw_node.raft.term,
            configuration,
        })
    }

    pub(super) fn validate_storage_activation_view(
        &self,
        observed: &StorageActivationView,
    ) -> Result<()> {
        if !Arc::ptr_eq(&self.incarnation, &observed.incarnation) {
            return Err(RaftError::Config(
                "storage activation belongs to a different driver incarnation".into(),
            ));
        }
        let current = self.storage_activation_view()?;
        if current.term != observed.term
            || current.epoch != observed.epoch
            || current.configuration != observed.configuration
        {
            return Err(RaftError::Config(
                "storage activation configuration changed during qualification".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_storage_submission(&self, submission: &StorageSubmission) -> Result<()> {
        if submission.command.requires_activation_qualification() {
            return Err(RaftError::UnsupportedOperation(
                "protocol activation requires qualified member observation",
            ));
        }
        if submission.command.storage_protocol() != Some(submission.protocol) {
            return Err(RaftError::InvalidState(
                "command belongs to a different storage protocol".into(),
            ));
        }
        if let Some(observed) = &submission.configuration {
            self.validate_storage_activation_view(observed)?;
        }
        match (self.config.membership_policy, submission.protocol) {
            (MembershipPolicy::FixedLocal, _) if submission.configuration.is_none() => Ok(()),
            (MembershipPolicy::Managed, StorageProtocol::ReplicaControl)
                if self.replica_control_reader_prepared && self.replica_control_active =>
            {
                Ok(())
            }
            (MembershipPolicy::Managed, StorageProtocol::ReplicaControl) => Err(
                RaftError::UnsupportedOperation("replica binding protocol is not activated"),
            ),
            _ => Err(RaftError::UnsupportedOperation(
                "conditional metadata requires fixed local membership",
            )),
        }
    }
}

/// Shared SC completion semantics for storage proposals and activation.
#[cfg(all(feature = "grpc", has_protos))]
pub(super) async fn await_storage_commit(
    receiver: super::oneshot::Receiver<Result<super::CommandResult>>,
) -> Result<super::CommandResult> {
    // Once enqueued, only a proven pre-submission refusal resolves uncertainty.
    match crate::raft::proposal::wait_for_commit(
        receiver,
        tokio::time::Instant::now() + std::time::Duration::from_secs(super::PROPOSAL_TIMEOUT_SECS),
    )
    .await
    {
        Err(error @ (RaftError::NotLeader { .. } | RaftError::ProposalRejected(_))) => Err(error),
        Err(error) => Err(RaftError::ProposalOutcomeUnknown(error.to_string())),
        result => result,
    }
}
