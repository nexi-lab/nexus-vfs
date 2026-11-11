//! Authenticated preparation of one owning leader's complete member set.

use super::{
    channel_try_send_err, oneshot, RaftError, Result, StateMachine, StorageActivationView,
    ZoneConsensus, ZoneConsensusDriver,
};

/// Every member in the original configuration acknowledged the required wire
/// protocol, and its owning driver revalidated that configuration afterward.
///
/// This process-local observation is bound to a driver incarnation, term and
/// membership epoch. Activation must consume and recheck the original view at
/// submission. Local preparation is durable; this value grants no storage or
/// membership authority and has no serialized representation.
#[derive(Debug)]
pub struct PreparedReplicaControl {
    view: StorageActivationView,
}

/// Preserve the actual consensus or authenticated peer failure at preparation.
#[derive(Debug, thiserror::Error)]
pub enum ReplicaPreparationError {
    #[error(transparent)]
    Consensus(#[from] RaftError),
    #[error("replica-control member {member} preparation: {error}")]
    Member {
        member: u64,
        #[source]
        error: Box<crate::transport::TransportError>,
    },
}

impl PreparedReplicaControl {
    /// The complete configured member set, including learners and witnesses.
    pub fn member_ids(&self) -> Vec<u64> {
        self.view.member_ids()
    }
}

impl<S: StateMachine + 'static> ZoneConsensus<S> {
    /// Prepare all members from one driver-owned configuration observation.
    ///
    /// Routes and exact Node channels come from this handle's existing zone
    /// transport. Each remote must explicitly acknowledge the required protocol.
    /// A failure preserves any completed local preparation; retries observe a
    /// fresh configuration and repeat the idempotent preparation operation.
    pub async fn prepare_replica_control_members(
        &self,
    ) -> std::result::Result<PreparedReplicaControl, ReplicaPreparationError> {
        let observed = self.storage_activation_view().await?;
        let members = observed.member_ids();
        let mut remote = Vec::new();
        // Resolve the original set before making any preparation request. Peer
        // routes may include stale or unconfigured nodes; they never define the
        // member set or qualify a missing member by substitution.
        for member in members {
            if member == self.id() {
                continue;
            }
            let context = self.forward_ctx.as_ref().ok_or_else(|| {
                RaftError::Config("member preparation requires the owning zone transport".into())
            })?;
            let address = context
                .peers
                .read()
                .map_err(|_| RaftError::Config("zone peer routes are unavailable".into()))?
                .route(member)
                .map(|route| crate::transport::NodeAddress::new(member, route.endpoint.clone()))
                .ok_or_else(|| {
                    RaftError::Config(format!("configured member {member} has no route"))
                })?;
            remote.push(address);
        }
        if let Some(context) = &self.forward_ctx {
            for address in remote {
                let mut client = context
                    .client_pool
                    .get_node(&address)
                    .await
                    .map_err(|error| ReplicaPreparationError::Member {
                        member: address.id,
                        error: Box::new(error),
                    })?;
                client
                    .prepare_replica_control_transport(&context.zone_id)
                    .await
                    .map_err(|error| ReplicaPreparationError::Member {
                        member: address.id,
                        error: Box::new(error),
                    })?;
            }
        }
        self.prepare_replica_control_reader().await?;
        let (tx, rx) = oneshot::channel();
        self.msg_tx
            .try_send(super::RaftMsg::CompleteReplicaControlPreparation { observed, tx })
            .map_err(channel_try_send_err)?;
        Ok(rx.await.map_err(|_| RaftError::ChannelClosed)??)
    }
}

impl<S: StateMachine + 'static> ZoneConsensusDriver<S> {
    pub(super) fn complete_replica_control_preparation(
        &self,
        observed: StorageActivationView,
    ) -> Result<PreparedReplicaControl> {
        self.validate_storage_activation_view(&observed)?;
        if !self.replica_control_reader_prepared {
            return Err(RaftError::InvalidState(
                "local replica-control reader has not prepared".into(),
            ));
        }
        Ok(PreparedReplicaControl { view: observed })
    }
}
