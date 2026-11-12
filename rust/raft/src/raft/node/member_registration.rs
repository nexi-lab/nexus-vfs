//! A member keeps its own member-address record equal to its advertise
//! address — the record's one write path besides membership changes
//! (`docs/member-address.md`, Self-registration).

use std::time::Duration;

use tokio::sync::watch;

use super::{ZoneConsensus, PROPOSAL_TIMEOUT_SECS};
use crate::raft::{member_address, Command, CommandResult, RaftError, Result, StateMachine};
use crate::transport::NodeAddress;

/// First retry delay; each failed round doubles it up to [`RETRY_MAX`].
const RETRY_FIRST: Duration = Duration::from_millis(250);
const RETRY_MAX: Duration = Duration::from_secs(30);

/// Plain configuration a resident zone registers its member address with.
#[derive(Clone, Debug)]
pub(crate) struct MemberRegistration {
    /// This node's advertise address.
    pub(crate) advertise: String,
    /// Operator seed addresses: `Propose` targets besides the registered
    /// members.
    pub(crate) seeds: Vec<NodeAddress>,
}

impl<S: StateMachine + 'static> ZoneConsensus<S> {
    /// Propose this member's address record until the local state machine
    /// holds it, or until `shutdown`. A record that already matches ends the
    /// task at once, so a steady restart writes nothing.
    pub(crate) async fn register_member_address(
        self,
        registration: MemberRegistration,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let node_id = self.id();
        let Some(command) = member_address::put(node_id, &registration.advertise) else {
            tracing::warn!(
                advertise = %registration.advertise,
                "advertise address is not a host:port dial address; this member's address \
                 stays unregistered",
            );
            return;
        };
        let wanted = member_address::registration(&command)
            .map(|(_, address)| address.to_string())
            .expect("put builds a canonical record");
        let mut retry = RETRY_FIRST;
        let mut warned = false;
        loop {
            let records = match self.with_state_machine(|sm| sm.member_addresses()).await {
                Ok(records) => records,
                Err(error) => {
                    tracing::warn!(%error, "member addresses unreadable; registration retries");
                    Vec::new()
                }
            };
            if records
                .iter()
                .any(|(id, address)| *id == node_id && *address == wanted)
            {
                tracing::info!(
                    local_node_id = node_id,
                    address = %wanted,
                    "member address registered",
                );
                return;
            }
            // Raced against shutdown so a zone being torn down releases this
            // handle (and with it the zone's store) without waiting out an RPC.
            let round = tokio::select! {
                _ = shutdown.changed() => return,
                round = self.submit_registration(&command, &records, &registration.seeds) => round,
            };
            if let Err(error) = round {
                if warned {
                    tracing::debug!(%error, "member address registration retrying");
                } else {
                    warned = true;
                    tracing::warn!(
                        local_node_id = node_id,
                        address = %wanted,
                        %error,
                        "member address registration not committed yet; retrying with backoff \
                         against the leader, the registered members and the seed addresses",
                    );
                }
            }
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(retry) => {}
            }
            retry = (retry * 2).min(RETRY_MAX);
        }
    }

    /// One registration round: the normal proposal path when a leader is
    /// known, then a `forwarded=false` Propose RPC to each registered member
    /// and seed address in turn.
    async fn submit_registration(
        &self,
        command: &Command,
        records: &[(u64, String)],
        seeds: &[NodeAddress],
    ) -> Result<()> {
        let ctx = self
            .forward_ctx
            .as_ref()
            .ok_or_else(|| RaftError::Config("zone has no transport to register over".into()))?;
        if self.leader_id().is_some() {
            match self.propose(command.clone()).await {
                Ok(CommandResult::Error(error)) => return Err(RaftError::Raft(error)),
                Ok(_) => return Ok(()),
                Err(error) => {
                    tracing::debug!(%error, "registration via the leader failed; asking members")
                }
            }
        }
        let use_tls = ctx.client_pool.config().tls.snapshot().uses_tls();
        let mut targets: Vec<String> = records
            .iter()
            .filter(|(id, _)| *id != self.id())
            .filter_map(|(id, address)| member_address::endpoint(*id, address, use_tls))
            .map(|route| route.endpoint)
            .collect();
        for seed in seeds {
            if !targets.contains(&seed.endpoint) {
                targets.push(seed.endpoint.clone());
            }
        }
        let mut last =
            RaftError::Config("no registered member or seed address to register with".into());
        for endpoint in &targets {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(PROPOSAL_TIMEOUT_SECS);
            match crate::transport::propose_to(
                ctx.client_pool.config(),
                endpoint,
                command,
                &ctx.zone_id,
                deadline,
            )
            .await
            {
                Ok(CommandResult::Error(error)) => last = RaftError::Raft(error),
                Ok(_) => return Ok(()),
                Err(error) => last = error,
            }
        }
        Err(last)
    }
}
