//! A member keeps its own member-address record equal to its advertise
//! address — the record's one write path besides membership changes
//! (`docs/member-address.md`, Self-registration).

use std::time::Duration;

use tokio::sync::watch;

use super::{ForwardContext, ZoneConsensus, PROPOSAL_TIMEOUT_SECS};
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
    /// Propose this member's address record until the zone's records hold
    /// it, or until `shutdown`. The records are the local state machine's;
    /// a state machine that keeps none (a witness) reads them from the leader
    /// or a seed. A record that already matches ends the task at once, so a
    /// steady restart writes nothing.
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
            // Raced against shutdown so a zone being torn down releases this
            // handle (and with it the zone's store) without waiting out an RPC.
            let round = tokio::select! {
                _ = shutdown.changed() => return,
                round = self.registration_round(&command, &wanted, &registration.seeds) => round,
            };
            match round {
                Ok(true) => {
                    tracing::info!(
                        local_node_id = node_id,
                        address = %wanted,
                        "member address registered",
                    );
                    return;
                }
                Ok(false) => {}
                Err(error) if warned => {
                    tracing::debug!(%error, "member address registration retrying");
                }
                Err(error) => {
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

    /// One registration round: `Ok(true)` when the zone's records already
    /// hold `wanted` for this member, else the put is submitted and the next
    /// round confirms it.
    async fn registration_round(
        &self,
        command: &Command,
        wanted: &str,
        seeds: &[NodeAddress],
    ) -> Result<bool> {
        let ctx = self
            .forward_ctx
            .as_ref()
            .ok_or_else(|| RaftError::Config("zone has no transport to register over".into()))?;
        let use_tls = ctx.client_pool.config().tls.read().unwrap().is_some();
        let records = match self.with_state_machine(|sm| sm.member_addresses()).await? {
            Some(records) => records,
            None => {
                let leader = self
                    .leader_id()
                    .and_then(|id| ctx.peers.read().unwrap().route(id).cloned())
                    .map(|route| route.endpoint);
                let targets = rpc_targets(self.id(), wanted, use_tls, leader, &[], seeds);
                self.reported_member_addresses(ctx, &targets).await?
            }
        };
        if records
            .iter()
            .any(|(id, address)| *id == self.id() && address == wanted)
        {
            return Ok(true);
        }
        let targets = rpc_targets(self.id(), wanted, use_tls, None, &records, seeds);
        self.submit_registration(ctx, command, &targets).await?;
        Ok(false)
    }

    /// The zone's records as the first of `targets` to answer reports them.
    async fn reported_member_addresses(
        &self,
        ctx: &ForwardContext,
        targets: &[String],
    ) -> Result<Vec<(u64, String)>> {
        let mut last = RaftError::Config(
            "no leader route or seed address to read member addresses from".into(),
        );
        for endpoint in targets {
            match crate::transport::member_addresses_at(
                ctx.client_pool.config(),
                endpoint,
                &ctx.zone_id,
            )
            .await
            {
                Ok(records) => return Ok(records),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Submit the put: through the normal proposal path when a leader is
    /// known, else as a `forwarded=false` Propose RPC to each of `targets` in
    /// turn.
    async fn submit_registration(
        &self,
        ctx: &ForwardContext,
        command: &Command,
        targets: &[String],
    ) -> Result<()> {
        if self.leader_id().is_some() {
            let committed = match self.propose(command.clone()).await {
                // The record committed; this replica applying it is its own
                // catch-up, not a reason to register again.
                Err(RaftError::CommittedNotVisible { result, .. }) => Ok(*result),
                other => other,
            };
            match committed {
                Ok(CommandResult::Error(error)) => return Err(RaftError::Raft(error)),
                Ok(_) => return Ok(()),
                Err(error) => {
                    tracing::debug!(%error, "registration via the leader failed; asking members")
                }
            }
        }
        let mut last =
            RaftError::Config("no registered member or seed address to register with".into());
        for endpoint in targets {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(PROPOSAL_TIMEOUT_SECS);
            match crate::transport::propose_to(
                ctx.client_pool.config(),
                endpoint,
                command,
                &ctx.zone_id,
                deadline,
            )
            .await
            .map(|committed| committed.result)
            {
                Ok(CommandResult::Error(error)) => last = RaftError::Raft(error),
                Ok(_) => return Ok(()),
                Err(error) => last = error,
            }
        }
        Err(last)
    }
}

/// The endpoints a registration round reaches the zone through, each once:
/// `first`, then the recorded members, then the seed addresses. The local
/// member (`node_id`, advertising `own`) is never one of them.
fn rpc_targets(
    node_id: u64,
    own: &str,
    use_tls: bool,
    first: Option<String>,
    records: &[(u64, String)],
    seeds: &[NodeAddress],
) -> Vec<String> {
    let recorded = records
        .iter()
        .filter(|(id, _)| *id != node_id)
        .filter_map(|(id, address)| member_address::endpoint(*id, address, use_tls))
        .map(|route| route.endpoint);
    let seeded = seeds.iter().map(|seed| seed.endpoint.clone());
    let mut targets: Vec<String> = Vec::new();
    for endpoint in first.into_iter().chain(recorded).chain(seeded) {
        if member_address::canonical(&endpoint).as_deref() != Some(own)
            && !targets.contains(&endpoint)
        {
            targets.push(endpoint);
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::rpc_targets;
    use crate::transport::NodeAddress;

    #[test]
    fn registration_targets_skip_the_local_member_and_repeat_nothing() {
        let seeds = [
            NodeAddress::parse("10.0.0.1:2126", false).unwrap(),
            NodeAddress::parse("10.0.0.9:2126", false).unwrap(),
            NodeAddress::parse("10.0.0.2:2126", false).unwrap(),
        ];
        let records = [
            (1, "10.0.0.1:2126".to_string()),
            (9, "10.0.0.8:2126".to_string()),
            (3, "10.0.0.3:2126".to_string()),
        ];
        assert_eq!(
            rpc_targets(
                9,
                "10.0.0.9:2126",
                false,
                Some("http://10.0.0.3:2126".to_string()),
                &records,
                &seeds,
            ),
            [
                "http://10.0.0.3:2126",
                "http://10.0.0.1:2126",
                "http://10.0.0.2:2126"
            ],
            "the leader first, then the other members' records, then the seeds; \
             never this member's own record or advertise address"
        );
        assert_eq!(
            rpc_targets(9, "10.0.0.9:2126", true, None, &records[..1], &[]),
            ["https://10.0.0.1:2126"],
            "a record is dialed with the reading node's TLS posture"
        );
    }
}
