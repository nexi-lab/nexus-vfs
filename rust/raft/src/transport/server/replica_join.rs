//! Read back a replica's existing admission through the original join protocol.

use super::{cluster_config, get_zone_node, member_endpoints, ZoneApiServiceImpl};
use crate::raft::member_address;
use crate::transport::{
    node_authority,
    proto::{JoinZoneRequest, JoinZoneResponse},
};
use std::time::Duration;
use tonic::{Request, Response, Status};

impl ZoneApiServiceImpl {
    pub(super) async fn read_replica_join(
        &self,
        request: Request<JoinZoneRequest>,
        replica_id: u64,
    ) -> Result<Response<JoinZoneResponse>, Status> {
        let denied = || Status::permission_denied("replica join requires its existing admission");
        let req = request.get_ref();
        if req.node_id != replica_id {
            return Err(denied());
        }
        node_authority::authorize_data_zone(request.extensions(), &self.registry, &req.zone_id)?;
        let address = member_address::canonical(&req.node_address).ok_or_else(denied)?;
        let node = get_zone_node(&self.registry, &req.zone_id)?;
        let view = tokio::time::timeout(Duration::from_secs(10), node.read_member_addresses())
            .await
            .map_err(|_| Status::unavailable("replica membership read timed out"))?
            .map_err(|error| Status::unavailable(format!("read replica membership: {error}")))?;
        let membership = view.membership;
        let role_matches = if req.as_learner {
            membership.is_learner(replica_id)
        } else {
            membership.is_voter(replica_id)
        };
        if !role_matches
            || !view
                .addresses
                .iter()
                .any(|(id, stored)| *id == replica_id && *stored == address)
        {
            return Err(denied());
        }
        if node_authority::current_replica_id(request.extensions())? != Some(replica_id) {
            return Err(denied());
        }
        node_authority::authorize_data_zone(request.extensions(), &self.registry, &req.zone_id)?;
        let addresses = member_endpoints(view.addresses, self.registry.tls_enabled());
        Ok(Response::new(JoinZoneResponse {
            success: true,
            error: None,
            leader_address: None,
            config: Some(cluster_config(
                &addresses,
                &membership.voters,
                &membership.learners,
            )),
            catching_up: false,
            commit_index: 0,
            applied_index: 0,
        }))
    }
}
