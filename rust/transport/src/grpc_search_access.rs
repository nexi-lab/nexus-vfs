//! Access control for SearchService at the daemon's gRPC boundary.
//!
//! Query, BatchQuery, Glob, Grep and Locate use the authenticated caller's
//! readable zones and the kernel's installed permission policy. Index management
//! and aggregate diagnostics require an administrator or a cluster node because
//! those operations act on the shared index. Every returned path is checked after
//! plugin execution, including cached and expanded results. Filtering may leave
//! fewer results than the requested limit.

use std::collections::HashMap;
use std::sync::Arc;

use kernel::kernel::{validate_path_fast, Kernel, KernelError, OperationContext};
use kernel::Permission;
use nexus_search_common::delegation::from_metadata;
use nexus_search_common::DELEGATION_METADATA_KEY;
use prost::Message;
use tonic::{metadata::MetadataMap, Status};

use crate::auth::{AuthCredentials, AuthProvider, PeerIdentity};
use crate::grpc_plugin_access::{
    request_token, AuthenticatedResponse, AuthorizedPluginCall, PluginGrpcPolicy,
};

/// Generated from the shared SearchService protocol, without the search engine.
pub mod proto {
    tonic::include_proto!("nexus.search.v1");
}

use proto::*;

pub const SERVICE_NAME: &str = "nexus.search.v1.SearchService";

pub struct SearchGrpcPolicy {
    kernel: Arc<Kernel>,
    auth: Arc<dyn AuthProvider>,
}

impl SearchGrpcPolicy {
    pub fn new(kernel: Arc<Kernel>, auth: Arc<dyn AuthProvider>) -> Self {
        Self { kernel, auth }
    }

    fn authenticate(
        &self,
        metadata: &MetadataMap,
        peer: Option<&PeerIdentity>,
        token: &str,
    ) -> Result<OperationContext, Status> {
        let token = request_token(metadata, token)?;
        // A gateway's node certificate authenticates its connection. An
        // explicit bearer still names the caller, whose authority must not be
        // replaced by that node's system privileges.
        self.auth.resolve(&AuthCredentials {
            token,
            peer: if token.is_empty() { peer } else { None },
        })
    }

    fn view(&self, ctx: OperationContext, requested: &str) -> Result<ReadView, Status> {
        ReadView::new(Arc::clone(&self.kernel), ctx, requested)
    }

    fn path_view(&self, ctx: OperationContext, path: &str) -> Result<ReadView, Status> {
        validate_path_fast(path).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let route = self.kernel.vfs_router_arc().route(path, &ctx.zone_id);
        let zone = route
            .as_ref()
            .map(|route| route.zone_id.as_str())
            .unwrap_or(ctx.zone_id.as_str())
            .to_owned();
        let view = self.view(ctx, &zone)?;
        if !view.allows(path)? {
            return Err(Status::permission_denied("search path is not readable"));
        }
        Ok(view)
    }

    fn admin(
        &self,
        metadata: &MetadataMap,
        peer: Option<&PeerIdentity>,
        token: &str,
    ) -> Result<Box<dyn AuthorizedPluginCall>, Status> {
        let ctx = self.authenticate(metadata, peer, token)?;
        if !privileged(&ctx) {
            return Err(Status::permission_denied(
                "search index management requires an administrator",
            ));
        }
        Ok(Box::new(AuthenticatedResponse))
    }
}

impl PluginGrpcPolicy for SearchGrpcPolicy {
    fn authorize(
        &self,
        method: &str,
        payload: &mut Vec<u8>,
        metadata: &MetadataMap,
        peer: Option<&PeerIdentity>,
    ) -> Result<Box<dyn AuthorizedPluginCall>, Status> {
        let method = method.rsplit('/').next().unwrap_or("");
        if method != "Query" && metadata.contains_key(DELEGATION_METADATA_KEY) {
            return Err(Status::unauthenticated(format!(
                "SearchDelegation permits only Query, got {method}",
            )));
        }

        macro_rules! admin {
            ($request:ty) => {{
                let request = decode_request::<$request>(payload)?;
                return self.admin(metadata, peer, &request.auth_token);
            }};
        }

        let filter = match method {
            "Query" => {
                let mut request = decode_request::<QueryRequest>(payload)?;
                // Peer fan-out carries the protobuf credential. Header-only
                // callers must retain their identity on those downstream calls.
                request.auth_token = request_token(metadata, &request.auth_token)?.to_owned();
                let target = if request.zone_id.is_empty() {
                    contracts::ROOT_ZONE_ID
                } else {
                    &request.zone_id
                };
                let delegation = from_metadata(
                    metadata,
                    peer.is_some_and(PeerIdentity::is_cluster_node),
                    "search",
                    target,
                )?;
                let ctx = match delegation {
                    Some(delegation) => {
                        if !request.auth_token.is_empty() {
                            return Err(Status::unauthenticated(
                                "delegation and bearer credentials cannot be combined",
                            ));
                        }
                        // Authenticate the issuing connection as well as its
                        // provenance, so provider revocations still apply.
                        self.authenticate(metadata, peer, &request.auth_token)?;
                        let (kind, subject) = delegation.subject;
                        if kind.is_empty() || subject.is_empty() {
                            return Err(Status::unauthenticated("empty delegated subject"));
                        }
                        let mut ctx = OperationContext::new(&subject, target, false, None, false);
                        ctx.subject_type = kind;
                        ctx.subject_id = Some(subject);
                        ctx.context_zone_id = Some(target.to_owned());
                        ctx.zone_perms = vec![(target.to_owned(), "r".into())];
                        ctx
                    }
                    None => self.authenticate(metadata, peer, &request.auth_token)?,
                };
                let view = self.view(ctx, &request.zone_id)?;
                request.zone_id = view.zone.clone();
                *payload = request.encode_to_vec();
                SearchResponse::Query(view)
            }
            "BatchQuery" => {
                let mut request = decode_request::<BatchQueryRequest>(payload)?;
                request.auth_token = request_token(metadata, &request.auth_token)?.to_owned();
                let ctx = self.authenticate(metadata, peer, &request.auth_token)?;
                let mut views = Vec::with_capacity(request.queries.len());
                for query in &mut request.queries {
                    let view = self.view(ctx.clone(), &query.zone_id)?;
                    query.zone_id = view.zone.clone();
                    // The protocol specifies one credential for the entire batch.
                    query.auth_token = request.auth_token.clone();
                    views.push(view);
                }
                *payload = request.encode_to_vec();
                SearchResponse::Batch(views)
            }
            "Glob" => {
                let request = decode_request::<GlobRequest>(payload)?;
                let ctx = self.authenticate(metadata, peer, &request.auth_token)?;
                SearchResponse::Glob(self.path_view(ctx, &request.root_path)?)
            }
            "Grep" => {
                let request = decode_request::<GrepRequest>(payload)?;
                let ctx = self.authenticate(metadata, peer, &request.auth_token)?;
                SearchResponse::Grep(self.path_view(ctx, &request.root_path)?)
            }
            "Locate" => {
                let mut request = decode_request::<LocateRequest>(payload)?;
                let ctx = self.authenticate(metadata, peer, &request.auth_token)?;
                let view = self.view(ctx, &request.zone_id)?;
                if !view.allows(&request.path)? {
                    return Err(Status::permission_denied("search path is not readable"));
                }
                request.zone_id = view.zone.clone();
                let path = request.path.clone();
                *payload = request.encode_to_vec();
                SearchResponse::Locate(view, path)
            }
            "Index" => admin!(IndexRequest),
            "Refresh" => admin!(RefreshRequest),
            "IndexDocuments" => admin!(IndexDocumentsRequest),
            "NotifyFileChange" => admin!(NotifyFileChangeRequest),
            "ParkedList" => admin!(ParkedListRequest),
            "ParkedRetry" => admin!(ParkedRetryRequest),
            "ParkedDiscard" => admin!(ParkedDiscardRequest),
            "AddIndexedDirectory" => admin!(AddIndexedDirectoryRequest),
            "RemoveIndexedDirectory" => admin!(RemoveIndexedDirectoryRequest),
            "ListIndexedDirectories" => admin!(ListIndexedDirectoriesRequest),
            "SetZoneIndexingMode" => admin!(SetZoneIndexingModeRequest),
            "ListZoneIndexingModes" => admin!(ListZoneIndexingModesRequest),
            "Health" => admin!(HealthRequest),
            "Stats" => admin!(StatsRequest),
            _ => return Err(Status::unimplemented("unknown SearchService method")),
        };
        Ok(Box::new(filter))
    }
}

fn privileged(ctx: &OperationContext) -> bool {
    ctx.is_admin || ctx.is_system
}

struct ReadView {
    kernel: Arc<Kernel>,
    ctx: OperationContext,
    zone: String,
}

impl ReadView {
    fn new(
        kernel: Arc<Kernel>,
        mut ctx: OperationContext,
        requested: &str,
    ) -> Result<Self, Status> {
        let zone = if requested.is_empty() {
            ctx.context_zone_id.as_deref().unwrap_or(&ctx.zone_id)
        } else {
            requested
        };
        let zone = if zone.is_empty() && privileged(&ctx) {
            contracts::ROOT_ZONE_ID
        } else {
            zone
        }
        .to_owned();
        if zone.is_empty()
            || (!privileged(&ctx)
                && !ctx
                    .zone_perms
                    .iter()
                    .any(|(granted, perms)| granted == &zone && perms.contains('r')))
        {
            return Err(Status::permission_denied("search zone is not readable"));
        }
        ctx.zone_id = zone.clone();
        Ok(Self { kernel, ctx, zone })
    }

    fn allows(&self, path: &str) -> Result<bool, Status> {
        if validate_path_fast(path).is_err() {
            return Ok(false);
        }
        // Synthetic views enforce their own access in sys_read, outside the
        // permission-provider slot. Cached snippets never execute sys_read.
        if !privileged(&self.ctx)
            && path
                .split('/')
                .find(|part| !part.is_empty() && *part != ".")
                == Some("__sys__")
        {
            return Ok(false);
        }
        let route = self.kernel.vfs_router_arc().route(path, &self.zone);
        if !privileged(&self.ctx)
            && route
                .as_ref()
                .is_some_and(|route| route.zone_id != self.zone)
        {
            return Ok(false);
        }
        match self.kernel.check_permission_with_route(
            path,
            route.as_ref(),
            Permission::Read,
            &self.ctx,
        ) {
            Ok(()) => Ok(true),
            Err(KernelError::PermissionDenied(_)) => Ok(false),
            Err(error) => Err(Status::internal(format!(
                "search authorization failed: {error}"
            ))),
        }
    }

    fn filter<T>(&self, values: &mut Vec<T>, path: impl Fn(&T) -> &str) -> Result<(), Status> {
        let mut decisions = HashMap::<String, bool>::new();
        let mut kept = Vec::with_capacity(values.len());
        for value in std::mem::take(values) {
            let path = path(&value);
            let allowed = if let Some(allowed) = decisions.get(path) {
                *allowed
            } else {
                let allowed = self.allows(path)?;
                decisions.insert(path.to_owned(), allowed);
                allowed
            };
            if allowed {
                kept.push(value);
            }
        }
        *values = kept;
        Ok(())
    }

    fn query(&self, response: &mut QueryResponse) -> Result<(), Status> {
        response
            .results
            .retain(|hit| hit.zone_id.is_empty() || hit.zone_id == self.zone);
        self.filter(&mut response.results, |hit| &hit.path)?;
        self.redact_error(&mut response.error);
        Ok(())
    }

    fn redact_error(&self, error: &mut Option<String>) {
        if !privileged(&self.ctx) && error.is_some() {
            // A walk/index error may name a file the caller cannot read.
            tracing::debug!(error = ?error, "search response error redacted");
            *error = Some("search operation failed".into());
        }
    }
}

enum SearchResponse {
    Query(ReadView),
    Batch(Vec<ReadView>),
    Glob(ReadView),
    Grep(ReadView),
    Locate(ReadView, String),
}

impl AuthorizedPluginCall for SearchResponse {
    fn complete(self: Box<Self>, payload: Vec<u8>) -> Result<Vec<u8>, Status> {
        match *self {
            Self::Query(view) => {
                let mut response = decode_response::<QueryResponse>(&payload)?;
                view.query(&mut response)?;
                Ok(response.encode_to_vec())
            }
            Self::Batch(views) => {
                let mut response = decode_response::<BatchQueryResponse>(&payload)?;
                if response.responses.len() != views.len() {
                    return Err(Status::internal("search batch response length mismatch"));
                }
                for (response, view) in response.responses.iter_mut().zip(views) {
                    view.query(response)?;
                }
                Ok(response.encode_to_vec())
            }
            Self::Glob(view) => {
                let mut response = decode_response::<GlobResponse>(&payload)?;
                view.filter(&mut response.paths, |path| path)?;
                view.redact_error(&mut response.error);
                Ok(response.encode_to_vec())
            }
            Self::Grep(view) => {
                let mut response = decode_response::<GrepResponse>(&payload)?;
                view.filter(&mut response.matches, |hit| &hit.path)?;
                view.redact_error(&mut response.error);
                Ok(response.encode_to_vec())
            }
            Self::Locate(view, path) => {
                if !view.allows(&path)? {
                    return Err(Status::permission_denied("search path is not readable"));
                }
                Ok(payload)
            }
        }
    }
}

fn decode_request<M: Message + Default>(payload: &[u8]) -> Result<M, Status> {
    M::decode(payload).map_err(|_| Status::invalid_argument("invalid search request"))
}

fn decode_response<M: Message + Default>(payload: &[u8]) -> Result<M, Status> {
    M::decode(payload).map_err(|_| Status::internal("invalid search response"))
}
