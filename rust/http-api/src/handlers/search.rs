//! `/v2/search/*` — HTTP shims over the upstream
//! `nexus.search.v1.SearchService` gRPC surface.  Each handler
//! parses query params, builds a typed proto request, dispatches
//! through the cached [`SearchBackend`] client, and serialises the
//! response as JSON.
//!
//! # Auth / zone / ReBAC
//!
//! Authentication happens in [`crate::middleware::auth`], which stamps
//! the resolved `OperationContext` into request extensions.  Handlers
//! derive the zone from that context via [`crate::zone`] and forward the
//! original bearer credential to Search. Paths remain canonical VFS paths;
//! the host Search policy applies the credential's zone ceiling and live
//! file permissions. Unpinned queries can fan out over readable zones.
//!
//! # Error shape (shared)
//!
//! Every handler surfaces backend / RPC errors as [`SearchError`];
//! the [`IntoResponse`] impl maps `BackendError` → HTTP 503 and
//! `tonic::Status` → HTTP status by gRPC `Code`.  Fence rejections
//! (`SearchError::Fence`) render through the fence module's own
//! [`IntoResponse`] so the 412 body's `X-Nexus-Revision` + payload
//! reach the caller intact.  A new handler reuses the enum + mapper
//! instead of hand-rolling its own.

use crate::error::grpc_status_to_http;
use crate::middleware::auth::BearerToken;
use crate::query::{parse_fusion_method, parse_query_type, query_request};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use contracts::operation_context::OperationContext;
use nexus_search_common::{require_discovery_filters, QueryParameters};
use serde::{Deserialize, Serialize};

use crate::search_proto::{
    BatchQueryRequest, DiscoveryFiles, DiscoveryFilter, GlobRequest, GrepRequest,
    QueryResponse as ProtoQueryResponse, QueryResult as ProtoQueryResult,
};
#[cfg(feature = "rebac")]
use crate::zone::is_privileged;
use crate::zone::{effective_zone, ZoneError};
use crate::{AppState, BackendError};

// ── /v2/search/glob ──────────────────────────────────────────────

/// Query params for `GET /v2/search/glob`.  Field names match the
/// proto's [`GlobRequest`] snake_case names 1:1 so a caller
/// hitting the HTTP surface reads the same doc as one hitting the
/// gRPC surface directly.
#[derive(Debug, Clone, Deserialize)]
pub struct GlobQuery {
    /// Directory the glob walks under.  Defaults to `/` when
    /// unspecified so a caller can drop the param for full-tree
    /// searches.
    #[serde(default = "default_root")]
    pub root_path: String,
    /// Glob pattern (fnmatch-style: `*.rs`, `**/*.md`).
    pub pattern: String,
    /// Cap on returned paths.  0 (or absent) = server default.
    #[serde(default)]
    pub max_results: u32,
    /// Sort results by most-recent-mtime first when `true`.
    #[serde(default)]
    pub sort_recency: bool,
    /// Optional assertion of the zone owning `root_path`. A mismatch
    /// is rejected; discovery addresses the canonical VFS namespace.
    #[serde(default)]
    pub zone_id: String,
    /// Optional working set. JSON `[]` searches nothing; omission walks the root.
    #[serde(default)]
    pub files: Option<Vec<String>>,
}

fn default_root() -> String {
    "/".to_string()
}

/// Response body of [`glob`].  Owned fields so deserialisation
/// callers do not need a `'static` byte source; field names
/// mirror the proto response so wire ↔ HTTP round-trips are
/// name-identical (a caller migrating from the gRPC surface
/// keeps its JSON parser).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobResponse {
    pub paths: Vec<String>,
    pub truncated: bool,
    /// Present only when the upstream reported an application
    /// error (RPC transport errors surface as HTTP 5xx instead).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Applied optional filter bits from the shared DiscoveryFilter protocol.
    #[serde(default)]
    pub applied_filters: u32,
}

pub(super) fn path_zone(
    state: &AppState,
    ctx: &OperationContext,
    root: &str,
    requested: &str,
) -> Result<String, SearchError> {
    let zone = transport::grpc_search_access::search_zone_for_path(&state.vfs_router, ctx, root)
        .map_err(SearchError::Rpc)?;
    effective_zone(ctx, &zone)?;
    if !requested.trim().is_empty() && requested.trim() != zone {
        return Err(SearchError::BadRequest(
            "zone_id does not match the zone owning the path".into(),
        ));
    }
    Ok(zone)
}

/// Handler for `GET /v2/search/glob`.
pub async fn glob(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Extension(ctx): Extension<OperationContext>,
    fence: crate::middleware::revision::RevisionFence,
    Query(params): Query<GlobQuery>,
) -> Result<Response, SearchError> {
    glob_with_params(state, token, ctx, fence, params).await
}

/// JSON form of the same search, for working sets that exceed URL limits.
pub async fn glob_post(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Extension(ctx): Extension<OperationContext>,
    fence: crate::middleware::revision::RevisionFence,
    Json(params): Json<GlobQuery>,
) -> Result<Response, SearchError> {
    glob_with_params(state, token, ctx, fence, params).await
}

async fn glob_with_params(
    state: AppState,
    token: BearerToken,
    ctx: OperationContext,
    fence: crate::middleware::revision::RevisionFence,
    params: GlobQuery,
) -> Result<Response, SearchError> {
    let root_path = params.root_path;
    let zone = path_zone(&state, &ctx, &root_path, &params.zone_id)?;
    // #4737: wait for the fenced revision to be applied on this node
    // BEFORE running the glob, so a caller who just wrote /ws/a.md
    // and passes X-Nexus-Min-Revision sees the row in the walk.
    let observed = fence
        .enforce(std::sync::Arc::clone(&state.kernel), &zone)
        .await
        .map_err(SearchError::Fence)?;
    let mut client = state.search.client().await?;
    let expected_filters = if params.files.is_some() {
        DiscoveryFilter::Files as u32
    } else {
        0
    };
    let req = GlobRequest {
        root_path,
        pattern: params.pattern,
        max_results: params.max_results,
        auth_token: token.0.to_string(),
        sort_recency: params.sort_recency,
        files: params.files.map(|paths| DiscoveryFiles { paths }),
    };
    let resp = crate::search_backend::bounded_rpc(client.glob(tonic::Request::new(req)))
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    require_discovery_filters(expected_filters, resp.applied_filters).map_err(SearchError::Rpc)?;
    let mut response = Json(GlobResponse {
        paths: resp.paths,
        truncated: resp.truncated,
        error: resp.error,
        applied_filters: resp.applied_filters,
    })
    .into_response();
    if let Some(tok) = observed {
        crate::middleware::revision::stamp_revision(&mut response, &tok);
    }
    Ok(response)
}

// ── /v2/search/grep ──────────────────────────────────────────────

/// Query params for `GET /v2/search/grep`.  Field names match the
/// proto's [`GrepRequest`] snake_case names 1:1 (same policy as
/// [`GlobQuery`]).
#[derive(Debug, Clone, Deserialize)]
pub struct GrepQuery {
    /// Directory the grep walks under.  Defaults to `/` for the
    /// same reason as [`GlobQuery::root_path`].
    #[serde(default = "default_root")]
    pub root_path: String,
    /// Regex compiled with the server-side `regex` crate.  Anchors,
    /// groups, and inline flags (`(?i)`) all work.
    pub pattern: String,
    /// Optional file-name filter (globset syntax).  Empty ⇒ scan
    /// every regular file.
    #[serde(default)]
    pub file_pattern: String,
    /// Case-insensitive match — kept as a separate wire field so
    /// "explicit case-insensitive" and "pattern contains `(?i)`"
    /// stay distinguishable.
    #[serde(default)]
    pub ignore_case: bool,
    /// Safety cap; 0 (or absent) = server-side default (1_000).
    #[serde(default)]
    pub max_results: u32,
    /// Lines of context before each match (default 0).
    #[serde(default)]
    pub before_context: u32,
    /// Lines of context after each match (default 0).
    #[serde(default)]
    pub after_context: u32,
    /// Invert: return lines that do NOT match the pattern.
    #[serde(default)]
    pub invert_match: bool,
    /// Sort matches by containing-file mtime descending.
    #[serde(default)]
    pub sort_recency: bool,
    /// Zone to search — same contract as [`GlobQuery::zone_id`] (#4740).
    #[serde(default)]
    pub zone_id: String,
    /// Optional working set. JSON `[]` searches nothing; omission walks the root.
    #[serde(default)]
    pub files: Option<Vec<String>>,
    #[serde(default)]
    pub block_type: Option<String>,
    #[serde(default)]
    pub section: Option<String>,
}

/// One match row in [`GrepResponse::matches`].  Same field names as
/// the proto's `GrepMatch`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrepMatch {
    pub path: String,
    pub line_number: u32,
    pub line: String,
    #[serde(default)]
    pub before: Vec<String>,
    #[serde(default)]
    pub after: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<GrepSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrepSection {
    pub heading: String,
    pub depth: u32,
    pub line_start: u32,
    pub line_end: u32,
}

/// Response body of [`grep`].  Same shape / policy as
/// [`GlobResponse`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrepResponse {
    pub matches: Vec<GrepMatch>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Applied optional filter bits from the shared DiscoveryFilter protocol.
    #[serde(default)]
    pub applied_filters: u32,
}

/// Handler for `GET /v2/search/grep`.
pub async fn grep(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Extension(ctx): Extension<OperationContext>,
    fence: crate::middleware::revision::RevisionFence,
    Query(params): Query<GrepQuery>,
) -> Result<Response, SearchError> {
    grep_with_params(state, token, ctx, fence, params).await
}

/// JSON form of the same search, for working sets that exceed URL limits.
pub async fn grep_post(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Extension(ctx): Extension<OperationContext>,
    fence: crate::middleware::revision::RevisionFence,
    Json(params): Json<GrepQuery>,
) -> Result<Response, SearchError> {
    grep_with_params(state, token, ctx, fence, params).await
}

async fn grep_with_params(
    state: AppState,
    token: BearerToken,
    ctx: OperationContext,
    fence: crate::middleware::revision::RevisionFence,
    params: GrepQuery,
) -> Result<Response, SearchError> {
    let root_path = params.root_path;
    let zone = path_zone(&state, &ctx, &root_path, &params.zone_id)?;
    // #4737: fence BEFORE the walk so a fresh write is visible in matches.
    let observed = fence
        .enforce(std::sync::Arc::clone(&state.kernel), &zone)
        .await
        .map_err(SearchError::Fence)?;
    let mut client = state.search.client().await?;
    let expected_filters = (if params.files.is_some() {
        DiscoveryFilter::Files as u32
    } else {
        0
    }) | (if params.block_type.is_some() {
        DiscoveryFilter::BlockType as u32
    } else {
        0
    }) | (if params.section.is_some() {
        DiscoveryFilter::Section as u32
    } else {
        0
    });
    let req = GrepRequest {
        root_path,
        pattern: params.pattern,
        file_pattern: params.file_pattern,
        ignore_case: params.ignore_case,
        max_results: params.max_results,
        before_context: params.before_context,
        after_context: params.after_context,
        invert_match: params.invert_match,
        auth_token: token.0.to_string(),
        sort_recency: params.sort_recency,
        files: params.files.map(|paths| DiscoveryFiles { paths }),
        block_type: params.block_type,
        section: params.section,
    };
    let resp = crate::search_backend::bounded_rpc(client.grep(tonic::Request::new(req)))
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    require_discovery_filters(expected_filters, resp.applied_filters).map_err(SearchError::Rpc)?;
    let body = GrepResponse {
        matches: resp
            .matches
            .into_iter()
            .map(|m| GrepMatch {
                path: m.path,
                line_number: m.line_number,
                line: m.line,
                before: m.before,
                after: m.after,
                section: m.section.map(|section| GrepSection {
                    heading: section.heading,
                    depth: section.depth,
                    line_start: section.line_start,
                    line_end: section.line_end,
                }),
            })
            .collect(),
        truncated: resp.truncated,
        error: resp.error,
        applied_filters: resp.applied_filters,
    };
    let mut response = Json(body).into_response();
    if let Some(tok) = observed {
        crate::middleware::revision::stamp_revision(&mut response, &tok);
    }
    Ok(response)
}

// ── /v2/search/query ─────────────────────────────────────────────

/// JSON body for `POST /v2/search/query`.  Field names match the
/// proto's [`crate::search_proto::QueryRequest`] snake_case names 1:1 (same policy as
/// [`GlobQuery`] / [`GrepQuery`]).  Enum-shaped fields land as
/// wire-friendly lowercase strings so a caller reading the proto
/// enum values and a caller reading this doc reach the same shape.
pub type QueryBody = QueryParameters;

/// One result row in [`QueryResponseBody::results`].  Every field
/// mirrors the proto's [`QueryResult`](ProtoQueryResult) so a
/// caller migrating from the gRPC surface keeps its JSON parser.
/// Optional fields serialise as absent (`skip_serializing_if =
/// Option::is_none`) so the wire stays compact for the common case
/// where an attribution field did not apply.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QueryHit {
    pub path: String,
    pub chunk_index: u32,
    pub chunk_text: String,
    pub score: f32,
    pub zone_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expanded_context: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyword_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_boost: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recency_boost: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expansion_variant_index: Option<u32>,
}

/// Response body of [`query`].  Same absent-when-none policy as
/// [`GlobResponse`] / [`GrepResponse`] for the `error` field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QueryResponseBody {
    pub results: Vec<QueryHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl From<ProtoQueryResponse> for QueryResponseBody {
    fn from(response: ProtoQueryResponse) -> Self {
        Self {
            results: response.results.into_iter().map(hit_from_proto).collect(),
            error: response.error,
        }
    }
}

/// One authenticated, order-preserving BatchQuery call. Each query addresses
/// one zone; an omitted zone selects the caller's default zone.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchQueryBody {
    pub queries: Vec<QueryBody>,
}

#[derive(Debug, Serialize)]
pub struct BatchQueryResponseBody {
    pub responses: Vec<QueryResponseBody>,
}

fn hit_from_proto(r: ProtoQueryResult) -> QueryHit {
    QueryHit {
        path: r.path,
        chunk_index: r.chunk_index,
        chunk_text: r.chunk_text,
        score: r.score,
        zone_id: r.zone_id,
        mtime_ms: r.mtime_ms,
        expanded_context: r.expanded_context,
        title_score: r.title_score,
        keyword_score: r.keyword_score,
        vector_score: r.vector_score,
        tier_boost: r.tier_boost,
        recency_boost: r.recency_boost,
        expansion_variant_index: r.expansion_variant_index,
    }
}

/// Handler for `POST /v2/search/query`.  JSON body variant of the
/// proto's `Query` RPC — GET-with-query-string would work for
/// simple cases but the request shape (hybrid knobs + recency
/// tuple + `path_prefix_boosts` map) is JSON-shaped in practice,
/// so a POST body keeps the wire honest.
///
/// # Federated vs single-zone dispatch
///
/// Under `--features rebac`, the handler consults the caller's
/// ReBAC-derived readable zone set:
///
/// * **0 or 1 zone** ⇒ single-zone fast path (unchanged).  The
///   common case pays nothing: one tonic call to the local plugin.
/// * **>1 zone** AND the wire body did NOT pin `zone_id` ⇒
///   dispatch through [`nexus_federated_search::FederatedSearchDispatcher`]:
///   fan out per zone, fuse via RRF, return one unified list.
/// * **>1 zone** BUT the wire body pinned `zone_id` ⇒ single-zone
///   path (the caller explicitly narrowed the scope).
///
/// A non-rebac build is unconditionally single-zone — the readable
/// zone set is not derivable there.
pub async fn query(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Extension(ctx): Extension<OperationContext>,
    fence: crate::middleware::revision::RevisionFence,
    Json(body): Json<QueryBody>,
) -> Result<Response, SearchError> {
    parse_query_type(&body.query_type).map_err(SearchError::BadRequest)?;
    parse_fusion_method(&body.fusion_method).map_err(SearchError::BadRequest)?;
    // #4740: the index zone is the caller's zone, never a wire-supplied
    // one (admins may still name a zone explicitly).
    let zone_id = effective_zone(&ctx, &body.zone_id)?;

    // Unpinned queries can fan out across the caller's readable zones.
    #[cfg(feature = "rebac")]
    {
        if body.zone_id.is_empty() {
            let subject = subject_for(&ctx);
            let subject = (subject.0.to_owned(), subject.1.to_owned());
            let cache = std::sync::Arc::clone(&state.accessible_zones);
            let store = std::sync::Arc::clone(&state.rebac_store);
            let accessible = tokio::task::spawn_blocking(move || {
                cache.lookup(&*store, (&subject.0, &subject.1))
            })
            .await
            .map_err(|_| nexus_federated_search::DispatchError::ZoneDiscoveryUnavailable)?
            .map_err(|_| nexus_federated_search::DispatchError::ZoneDiscoveryUnavailable)?;
            if accessible.len() > 1 {
                return dispatch_federated(state, ctx, token, fence, body, &zone_id).await;
            }
        }
    }

    // Issue #4737: wait for the fenced revision to be applied on this
    // node BEFORE running the search, so a read-after-write against a
    // co-hosted cluster observes the just-committed row.  No-op when
    // the caller did not send X-Nexus-Min-Revision.
    let observed = fence
        .enforce(std::sync::Arc::clone(&state.kernel), &zone_id)
        .await
        .map_err(SearchError::Fence)?;
    let mut client = state.search.client().await?;
    let mut body = body;
    body.zone_id = zone_id;
    let mut req = query_request(body).map_err(SearchError::BadRequest)?;
    req.auth_token = token.0.to_string();
    let resp = crate::search_backend::bounded_rpc(client.query(tonic::Request::new(req)))
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    let mut response = Json(QueryResponseBody::from(resp)).into_response();
    if let Some(tok) = observed {
        crate::middleware::revision::stamp_revision(&mut response, &tok);
    }
    Ok(response)
}

/// HTTP adapter for BatchQuery. The host authorizes the entire batch under the
/// original credential, then applies live file permissions to each response.
pub async fn batch_query(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Extension(ctx): Extension<OperationContext>,
    fence: crate::middleware::revision::RevisionFence,
    Json(body): Json<BatchQueryBody>,
) -> Result<Response, SearchError> {
    nexus_search_common::query::validate_batch_size(body.queries.len())
        .map_err(SearchError::BadRequest)?;
    let queries = body
        .queries
        .into_iter()
        .map(|mut query| {
            query.zone_id = effective_zone(&ctx, &query.zone_id)?;
            query_request(query).map_err(SearchError::BadRequest)
        })
        .collect::<Result<Vec<_>, SearchError>>()?;
    // As with federated Query, the request fence covers the caller's default
    // zone on this node. It does not fence remote replicas or other zones.
    let fence_zone = effective_zone(&ctx, "")?;
    let observed = fence
        .enforce(std::sync::Arc::clone(&state.kernel), &fence_zone)
        .await
        .map_err(SearchError::Fence)?;
    let response = crate::search_backend::bounded_rpc(state.search.client().await?.batch_query(
        BatchQueryRequest {
            queries,
            auth_token: token.0.to_string(),
        },
    ))
    .await
    .map_err(SearchError::Rpc)?
    .into_inner();
    let mut response = Json(BatchQueryResponseBody {
        responses: response.responses.into_iter().map(Into::into).collect(),
    })
    .into_response();
    if let Some(token) = observed {
        crate::middleware::revision::stamp_revision(&mut response, &token);
    }
    Ok(response)
}

/// Dispatch a multi-zone query through the federated dispatcher.
/// Called ONLY from the federated fast-out in [`query`] above — the
/// caller has already confirmed the caller's readable zone set has
/// more than one entry and no wire `zone_id` narrows the scope.
///
/// Fences against `fence_zone` (the caller's index zone from
/// `effective_zone`) so a read-after-write in the caller's default
/// zone still sees its own writes.  The revision fence covers this
/// node and default zone; it does not fence remote replicas.
#[cfg(feature = "rebac")]
async fn dispatch_federated(
    state: AppState,
    ctx: OperationContext,
    token: BearerToken,
    fence: crate::middleware::revision::RevisionFence,
    body: QueryBody,
    fence_zone: &str,
) -> Result<Response, SearchError> {
    let observed = fence
        .enforce(std::sync::Arc::clone(&state.kernel), fence_zone)
        .await
        .map_err(SearchError::Fence)?;
    let subject = subject_for(&ctx);
    let req = nexus_federated_search::SearchRequest {
        auth_token: token.0.to_string(),
        parameters: std::sync::Arc::new(body),
        // Overwritten by the dispatcher from `subject` — the field
        // must exist on construction.
        subject: (String::new(), String::new()),
    };
    let zones: Vec<String> = ctx
        .zone_perms
        .iter()
        .filter(|(_, perms)| perms.contains('r'))
        .map(|(zone, _)| zone.clone())
        .collect();
    let filter = (!is_privileged(&ctx)).then_some(zones.as_slice());
    let resp = state.federated.search(subject, req, filter).await?;
    let results = resp
        .results
        .into_iter()
        .map(crate::handlers::search::QueryHit::from)
        .collect();
    // The federated envelope carries zones_searched / zones_failed
    // that a caller may want to inspect; today the wire shape stays
    // the plain `{results, error}` for byte-compat with the single-
    // zone path.  Surfacing the per-zone breakdown is a wire-level
    // addition (needs a caller who reads it) — deferred.
    let error = (!resp.zones_failed.is_empty()).then(|| {
        format!(
            "{} zone(s) failed: {}",
            resp.zones_failed.len(),
            resp.zones_failed
                .iter()
                .map(|f| format!("{}={}", f.zone_id, f.error))
                .collect::<Vec<_>>()
                .join("; ")
        )
    });
    let mut response = Json(QueryResponseBody { results, error }).into_response();
    if let Some(tok) = observed {
        crate::middleware::revision::stamp_revision(&mut response, &tok);
    }
    Ok(response)
}

/// Extract a `(subject_type, subject_id)` pair from the caller's
/// [`OperationContext`].  `OperationContext` already models the
/// ReBAC subject with two typed fields — `subject_type` (defaults to
/// `"user"`) and `subject_id` (the id string; `None` for the legacy
/// user_id-only path).  Empty / absent id maps to `("user",
/// "anonymous")` — matches the Python delegation-mint fallback and
/// keeps the "who is this?" question always answerable.
#[cfg(feature = "rebac")]
fn subject_for(ctx: &OperationContext) -> (&str, &str) {
    let subject_type = if ctx.subject_type.is_empty() {
        "user"
    } else {
        ctx.subject_type.as_str()
    };
    // Prefer the typed subject_id; fall back to user_id when the
    // caller went through the legacy no-typed-subject path.  Empty
    // in both maps to the anonymous fallback.
    let subject_id: &str = ctx.subject_id.as_deref().unwrap_or(ctx.user_id.as_str());
    let subject_id = if subject_id.is_empty() {
        "anonymous"
    } else {
        subject_id
    };
    (subject_type, subject_id)
}

// ── Router + shared error ────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v2/search/glob", get(glob).post(glob_post))
        .route("/v2/search/grep", get(grep).post(grep_post))
        .route("/v2/search/query", post(query))
        .route("/v2/search/query/batch", post(batch_query))
}

/// Shared handler-level error surfaced as an HTTP response.
///
/// Three-state mapping:
///   * `BackendUnavailable` → 503 (backend down; retry-friendly).
///   * `BadRequest(msg)` → 400 (caller-side error caught before RPC —
///     e.g. an unknown `query_type` string).  Emitting `Ok` and
///     letting the request through would silently downgrade to the
///     proto's `UNSPECIFIED = 0 ⇒ keyword` posture, hiding caller
///     typos (`"semantik"`) as "keyword returned no hits" for weeks.
///   * `Rpc(status)` → gRPC `Code` mapped via [`grpc_status_to_http`]
///     — see that fn's docstring for the full table.  The upstream
///     `tonic::Status::message()` rides through in the JSON body so
///     operators debugging a hang see the source signal.
///
/// One enum per `search.rs` — every handler in this module maps
/// its errors through here so the error contract stays uniform
/// across `glob`, `grep`, `query`, and every future route.
#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    #[error("backend unavailable: {0}")]
    BackendUnavailable(#[from] BackendError),
    #[cfg(feature = "rebac")]
    #[error("{0}")]
    Discovery(#[from] nexus_federated_search::DispatchError),
    #[error("bad request: {0}")]
    BadRequest(String),
    /// #4740: zone refusal — zone-less non-admin caller, an explicit
    /// `zone_id` that is not the caller's, or a path naming another
    /// zone.  403.
    #[error("forbidden: {0}")]
    Forbidden(#[from] ZoneError),
    /// #4737: read-your-writes fence rejected the request (400 / 412 /
    /// 501 / 503 shape owned by [`crate::middleware::revision::FenceError`]).
    /// Handed through verbatim so the 412 body's `current_revision` +
    /// `waited_ms` + `X-Nexus-Revision` header reach the caller
    /// intact (the generic `{"error": ...}` envelope below would lose them).
    #[error("revision fence: {0}")]
    Fence(crate::middleware::revision::FenceError),
    #[error("rpc failed: {0}")]
    Rpc(tonic::Status),
}

impl IntoResponse for SearchError {
    fn into_response(self) -> Response {
        // `FenceError` owns its own `IntoResponse` (412 body carries
        // current_revision + waited_ms + stamps X-Nexus-Revision — none
        // of that fits the generic `{"error": ...}` shape below), so
        // pass it through untouched.
        if let SearchError::Fence(e) = self {
            return e.into_response();
        }
        let overloaded =
            matches!(&self, SearchError::Rpc(s) if s.code() == tonic::Code::ResourceExhausted);
        let (status, message) = match self {
            SearchError::BackendUnavailable(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
            #[cfg(feature = "rebac")]
            SearchError::Discovery(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
            SearchError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            SearchError::Forbidden(e) => (StatusCode::FORBIDDEN, e.to_string()),
            SearchError::Rpc(s) => (grpc_status_to_http(s.code()), s.message().to_string()),
            SearchError::Fence(_) => unreachable!("handled above"),
        };
        let mut response = (status, Json(serde_json::json!({ "error": message }))).into_response();
        if overloaded {
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_static("5"),
            );
        }
        response
    }
}
