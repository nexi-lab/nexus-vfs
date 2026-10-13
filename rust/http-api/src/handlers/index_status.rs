//! Search index status through the authenticated Search gRPC host.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use contracts::operation_context::OperationContext;
use serde::{Deserialize, Serialize};

use crate::handlers::search::SearchError;
use crate::middleware::auth::BearerToken;
use crate::middleware::revision::RevisionFence;
use crate::search_proto::{HealthRequest, LocateRequest};
use crate::zone::effective_zone;
use crate::AppState;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocateBody {
    pub path: String,
    #[serde(default)]
    pub zone_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocateResponseBody {
    pub indexed: bool,
    pub chunk_count: u32,
    pub mtime_ms: Option<i64>,
    pub zone_id: String,
}

pub async fn locate(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Extension(ctx): Extension<OperationContext>,
    fence: RevisionFence,
    Json(body): Json<LocateBody>,
) -> Result<Response, SearchError> {
    let zone_id = effective_zone(&ctx, &body.zone_id)?;
    let observed = fence
        .enforce(std::sync::Arc::clone(&state.kernel), &zone_id)
        .await
        .map_err(SearchError::Fence)?;
    let result = state
        .search
        .client()
        .await?
        .locate(LocateRequest {
            path: body.path,
            zone_id,
            auth_token: token.0.to_string(),
        })
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    let mut response = Json(LocateResponseBody {
        indexed: result.indexed,
        chunk_count: result.chunk_count,
        mtime_ms: result.mtime_ms,
        zone_id: result.zone_id,
    })
    .into_response();
    if let Some(token) = observed {
        crate::middleware::revision::stamp_revision(&mut response, &token);
    }
    Ok(response)
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponseBody {
    pub status: String,
    pub detail: String,
    pub fts_writer_faults: u32,
    pub fts_writer_unavailable: u32,
    pub last_verified_commit_age_ms: Option<i64>,
    pub dispatch_panics: u32,
}

pub async fn health(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
) -> Result<Json<HealthResponseBody>, SearchError> {
    let result = state
        .search
        .client()
        .await?
        .health(HealthRequest {
            auth_token: token.0.to_string(),
        })
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    Ok(Json(HealthResponseBody {
        status: result.status,
        detail: result.detail,
        fts_writer_faults: result.fts_writer_faults,
        fts_writer_unavailable: result.fts_writer_unavailable,
        last_verified_commit_age_ms: result.last_verified_commit_age_ms,
        dispatch_panics: result.dispatch_panics,
    }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v2/search/locate", post(locate))
        .route("/v2/search/health", get(health))
}
