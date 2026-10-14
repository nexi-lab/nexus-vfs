//! Path configuration HTTP transport over the authenticated Search gRPC service.
use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};

use crate::handlers::search::SearchError;
use crate::middleware::auth::BearerToken;
use crate::search_proto::{
    self, DeletePathContextRequest, ListPathContextsRequest, PutPathContextRequest,
};
use crate::AppState;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutBody {
    #[serde(default = "default_zone")]
    pub zone_id: String,
    pub path_prefix: String,
    pub description: String,
    pub weight: Option<f64>,
}

fn default_zone() -> String {
    crate::zone::ROOT_ZONE_ID.to_owned()
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub zone_id: Option<String>,
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    pub zone_id: String,
    pub path_prefix: String,
}

#[derive(Serialize)]
pub struct Record {
    zone_id: String,
    path_prefix: String,
    description: String,
    weight: Option<f64>,
    created_at: String,
    updated_at: String,
}

impl From<search_proto::PathContext> for Record {
    fn from(record: search_proto::PathContext) -> Self {
        Self {
            zone_id: record.zone_id,
            path_prefix: record.path_prefix,
            description: record.description,
            weight: record.weight,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }
}

#[derive(Serialize)]
pub struct ListBody {
    contexts: Vec<Record>,
}

#[derive(Serialize)]
pub struct DeletedBody {
    zone_id: String,
    path_prefix: String,
    status: &'static str,
}

pub async fn put(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Json(body): Json<PutBody>,
) -> Result<Json<Record>, SearchError> {
    let result = crate::search_backend::bounded_rpc(state.search.client().await?.put_path_context(
        PutPathContextRequest {
            zone_id: body.zone_id,
            path_prefix: body.path_prefix,
            description: body.description,
            weight: body.weight,
            auth_token: token.0.to_string(),
        },
    ))
    .await
    .map_err(SearchError::Rpc)?
    .into_inner();
    Ok(Json(result.into()))
}

pub async fn list(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListBody>, SearchError> {
    let result =
        crate::search_backend::bounded_rpc(state.search.client().await?.list_path_contexts(
            ListPathContextsRequest {
                zone_id: query.zone_id,
                auth_token: token.0.to_string(),
            },
        ))
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    Ok(Json(ListBody {
        contexts: result.contexts.into_iter().map(Into::into).collect(),
    }))
}

pub async fn delete(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<DeletedBody>, SearchError> {
    let result =
        crate::search_backend::bounded_rpc(state.search.client().await?.delete_path_context(
            DeletePathContextRequest {
                zone_id: query.zone_id,
                path_prefix: query.path_prefix,
                auth_token: token.0.to_string(),
            },
        ))
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    Ok(Json(DeletedBody {
        zone_id: result.zone_id,
        path_prefix: result.path_prefix,
        status: "deleted",
    }))
}

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/v2/search/path-contexts",
        get(list).put(put).delete(delete),
    )
}
