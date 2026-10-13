//! Durable directory registration and zone indexing configuration.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Extension, Json, Router};
use contracts::operation_context::OperationContext;
use serde::{Deserialize, Serialize};

use crate::handlers::search::SearchError;
use crate::middleware::auth::BearerToken;
use crate::search_proto::{
    AddIndexedDirectoryRequest, ListIndexedDirectoriesRequest, ListZoneIndexingModesRequest,
    RemoveIndexedDirectoryRequest, SetZoneIndexingModeRequest,
};
use crate::zone::effective_zone;
use crate::AppState;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryParameters {
    pub path: String,
    #[serde(default)]
    pub zone_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryQuery {
    #[serde(default)]
    pub zone_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddedBody {
    pub added: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemovedBody {
    pub removed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn add_directory(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Extension(ctx): Extension<OperationContext>,
    Json(body): Json<DirectoryParameters>,
) -> Result<Json<AddedBody>, SearchError> {
    let result = state
        .search
        .client()
        .await?
        .add_indexed_directory(AddIndexedDirectoryRequest {
            path: body.path,
            zone_id: effective_zone(&ctx, &body.zone_id)?,
            auth_token: token.0.to_string(),
        })
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    Ok(Json(AddedBody {
        added: result.added,
        error: result.error,
    }))
}

pub async fn remove_directory(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Extension(ctx): Extension<OperationContext>,
    Query(body): Query<DirectoryParameters>,
) -> Result<Json<RemovedBody>, SearchError> {
    let result = state
        .search
        .client()
        .await?
        .remove_indexed_directory(RemoveIndexedDirectoryRequest {
            path: body.path,
            zone_id: effective_zone(&ctx, &body.zone_id)?,
            auth_token: token.0.to_string(),
        })
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    Ok(Json(RemovedBody {
        removed: result.removed,
        error: result.error,
    }))
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Directory {
    pub path: String,
    pub zone_id: String,
    pub added_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoriesBody {
    pub directories: Vec<Directory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn list_directories(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Extension(ctx): Extension<OperationContext>,
    Query(query): Query<DirectoryQuery>,
) -> Result<Json<DirectoriesBody>, SearchError> {
    let result = state
        .search
        .client()
        .await?
        .list_indexed_directories(ListIndexedDirectoriesRequest {
            zone_id: effective_zone(&ctx, &query.zone_id)?,
            auth_token: token.0.to_string(),
        })
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    Ok(Json(DirectoriesBody {
        directories: result
            .directories
            .into_iter()
            .map(|directory| Directory {
                path: directory.path,
                zone_id: directory.zone_id,
                added_at_ms: directory.added_at_ms,
            })
            .collect(),
        error: result.error,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModeBody {
    pub mode: String,
    #[serde(default)]
    pub zone_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModeResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn set_mode(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Extension(ctx): Extension<OperationContext>,
    Json(body): Json<ModeBody>,
) -> Result<Json<ModeResult>, SearchError> {
    let result = state
        .search
        .client()
        .await?
        .set_zone_indexing_mode(SetZoneIndexingModeRequest {
            mode: body.mode,
            zone_id: effective_zone(&ctx, &body.zone_id)?,
            auth_token: token.0.to_string(),
        })
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    Ok(Json(ModeResult {
        error: result.error,
    }))
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZoneMode {
    pub zone_id: String,
    pub mode: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModesBody {
    pub modes: Vec<ZoneMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn list_modes(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
) -> Result<Json<ModesBody>, SearchError> {
    let result = state
        .search
        .client()
        .await?
        .list_zone_indexing_modes(ListZoneIndexingModesRequest {
            auth_token: token.0.to_string(),
        })
        .await
        .map_err(SearchError::Rpc)?
        .into_inner();
    Ok(Json(ModesBody {
        modes: result
            .modes
            .into_iter()
            .map(|mode| ZoneMode {
                zone_id: mode.zone_id,
                mode: mode.mode,
            })
            .collect(),
        error: result.error,
    }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v2/documents/directories",
            get(list_directories)
                .post(add_directory)
                .delete(remove_directory),
        )
        .route(
            "/v2/documents/indexing-modes",
            get(list_modes).put(set_mode),
        )
}
