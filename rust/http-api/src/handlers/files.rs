//! File HTTP operations delegate to the node's typed VFS RPCs.

use crate::error::grpc_status_to_http;
use crate::middleware::auth::BearerToken;
use crate::{AppState, BackendError};
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::map_response;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use contracts::constants::MAX_GRPC_MESSAGE_BYTES;
use kernel::kernel::vfs_proto::{
    BatchStatItem, BatchStatRequest, DeleteRequest, MkdirRequest, ReadRequest, ReaddirRequest,
    RenameRequest, StatRequest, StatResponse, WriteRequest,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use transport::grpc::RpcErrorCode;

#[derive(Debug, thiserror::Error)]
enum FileError {
    #[error("{0}")]
    Backend(#[from] BackendError),
    #[error("{0}")]
    Rpc(Box<tonic::Status>),
    #[error("{message}")]
    Rejected { status: StatusCode, message: String },
}

impl From<tonic::Status> for FileError {
    fn from(status: tonic::Status) -> Self {
        Self::Rpc(Box::new(status))
    }
}

impl IntoResponse for FileError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Backend(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()),
            Self::Rpc(error) => (
                grpc_status_to_http(error.code()),
                error.message().to_owned(),
            ),
            Self::Rejected { status, message } => (status, message),
        };
        (status, Json(serde_json::json!({"error":message}))).into_response()
    }
}

impl FileError {
    fn protocol(message: &str) -> Self {
        Self::Rejected {
            status: StatusCode::BAD_GATEWAY,
            message: message.to_owned(),
        }
    }
}

fn check_reply(is_error: bool, payload: &[u8]) -> Result<(), FileError> {
    if !is_error {
        return Ok(());
    }
    #[derive(Deserialize)]
    struct WireError {
        code: i64,
        message: String,
    }
    let error: WireError = serde_json::from_slice(payload)
        .map_err(|_| FileError::protocol("VFS returned an invalid error response"))?;
    let status = match error.code {
        code if code == RpcErrorCode::InvalidPath as i64
            || code == RpcErrorCode::ValidationError as i64
            || code == RpcErrorCode::OffsetOutOfRange as i64 =>
        {
            StatusCode::BAD_REQUEST
        }
        code if code == RpcErrorCode::PermissionError as i64 => StatusCode::FORBIDDEN,
        code if code == RpcErrorCode::AccessDenied as i64 => StatusCode::UNAUTHORIZED,
        code if code == RpcErrorCode::FileNotFound as i64 => StatusCode::NOT_FOUND,
        code if code == RpcErrorCode::Conflict as i64 => StatusCode::CONFLICT,
        code if code == RpcErrorCode::InternalError as i64 => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_GATEWAY,
    };
    Err(FileError::Rejected {
        status,
        message: error.message,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathQuery {
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteQuery {
    path: String,
    #[serde(default)]
    recursive: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    path: String,
    #[serde(default)]
    recursive: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryBody {
    path: String,
    #[serde(default)]
    parents: bool,
    #[serde(default)]
    exist_ok: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameBody {
    path: String,
    new_path: String,
}

#[derive(Serialize)]
struct FileMetadata {
    path: String,
    size: i64,
    mime_type: String,
    is_directory: bool,
    version: u32,
    gen: u64,
    zone_id: String,
    created_at_ms: Option<i64>,
    modified_at_ms: Option<i64>,
    owner_id: String,
}

#[derive(Serialize)]
struct DirectoryListing {
    entries: Vec<FileMetadata>,
}

macro_rules! metadata_from {
    ($($source:ty),+ $(,)?) => { $(
        impl From<$source> for FileMetadata {
            fn from(value: $source) -> Self {
                Self {
                    path: value.path, size: value.size, mime_type: value.mime_type,
                    is_directory: value.is_directory, version: value.version, gen: value.gen,
                    zone_id: value.zone_id, created_at_ms: value.created_at_ms,
                    modified_at_ms: value.modified_at_ms, owner_id: value.owner_id,
                }
            }
        }
    )+ };
}
metadata_from!(StatResponse, BatchStatItem);

async fn read(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Query(query): Query<PathQuery>,
) -> Result<Response, FileError> {
    let reply = state
        .vfs
        .client()
        .await?
        .read(ReadRequest {
            path: query.path,
            auth_token: token.0.to_string(),
            ..Default::default()
        })
        .await?
        .into_inner();
    check_reply(reply.is_error, &reply.error_payload)?;
    let mut response = Response::new(Body::from(reply.content));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(response)
}

async fn write(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Query(query): Query<PathQuery>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, FileError> {
    let request = WriteRequest {
        path: query.path,
        content: body.to_vec(),
        auth_token: token.0.to_string(),
    };
    if request.encoded_len() > MAX_GRPC_MESSAGE_BYTES {
        return Err(FileError::Rejected {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: "File exceeds the VFS RPC message limit".into(),
        });
    }
    let reply = state.vfs.client().await?.write(request).await?.into_inner();
    check_reply(reply.is_error, &reply.error_payload)?;
    Ok(Json(
        serde_json::json!({"size":reply.size,"gen":reply.gen,"content_id":reply.content_id}),
    ))
}

async fn metadata(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Query(query): Query<PathQuery>,
) -> Result<Json<FileMetadata>, FileError> {
    let reply = state
        .vfs
        .client()
        .await?
        .stat(StatRequest {
            path: query.path,
            auth_token: token.0.to_string(),
            zone_id: String::new(),
        })
        .await?
        .into_inner();
    check_reply(reply.is_error, &reply.error_payload)?;
    if !reply.found {
        return Err(FileError::Rejected {
            status: StatusCode::NOT_FOUND,
            message: "File does not exist".into(),
        });
    }
    Ok(Json(reply.into()))
}

async fn list(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Query(query): Query<ListQuery>,
) -> Result<Json<DirectoryListing>, FileError> {
    let mut client = state.vfs.client().await?;
    let reply = client
        .readdir(ReaddirRequest {
            path: query.path,
            auth_token: token.0.to_string(),
            recursive: query.recursive,
            ..Default::default()
        })
        .await?
        .into_inner();
    check_reply(reply.is_error, &reply.error_payload)?;
    // One vectored stat preserves the native metadata and permission contract.
    let paths: Vec<_> = reply.entries.into_iter().map(|entry| entry.name).collect();
    if paths.is_empty() {
        return Ok(Json(DirectoryListing {
            entries: Vec::new(),
        }));
    }
    let expected = paths.len();
    let stats = client
        .batch_stat(BatchStatRequest {
            paths,
            auth_token: token.0.to_string(),
            zone_id: String::new(),
        })
        .await?
        .into_inner();
    if stats.results.len() != expected {
        return Err(FileError::protocol(
            "VFS returned an incomplete metadata batch",
        ));
    }
    let entries: Vec<FileMetadata> = stats
        .results
        .into_iter()
        .filter(|item| item.found)
        .map(Into::into)
        .collect();
    Ok(Json(DirectoryListing { entries }))
}

async fn delete(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<serde_json::Value>, FileError> {
    let reply = state
        .vfs
        .client()
        .await?
        .delete(DeleteRequest {
            path: query.path,
            auth_token: token.0.to_string(),
            recursive: query.recursive,
        })
        .await?
        .into_inner();
    check_reply(reply.is_error, &reply.error_payload)?;
    let deleted = reply
        .success
        .ok_or_else(|| FileError::protocol("VFS did not acknowledge deletion"))?;
    Ok(Json(serde_json::json!({"deleted":deleted})))
}

async fn mkdir(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Json(body): Json<DirectoryBody>,
) -> Result<Json<serde_json::Value>, FileError> {
    let reply = state
        .vfs
        .client()
        .await?
        .mkdir(MkdirRequest {
            path: body.path,
            auth_token: token.0.to_string(),
            parents: body.parents,
            exist_ok: body.exist_ok,
        })
        .await?
        .into_inner();
    check_reply(reply.is_error, &reply.error_payload)?;
    if !reply.hit {
        return Err(FileError::protocol(
            "VFS did not acknowledge directory creation",
        ));
    }
    Ok(Json(serde_json::json!({"hit":reply.hit})))
}

async fn rename(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
    Json(body): Json<RenameBody>,
) -> Result<Json<serde_json::Value>, FileError> {
    let reply = state
        .vfs
        .client()
        .await?
        .rename(RenameRequest {
            path: body.path,
            new_path: body.new_path,
            auth_token: token.0.to_string(),
        })
        .await?
        .into_inner();
    check_reply(reply.is_error, &reply.error_payload)?;
    if !reply.hit || !reply.success {
        return Err(FileError::protocol("VFS did not acknowledge rename"));
    }
    Ok(Json(
        serde_json::json!({"success":reply.success,"is_directory":reply.is_directory}),
    ))
}

async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v2/files",
            get(read)
                .put(write)
                .delete(delete)
                .layer(DefaultBodyLimit::max(MAX_GRPC_MESSAGE_BYTES)),
        )
        .route("/v2/files/metadata", get(metadata))
        .route("/v2/files/rename", post(rename))
        .route("/v2/directories", get(list).post(mkdir))
        .layer(map_response(no_store))
}
