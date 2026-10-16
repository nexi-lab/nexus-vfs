//! The request's authenticated principal, projected from the shared auth context.

use axum::{extract::Extension, http::header, response::IntoResponse, routing::get, Json, Router};
use contracts::operation_context::OperationContext;
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityResponse {
    pub subject_type: String,
    pub subject_id: String,
    pub user_id: String,
    pub agent_id: Option<String>,
    pub zone_id: String,
    pub is_admin: bool,
    pub zone_perms: Vec<(String, String)>,
}

async fn whoami(Extension(ctx): Extension<OperationContext>) -> impl IntoResponse {
    let identity = IdentityResponse {
        subject_type: ctx.subject_type,
        subject_id: ctx.subject_id.unwrap_or_else(|| ctx.user_id.clone()),
        user_id: ctx.user_id,
        agent_id: ctx.agent_id,
        zone_id: ctx.zone_id,
        is_admin: ctx.is_admin,
        zone_perms: ctx.zone_perms,
    };
    ([(header::CACHE_CONTROL, "no-store")], Json(identity))
}

pub fn router() -> Router<AppState> {
    Router::new().route("/v2/auth/whoami", get(whoami))
}
