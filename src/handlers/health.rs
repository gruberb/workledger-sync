use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::AppState;

pub async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    match state.repo.health_check().await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "degraded" })),
        ),
    }
}
