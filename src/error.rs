use std::fmt;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub enum AppError {
    NotFound(String),
    BadRequest(String),
    Database(sqlx::Error),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::NotFound(msg) => write!(f, "not found: {msg}"),
            AppError::BadRequest(msg) => write!(f, "bad request: {msg}"),
            AppError::Database(e) => write!(f, "database error: {e}"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::NotFound(msg) => {
                tracing::warn!(error_type = "not_found", message = %msg, "Responding with 404");
                (StatusCode::NOT_FOUND, msg)
            }
            AppError::BadRequest(msg) => {
                tracing::warn!(error_type = "bad_request", message = %msg, "Responding with 400");
                (StatusCode::BAD_REQUEST, msg)
            }
            AppError::Database(e) => {
                tracing::error!(error_type = "database", error = %e, "Responding with 500");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Database(e)
    }
}
