use axum::{extract::State, response::IntoResponse, Json};

use crate::error::AppError;
use crate::AppState;

pub async fn get_metrics(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let metrics = state.repo.get_metrics().await?;
    Ok(Json(metrics))
}
