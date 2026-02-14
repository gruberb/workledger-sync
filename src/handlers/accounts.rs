use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use base64::Engine;
use rand::Rng;

use crate::error::AppError;
use crate::middleware::auth::AuthToken;
use crate::util::token_prefix;
use crate::models::account::{
    CreateAccountRequest, CreateAccountResponse, DeleteResponse, ValidateResponse,
};
use crate::sync_id::is_valid_auth_token;
use crate::AppState;

/// POST /api/v1/accounts — create a new account.
/// The client sends an auth token: SHA-256("auth:" + syncId).
/// The server never sees the raw sync ID.
pub async fn create_account(
    State(state): State<AppState>,
    Json(body): Json<CreateAccountRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        handler = "create_account",
        auth_token = %token_prefix(&body.auth_token),
        "Handler: POST /api/v1/accounts"
    );

    if !state.rate_limiter.check(&body.auth_token).await {
        return Err(AppError::TooManyRequests("Rate limit exceeded".into()));
    }

    if !is_valid_auth_token(&body.auth_token) {
        tracing::warn!(handler = "create_account", "Validation failed: invalid auth token format");
        return Err(AppError::BadRequest("Invalid auth token format".into()));
    }

    let salt: [u8; 16] = rand::thread_rng().gen();

    tracing::debug!(handler = "create_account", "Dispatching to repo.create_account");
    state.repo.create_account(&body.auth_token, &salt).await?;
    tracing::debug!(handler = "create_account", "Repo returned: account created");

    tracing::info!(
        handler = "create_account",
        auth_token = %token_prefix(&body.auth_token),
        status = 201,
        "Responding: account created with salt"
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateAccountResponse {
            salt: base64::engine::general_purpose::STANDARD.encode(salt),
        }),
    ))
}

/// GET /api/v1/accounts/validate — check if an account exists and return salt.
pub async fn validate_account(
    State(state): State<AppState>,
    Extension(AuthToken(auth_token)): Extension<AuthToken>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        handler = "validate_account",
        auth_token = %token_prefix(&auth_token),
        "Handler: GET /api/v1/accounts/validate"
    );

    tracing::debug!(handler = "validate_account", "Dispatching to repo.find_account");
    let account = state.repo.find_account(&auth_token).await?;
    tracing::debug!(
        handler = "validate_account",
        found = account.is_some(),
        "Repo returned"
    );

    match account {
        Some(account) => {
            tracing::debug!(handler = "validate_account", "Dispatching to repo.update_last_seen");
            if let Err(e) = state.repo.update_last_seen(&auth_token).await {
                tracing::warn!(error = %e, "Failed to update last_seen");
            }

            tracing::info!(
                handler = "validate_account",
                auth_token = %token_prefix(&auth_token),
                entry_count = account.entry_count,
                status = 200,
                "Responding: account valid"
            );

            Ok(Json(ValidateResponse {
                valid: true,
                entry_count: account.entry_count,
                created_at: account.created_at,
                salt: base64::engine::general_purpose::STANDARD.encode(account.salt),
            }))
        }
        None => {
            tracing::info!(
                handler = "validate_account",
                auth_token = %token_prefix(&auth_token),
                status = 200,
                "Responding: account not found (valid=false)"
            );
            Ok(Json(ValidateResponse {
                valid: false,
                entry_count: 0,
                created_at: 0,
                salt: String::new(),
            }))
        }
    }
}

/// DELETE /api/v1/accounts — delete account and all entries.
pub async fn delete_account(
    State(state): State<AppState>,
    Extension(AuthToken(auth_token)): Extension<AuthToken>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        handler = "delete_account",
        auth_token = %token_prefix(&auth_token),
        "Handler: DELETE /api/v1/accounts"
    );

    tracing::debug!(handler = "delete_account", "Dispatching to repo.delete_account");
    let deleted = state.repo.delete_account(&auth_token).await?;
    tracing::debug!(handler = "delete_account", deleted, "Repo returned");

    if !deleted {
        return Err(AppError::NotFound("Account not found".into()));
    }

    tracing::info!(
        handler = "delete_account",
        auth_token = %token_prefix(&auth_token),
        status = 200,
        "Responding: account deleted"
    );

    Ok(Json(DeleteResponse { deleted: true }))
}
