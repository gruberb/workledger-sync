use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::sync_id::is_valid_auth_token;

const AUTH_TOKEN_HEADER: &str = "x-auth-token";

/// Extract and validate the X-Auth-Token header.
/// The auth token is SHA-256("auth:" + syncId), computed client-side.
/// The server stores it directly — no re-hashing needed.
/// The raw sync ID never reaches the server.
pub async fn require_auth_token(mut req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().path().to_string();

    let token = req
        .headers()
        .get(AUTH_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match token {
        Some(t) if is_valid_auth_token(&t) => {
            tracing::debug!(
                auth_token = %&t[..12],
                method = %method,
                uri = %uri,
                "Auth middleware: token valid, forwarding to handler"
            );
            req.extensions_mut().insert(AuthToken(t));
            next.run(req).await
        }
        Some(_) => {
            tracing::warn!(
                method = %method,
                uri = %uri,
                "Auth middleware: rejected — invalid token format"
            );
            (StatusCode::BAD_REQUEST, "Invalid auth token format").into_response()
        }
        None => {
            tracing::warn!(
                method = %method,
                uri = %uri,
                "Auth middleware: rejected — missing X-Auth-Token header"
            );
            (StatusCode::UNAUTHORIZED, "Missing X-Auth-Token header").into_response()
        }
    }
}

/// Extractor for the validated auth token.
/// This is SHA-256("auth:" + syncId), matching what's stored in the DB.
#[derive(Debug, Clone)]
pub struct AuthToken(pub String);
