use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Middleware that validates the `Authorization: Bearer <token>` header
/// against the `ADMIN_TOKEN` environment variable.
///
/// - If `ADMIN_TOKEN` is not set, returns 404 (hides the endpoint entirely).
/// - If the token is missing or wrong, returns 401.
pub async fn require_admin_token(req: Request, next: Next) -> Response {
    let expected = match std::env::var("ADMIN_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    let provided = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(token) if token == expected => next.run(req).await,
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}
