pub mod config;
pub mod db;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod repository;
pub mod sqlite_repo;
pub mod sync_id;
pub mod util;

use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post},
    Router,
};
use middleware::rate_limit::RateLimiter;
use repository::SyncRepository;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub repo: Arc<dyn SyncRepository>,
    pub max_entries_per_account: i64,
    pub rate_limiter: RateLimiter,
}

fn authenticated_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/accounts/validate",
            get(handlers::accounts::validate_account),
        )
        .route(
            "/api/v1/accounts",
            delete(handlers::accounts::delete_account),
        )
        .route("/api/v1/sync/push", post(handlers::sync::push))
        .route("/api/v1/sync/pull", get(handlers::sync::pull))
        .route("/api/v1/sync/full", post(handlers::sync::full_sync))
        .layer(axum_middleware::from_fn(middleware::auth::require_auth_token))
}

fn public_routes() -> Router<AppState> {
    Router::new().route(
        "/api/v1/accounts",
        post(handlers::accounts::create_account),
    )
}

fn health_routes() -> Router<AppState> {
    Router::new().route("/health", get(handlers::health::health_check))
}

fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/admin/metrics", get(handlers::admin::get_metrics))
        .layer(axum_middleware::from_fn(
            middleware::admin_auth::require_admin_token,
        ))
}

/// Build the full application router (used by main and tests).
pub fn build_app(state: AppState) -> Router {
    Router::new()
        .merge(authenticated_routes())
        .merge(public_routes())
        .merge(health_routes())
        .merge(admin_routes())
        .with_state(state)
}
