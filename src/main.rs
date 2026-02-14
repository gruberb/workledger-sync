use axum::http::StatusCode;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing_subscriber::EnvFilter;

use workledger_sync::config::Config;
use workledger_sync::middleware::rate_limit::RateLimiter;
use workledger_sync::repository::SyncRepository;
use workledger_sync::sqlite_repo::SqliteRepository;
use workledger_sync::util::now_millis;
use workledger_sync::{build_app, db, AppState};

fn build_cors(config: &Config) -> CorsLayer {
    use axum::http::{header, Method};

    let origins: Vec<_> = config
        .cors_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::HeaderName::from_static("x-auth-token")])
}

/// Background job: purge inactive accounts.
async fn cleanup_job(repo: Arc<dyn SyncRepository>, inactive_days: i64) {
    let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));

    loop {
        interval.tick().await;

        let cutoff = now_millis() - (inactive_days * 24 * 60 * 60 * 1000);

        match repo.purge_inactive_accounts(cutoff).await {
            Ok(count) => {
                if count > 0 {
                    tracing::info!("Cleaned up {} inactive accounts", count);
                }
            }
            Err(e) => tracing::error!("Cleanup job error: {e}"),
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env();

    let pool = db::init_pool(&config.database_url)
        .await
        .expect("Failed to initialize database");

    tracing::info!("Database initialized at {}", config.database_url);

    let cors = build_cors(&config);

    let repo = Arc::new(SqliteRepository::new(pool.clone()));
    let rate_limiter = RateLimiter::new(
        config.rate_limit_account_creation,
        config.rate_limit_account_creation,
    );
    let state = AppState {
        repo: repo.clone(),
        max_entries_per_account: config.max_entries_per_account,
        rate_limiter: rate_limiter.clone(),
    };

    let app = build_app(state)
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)))
        .layer(RequestBodyLimitLayer::new(config.max_payload_bytes))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_request(trace::DefaultOnRequest::new().level(Level::INFO))
                .on_response(
                    trace::DefaultOnResponse::new()
                        .level(Level::INFO)
                        .latency_unit(tower_http::LatencyUnit::Millis),
                ),
        )
        .layer(cors);

    // Spawn cleanup background jobs
    tokio::spawn(cleanup_job(repo, config.cleanup_inactive_days));
    tokio::spawn({
        let rl = rate_limiter;
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(600));
            loop {
                interval.tick().await;
                rl.cleanup().await;
            }
        }
    });

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("Starting server on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server error");
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install Ctrl+C handler");
    tracing::info!("Shutting down...");
}
