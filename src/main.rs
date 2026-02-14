use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{AllowHeaders, AllowMethods, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing_subscriber::EnvFilter;

use workledger_sync::config::Config;
use workledger_sync::repository::SyncRepository;
use workledger_sync::sqlite_repo::SqliteRepository;
use workledger_sync::util::now_millis;
use workledger_sync::{build_app, db, AppState};

fn build_cors(config: &Config) -> CorsLayer {
    let origins: Vec<_> = config
        .cors_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(AllowMethods::any())
        .allow_headers(AllowHeaders::any())
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
    let state = AppState {
        repo: repo.clone(),
        max_entries_per_account: config.max_entries_per_account,
    };

    let app = build_app(state)
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

    // Spawn cleanup background job
    tokio::spawn(cleanup_job(repo, config.cleanup_inactive_days));

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
