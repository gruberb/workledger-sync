use std::env;

pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub cors_origins: Vec<String>,
    pub max_entries_per_account: i64,
    pub max_payload_bytes: usize,
    pub cleanup_inactive_days: i64,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:workledger-sync.db".to_string()),
            cors_origins: env::var("CORS_ORIGINS")
                .unwrap_or_else(|_| {
                    "https://workledger.org,https://www.workledger.org,http://localhost:5173".to_string()
                })
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            max_entries_per_account: env::var("MAX_ENTRIES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000),
            max_payload_bytes: env::var("MAX_PAYLOAD_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_048_576), // 1 MB
            cleanup_inactive_days: env::var("CLEANUP_INACTIVE_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(90),
        }
    }
}
