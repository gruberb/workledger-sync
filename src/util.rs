use std::time::{SystemTime, UNIX_EPOCH};

pub fn token_prefix(t: &str) -> &str {
    &t[..t.len().min(12)]
}

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
