use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    pub accounts: AccountMetrics,
    pub entries: EntryMetrics,
    pub storage: StorageMetrics,
    pub collected_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountMetrics {
    pub total: i64,
    pub active_last_24h: i64,
    pub active_last_7d: i64,
    pub active_last_30d: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryMetrics {
    pub total: i64,
    pub active: i64,
    pub archived: i64,
    pub deleted: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageMetrics {
    pub total_payload_bytes: i64,
}
