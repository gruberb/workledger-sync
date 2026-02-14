use serde::{Deserialize, Serialize};

use super::entry::SyncEntry;

#[derive(Debug, Deserialize)]
pub struct PushRequest {
    pub entries: Vec<SyncEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PushResponse {
    pub accepted: usize,
    pub conflicts: Vec<ConflictEntry>,
    pub server_seq: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictEntry {
    pub id: String,
    pub server_updated_at: i64,
    pub server_seq: i64,
}

#[derive(Debug, Deserialize)]
pub struct PullQuery {
    pub since: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PullResponse {
    pub entries: Vec<SyncEntry>,
    pub server_seq: i64,
    pub has_more: bool,
}

#[derive(Debug, Deserialize)]
pub struct FullSyncRequest {
    pub entries: Vec<SyncEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FullSyncResponse {
    pub entries: Vec<SyncEntry>,
    pub server_seq: i64,
    pub merged: usize,
}
