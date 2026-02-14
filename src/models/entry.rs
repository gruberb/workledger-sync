use serde::{Deserialize, Serialize};

/// Entry as sent/received over the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncEntry {
    pub id: String,
    pub updated_at: i64,
    pub is_archived: bool,
    pub is_deleted: bool,
    pub encrypted_payload: String, // base64
    pub integrity_hash: String,
    #[serde(skip_deserializing)]
    pub server_seq: Option<i64>,
}

/// Entry as stored in the database (without sync_id, which is a query parameter).
#[derive(Debug, sqlx::FromRow)]
pub struct DbEntry {
    pub id: String,
    pub updated_at: i64,
    pub is_archived: bool,
    pub is_deleted: bool,
    pub encrypted_payload: Vec<u8>,
    pub integrity_hash: String,
    pub server_seq: i64,
}

impl DbEntry {
    pub fn to_sync_entry(&self) -> SyncEntry {
        use base64::Engine;
        SyncEntry {
            id: self.id.clone(),
            updated_at: self.updated_at,
            is_archived: self.is_archived,
            is_deleted: self.is_deleted,
            encrypted_payload: base64::engine::general_purpose::STANDARD
                .encode(&self.encrypted_payload),
            integrity_hash: self.integrity_hash.clone(),
            server_seq: Some(self.server_seq),
        }
    }
}
