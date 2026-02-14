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

impl SyncEntry {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() || self.id.len() > 256 {
            return Err(format!("id length must be 1-256, got {}", self.id.len()));
        }
        if self.updated_at <= 0 {
            return Err("updatedAt must be positive".into());
        }
        if self.encrypted_payload.is_empty() || self.encrypted_payload.len() > 700_000 {
            return Err(format!(
                "encryptedPayload length must be 1-700000, got {}",
                self.encrypted_payload.len()
            ));
        }
        if self.integrity_hash.len() != 64
            || !self.integrity_hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err("integrityHash must be exactly 64 hex chars".into());
        }
        Ok(())
    }
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
