use serde::{Deserialize, Serialize};

const MAX_ENTRY_ID_LEN: usize = 256;
pub const MAX_ENCRYPTED_PAYLOAD_LEN: usize = 700_000;

/// Why an entry was rejected. Size is separate because clients treat it
/// differently: a malformed entry is a bug, an oversized one can never be
/// accepted and should be skipped instead of retried.
#[derive(Debug, PartialEq, Eq)]
pub enum EntryValidationError {
    Invalid(String),
    TooLarge { len: usize },
}

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
    pub fn validate(&self) -> Result<(), EntryValidationError> {
        use EntryValidationError::{Invalid, TooLarge};

        if self.id.is_empty() || self.id.len() > MAX_ENTRY_ID_LEN {
            return Err(Invalid(format!(
                "id length must be 1-{MAX_ENTRY_ID_LEN}, got {}",
                self.id.len()
            )));
        }
        if self.updated_at <= 0 {
            return Err(Invalid("updatedAt must be positive".into()));
        }
        if self.encrypted_payload.len() > MAX_ENCRYPTED_PAYLOAD_LEN {
            return Err(TooLarge { len: self.encrypted_payload.len() });
        }
        // Deleted entries may have an empty payload and hash (clients before
        // 3.3.0 send empty tombstones; newer clients send encrypted ones).
        if !self.is_deleted {
            if self.encrypted_payload.is_empty() {
                return Err(Invalid("encryptedPayload must not be empty".into()));
            }
            if self.integrity_hash.len() != 64
                || !self.integrity_hash.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(Invalid("integrityHash must be exactly 64 hex chars".into()));
            }
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
