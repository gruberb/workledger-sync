use serde::{Deserialize, Serialize};

pub struct AccountInfo {
    pub entry_count: i64,
    pub created_at: i64,
    pub salt: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAccountRequest {
    pub auth_token: String, // hex-encoded SHA-256("auth:" + syncId)
}

#[derive(Debug, Serialize)]
pub struct CreateAccountResponse {
    pub salt: String, // base64-encoded
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateResponse {
    pub valid: bool,
    pub entry_count: i64,
    pub created_at: i64,
    pub salt: String, // base64-encoded, needed for key derivation
}

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub deleted: bool,
}
