use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore, Nonce};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;

use workledger_sync::sqlite_repo::SqliteRepository;
use workledger_sync::{build_app, db, AppState};

// -- Helpers ------------------------------------------------------------------

async fn setup_app() -> axum::Router {
    setup_app_with_limit(10_000).await
}

async fn setup_app_with_limit(max_entries: i64) -> axum::Router {
    let pool = db::init_pool("sqlite::memory:").await.unwrap();
    let repo = Arc::new(SqliteRepository::new(pool));
    let state = AppState {
        repo,
        max_entries_per_account: max_entries,
    };
    build_app(state)
}

async fn json_request(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth_token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let has_body = body.is_some();
    let body_str = body.map(|b| b.to_string()).unwrap_or_default();
    let mut builder = Request::builder().method(method).uri(uri);

    if let Some(token) = auth_token {
        builder = builder.header("x-auth-token", token);
    }
    if has_body {
        builder = builder.header("content-type", "application/json");
    }

    let req = builder.body(Body::from(body_str)).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// Generate a sync ID client-side: `wl-` + 32 hex chars (128 bits).
fn generate_sync_id() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    format!("wl-{}", hex::encode(bytes))
}

/// Split-key derivation: auth token for server authentication.
/// SHA-256("auth:" + syncId) — this is what the server stores and sees.
fn derive_auth_token(sync_id: &str) -> String {
    let hash = Sha256::digest(format!("auth:{sync_id}").as_bytes());
    hex::encode(hash)
}

/// Split-key derivation: crypto seed for encryption key derivation.
/// SHA-256("crypto:" + syncId) — this NEVER leaves the client.
fn derive_crypto_seed(sync_id: &str) -> Vec<u8> {
    Sha256::digest(format!("crypto:{sync_id}").as_bytes()).to_vec()
}

/// Derive an AES-256-GCM key from a crypto seed and base64-encoded salt.
fn derive_key(crypto_seed: &[u8], salt_b64: &str) -> Vec<u8> {
    let salt = base64::engine::general_purpose::STANDARD
        .decode(salt_b64)
        .unwrap();
    let mut key = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(crypto_seed, &salt, 100_000, &mut key);
    key
}

/// Encrypt plaintext with AES-256-GCM. Returns base64-encoded (nonce || ciphertext).
fn encrypt(key: &[u8], plaintext: &str) -> String {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).unwrap();

    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    base64::engine::general_purpose::STANDARD.encode(&combined)
}

/// Decrypt base64-encoded (nonce || ciphertext) with AES-256-GCM.
fn decrypt(key: &[u8], encrypted_b64: &str) -> Result<String, &'static str> {
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encrypted_b64)
        .map_err(|_| "bad base64")?;
    if combined.len() < 12 {
        return Err("too short");
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| "decrypt failed")?;
    String::from_utf8(plaintext).map_err(|_| "bad utf8")
}

/// Compute SHA-256 integrity hash of plaintext.
fn integrity_hash(plaintext: &str) -> String {
    let hash = Sha256::digest(plaintext.as_bytes());
    hex::encode(hash)
}

/// Create an account using split-key design.
/// Returns (auth_token, crypto_seed, salt_b64).
async fn create_account(app: &axum::Router) -> (String, Vec<u8>, String) {
    let sync_id = generate_sync_id();
    let auth_token = derive_auth_token(&sync_id);
    let crypto_seed = derive_crypto_seed(&sync_id);

    let (status, body) = json_request(
        app,
        "POST",
        "/api/v1/accounts",
        None,
        Some(json!({ "authToken": auth_token })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let salt = body["salt"].as_str().unwrap().to_string();
    (auth_token, crypto_seed, salt)
}

// -- Tests --------------------------------------------------------------------

#[tokio::test]
async fn test_create_account_and_validate() {
    let app = setup_app().await;
    let (auth_token, _crypto_seed, salt) = create_account(&app).await;

    // Validate using the auth token in header
    let (status, body) = json_request(
        &app,
        "GET",
        "/api/v1/accounts/validate",
        Some(&auth_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true);
    assert_eq!(body["entryCount"], 0);
    assert_eq!(body["salt"].as_str().unwrap(), salt);
}

#[tokio::test]
async fn test_validate_nonexistent_account() {
    let app = setup_app().await;
    // Use a valid-format auth token (64 hex chars) that doesn't exist
    let fake_token = "0000000000000000000000000000000000000000000000000000000000000000";
    let (status, body) = json_request(
        &app,
        "GET",
        "/api/v1/accounts/validate",
        Some(fake_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], false);
}

#[tokio::test]
async fn test_push_pull_roundtrip_with_encryption() {
    let app = setup_app().await;
    let (auth_token, crypto_seed, salt) = create_account(&app).await;

    // Derive encryption key from crypto seed (NOT from auth token)
    let key = derive_key(&crypto_seed, &salt);

    // Encrypt two entries
    let entry1_plain = r#"{"blocks":[{"type":"paragraph","content":"Hello world"}],"tags":["work"],"dayKey":"2026-02-14"}"#;
    let entry2_plain = r#"{"blocks":[{"type":"paragraph","content":"Secret notes"}],"tags":["personal"],"dayKey":"2026-02-14"}"#;

    let entry1_encrypted = encrypt(&key, entry1_plain);
    let entry2_encrypted = encrypt(&key, entry2_plain);

    // Push entries (auth token in header)
    let push_body = json!({
        "entries": [
            {
                "id": "entry-001",
                "updatedAt": 1000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": entry1_encrypted,
                "integrityHash": integrity_hash(entry1_plain)
            },
            {
                "id": "entry-002",
                "updatedAt": 2000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": entry2_encrypted,
                "integrityHash": integrity_hash(entry2_plain)
            }
        ]
    });

    let (status, body) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(push_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 2);
    assert_eq!(body["conflicts"].as_array().unwrap().len(), 0);

    // Pull entries back
    let (status, body) = json_request(
        &app,
        "GET",
        "/api/v1/sync/pull?since=0",
        Some(&auth_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);

    // Decrypt and verify each entry
    for entry in entries {
        let payload_b64 = entry["encryptedPayload"].as_str().unwrap();
        let decrypted = decrypt(&key, payload_b64).expect("decryption should succeed");
        let hash = entry["integrityHash"].as_str().unwrap();

        assert_eq!(integrity_hash(&decrypted), hash);

        let parsed: Value = serde_json::from_str(&decrypted).unwrap();
        assert!(parsed["blocks"].is_array());
        assert!(parsed["tags"].is_array());
    }
}

#[tokio::test]
async fn test_entries_are_actually_encrypted_on_server() {
    let app = setup_app().await;
    let (auth_token, crypto_seed, salt) = create_account(&app).await;
    let key = derive_key(&crypto_seed, &salt);

    let plaintext = r#"{"blocks":[],"tags":["TOP SECRET"],"dayKey":"2026-02-14"}"#;
    let encrypted = encrypt(&key, plaintext);

    let push_body = json!({
        "entries": [{
            "id": "entry-secret",
            "updatedAt": 1000,
            "isArchived": false,
            "isDeleted": false,
            "encryptedPayload": encrypted,
            "integrityHash": integrity_hash(plaintext)
        }]
    });

    let (status, _) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(push_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = json_request(
        &app,
        "GET",
        "/api/v1/sync/pull?since=0",
        Some(&auth_token),
        None,
    )
    .await;

    let stored_payload = body["entries"][0]["encryptedPayload"].as_str().unwrap();

    let raw_bytes = base64::engine::general_purpose::STANDARD
        .decode(stored_payload)
        .unwrap();
    let as_string = String::from_utf8_lossy(&raw_bytes);

    assert!(
        !as_string.contains("TOP SECRET"),
        "Plaintext content should not be visible in stored payload"
    );
    assert!(
        !as_string.contains("dayKey"),
        "Plaintext keys should not be visible in stored payload"
    );
}

#[tokio::test]
async fn test_different_users_cannot_decrypt_each_others_entries() {
    let app = setup_app().await;

    let (auth_token_a, crypto_seed_a, salt_a) = create_account(&app).await;
    let (auth_token_b, crypto_seed_b, salt_b) = create_account(&app).await;

    assert_ne!(auth_token_a, auth_token_b);

    let key_a = derive_key(&crypto_seed_a, &salt_a);
    let key_b = derive_key(&crypto_seed_b, &salt_b);

    assert_ne!(key_a, key_b, "Different accounts must derive different keys");

    // User A pushes an encrypted entry
    let secret_a = r#"{"blocks":[{"type":"paragraph","content":"User A private data"}],"tags":[],"dayKey":"2026-02-14"}"#;
    let encrypted_a = encrypt(&key_a, secret_a);

    let (status, _) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token_a),
        Some(json!({
            "entries": [{
                "id": "entry-a1",
                "updatedAt": 1000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": encrypted_a,
                "integrityHash": integrity_hash(secret_a)
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // User B pushes an encrypted entry
    let secret_b = r#"{"blocks":[{"type":"paragraph","content":"User B private data"}],"tags":[],"dayKey":"2026-02-14"}"#;
    let encrypted_b = encrypt(&key_b, secret_b);

    let (status, _) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token_b),
        Some(json!({
            "entries": [{
                "id": "entry-b1",
                "updatedAt": 1000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": encrypted_b,
                "integrityHash": integrity_hash(secret_b)
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Pull each user's entries
    let (_, body_a) = json_request(
        &app,
        "GET",
        "/api/v1/sync/pull?since=0",
        Some(&auth_token_a),
        None,
    )
    .await;

    let (_, body_b) = json_request(
        &app,
        "GET",
        "/api/v1/sync/pull?since=0",
        Some(&auth_token_b),
        None,
    )
    .await;

    assert_eq!(body_a["entries"].as_array().unwrap().len(), 1);
    assert_eq!(body_b["entries"].as_array().unwrap().len(), 1);

    let payload_a = body_a["entries"][0]["encryptedPayload"].as_str().unwrap();
    let payload_b = body_b["entries"][0]["encryptedPayload"].as_str().unwrap();

    let decrypted_a = decrypt(&key_a, payload_a).expect("A should decrypt own entry");
    assert!(decrypted_a.contains("User A private data"));

    let decrypted_b = decrypt(&key_b, payload_b).expect("B should decrypt own entry");
    assert!(decrypted_b.contains("User B private data"));

    // Cross-decryption must fail
    assert!(
        decrypt(&key_b, payload_a).is_err(),
        "User B's key must not decrypt User A's entries"
    );
    assert!(
        decrypt(&key_a, payload_b).is_err(),
        "User A's key must not decrypt User B's entries"
    );
}

#[tokio::test]
async fn test_server_cannot_derive_encryption_key() {
    // This test verifies the split-key design:
    // The auth token (what the server sees) cannot be used to derive the encryption key.
    let app = setup_app().await;
    let (auth_token, crypto_seed, salt) = create_account(&app).await;

    // The real encryption key uses the crypto seed
    let real_key = derive_key(&crypto_seed, &salt);

    // If the server tried to use the auth token as key material, it would get a different key
    let salt_bytes = base64::engine::general_purpose::STANDARD
        .decode(&salt)
        .unwrap();
    let mut server_attempt = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(auth_token.as_bytes(), &salt_bytes, 100_000, &mut server_attempt);

    assert_ne!(
        real_key, server_attempt,
        "Auth token must not derive the same key as crypto seed"
    );

    // Encrypt with real key, verify server's attempted key can't decrypt
    let plaintext = r#"{"secret":"data"}"#;
    let encrypted = encrypt(&real_key, plaintext);

    assert!(
        decrypt(&server_attempt, &encrypted).is_err(),
        "Server's key attempt must fail to decrypt"
    );
}

#[tokio::test]
async fn test_full_sync_merges_entries() {
    let app = setup_app().await;
    let (auth_token, crypto_seed, salt) = create_account(&app).await;
    let key = derive_key(&crypto_seed, &salt);

    // Push one entry first
    let entry1 = r#"{"content":"entry 1"}"#;
    let (status, _) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(json!({
            "entries": [{
                "id": "entry-001",
                "updatedAt": 1000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": encrypt(&key, entry1),
                "integrityHash": integrity_hash(entry1)
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Full sync from a "second device"
    let entry2 = r#"{"content":"entry 2 from device B"}"#;
    let (status, body) = json_request(
        &app,
        "POST",
        "/api/v1/sync/full",
        Some(&auth_token),
        Some(json!({
            "entries": [{
                "id": "entry-002",
                "updatedAt": 2000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": encrypt(&key, entry2),
                "integrityHash": integrity_hash(entry2)
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "Full sync should return all entries");

    for entry in entries {
        let payload = entry["encryptedPayload"].as_str().unwrap();
        decrypt(&key, payload).expect("All entries should be decryptable with the account key");
    }
}

#[tokio::test]
async fn test_lww_conflict_resolution() {
    let app = setup_app().await;
    let (auth_token, crypto_seed, salt) = create_account(&app).await;
    let key = derive_key(&crypto_seed, &salt);

    let v1 = r#"{"content":"version 1"}"#;
    let (status, _) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(json!({
            "entries": [{
                "id": "entry-conflict",
                "updatedAt": 2000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": encrypt(&key, v1),
                "integrityHash": integrity_hash(v1)
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Older version should conflict
    let v_old = r#"{"content":"old version"}"#;
    let (status, body) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(json!({
            "entries": [{
                "id": "entry-conflict",
                "updatedAt": 1000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": encrypt(&key, v_old),
                "integrityHash": integrity_hash(v_old)
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 0);
    assert_eq!(body["conflicts"].as_array().unwrap().len(), 1);
    assert_eq!(body["conflicts"][0]["id"], "entry-conflict");

    // Newer version should win
    let v2 = r#"{"content":"version 2 wins"}"#;
    let (status, body) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(json!({
            "entries": [{
                "id": "entry-conflict",
                "updatedAt": 3000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": encrypt(&key, v2),
                "integrityHash": integrity_hash(v2)
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 1);

    let (_, body) = json_request(
        &app,
        "GET",
        "/api/v1/sync/pull?since=0",
        Some(&auth_token),
        None,
    )
    .await;
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    let decrypted = decrypt(&key, entries[0]["encryptedPayload"].as_str().unwrap()).unwrap();
    assert!(decrypted.contains("version 2 wins"));
}

#[tokio::test]
async fn test_delete_account_removes_everything() {
    let app = setup_app().await;
    let (auth_token, crypto_seed, salt) = create_account(&app).await;
    let key = derive_key(&crypto_seed, &salt);

    let entry = r#"{"content":"will be deleted"}"#;
    let (status, _) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(json!({
            "entries": [{
                "id": "entry-doomed",
                "updatedAt": 1000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": encrypt(&key, entry),
                "integrityHash": integrity_hash(entry)
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) =
        json_request(&app, "DELETE", "/api/v1/accounts", Some(&auth_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], true);

    let (status, body) = json_request(
        &app,
        "GET",
        "/api/v1/accounts/validate",
        Some(&auth_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], false);
}

#[tokio::test]
async fn test_missing_auth_token_header_rejected() {
    let app = setup_app().await;
    let (status, _) = json_request(&app, "GET", "/api/v1/sync/pull?since=0", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_invalid_auth_token_format_rejected() {
    let app = setup_app().await;
    let (status, _) = json_request(
        &app,
        "GET",
        "/api/v1/sync/pull?since=0",
        Some("bad-format"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_entry_limit_enforcement() {
    let app = setup_app_with_limit(2).await;
    let (auth_token, crypto_seed, salt) = create_account(&app).await;
    let key = derive_key(&crypto_seed, &salt);

    // Push 2 entries (at the limit)
    let entry1 = r#"{"content":"entry 1"}"#;
    let entry2 = r#"{"content":"entry 2"}"#;
    let (status, body) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(json!({
            "entries": [
                {
                    "id": "e1",
                    "updatedAt": 1000,
                    "isArchived": false,
                    "isDeleted": false,
                    "encryptedPayload": encrypt(&key, entry1),
                    "integrityHash": integrity_hash(entry1)
                },
                {
                    "id": "e2",
                    "updatedAt": 2000,
                    "isArchived": false,
                    "isDeleted": false,
                    "encryptedPayload": encrypt(&key, entry2),
                    "integrityHash": integrity_hash(entry2)
                }
            ]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 2);

    // Push a third entry — should be rejected (limit is 2)
    let entry3 = r#"{"content":"entry 3"}"#;
    let (status, body) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(json!({
            "entries": [{
                "id": "e3",
                "updatedAt": 3000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": encrypt(&key, entry3),
                "integrityHash": integrity_hash(entry3)
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("limit"));
}

#[tokio::test]
async fn test_pull_pagination_has_more() {
    let app = setup_app().await;
    let (auth_token, crypto_seed, salt) = create_account(&app).await;
    let key = derive_key(&crypto_seed, &salt);

    // Push 3 entries
    let entries: Vec<Value> = (1..=3)
        .map(|i| {
            let plain = format!(r#"{{"content":"entry {}"}}"#, i);
            json!({
                "id": format!("e{}", i),
                "updatedAt": i * 1000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": encrypt(&key, &plain),
                "integrityHash": integrity_hash(&plain)
            })
        })
        .collect();

    let (status, _) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(json!({ "entries": entries })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Pull with limit=2 — should get 2 entries and hasMore=true
    let (status, body) = json_request(
        &app,
        "GET",
        "/api/v1/sync/pull?since=0&limit=2",
        Some(&auth_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["entries"].as_array().unwrap().len(), 2);
    assert_eq!(body["hasMore"], true);

    // Pull remaining with since = last server_seq from previous page
    let last_seq = body["entries"][1]["serverSeq"].as_i64().unwrap();
    let (status, body) = json_request(
        &app,
        "GET",
        &format!("/api/v1/sync/pull?since={}&limit=2", last_seq),
        Some(&auth_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["entries"].as_array().unwrap().len(), 1);
    assert_eq!(body["hasMore"], false);
}

#[tokio::test]
async fn test_entry_count_updates_after_push() {
    let app = setup_app().await;
    let (auth_token, crypto_seed, salt) = create_account(&app).await;
    let key = derive_key(&crypto_seed, &salt);

    // Validate — entry count starts at 0
    let (_, body) = json_request(
        &app,
        "GET",
        "/api/v1/accounts/validate",
        Some(&auth_token),
        None,
    )
    .await;
    assert_eq!(body["entryCount"], 0);

    // Push 2 entries
    let entries: Vec<Value> = (1..=2)
        .map(|i| {
            let plain = format!(r#"{{"content":"entry {}"}}"#, i);
            json!({
                "id": format!("e{}", i),
                "updatedAt": i * 1000,
                "isArchived": false,
                "isDeleted": false,
                "encryptedPayload": encrypt(&key, &plain),
                "integrityHash": integrity_hash(&plain)
            })
        })
        .collect();

    let (status, _) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(json!({ "entries": entries })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Validate — entry count should be 2
    let (_, body) = json_request(
        &app,
        "GET",
        "/api/v1/accounts/validate",
        Some(&auth_token),
        None,
    )
    .await;
    assert_eq!(body["entryCount"], 2);

    // Push a deleted entry — should not count
    let deleted_plain = r#"{"content":"deleted"}"#;
    let (status, _) = json_request(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(&auth_token),
        Some(json!({
            "entries": [{
                "id": "e3",
                "updatedAt": 3000,
                "isArchived": false,
                "isDeleted": true,
                "encryptedPayload": encrypt(&key, deleted_plain),
                "integrityHash": integrity_hash(deleted_plain)
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Entry count should still be 2 (deleted entries don't count)
    let (_, body) = json_request(
        &app,
        "GET",
        "/api/v1/accounts/validate",
        Some(&auth_token),
        None,
    )
    .await;
    assert_eq!(body["entryCount"], 2);
}
