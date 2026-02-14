use async_trait::async_trait;
use base64::Engine;
use sqlx::SqlitePool;

use crate::error::AppError;
use crate::models::account::AccountInfo;
use crate::models::entry::{DbEntry, SyncEntry};
use crate::models::sync::ConflictEntry;
use crate::repository::{SyncRepository, UpsertResult};
use crate::util::now_millis;

pub struct SqliteRepository {
    pool: SqlitePool,
}

impl SqliteRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[async_trait]
impl SyncRepository for SqliteRepository {
    async fn create_account(&self, auth_token: &str, salt: &[u8]) -> Result<(), AppError> {
        let token_prefix = &auth_token[..12];
        tracing::debug!(auth_token = %token_prefix, "db: INSERT accounts");

        let now = now_millis();

        sqlx::query(
            "INSERT INTO accounts (sync_id, salt, created_at, last_seen_at, entry_count) VALUES (?, ?, ?, ?, 0)",
        )
        .bind(auth_token)
        .bind(salt)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        tracing::debug!(auth_token = %token_prefix, "db: account row inserted");

        sqlx::query("INSERT INTO sync_cursors (sync_id, next_seq) VALUES (?, 1)")
            .bind(auth_token)
            .execute(&self.pool)
            .await?;

        tracing::debug!(auth_token = %token_prefix, "db: sync cursor initialized at seq=1");

        Ok(())
    }

    async fn find_account(&self, auth_token: &str) -> Result<Option<AccountInfo>, AppError> {
        let token_prefix = &auth_token[..12];
        tracing::debug!(auth_token = %token_prefix, "db: SELECT account");

        let row: Option<(i64, i64, Vec<u8>)> = sqlx::query_as(
            "SELECT entry_count, created_at, salt FROM accounts WHERE sync_id = ?",
        )
        .bind(auth_token)
        .fetch_optional(&self.pool)
        .await?;

        match &row {
            Some((entry_count, _, _)) => {
                tracing::debug!(auth_token = %token_prefix, entry_count, "db: account found");
            }
            None => {
                tracing::debug!(auth_token = %token_prefix, "db: account not found");
            }
        }

        Ok(row.map(|(entry_count, created_at, salt)| AccountInfo {
            entry_count,
            created_at,
            salt,
        }))
    }

    async fn account_exists(&self, auth_token: &str) -> Result<bool, AppError> {
        let token_prefix = &auth_token[..12];
        tracing::debug!(auth_token = %token_prefix, "db: SELECT 1 (account exists check)");

        let exists: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM accounts WHERE sync_id = ?")
                .bind(auth_token)
                .fetch_optional(&self.pool)
                .await?;

        let found = exists.is_some();
        tracing::debug!(auth_token = %token_prefix, found, "db: account exists result");

        Ok(found)
    }

    async fn delete_account(&self, auth_token: &str) -> Result<bool, AppError> {
        let token_prefix = &auth_token[..12];
        tracing::debug!(auth_token = %token_prefix, "db: DELETE account (cascade)");

        let result = sqlx::query("DELETE FROM accounts WHERE sync_id = ?")
            .bind(auth_token)
            .execute(&self.pool)
            .await?;

        let deleted = result.rows_affected() > 0;
        tracing::debug!(
            auth_token = %token_prefix,
            rows_affected = result.rows_affected(),
            deleted,
            "db: delete result"
        );

        Ok(deleted)
    }

    async fn update_last_seen(&self, auth_token: &str) -> Result<(), AppError> {
        tracing::debug!(auth_token = %&auth_token[..12], "db: UPDATE last_seen_at");

        sqlx::query("UPDATE accounts SET last_seen_at = ? WHERE sync_id = ?")
            .bind(now_millis())
            .bind(auth_token)
            .execute(&self.pool)
            .await?;

        tracing::debug!(auth_token = %&auth_token[..12], "db: last_seen_at updated");

        Ok(())
    }

    async fn upsert_entry(
        &self,
        auth_token: &str,
        entry: &SyncEntry,
    ) -> Result<UpsertResult, AppError> {
        let token_prefix = &auth_token[..12];
        tracing::debug!(
            auth_token = %token_prefix,
            entry_id = %entry.id,
            updated_at = entry.updated_at,
            "db: upsert entry — checking existing"
        );

        let existing: Option<DbEntry> = sqlx::query_as(
            "SELECT id, updated_at, is_archived, is_deleted, encrypted_payload, integrity_hash, server_seq \
             FROM entries WHERE sync_id = ? AND id = ?",
        )
        .bind(auth_token)
        .bind(&entry.id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(existing) = &existing {
            tracing::debug!(
                entry_id = %entry.id,
                server_updated_at = existing.updated_at,
                client_updated_at = entry.updated_at,
                "db: existing entry found, comparing timestamps"
            );
            if existing.updated_at >= entry.updated_at {
                tracing::debug!(
                    entry_id = %entry.id,
                    server_seq = existing.server_seq,
                    "db: conflict — server version newer, rejecting client entry"
                );
                return Ok(UpsertResult::Conflict(ConflictEntry {
                    id: entry.id.clone(),
                    server_updated_at: existing.updated_at,
                    server_seq: existing.server_seq,
                }));
            }
        } else {
            tracing::debug!(entry_id = %entry.id, "db: no existing entry, will insert");
        }

        tracing::debug!(auth_token = %token_prefix, "db: SELECT next_seq from sync_cursors");

        let seq: (i64,) =
            sqlx::query_as("SELECT next_seq FROM sync_cursors WHERE sync_id = ?")
                .bind(auth_token)
                .fetch_one(&self.pool)
                .await?;
        let server_seq = seq.0;

        tracing::debug!(
            auth_token = %token_prefix,
            server_seq,
            "db: UPDATE sync_cursors next_seq → {}",
            server_seq + 1
        );

        sqlx::query("UPDATE sync_cursors SET next_seq = ? WHERE sync_id = ?")
            .bind(server_seq + 1)
            .bind(auth_token)
            .execute(&self.pool)
            .await?;

        let payload = base64::engine::general_purpose::STANDARD
            .decode(&entry.encrypted_payload)
            .map_err(|_| AppError::BadRequest("Invalid base64 in encrypted_payload".into()))?;

        tracing::debug!(
            entry_id = %entry.id,
            server_seq,
            payload_bytes = payload.len(),
            "db: INSERT/UPDATE entry"
        );

        sqlx::query(
            "INSERT INTO entries (id, sync_id, updated_at, is_archived, is_deleted, encrypted_payload, integrity_hash, server_seq) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (sync_id, id) DO UPDATE SET \
               updated_at = excluded.updated_at, \
               is_archived = excluded.is_archived, \
               is_deleted = excluded.is_deleted, \
               encrypted_payload = excluded.encrypted_payload, \
               integrity_hash = excluded.integrity_hash, \
               server_seq = excluded.server_seq",
        )
        .bind(&entry.id)
        .bind(auth_token)
        .bind(entry.updated_at)
        .bind(entry.is_archived)
        .bind(entry.is_deleted)
        .bind(&payload)
        .bind(&entry.integrity_hash)
        .bind(server_seq)
        .execute(&self.pool)
        .await?;

        tracing::debug!(
            entry_id = %entry.id,
            server_seq,
            "db: entry upserted successfully"
        );

        Ok(UpsertResult::Accepted(server_seq))
    }

    async fn get_entries_since(
        &self,
        auth_token: &str,
        since: i64,
        limit: i64,
    ) -> Result<Vec<DbEntry>, AppError> {
        tracing::debug!(
            auth_token = %&auth_token[..12],
            since,
            limit,
            "db: SELECT entries WHERE server_seq > since"
        );

        let rows = sqlx::query_as(
            "SELECT id, updated_at, is_archived, is_deleted, encrypted_payload, integrity_hash, server_seq \
             FROM entries WHERE sync_id = ? AND server_seq > ? ORDER BY server_seq ASC LIMIT ?",
        )
        .bind(auth_token)
        .bind(since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        tracing::debug!(
            auth_token = %&auth_token[..12],
            rows_returned = rows.len(),
            "db: entries fetched"
        );

        Ok(rows)
    }

    async fn get_all_entries(&self, auth_token: &str) -> Result<Vec<DbEntry>, AppError> {
        tracing::debug!(auth_token = %&auth_token[..12], "db: SELECT all entries");

        let rows = sqlx::query_as(
            "SELECT id, updated_at, is_archived, is_deleted, encrypted_payload, integrity_hash, server_seq \
             FROM entries WHERE sync_id = ? ORDER BY server_seq ASC",
        )
        .bind(auth_token)
        .fetch_all(&self.pool)
        .await?;

        tracing::debug!(
            auth_token = %&auth_token[..12],
            rows_returned = rows.len(),
            "db: all entries fetched"
        );

        Ok(rows)
    }

    async fn get_current_seq(&self, auth_token: &str) -> Result<i64, AppError> {
        tracing::debug!(auth_token = %&auth_token[..12], "db: SELECT current seq");

        let seq: (i64,) =
            sqlx::query_as("SELECT next_seq - 1 FROM sync_cursors WHERE sync_id = ?")
                .bind(auth_token)
                .fetch_one(&self.pool)
                .await?;

        tracing::debug!(
            auth_token = %&auth_token[..12],
            current_seq = seq.0,
            "db: current seq fetched"
        );

        Ok(seq.0)
    }

    async fn update_entry_count(&self, auth_token: &str) -> Result<(), AppError> {
        tracing::debug!(auth_token = %&auth_token[..12], "db: UPDATE entry_count (recount)");

        sqlx::query(
            "UPDATE accounts SET entry_count = \
             (SELECT COUNT(*) FROM entries WHERE sync_id = ? AND is_deleted = 0) \
             WHERE sync_id = ?",
        )
        .bind(auth_token)
        .bind(auth_token)
        .execute(&self.pool)
        .await?;

        tracing::debug!(auth_token = %&auth_token[..12], "db: entry_count updated");

        Ok(())
    }

    async fn purge_inactive_accounts(&self, cutoff: i64) -> Result<u64, AppError> {
        tracing::debug!(cutoff, "db: DELETE inactive accounts");

        let result = sqlx::query("DELETE FROM accounts WHERE last_seen_at < ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;

        let rows = result.rows_affected();
        tracing::debug!(rows_affected = rows, "db: inactive accounts purged");

        Ok(rows)
    }
}
