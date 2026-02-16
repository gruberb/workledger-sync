use async_trait::async_trait;

use crate::error::AppError;
use crate::models::account::AccountInfo;
use crate::models::entry::{DbEntry, SyncEntry};
use crate::models::metrics::Metrics;
use crate::models::sync::ConflictEntry;

pub enum UpsertResult {
    Accepted(i64),
    Conflict(ConflictEntry),
}

#[async_trait]
pub trait SyncRepository: Send + Sync {
    async fn create_account(&self, auth_token: &str, salt: &[u8]) -> Result<(), AppError>;
    async fn find_account(&self, auth_token: &str) -> Result<Option<AccountInfo>, AppError>;
    async fn account_exists(&self, auth_token: &str) -> Result<bool, AppError>;
    async fn delete_account(&self, auth_token: &str) -> Result<bool, AppError>;
    async fn update_last_seen(&self, auth_token: &str) -> Result<(), AppError>;

    async fn upsert_entry(
        &self,
        auth_token: &str,
        entry: &SyncEntry,
    ) -> Result<UpsertResult, AppError>;
    async fn get_entries_since(
        &self,
        auth_token: &str,
        since: i64,
        limit: i64,
    ) -> Result<Vec<DbEntry>, AppError>;
    async fn get_all_entries(&self, auth_token: &str, limit: i64) -> Result<Vec<DbEntry>, AppError>;
    async fn get_entries_since_with_seq(
        &self,
        auth_token: &str,
        since: i64,
        limit: i64,
    ) -> Result<(Vec<DbEntry>, i64), AppError>;
    async fn get_all_entries_with_seq(
        &self,
        auth_token: &str,
        limit: i64,
    ) -> Result<(Vec<DbEntry>, i64), AppError>;
    async fn get_current_seq(&self, auth_token: &str) -> Result<i64, AppError>;
    async fn update_entry_count(&self, auth_token: &str) -> Result<(), AppError>;
    async fn purge_inactive_accounts(&self, cutoff: i64) -> Result<u64, AppError>;
    async fn health_check(&self) -> Result<(), AppError>;
    async fn get_metrics(&self) -> Result<Metrics, AppError>;
}
