use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Extension, Json,
};

use crate::error::AppError;
use crate::middleware::auth::AuthToken;
use crate::util::token_prefix;
use crate::models::account::AccountInfo;
use crate::models::entry::{EntryValidationError, SyncEntry, MAX_ENCRYPTED_PAYLOAD_LEN};
use crate::models::sync::{
    FullSyncRequest, FullSyncResponse, PullQuery, PullResponse, PushRequest, PushResponse,
};
use crate::repository::UpsertResult;
use crate::AppState;

/// Validates every entry before any is written, so a batch is all-or-nothing.
fn validate_entries(entries: &[SyncEntry]) -> Result<(), AppError> {
    for entry in entries {
        match entry.validate() {
            Ok(()) => {}
            Err(EntryValidationError::TooLarge { len }) => {
                return Err(AppError::PayloadTooLarge(format!(
                    "Entry '{}' encryptedPayload is {len} chars, limit is {MAX_ENCRYPTED_PAYLOAD_LEN}",
                    entry.id
                )));
            }
            Err(EntryValidationError::Invalid(msg)) => {
                return Err(AppError::BadRequest(format!("Invalid entry '{}': {msg}", entry.id)));
            }
        }
    }
    Ok(())
}

/// Rejects the batch if it would push the account over its entry limit.
///
/// Only entries that would become new live rows count. Updates and deletes of
/// existing entries don't grow the account, and counting them made every
/// batched re-push fail once an account was within one batch of the limit.
async fn check_entry_limit(
    state: &AppState,
    auth_token: &str,
    account: &AccountInfo,
    entries: &[SyncEntry],
) -> Result<(), AppError> {
    let mut live_ids: Vec<&str> = entries
        .iter()
        .filter(|e| !e.is_deleted)
        .map(|e| e.id.as_str())
        .collect();
    live_ids.sort_unstable();
    live_ids.dedup();

    let already_live = state.repo.count_live_entries(auth_token, &live_ids).await?;
    let new_live = live_ids.len() as i64 - already_live;
    if account.entry_count + new_live > state.max_entries_per_account {
        tracing::warn!(new_live, current = account.entry_count, "Entry limit exceeded");
        return Err(AppError::BadRequest("Entry limit exceeded".into()));
    }
    Ok(())
}

/// POST /api/v1/sync/push
pub async fn push(
    State(state): State<AppState>,
    Extension(AuthToken(auth_token)): Extension<AuthToken>,
    Json(body): Json<PushRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        handler = "push",
        auth_token = %token_prefix(&auth_token),
        entry_count = body.entries.len(),
        "Handler: POST /api/v1/sync/push"
    );

    tracing::debug!(handler = "push", "Dispatching to repo.find_account (verify + entry limit)");
    let account = state
        .repo
        .find_account(&auth_token)
        .await?
        .ok_or_else(|| AppError::NotFound("Account not found".into()))?;
    tracing::debug!(
        handler = "push",
        current_entries = account.entry_count,
        max_entries = state.max_entries_per_account,
        "Repo returned: account found"
    );

    validate_entries(&body.entries)?;
    check_entry_limit(&state, &auth_token, &account, &body.entries).await?;

    let mut accepted = 0usize;
    let mut conflicts = Vec::new();
    let mut max_seq: i64 = 0;

    for (i, entry) in body.entries.iter().enumerate() {
        tracing::debug!(
            handler = "push",
            entry_index = i,
            entry_id = %entry.id,
            "Dispatching to repo.upsert_entry"
        );
        match state.repo.upsert_entry(&auth_token, entry).await? {
            UpsertResult::Accepted(seq) => {
                tracing::debug!(
                    handler = "push",
                    entry_id = %entry.id,
                    server_seq = seq,
                    "Repo returned: entry accepted"
                );
                accepted += 1;
                max_seq = max_seq.max(seq);
            }
            UpsertResult::Conflict(conflict) => {
                tracing::debug!(
                    handler = "push",
                    entry_id = %entry.id,
                    server_updated_at = conflict.server_updated_at,
                    "Repo returned: entry conflict"
                );
                max_seq = max_seq.max(conflict.server_seq);
                conflicts.push(conflict);
            }
        }
    }

    if accepted > 0 {
        tracing::debug!(handler = "push", "Dispatching to repo.update_entry_count");
        state.repo.update_entry_count(&auth_token).await?;
        tracing::debug!(handler = "push", "Dispatching to repo.update_last_seen");
        if let Err(e) = state.repo.update_last_seen(&auth_token).await {
            tracing::warn!(error = %e, "Failed to update last_seen");
        }
    }

    // Derive serverSeq from upsert results; fall back to DB only for empty pushes
    let current_seq = if max_seq > 0 {
        max_seq
    } else {
        tracing::debug!(handler = "push", "Empty push, dispatching to repo.get_current_seq");
        state.repo.get_current_seq(&auth_token).await?
    };

    tracing::info!(
        handler = "push",
        auth_token = %token_prefix(&auth_token),
        accepted,
        conflicts = conflicts.len(),
        server_seq = current_seq,
        status = 200,
        "Responding: push complete"
    );

    Ok(Json(PushResponse {
        accepted,
        conflicts,
        server_seq: current_seq,
    }))
}

/// GET /api/v1/sync/pull
pub async fn pull(
    State(state): State<AppState>,
    Extension(AuthToken(auth_token)): Extension<AuthToken>,
    Query(params): Query<PullQuery>,
) -> Result<impl IntoResponse, AppError> {
    let since = params.since.unwrap_or(0);
    let limit = params.limit.unwrap_or(100).clamp(1, 500);

    tracing::info!(
        handler = "pull",
        auth_token = %token_prefix(&auth_token),
        since,
        limit,
        "Handler: GET /api/v1/sync/pull"
    );

    if !state.repo.account_exists(&auth_token).await? {
        return Err(AppError::NotFound("Account not found".into()));
    }

    // Fetch one extra to determine hasMore, atomically with seq
    tracing::debug!(handler = "pull", fetch_limit = limit + 1, "Dispatching to repo.get_entries_since_with_seq");
    let (rows, current_seq) = state
        .repo
        .get_entries_since_with_seq(&auth_token, since, limit + 1)
        .await?;
    tracing::debug!(handler = "pull", rows_fetched = rows.len(), current_seq, "Repo returned");

    let has_more = rows.len() as i64 > limit;
    let entries: Vec<SyncEntry> = rows
        .iter()
        .take(limit as usize)
        .map(|r| r.to_sync_entry())
        .collect();

    tracing::debug!(handler = "pull", "Dispatching to repo.update_last_seen");
    if let Err(e) = state.repo.update_last_seen(&auth_token).await {
        tracing::warn!(error = %e, "Failed to update last_seen");
    }

    tracing::info!(
        handler = "pull",
        auth_token = %token_prefix(&auth_token),
        returned = entries.len(),
        server_seq = current_seq,
        has_more,
        status = 200,
        "Responding: pull complete"
    );

    Ok(Json(PullResponse {
        entries,
        server_seq: current_seq,
        has_more,
    }))
}

/// POST /api/v1/sync/full: initial full sync.
///
/// Kept for clients before 3.3.0. Newer clients reconcile with a paginated
/// pull plus batched pushes, because one request with every entry exceeds the
/// request body limit for large notebooks.
pub async fn full_sync(
    State(state): State<AppState>,
    Extension(AuthToken(auth_token)): Extension<AuthToken>,
    Json(body): Json<FullSyncRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        handler = "full_sync",
        auth_token = %token_prefix(&auth_token),
        client_entries = body.entries.len(),
        "Handler: POST /api/v1/sync/full"
    );

    let account = state
        .repo
        .find_account(&auth_token)
        .await?
        .ok_or_else(|| AppError::NotFound("Account not found".into()))?;

    validate_entries(&body.entries)?;
    check_entry_limit(&state, &auth_token, &account, &body.entries).await?;

    let mut merged = 0usize;

    for (i, entry) in body.entries.iter().enumerate() {
        tracing::debug!(
            handler = "full_sync",
            entry_index = i,
            entry_id = %entry.id,
            "Dispatching to repo.upsert_entry"
        );
        if let UpsertResult::Accepted(seq) = state.repo.upsert_entry(&auth_token, entry).await? {
            tracing::debug!(
                handler = "full_sync",
                entry_id = %entry.id,
                server_seq = seq,
                "Repo returned: entry merged"
            );
            merged += 1;
        }
    }

    tracing::debug!(handler = "full_sync", "Dispatching to repo.get_all_entries_with_seq");
    let (all_rows, current_seq) = state.repo.get_all_entries_with_seq(&auth_token, state.max_entries_per_account).await?;
    let entries: Vec<SyncEntry> = all_rows.iter().map(|r| r.to_sync_entry()).collect();
    tracing::debug!(handler = "full_sync", total_entries = entries.len(), current_seq, "Repo returned: all entries + seq");

    tracing::debug!(handler = "full_sync", "Dispatching to repo.update_entry_count");
    state.repo.update_entry_count(&auth_token).await?;

    tracing::debug!(handler = "full_sync", "Dispatching to repo.update_last_seen");
    if let Err(e) = state.repo.update_last_seen(&auth_token).await {
        tracing::warn!(error = %e, "Failed to update last_seen");
    }

    tracing::info!(
        handler = "full_sync",
        auth_token = %token_prefix(&auth_token),
        merged,
        total_entries = entries.len(),
        server_seq = current_seq,
        status = 200,
        "Responding: full sync complete"
    );

    Ok(Json(FullSyncResponse {
        entries,
        server_seq: current_seq,
        merged,
    }))
}
