use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Extension, Json,
};

use crate::error::AppError;
use crate::middleware::auth::AuthToken;
use crate::util::token_prefix;
use crate::models::entry::SyncEntry;
use crate::models::sync::{
    FullSyncRequest, FullSyncResponse, PullQuery, PullResponse, PushRequest, PushResponse,
};
use crate::repository::UpsertResult;
use crate::AppState;

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

    if account.entry_count + body.entries.len() as i64 > state.max_entries_per_account {
        tracing::warn!(handler = "push", "Entry limit exceeded");
        return Err(AppError::BadRequest("Entry limit exceeded".into()));
    }

    for entry in &body.entries {
        if let Err(msg) = entry.validate() {
            return Err(AppError::BadRequest(format!("Invalid entry '{}': {msg}", entry.id)));
        }
    }

    let mut accepted = 0usize;
    let mut conflicts = Vec::new();

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
            }
            UpsertResult::Conflict(conflict) => {
                tracing::debug!(
                    handler = "push",
                    entry_id = %entry.id,
                    server_updated_at = conflict.server_updated_at,
                    "Repo returned: entry conflict"
                );
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

    tracing::debug!(handler = "push", "Dispatching to repo.get_current_seq");
    let current_seq = state.repo.get_current_seq(&auth_token).await?;

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

    // Fetch one extra to determine hasMore
    tracing::debug!(handler = "pull", fetch_limit = limit + 1, "Dispatching to repo.get_entries_since");
    let rows = state
        .repo
        .get_entries_since(&auth_token, since, limit + 1)
        .await?;
    tracing::debug!(handler = "pull", rows_fetched = rows.len(), "Repo returned");

    let has_more = rows.len() as i64 > limit;
    let entries: Vec<SyncEntry> = rows
        .iter()
        .take(limit as usize)
        .map(|r| r.to_sync_entry())
        .collect();

    tracing::debug!(handler = "pull", "Dispatching to repo.get_current_seq");
    let current_seq = state.repo.get_current_seq(&auth_token).await?;

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

/// POST /api/v1/sync/full — initial full sync
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

    if account.entry_count + body.entries.len() as i64 > state.max_entries_per_account {
        return Err(AppError::BadRequest("Entry limit exceeded".into()));
    }

    for entry in &body.entries {
        if let Err(msg) = entry.validate() {
            return Err(AppError::BadRequest(format!("Invalid entry '{}': {msg}", entry.id)));
        }
    }

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

    tracing::debug!(handler = "full_sync", "Dispatching to repo.get_all_entries");
    let all_rows = state.repo.get_all_entries(&auth_token, state.max_entries_per_account).await?;
    let entries: Vec<SyncEntry> = all_rows.iter().map(|r| r.to_sync_entry()).collect();
    tracing::debug!(handler = "full_sync", total_entries = entries.len(), "Repo returned: all entries");

    tracing::debug!(handler = "full_sync", "Dispatching to repo.get_current_seq");
    let current_seq = state.repo.get_current_seq(&auth_token).await?;

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
