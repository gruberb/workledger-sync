# Architecture Rules

## Repository Pattern

All database access goes through the `SyncRepository` trait (`src/repository.rs`). The SQLite implementation lives in `src/sqlite_repo.rs`.

- **No raw SQL in handlers.** Handlers call `state.repo.method()`.
- To add a new query, add a method to `SyncRepository` trait and implement it in `SqliteRepository`.
- The trait uses `async_trait` for dynamic dispatch via `Arc<dyn SyncRepository>`.

## Handler Pattern

Handlers are thin. They follow this pattern:

1. Extract and validate input
2. Call `state.repo.method()`
3. Return response

```rust
pub async fn my_handler(
    State(state): State<AppState>,
    Extension(AuthToken(auth_token)): Extension<AuthToken>,
    Json(body): Json<MyRequest>,
) -> Result<impl IntoResponse, AppError> {
    // validate
    // state.repo.do_thing(&auth_token, ...).await?
    // Ok(Json(response))
}
```

## Error Handling

- All handlers return `Result<impl IntoResponse, AppError>`
- Use `?` operator for DB calls (auto-converts via `From<sqlx::Error>`)
- Never use `(StatusCode, String)` tuples as error types
- `AppError` variants: `NotFound`, `BadRequest`, `Unauthorized`, `Database`, `Internal`

## State Management

- `AppState` holds `Arc<dyn SyncRepository>` and config values
- Routes use `State<AppState>` for the repository
- Auth token comes from `Extension<AuthToken>` (injected by auth middleware)
- Don't add `SqlitePool` directly to handlers

## Shared Utilities

- `now_millis()` in `src/util.rs` — single source for current time in milliseconds
- Don't duplicate utility functions across modules
