# WorkLedger Sync Server

Zero-knowledge encrypted sync server for WorkLedger notes. Built with Rust, Axum, and SQLite.

## Commands

```bash
cargo build              # Build
cargo test               # Run all tests (13 integration + unit tests)
cargo clippy             # Lint
cargo clippy && cargo test  # Full verification
RUST_LOG=debug cargo run # Run with debug logging
```

## Architecture

- **Repository pattern**: All DB access goes through `SyncRepository` trait (`src/repository.rs`), implemented by `SqliteRepository` (`src/sqlite_repo.rs`). Handlers never contain raw SQL.
- **AppState**: Handlers use `State<AppState>` for the repository and config. Auth tokens come from `Extension<AuthToken>` (set by middleware).
- **Error handling**: All handlers return `Result<impl IntoResponse, AppError>`. Use `?` for DB calls. Never use `(StatusCode, String)` tuples.
- **Thin handlers**: Validate input, call `state.repo.method()`, return response. No business logic in handlers beyond input validation.

## Key Conventions

- `now_millis()` lives in `src/util.rs` — use it everywhere, don't duplicate
- Auth token = `SHA-256("auth:" + syncId)`, 64 hex chars. Never log or store raw sync IDs.
- All entry payloads are encrypted client-side (AES-256-GCM). The server stores opaque blobs.
- LWW (Last-Write-Wins) conflict resolution: server version wins ties on `updated_at`.
- OpenAPI spec: `openapi.yaml`
