-- NOTE: sync_id columns store the auth token: SHA-256("auth:" + syncId).
-- The raw sync ID and crypto seed never reach the server (split-key design).
CREATE TABLE IF NOT EXISTS accounts (
    sync_id       TEXT PRIMARY KEY,   -- auth token: SHA-256("auth:" + syncId), 64 hex chars
    salt          BLOB NOT NULL,
    created_at    INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    entry_count   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS entries (
    id                TEXT NOT NULL,
    sync_id           TEXT NOT NULL REFERENCES accounts(sync_id) ON DELETE CASCADE,
    updated_at        INTEGER NOT NULL,
    is_archived       INTEGER NOT NULL DEFAULT 0,
    is_deleted        INTEGER NOT NULL DEFAULT 0,
    encrypted_payload BLOB NOT NULL,
    integrity_hash    TEXT NOT NULL,
    server_seq        INTEGER NOT NULL,
    PRIMARY KEY (sync_id, id)
);

CREATE INDEX IF NOT EXISTS idx_entries_seq ON entries(sync_id, server_seq);

CREATE TABLE IF NOT EXISTS sync_cursors (
    sync_id   TEXT PRIMARY KEY REFERENCES accounts(sync_id) ON DELETE CASCADE,
    next_seq  INTEGER NOT NULL DEFAULT 1
);
