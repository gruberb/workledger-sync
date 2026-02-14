<p align="center">
  <img src="logo.svg" alt="WorkLedger Sync" width="128" height="128">
</p>

<h1 align="center">WorkLedger Sync</h1>

<p align="center">
  <strong>Zero-knowledge encrypted sync for WorkLedger</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-stable-orange?logo=rust" alt="Rust">&nbsp;
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-green" alt="AES-256-GCM">&nbsp;
  <img src="https://img.shields.io/badge/database-SQLite-blue" alt="SQLite">&nbsp;
  <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="MIT License">
</p>

---

A privacy-first sync server for [WorkLedger](https://workledger.app) notes. The server never sees your plaintext — all entries are encrypted client-side using a key derived from a secret that never leaves your device.

## Features

- **Zero-knowledge encryption** — split-key design ensures the server cannot derive your encryption key, even from request headers
- **End-to-end encrypted** — AES-256-GCM with PBKDF2 key derivation (100,000 iterations)
- **Server never sees plaintext** — entries are opaque encrypted blobs to the server
- **Last-Write-Wins conflict resolution** — deterministic sync with server-wins tie-breaking
- **Paginated incremental sync** — efficient pull with sequence-based pagination
- **Full sync support** — first-device onboarding merges all entries in one call
- **Built with Rust** — Axum web framework + SQLite via sqlx

## How It Works

WorkLedger uses a **split-key design** so the server can identify your account without ever being able to read your notes. Here's what happens step by step:

### 1. You hit "Generate" in the app

The client generates a random sync ID locally — this is your master secret:

```
syncId = "wl-26ed5d6a7708493bf281..."    ← random, stays on your device
```

### 2. Two keys are derived from it

The client hashes the sync ID twice, with different prefixes, producing two **completely unrelated** values:

```
SHA-256("auth:"   + syncId)  →  a]1f3c7b...  (identity key)
SHA-256("crypto:" + syncId)  →  9d4e8a2f...  (encryption seed)
```

These are one-way hashes — you can't reverse either one to get the sync ID, and knowing one tells you nothing about the other.

### 3. The identity key creates your account

The client sends only the identity key to the server. The server stores it as your account ID and returns a random `salt`:

```
CLIENT                                     SERVER

POST /accounts { authToken: "a1f3c7b..." } ──────►  stores "a1f3c7b..." as account ID
                                           ◄──────  returns { salt: "xK8r..." }
```

### 4. The encryption seed becomes your AES key

The client combines the encryption seed with the server's salt to derive the actual encryption key. This all happens locally — the encryption seed and the AES key never leave your device:

```
encryption seed  +  salt  ──► PBKDF2 (100,000 rounds) ──► AES-256 key
```

### 5. Sync uses both keys independently

When syncing, the identity key tells the server *whose* data this is, while the encryption key protects *what* the data contains:

```
CLIENT                                     SERVER

encrypt(notes, AES key)
    │
    ├── POST /sync/push ──────────────────────────►  matches account by
    │   X-Auth-Token: "a1f3c7b..."                   identity key, stores
    │   Body: { entries: [encrypted blobs] }         encrypted blobs
    │
    ├── GET /sync/pull ───────────────────────────►  finds entries by
    │   X-Auth-Token: "a1f3c7b..."                   identity key,
    │                                  ◄──────────   returns encrypted blobs
    │
decrypt(blobs, AES key)
```

**The result:** the server can store and retrieve your data but can never read it. Even with full database access and every request header logged, the server only has the identity key — which reveals nothing about the encryption key.

## API Overview

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| `POST` | `/api/v1/accounts` | - | Create account, receive salt |
| `GET` | `/api/v1/accounts/validate` | `X-Auth-Token` | Validate account, get salt |
| `DELETE` | `/api/v1/accounts` | `X-Auth-Token` | Delete account + all entries |
| `POST` | `/api/v1/sync/push` | `X-Auth-Token` | Push encrypted entries (LWW) |
| `GET` | `/api/v1/sync/pull` | `X-Auth-Token` | Pull entries since sequence N |
| `POST` | `/api/v1/sync/full` | `X-Auth-Token` | Full sync (merge + return all) |
| `GET` | `/health` | - | Health check |

See the [interactive API docs](https://gruberb.github.io/workledger-sync/) or [`openapi.yaml`](openapi.yaml) for the full specification.

## Getting Started

### Prerequisites

- Rust (stable)
- SQLite 3

### Build & Run

```bash
# Build
cargo build

# Run with debug logging
RUST_LOG=debug cargo run

# Run tests
cargo test

# Lint
cargo clippy
```

The server starts on `http://localhost:3000` by default.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `DATABASE_URL` | `sqlite:workledger-sync.db` | SQLite database path |
| `CORS_ORIGINS` | `https://workledger.app,http://localhost:5173` | Comma-separated allowed origins |
| `MAX_ENTRIES` | `10000` | Max entries per account |
| `MAX_PAYLOAD_BYTES` | `1048576` | Max request payload (1 MB) |
| `CLEANUP_INACTIVE_DAYS` | `90` | Days before inactive account cleanup |

## Security Model

### What the server stores

- `authToken` — a SHA-256 hash (used for authentication lookups)
- `salt` — random 16 bytes (returned to client for key derivation)
- Encrypted payloads — opaque base64 blobs
- Metadata — timestamps, archived/deleted flags, sequence numbers

### What the server cannot derive

- `syncId` — the user's secret, never transmitted
- `cryptoSeed` — independent derivation from syncId, never transmitted
- Encryption key — derived from cryptoSeed + salt via PBKDF2
- Plaintext content — encrypted with AES-256-GCM client-side

## License

[MIT](LICENSE)
