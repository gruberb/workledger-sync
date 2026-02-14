# API Rules

## OpenAPI Spec

The full API spec is at `openapi.yaml`. Keep it in sync with any endpoint changes.

## Authentication

- Header: `X-Auth-Token` (64 hex chars, SHA-256 hash)
- All endpoints except `POST /accounts` require the header
- Auth middleware validates format and injects `AuthToken` extension

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/accounts` | No | Create account (sends `{ "authToken": "..." }`) |
| GET | `/api/v1/accounts/validate` | Yes | Check account exists, get salt |
| DELETE | `/api/v1/accounts` | Yes | Delete account + all entries (cascade) |
| POST | `/api/v1/sync/push` | Yes | Push encrypted entries (LWW) |
| GET | `/api/v1/sync/pull` | Yes | Pull entries since `?since=N&limit=M` |
| POST | `/api/v1/sync/full` | Yes | Initial full sync (merge + return all) |
| GET | `/health` | No | Health check |

## Sync Protocol

- **Push**: Client sends entries. Server applies LWW on `updatedAt`. Server wins ties. Returns accepted count + conflicts.
- **Pull**: Paginated. Fetch entries with `server_seq > since`. `hasMore` indicates more pages.
- **Full sync**: For first sync on new device. Client sends all entries, server merges via LWW, returns all entries.
- **Conflict resolution**: Conflicts returned with `serverUpdatedAt` so client can resolve.

## Response Format

- Success: JSON body with relevant fields
- Error: `{ "error": "message" }` with appropriate HTTP status
- Account creation returns 201, other successes return 200
