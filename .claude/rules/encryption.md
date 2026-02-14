# Split-Key Zero-Knowledge Design

## How Authentication Works

The user generates a random sync ID locally (`wl-` + 32 hex chars). Two independent values are derived:

```
syncId     = "wl-<random>"                    // user's secret, NEVER sent to server
authToken  = hex(SHA-256("auth:" + syncId))    // sent in X-Auth-Token header
cryptoSeed = SHA-256("crypto:" + syncId)       // used for encryption, NEVER leaves client
```

The server stores `authToken` directly in the `accounts.sync_id` column for lookups. The auth middleware validates the `X-Auth-Token` header (64 hex chars) and injects `AuthToken` into request extensions.

## How Encryption Works

1. Server returns a random 16-byte `salt` on account creation
2. Client derives AES key: `PBKDF2(cryptoSeed, salt, 100000, SHA-256)` → 256-bit key
3. Client encrypts entries: AES-256-GCM with random 12-byte IV
4. Payload format: `base64(IV || ciphertext || GCM tag)`
5. Integrity hash: `hex(SHA-256(plaintext))` for client-side verification

## What the Server Knows vs Doesn't Know

**Server knows:** authToken (a SHA-256 hash), salt, encrypted payloads, metadata (timestamps, archived/deleted flags)

**Server CANNOT derive:** syncId, cryptoSeed, encryption key, plaintext content

Even if the server logs every request header, it cannot derive the encryption key because `authToken` and `cryptoSeed` are independent SHA-256 derivations from the syncId.

## IMPORTANT

- NEVER log or store raw sync IDs
- NEVER log encrypted payloads at debug level (they're opaque but still sensitive metadata)
- The `authToken` prefix (`[..12]`) in logs is safe — it's already a hash
