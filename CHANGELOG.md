# Changelog

All notable changes to this project are documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.0] - 2026-10-11

### Changed

- An entry whose `encryptedPayload` exceeds 700,000 chars now gets 413 instead of 400, so clients can tell "too large, skip it" from "malformed". The batch is still rejected as a whole.
- `/api/v1/sync/full` is marked deprecated. WorkLedger 3.3.0 reconciles with paginated pulls and batched pushes; the endpoint stays for older clients.
- Docs and OpenAPI describe client payload format v2, encrypted tombstones, and `integrityHash` as an opaque ciphertext hash.

### Fixed

- The entry limit counted every entry in a push, including updates and deletes of existing entries. Once an account was within one batch of the limit, every batched re-push failed. Only entries that would become new live rows count now.

## [0.1.1] - 2026-05-19

### Fixed

- Switched `auto_stop_machines` from `suspend` to `stop` in `fly.toml`. The app shuts down cleanly on SIGINT, which Fly's suspend mode does not expect — that left the machine in inconsistent states between wake cycles, occasionally wedging it in `starting` for hours and producing spurious CORS errors at the proxy edge.
