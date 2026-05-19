# Changelog

All notable changes to this project are documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.1] - 2026-05-19

### Fixed

- Switched `auto_stop_machines` from `suspend` to `stop` in `fly.toml`. The app shuts down cleanly on SIGINT, which Fly's suspend mode does not expect — that left the machine in inconsistent states between wake cycles, occasionally wedging it in `starting` for hours and producing spurious CORS errors at the proxy edge.
