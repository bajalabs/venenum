# Changelog

All notable changes to this project are written here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-11-10

### Added

- `POST /v1/scan`: download an object from an allowed origin (no redirects, size cap, time limit), check its sha256 and size, scan it with clamd.
- `POST /v1/scan/bytes`: scan the request body, with the same checks.
- Request signing v1: `X-Venenum-Caller` and `X-Venenum-Signature: t=,v1=` (HMAC-SHA256 over the caller, the timestamp and the raw body), with a published test vector and Node.js and Python clients.
- `GET /health` (fails when clamd is unreachable or its signatures are older than the configured age) and `GET /v1/version`.
- Every setting as an environment variable with a default; invalid settings stop the service at start.
- A non-root Node image, `compose.yaml` with the official `clamav/clamav` image, and an end-to-end smoke test.

[Unreleased]: https://github.com/bajalabs/venenum/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bajalabs/venenum/releases/tag/v1.0.0
