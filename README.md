# venenum

[![CI](https://github.com/bajalabs/venenum/actions/workflows/ci.yml/badge.svg)](https://github.com/bajalabs/venenum/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/bajalabs/venenum)](LICENSE)
[![Release](https://img.shields.io/github/v/release/bajalabs/venenum)](https://github.com/bajalabs/venenum/releases)

A small HTTP service in front of [ClamAV](https://www.clamav.net) for applications that need to scan uploaded files: a signed request names an object on an allowed origin (or sends the bytes), venenum checks it is the object the caller described, streams it to `clamd`, and answers `clean` or `infected`. It stores nothing.

```
your app ──POST /v1/scan {url, sha256, size}──▶ venenum ──GET url (allowed origin, no redirects, ≤ max bytes)──▶ object store
   ▲                                              │ sha256 and size checked, INSTREAM to clamd
   └──────── {verdict, threat, sha256, size, engine, signatures} ◀─┘
```

## Quick start

Requires Node.js 24, pnpm 10 (`corepack enable`), and Docker with Compose for the full service.

```sh
pnpm install
pnpm test                                            # unit tests against a fake clamd

KEY=$(openssl rand -hex 32)
printf 'VENENUM_HMAC_KEYS=my-app:%s\n' "$KEY" > .env  # one caller, one key
docker compose up -d --build --wait                  # venenum + clamav/clamav; the first start downloads the signatures (minutes)
curl -s http://127.0.0.1:3330/health                 # {"ok":true,"engine":"ClamAV 1.5.4",…}

VENENUM_CALLER=my-app VENENUM_KEY=$KEY node examples/client.mjs bytes README.md
# 200 {"verdict":"clean",…}
```

`docker compose down` stops it; `docker compose down -v` also removes the signature database volume.

## What is inside

| Path | What it holds |
|---|---|
| `src/` | The service (TypeScript run directly by Node 24, no build step): `server.ts` (routes), `signing.ts` (request signing), `fetch.ts` (origin check, bounded download), `clamd.ts` (clamd client), `config.ts` (settings), `main.ts`, `healthcheck.ts`. |
| `test/` | 5 vitest files, 21 tests, against a fake clamd on a Unix socket and a local file server; no ClamAV needed. |
| `examples/` | Clients in Node.js (`client.mjs`) and Python (`client.py`), standard library only. |
| `scripts/smoke.ts` | The end-to-end check CI runs against `docker compose`: EICAR is infected, a clean file is clean, through both routes. |
| `Dockerfile`, `compose.yaml` | The service image (Node on Alpine, non-root) and the pair with the official `clamav/clamav` image. |
| `docs/signing.md` | The signing algorithm, a test vector, and clients. |

## API

All responses are JSON. Errors are `{ "error": { "code": "…", "message": "…" } }`.

### `POST /v1/scan`

Scan an object that venenum downloads from an allowed origin. Body (`Content-Type: application/json`, signed):

```json
{ "url": "https://files.example.com/uploads/report.pdf", "sha256": "<64 lowercase hex>", "size": 48213, "ref": "upload-42" }
```

`url` must be on an origin in `VENENUM_FETCH_ORIGINS`; redirects are not followed; the download stops at `VENENUM_MAX_BYTES`. The downloaded bytes must have exactly the `sha256` and `size` given. `ref` is optional, echoed back and logged (up to 256 characters). A presigned object-store URL works well: the caller hashes the object when it stores it.

### `POST /v1/scan/bytes`

Scan bytes the caller already holds. The body is the object (`Content-Type: application/octet-stream`, signed over the raw bytes), with `X-Scan-Sha256` (64 hex), `X-Scan-Size` and an optional `X-Scan-Ref` header.

### The verdict

`200` with:

```json
{
  "verdict": "clean",
  "reference": "ClamAV 1.5.4 / daily 27832",
  "threat": null,
  "sha256": "…", "size": 48213, "ref": "upload-42",
  "engine": "ClamAV 1.5.4", "signatures": "27832", "signatures_at": "2026-11-10T08:24:00.000Z",
  "scanned_at": "2026-11-10T10:02:11.512Z"
}
```

`verdict` is `clean` or `infected`; when infected, `threat` and `reference` carry the signature name (for example `Eicar-Test-Signature`). A problem is never a verdict:

| Status | Code | When |
|---|---|---|
| 400 | `invalid_body` | missing or malformed `url`, `sha256`, `size`, or the bytes headers; invalid JSON |
| 401 | `invalid_signature` | missing, unknown, stale or wrong signature ([docs/signing.md](docs/signing.md)) |
| 403 | `origin_not_allowed` | the URL is not on an allowed origin, or carries credentials |
| 409 | `integrity_mismatch` | the bytes do not have the sha256 or size the caller gave |
| 413 | `too_large` | over `VENENUM_MAX_BYTES` (declared, sent or streamed) |
| 415 | | a content type other than JSON (`/v1/scan`) or octet-stream (`/v1/scan/bytes`) |
| 502 | `download_failed` | the origin answered an error, a redirect, or did not answer in time |
| 503 | `scanner_unavailable` | clamd is unreachable, failed, or its signatures are stale |

### `GET /health` and `GET /v1/version`

`/health` answers `200 {"ok": true, "engine", "signatures", "signatures_at", "age_hours"}` while clamd answers and its signature database is younger than `VENENUM_MAX_SIGNATURE_AGE_HOURS`, and `503` with `"reason": "signatures_stale"` or `"clamd_unavailable"` otherwise. Use it for load balancer and container health checks. `/v1/version` answers the same facts, always with `200`.

## Request signing

Every scan request carries `X-Venenum-Caller: <caller>` and `X-Venenum-Signature: t=<unix seconds>,v1=<hex>`, where `v1` is HMAC-SHA256 with the caller's 32-byte key over `<caller>.<t>.` followed by the raw request body. The window is 60 seconds by default. The exact algorithm, a test vector, and Node.js and Python code are in [docs/signing.md](docs/signing.md).

## Configuration

Every setting is an environment variable; defaults apply when it is unset or empty. Invalid values stop the service at start, with every problem listed.

| Variable | Default | What it does |
|---|---|---|
| `VENENUM_HMAC_KEYS` | none | Callers and keys: `caller:<64 hex>,caller2:<64 hex>`. Empty: every scan is refused. |
| `VENENUM_FETCH_ORIGINS` | none | Origins `/v1/scan` may download from, comma-separated (`https://files.example.com`). Empty: `/v1/scan` refuses every URL. |
| `VENENUM_MAX_BYTES` | `26214400` (25 MiB) | Largest object, for both routes. Keep it under clamd's `StreamMaxLength` (100 MiB in the official image). |
| `VENENUM_MAX_SIGNATURE_AGE_HOURS` | `72` | Older ClamAV signatures make `/health` and every scan fail. |
| `VENENUM_SIGNING_WINDOW_SECONDS` | `60` | Accepted clock difference for the request timestamp (up to 3600). |
| `VENENUM_FETCH_TIMEOUT_MS` | `60000` | Time limit for a download. |
| `VENENUM_JSON_BODY_LIMIT` | `65536` | Largest JSON body for `/v1/scan`, in bytes. |
| `VENENUM_LOG_LEVEL` | `info` | `fatal`, `error`, `warn`, `info`, `debug`, `trace` or `silent` (JSON logs on stdout). |
| `CLAMD_SOCKET` | `/tmp/clamd.sock` | clamd's Unix socket, when `CLAMD_HOST` is not set. |
| `CLAMD_HOST`, `CLAMD_PORT` | none, `3310` | clamd over TCP instead of a socket (compose uses `clamav:3310`). |
| `CLAMD_TIMEOUT_MS` | `90000` | Time limit for one clamd command. |
| `HOST`, `PORT` | `0.0.0.0`, `3330` | Where the service listens. |
| `VENENUM_BIND`, `VENENUM_PORT` | `127.0.0.1`, `3330` | `compose.yaml` only: the host address and port the service is published on. |

## Run it

- **Compose** (above): `compose.yaml` runs `venenum` (built from the `Dockerfile`) and `clamav/clamav:1.5.4-debian` (amd64 and arm64) with the signature database on a named volume. clamd is not published; venenum is published on `127.0.0.1:3330`.
- **Image only**: `docker build -t venenum .` and run it with `CLAMD_HOST`/`CLAMD_PORT` pointing at a clamd you run. The image's health check calls `/health`.
- **Node directly**: `pnpm install --prod && node src/main.ts` with `CLAMD_SOCKET` or `CLAMD_HOST` set.

Put venenum on a private network or behind TLS: it speaks plain HTTP. See [SECURITY.md](SECURITY.md) for the threat model.

## Limitations

- One object per request, held in memory while it is checked and scanned: memory use is up to `VENENUM_MAX_BYTES` per concurrent scan.
- No queue, retry or result store: the caller keeps the verdict.
- No replay cache: a signed request can be replayed within the signing window (it only repeats the same scan).
- Archives, encrypted files and the limits of detection are ClamAV's: a `clean` verdict means no signature matched, not that a file is safe.
- `/health` and `/v1/version` are unauthenticated and reveal the engine and signature versions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Baja Labs. ClamAV is a separate project under the GPL-2.0, used here as a network service through its official image.

## Citation

If you refer to this project in writing, cite it as: Baja Labs (2026). *venenum: an HTTP service in front of ClamAV*. https://github.com/bajalabs/venenum
