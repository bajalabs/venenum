# Security

## Reporting a vulnerability

Report security issues privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability** (https://github.com/bajalabs/venenum/security/advisories/new). Do not open a public issue for a security problem. Include what you found, how to reproduce it, and its impact. We aim to acknowledge a report within five working days and to agree on a disclosure date with you.

Fixes go into the latest release.

## Threat model

venenum sits between applications that receive untrusted files and a ClamAV daemon. It is designed to be reachable only by those applications, on a private network or behind TLS.

### What it protects

- **The scan path from abuse.** Only callers holding a key can make it download or scan anything. A request carries `X-Venenum-Caller` and an HMAC-SHA256 signature over a timestamp and the exact body ([docs/signing.md](docs/signing.md)); the comparison is constant-time and the timestamp must be within the signing window (60 s by default).
- **The network behind it (SSRF).** `POST /v1/scan` downloads only from origins listed in `VENENUM_FETCH_ORIGINS` (scheme, host and port must match exactly), refuses URLs with credentials, and never follows redirects, so an allowed origin cannot bounce the request elsewhere. With no origins configured it downloads nothing.
- **The verdict's subject.** The caller states the object's sha256 and size; venenum refuses (`409`) bytes that differ, so a verdict always applies to the object the caller meant, even if the stored object was swapped between upload and scan.
- **Its own resources.** Objects are capped at `VENENUM_MAX_BYTES` whether the size is declared, sent or only discovered while streaming; JSON bodies are capped at `VENENUM_JSON_BODY_LIMIT`; downloads and clamd commands have time limits; clamd replies are bounded.
- **Stale protection.** When the signature database is older than `VENENUM_MAX_SIGNATURE_AGE_HOURS`, or clamd does not answer, `/health` fails and every scan answers `503`: an outdated or missing engine never produces a `clean` verdict.

### What it does not protect against

- **Network attackers between the caller and venenum.** The service speaks plain HTTP. The signature stops tampering with the body, but not reading it. Use TLS (a reverse proxy or a service mesh) or a private network.
- **Replay inside the window.** There is no nonce cache: a captured request can be sent again within the signing window. It can only repeat the same scan of the same bytes.
- **Unsigned headers.** `X-Scan-Sha256` and `X-Scan-Size` are checked against the signed body; `X-Scan-Ref` and the `ref` in a JSON body are labels for logs and are only as trustworthy as the caller.
- **A compromised caller key.** Anyone with a key can use the service within the limits above. Keep keys in a secret store, give each application its own caller name, and rotate as described in [docs/signing.md](docs/signing.md).
- **An allowed origin that serves hostile content, or a DNS answer that changes.** venenum trusts the origins you list; list object-store endpoints you control, not shared or user-controlled hosts.
- **Detection limits.** `clean` means ClamAV matched no signature. It is one layer, not a guarantee: keep uploads quarantined until scanned, and treat files as untrusted afterwards too.
- **Information on the health endpoints.** `/health` and `/v1/version` are unauthenticated and show the engine and signature versions.

### Operating it safely

- Run the image as provided: a non-root user, no shell entrypoint, only port 3330. In `compose.yaml`, clamd is not published and venenum is bound to `127.0.0.1` unless you change `VENENUM_BIND`.
- Generate keys with `openssl rand -hex 32`; never commit `.env`.
- Keep the clamav container updating its signatures (the official image runs freshclam) and alert on `/health`.
- The service logs the caller, the reference, the verdict and the size of each scan, never the body or the signature.
