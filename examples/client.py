#!/usr/bin/env python3
"""A venenum client in Python with the standard library only (Python 3.9 or newer). The signing is the part to copy:
    v1 = HMAC-SHA256(key, f"{caller}.{t}.".encode() + raw body), hex; headers X-Venenum-Caller and X-Venenum-Signature: t=...,v1=...

    VENENUM_URL=http://127.0.0.1:3330 VENENUM_CALLER=my-app VENENUM_KEY=<64 hex> python3 examples/client.py bytes ./file.pdf
    ... python3 examples/client.py url https://files.example.com/a.pdf <sha256> <size>
    python3 examples/client.py vector      # prints the docs/signing.md test-vector signature
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("VENENUM_URL", "http://127.0.0.1:3330").rstrip("/")
CALLER = os.environ.get("VENENUM_CALLER", "")
KEY = os.environ.get("VENENUM_KEY", "")


def sign(caller: str, hex_key: str, body: bytes, t: int | None = None) -> dict[str, str]:
    """The two headers for a request whose exact body bytes are `body`."""
    t = int(time.time()) if t is None else t
    v1 = hmac.new(bytes.fromhex(hex_key), f"{caller}.{t}.".encode() + body, hashlib.sha256).hexdigest()
    return {"X-Venenum-Caller": caller, "X-Venenum-Signature": f"t={t},v1={v1}"}


def _post(path: str, body: bytes, headers: dict[str, str]) -> tuple[int, dict]:
    request = urllib.request.Request(f"{BASE}{path}", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def scan_bytes(data: bytes, ref: str | None = None) -> tuple[int, dict]:
    """Scan bytes you hold: POST /v1/scan/bytes with the bytes as the body."""
    headers = {
        "Content-Type": "application/octet-stream",
        "X-Scan-Sha256": hashlib.sha256(data).hexdigest(),
        "X-Scan-Size": str(len(data)),
        **({"X-Scan-Ref": ref} if ref else {}),
        **sign(CALLER, KEY, data),
    }
    return _post("/v1/scan/bytes", data, headers)


def scan_url(url: str, sha256: str, size: int, ref: str | None = None) -> tuple[int, dict]:
    """Scan an object on an allowed origin: POST /v1/scan. Sign the exact JSON bytes you send."""
    body = json.dumps({"url": url, "sha256": sha256, "size": size, **({"ref": ref} if ref else {})}, separators=(",", ":")).encode()
    return _post("/v1/scan", body, {"Content-Type": "application/json", **sign(CALLER, KEY, body)})


def main(argv: list[str]) -> int:
    if argv[:1] == ["vector"]:
        body = b'{"url":"https://files.example.com/report.pdf","sha256":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae","size":3,"ref":"doc-42"}'
        print(sign("example-app", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", body, 1700000000)["X-Venenum-Signature"])
        return 0
    if argv[:1] == ["bytes"] and len(argv) >= 2:
        with open(argv[1], "rb") as f:
            status, body = scan_bytes(f.read(), argv[1])
    elif argv[:1] == ["url"] and len(argv) >= 4:
        status, body = scan_url(argv[1], argv[2], int(argv[3]), argv[4] if len(argv) > 4 else None)
    else:
        print("usage: client.py bytes <file> | url <url> <sha256> <size> [ref] | vector", file=sys.stderr)
        return 2
    print(status, json.dumps(body, separators=(",", ":")))
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
