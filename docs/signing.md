# Request signing (v1)

Every `POST /v1/scan` and `POST /v1/scan/bytes` carries two headers. A request without them, with an unknown caller, outside the time window, or with a signature that does not match is answered `401 invalid_signature`.

```
X-Venenum-Caller: <caller>
X-Venenum-Signature: t=<timestamp>,v1=<signature>
```

## The algorithm

1. **Key.** Each caller has a 32-byte secret, written as 64 hexadecimal characters (`openssl rand -hex 32`). The service knows it through `VENENUM_HMAC_KEYS=caller:key,…`. Decode the hex to 32 bytes; the HMAC key is those bytes, not the hex text.
2. **Timestamp.** `t` is the current Unix time in whole seconds, as decimal digits (no sign, no fraction).
3. **Message.** The bytes of the ASCII string `<caller>.<t>.` followed by the **exact raw bytes of the request body**: the JSON text you send for `/v1/scan` (sign the string you put on the wire, not an object you serialise again), or the file bytes for `/v1/scan/bytes`.
4. **Signature.** `v1` = HMAC-SHA256(key, message), written as 64 lowercase hexadecimal characters.
5. **Headers.** `X-Venenum-Caller: <caller>` and `X-Venenum-Signature: t=<t>,v1=<v1>`. The two parts may come in either order, separated by a comma.

The service recomputes the HMAC with the caller's key over the body it received, compares it in constant time, and accepts the request when `|now − t|` is at most `VENENUM_SIGNING_WINDOW_SECONDS` (60 by default). Keep the caller's clock in sync (NTP).

The `X-Scan-Sha256`, `X-Scan-Size` and `X-Scan-Ref` headers of `/v1/scan/bytes` are **not** signed; the service checks the digest and size against the signed body, so a changed value only causes `409 integrity_mismatch`. `X-Scan-Ref` is echoed back and logged; treat it as a label, not as a fact.

## Test vector

| Input | Value |
|---|---|
| caller | `example-app` |
| t | `1700000000` |
| key (hex) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| body | `{"url":"https://files.example.com/report.pdf","sha256":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae","size":3,"ref":"doc-42"}` |
| **v1** | `e3a1cc5806ef5d189b9ababace90ada8141f69d3eeeb2a7a208072a94d1c77ea` |

So the header is `X-Venenum-Signature: t=1700000000,v1=e3a1cc5806ef5d189b9ababace90ada8141f69d3eeeb2a7a208072a94d1c77ea`. The tests check that the service and both example clients produce exactly this value (`node examples/client.mjs vector`, `python3 examples/client.py vector`).

## Node.js

```js
import { createHmac } from "node:crypto";

function sign(caller, hexKey, body, t = Math.floor(Date.now() / 1000)) {
  const v1 = createHmac("sha256", Buffer.from(hexKey, "hex")).update(`${caller}.${t}.`).update(body).digest("hex");
  return { "X-Venenum-Caller": caller, "X-Venenum-Signature": `t=${t},v1=${v1}` };
}

const body = JSON.stringify({ url: "https://files.example.com/report.pdf", sha256: "…", size: 1234, ref: "doc-42" });
const res = await fetch("http://127.0.0.1:3330/v1/scan", {
  method: "POST",
  headers: { "Content-Type": "application/json", ...sign("my-app", process.env.VENENUM_KEY, body) },
  body, // the same string that was signed
});
console.log(res.status, await res.json());
```

The full client, with `/v1/scan/bytes`, is [`examples/client.mjs`](../examples/client.mjs).

## Python

```python
import hashlib, hmac, json, os, time, urllib.request

def sign(caller: str, hex_key: str, body: bytes, t: int | None = None) -> dict[str, str]:
    t = int(time.time()) if t is None else t
    v1 = hmac.new(bytes.fromhex(hex_key), f"{caller}.{t}.".encode() + body, hashlib.sha256).hexdigest()
    return {"X-Venenum-Caller": caller, "X-Venenum-Signature": f"t={t},v1={v1}"}

body = json.dumps({"url": "https://files.example.com/report.pdf", "sha256": "…", "size": 1234}).encode()
request = urllib.request.Request(
    "http://127.0.0.1:3330/v1/scan", data=body, method="POST",
    headers={"Content-Type": "application/json", **sign("my-app", os.environ["VENENUM_KEY"], body)},
)
with urllib.request.urlopen(request) as response:
    print(response.status, json.load(response))
```

The full client, with `/v1/scan/bytes` and error handling, is [`examples/client.py`](../examples/client.py) (standard library only).

## Rotating a key

A caller name maps to one key. To rotate without downtime, add a second caller name with the new key (`my-app:old,my-app-2:new`), move the client to the new name, then remove the old pair. Restart the service after changing `VENENUM_HMAC_KEYS`.
