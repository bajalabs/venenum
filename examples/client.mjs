#!/usr/bin/env node
// A venenum client in Node.js with no dependencies (Node 18 or newer). The signing is the part to copy:
//   v1 = HMAC-SHA256(key, `${caller}.${t}.` + raw body), hex; headers X-Venenum-Caller and X-Venenum-Signature: t=…,v1=…
//
//   VENENUM_URL=http://127.0.0.1:3330 VENENUM_CALLER=my-app VENENUM_KEY=<64 hex> node examples/client.mjs bytes ./file.pdf
//   … node examples/client.mjs url https://files.example.com/a.pdf <sha256> <size>
//   node examples/client.mjs vector      # prints the docs/signing.md test-vector signature
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * The two headers for a request whose exact body bytes are `body` (a string is signed as its UTF-8 bytes).
 * @param {string} caller @param {string} hexKey @param {string | Uint8Array} body @param {number} [t]
 * @returns {Record<string, string>}
 */
export function sign(caller, hexKey, body, t = Math.floor(Date.now() / 1000)) {
  const v1 = createHmac("sha256", Buffer.from(hexKey, "hex")).update(`${caller}.${t}.`).update(body).digest("hex");
  return { "X-Venenum-Caller": caller, "X-Venenum-Signature": `t=${t},v1=${v1}` };
}

const base = (process.env.VENENUM_URL ?? "http://127.0.0.1:3330").replace(/\/+$/, "");
const caller = process.env.VENENUM_CALLER ?? "";
const key = process.env.VENENUM_KEY ?? "";

/** Scan bytes you hold: POST /v1/scan/bytes with the bytes as the body. @param {Buffer} bytes @param {string} [ref] */
export async function scanBytes(bytes, ref) {
  const headers = {
    "Content-Type": "application/octet-stream",
    "X-Scan-Sha256": createHash("sha256").update(bytes).digest("hex"),
    "X-Scan-Size": String(bytes.length),
    ...(ref ? { "X-Scan-Ref": ref } : {}),
    ...sign(caller, key, bytes),
  };
  const res = await fetch(`${base}/v1/scan/bytes`, { method: "POST", headers, body: bytes });
  return { status: res.status, body: await res.json() };
}

/**
 * Scan an object on an allowed origin: POST /v1/scan with its URL, sha256 and size. Sign the exact JSON you send.
 * @param {string} url @param {string} sha256 @param {number} size @param {string} [ref]
 */
export async function scanUrl(url, sha256, size, ref) {
  const body = JSON.stringify({ url, sha256, size, ...(ref ? { ref } : {}) });
  const res = await fetch(`${base}/v1/scan`, { method: "POST", headers: { "Content-Type": "application/json", ...sign(caller, key, body) }, body });
  return { status: res.status, body: await res.json() };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [command, ...args] = process.argv.slice(2);
  if (command === "vector") {
    const body = '{"url":"https://files.example.com/report.pdf","sha256":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae","size":3,"ref":"doc-42"}';
    console.log(sign("example-app", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", body, 1700000000)["X-Venenum-Signature"]);
  } else if (command === "bytes" && args[0]) {
    const r = await scanBytes(readFileSync(args[0]), args[0]);
    console.log(r.status, JSON.stringify(r.body));
    process.exitCode = r.status === 200 ? 0 : 1;
  } else if (command === "url" && args.length >= 3) {
    const r = await scanUrl(String(args[0]), String(args[1]), Number(args[2]), args[3]);
    console.log(r.status, JSON.stringify(r.body));
    process.exitCode = r.status === 200 ? 0 : 1;
  } else {
    console.error("usage: client.mjs bytes <file> | url <url> <sha256> <size> [ref] | vector");
    process.exitCode = 2;
  }
}
