import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { build } from "../src/server.ts";
import { signHeaders } from "../src/signing.ts";
import { EICAR, fakeClamd, fileServer, KEY, settings } from "./helpers.ts";

const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const clean = Buffer.from("a clean document");
const eicar = Buffer.from(EICAR);
const big = Buffer.alloc(2_000_000, 1);

let clamd: Awaited<ReturnType<typeof fakeClamd>>;
let files: Awaited<ReturnType<typeof fileServer>>;
let app: ReturnType<typeof build>;

beforeAll(async () => {
  clamd = await fakeClamd();
  files = await fileServer({ "clean.bin": clean, "eicar.com": eicar, "big.bin": big });
  app = build(settings({ origins: [files.origin], clamd: clamd.options }), { logger: false });
});
afterAll(async () => {
  await app.close();
  await files.close();
  await clamd.close();
});

const post = (body: unknown, caller = "app", key = KEY) => {
  const raw = JSON.stringify(body);
  return app.inject({ method: "POST", url: "/v1/scan", headers: { "content-type": "application/json", ...signHeaders(caller, raw, key) }, payload: raw });
};
const put = (bytes: Buffer, headers: Record<string, string>, key = KEY) =>
  app.inject({ method: "POST", url: "/v1/scan/bytes", headers: { "content-type": "application/octet-stream", ...signHeaders("app", bytes, key), ...headers }, payload: bytes });

describe("health", () => {
  test("health and version report the engine and the signature age", async () => {
    const h = await app.inject({ method: "GET", url: "/health" });
    expect(h.statusCode).toBe(200);
    expect(h.json()).toMatchObject({ ok: true, engine: "ClamAV 1.4.3", signatures: "27600" });
    const v = await app.inject({ method: "GET", url: "/v1/version" });
    expect(v.statusCode).toBe(200);
    expect(v.json().signatures).toBe("27600");
  });

  test("stale signatures fail health and make every scan 503", async () => {
    const old = await fakeClamd({ versionDate: "Mon Oct 05 10:00:00 2026" });
    const stale = build(settings({ origins: [files.origin], clamd: old.options }), { logger: false });
    try {
      const h = await stale.inject({ method: "GET", url: "/health" });
      expect(h.statusCode).toBe(503);
      expect(h.json().reason).toBe("signatures_stale");
      expect((await stale.inject({ method: "GET", url: "/v1/version" })).statusCode).toBe(200);
      const raw = JSON.stringify({ url: `${files.origin}/clean.bin`, sha256: sha(clean), size: clean.length });
      const s = await stale.inject({ method: "POST", url: "/v1/scan", headers: { "content-type": "application/json", ...signHeaders("app", raw, KEY) }, payload: raw });
      expect(s.statusCode).toBe(503);
      expect(s.json().error.code).toBe("scanner_unavailable");
    } finally {
      await stale.close();
      await old.close();
    }
  });

  test("an unreachable clamd fails health with the reason", async () => {
    const down = build(settings({ clamd: { connection: { path: "/nonexistent/clamd.sock" }, timeoutMs: 1_000 } }), { logger: false });
    const h = await down.inject({ method: "GET", url: "/health" });
    expect(h.statusCode).toBe(503);
    expect(h.json()).toMatchObject({ ok: false, reason: "clamd_unavailable" });
    await down.close();
  });
});

describe("POST /v1/scan", () => {
  test("clean and infected verdicts carry the digest, size, engine and reference", async () => {
    const c = await post({ url: `${files.origin}/clean.bin`, sha256: sha(clean), size: clean.length, ref: "doc-1" });
    expect(c.statusCode).toBe(200);
    expect(c.json()).toMatchObject({ verdict: "clean", reference: "ClamAV 1.4.3 / daily 27600", threat: null, sha256: sha(clean), size: clean.length, ref: "doc-1" });
    const i = await post({ url: `${files.origin}/eicar.com`, sha256: sha(eicar), size: eicar.length });
    expect(i.statusCode).toBe(200);
    expect(i.json()).toMatchObject({ verdict: "infected", reference: "Win.Test.EICAR_HDB-1", threat: "Win.Test.EICAR_HDB-1", ref: null });
  });

  test("refusals: signature 401, origin 403, digest or size 409, too large 413, redirect and download 502, body 400", async () => {
    const ok = { url: `${files.origin}/clean.bin`, sha256: sha(clean), size: clean.length };
    expect((await post(ok, "app", "d".repeat(64))).statusCode).toBe(401);
    expect((await post(ok, "stranger")).json().error.code).toBe("invalid_signature");
    expect((await post({ ...ok, url: "https://elsewhere.example/x" })).json().error.code).toBe("origin_not_allowed");
    expect((await post({ ...ok, url: `${files.origin.replace("http://", "http://user:pw@")}/clean.bin` })).statusCode).toBe(403);
    expect((await post({ ...ok, sha256: "f".repeat(64) })).json().error.code).toBe("integrity_mismatch");
    expect((await post({ ...ok, size: clean.length + 1 })).statusCode).toBe(409);
    expect((await post({ url: `${files.origin}/big.bin`, sha256: sha(big), size: big.length })).statusCode).toBe(413);
    expect((await post({ url: `${files.origin}/big.bin`, sha256: sha(big), size: 10 })).statusCode).toBe(413); // the stream is bigger than the cap
    expect((await post({ ...ok, url: `${files.origin}/redirect` })).json().error.code).toBe("download_failed");
    expect((await post({ ...ok, url: `${files.origin}/missing` })).statusCode).toBe(502);
    expect((await post({ sha256: "x" })).statusCode).toBe(400);
    expect((await post({ ...ok, sha256: ok.sha256.toUpperCase() })).statusCode).toBe(400);
    const raw = "{bad";
    const r = await app.inject({ method: "POST", url: "/v1/scan", headers: { "content-type": "application/json", ...signHeaders("app", raw, KEY) }, payload: raw });
    expect(r.statusCode).toBe(400);
  });

  test("the signature covers the exact bytes: a re-serialised body is refused", async () => {
    const raw = JSON.stringify({ url: `${files.origin}/clean.bin`, sha256: sha(clean), size: clean.length });
    const headers = { "content-type": "application/json", ...signHeaders("app", raw, KEY) };
    const r = await app.inject({ method: "POST", url: "/v1/scan", headers, payload: JSON.stringify(JSON.parse(raw), null, 1) });
    expect(r.statusCode).toBe(401);
  });

  test("other content types are refused", async () => {
    const r = await app.inject({ method: "POST", url: "/v1/scan", headers: { "content-type": "text/plain", ...signHeaders("app", "x", KEY) }, payload: "x" });
    expect(r.statusCode).toBe(415);
  });
});

describe("POST /v1/scan/bytes", () => {
  test("the raw body is scanned and the headers must match it", async () => {
    const c = await put(clean, { "x-scan-sha256": sha(clean), "x-scan-size": String(clean.length), "x-scan-ref": "image/1" });
    expect(c.statusCode).toBe(200);
    expect(c.json()).toMatchObject({ verdict: "clean", sha256: sha(clean), ref: "image/1" });
    expect(c.json().scanned_at).toBeTruthy();
    expect((await put(eicar, { "x-scan-sha256": sha(eicar), "x-scan-size": String(eicar.length) })).json().verdict).toBe("infected");
    expect((await put(clean, { "x-scan-sha256": "f".repeat(64), "x-scan-size": String(clean.length) })).statusCode).toBe(409);
    expect((await put(clean, { "x-scan-sha256": sha(clean), "x-scan-size": "3" })).statusCode).toBe(409);
    expect((await put(clean, { "x-scan-size": "1" })).statusCode).toBe(400);
    expect((await put(clean, { "x-scan-sha256": sha(clean), "x-scan-size": String(clean.length) }, "d".repeat(64))).statusCode).toBe(401);
    expect((await put(big, { "x-scan-sha256": sha(big), "x-scan-size": String(big.length) })).statusCode).toBe(413);
  });
});
