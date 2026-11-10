/**
 * The HTTP service. POST /v1/scan fetches an object from an allowed origin and scans it; POST /v1/scan/bytes scans the body.
 * Both are signed (src/signing.ts), check the object's sha256 and size against what the caller said, and answer a verdict.
 * GET /health is 200 only while clamd answers and its signatures are fresh; GET /v1/version always answers the same facts.
 */
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { type ClamdVersion, scanBytes, type Verdict, version } from "./clamd.ts";
import type { Settings } from "./config.ts";
import { fetchBytes, originAllowed, ScanError, sha256 } from "./fetch.ts";
import { CALLER_HEADER, SIGNATURE_HEADER, verifySignature } from "./signing.ts";

export interface Deps {
  version?: (options: Settings["clamd"]) => Promise<ClamdVersion>;
  scanBytes?: (options: Settings["clamd"], bytes: Uint8Array) => Promise<Verdict>;
  fetchImpl?: typeof fetch;
  logger?: boolean | { level: string };
}

type Status =
  | { ok: true; engine: string; signatures: string; signatures_at: string; age_hours: number }
  | { ok: false; reason: "signatures_stale"; engine: string; signatures: string; signatures_at: string; age_hours: number }
  | { ok: false; reason: "clamd_unavailable"; detail: string };

const header = (req: FastifyRequest, name: string) => {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
};

export function build(settings: Settings, deps: Deps = {}) {
  const clamdVersion = deps.version ?? version;
  const scan = deps.scanBytes ?? scanBytes;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const app = Fastify({ logger: deps.logger ?? { level: settings.logLevel }, bodyLimit: settings.jsonBodyLimit });

  // Only JSON and octet-stream bodies are read (anything else is 415), and both keep the raw bytes the signature covers.
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("application/json", { parseAs: "buffer" }, (req, body: Buffer, done) => {
    req.rawBody = body;
    try {
      done(null, body.length ? JSON.parse(body.toString("utf8")) : {});
    } catch {
      done(Object.assign(new Error("invalid JSON"), { statusCode: 400 }), undefined);
    }
  });
  app.addContentTypeParser("application/octet-stream", { parseAs: "buffer", bodyLimit: settings.maxBytes + 1 }, (req, body: Buffer, done) => {
    req.rawBody = body;
    done(null, body);
  });

  const fail = (reply: FastifyReply, status: number, code: string, message?: string) => reply.code(status).send({ error: { code, message: message ?? code } });

  const status = async (): Promise<Status> => {
    try {
      const v = await clamdVersion(settings.clamd);
      const facts = { engine: v.engine, signatures: v.signatures, signatures_at: v.signatures_at, age_hours: Math.round(v.age_ms / 3_600_000) };
      return v.age_ms > settings.maxSignatureAgeMs ? { ok: false, reason: "signatures_stale", ...facts } : { ok: true, ...facts };
    } catch (e) {
      return { ok: false, reason: "clamd_unavailable", detail: e instanceof Error ? e.message : String(e) };
    }
  };

  app.get("/health", async (req, reply) => {
    const s = await status();
    if (!s.ok) req.log.warn({ status: s }, "health not ok");
    return reply.code(s.ok ? 200 : 503).send(s);
  });
  app.get("/v1/version", async (_req, reply) => reply.code(200).send(await status()));

  const signed = async (req: FastifyRequest, reply: FastifyReply) => {
    const r = verifySignature(header(req, CALLER_HEADER), header(req, SIGNATURE_HEADER), req.rawBody ?? Buffer.alloc(0), settings.keys, { windowSeconds: settings.signingWindowSeconds });
    if (!r.ok) {
      req.log.info({ reason: r.reason, caller: header(req, CALLER_HEADER) }, "signature refused");
      return fail(reply, 401, "invalid_signature", `request signature refused (${r.reason})`);
    }
    req.caller = r.caller;
  };

  /** The verdict on bytes in hand: the digest and size must match what the caller said, then clamd decides. */
  const verdict = async (req: FastifyRequest, reply: FastifyReply, bytes: Uint8Array, expected: { sha256: string; size: number; ref: string | null }) => {
    const s = await status();
    if (!s.ok) return fail(reply, 503, "scanner_unavailable", s.reason);
    const digest = sha256(bytes);
    if (digest !== expected.sha256 || bytes.byteLength !== expected.size) return fail(reply, 409, "integrity_mismatch", `got sha256 ${digest} and ${bytes.byteLength} bytes`);
    let v: Verdict;
    try {
      v = await scan(settings.clamd, bytes);
    } catch (e) {
      req.log.error({ err: e, ref: expected.ref }, "scan failed");
      return fail(reply, 503, "scanner_unavailable", e instanceof Error ? e.message : String(e));
    }
    const result = v.clean ? "clean" : "infected";
    req.log.info({ ref: expected.ref, caller: req.caller, verdict: result, size: bytes.byteLength }, "scanned");
    return reply.code(200).send({
      verdict: result,
      reference: v.clean ? `${s.engine} / daily ${s.signatures}` : v.threat,
      threat: v.threat,
      sha256: digest,
      size: bytes.byteLength,
      ref: expected.ref,
      engine: s.engine,
      signatures: s.signatures,
      signatures_at: s.signatures_at,
      scanned_at: new Date().toISOString(),
    });
  };

  app.post("/v1/scan/bytes", { preHandler: signed, bodyLimit: settings.maxBytes + 1 }, async (req, reply) => {
    const bytes = Buffer.isBuffer(req.body) ? req.body : null;
    if (!bytes) return fail(reply, 400, "invalid_body", "send the object as application/octet-stream");
    const digest = String(header(req, "x-scan-sha256") ?? "").toLowerCase();
    const size = Number(header(req, "x-scan-size"));
    if (!/^[0-9a-f]{64}$/.test(digest) || !Number.isSafeInteger(size) || size < 0) return fail(reply, 400, "invalid_body", "X-Scan-Sha256 (64 hex) and X-Scan-Size are required");
    if (bytes.byteLength > settings.maxBytes || size > settings.maxBytes) return fail(reply, 413, "too_large", `more than ${settings.maxBytes} bytes`);
    return verdict(req, reply, bytes, { sha256: digest, size, ref: header(req, "x-scan-ref")?.slice(0, 256) ?? null });
  });

  app.post("/v1/scan", { preHandler: signed }, async (req, reply) => {
    const b = (req.body ?? {}) as { url?: unknown; sha256?: unknown; size?: unknown; ref?: unknown };
    if (typeof b.url !== "string" || typeof b.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(b.sha256) || !Number.isSafeInteger(b.size) || (b.size as number) < 0) {
      return fail(reply, 400, "invalid_body", "url, sha256 (64 lowercase hex) and size are required");
    }
    const size = b.size as number;
    if (!originAllowed(b.url, settings.origins)) return fail(reply, 403, "origin_not_allowed", "the url is not on an allowed origin");
    if (size > settings.maxBytes) return fail(reply, 413, "too_large", `size ${size} > ${settings.maxBytes}`);
    const pre = await status();
    if (!pre.ok) return fail(reply, 503, "scanner_unavailable", pre.reason);
    let bytes: Uint8Array;
    try {
      bytes = await fetchBytes(b.url, { maxBytes: settings.maxBytes, timeoutMs: settings.fetchTimeoutMs, fetchImpl });
    } catch (e) {
      if (e instanceof ScanError) return fail(reply, e.status, e.code, e.message);
      throw e;
    }
    return verdict(req, reply, bytes, { sha256: b.sha256, size, ref: typeof b.ref === "string" ? b.ref.slice(0, 256) : null });
  });

  return app;
}
