/**
 * Request signing, scheme v1 (docs/signing.md has the exact algorithm, a test vector and clients).
 *
 *   X-Venenum-Caller:    <caller>
 *   X-Venenum-Signature: t=<unix seconds>,v1=<64 lowercase hex>
 *
 * v1 = HMAC-SHA256(key, "<caller>.<t>." + raw request body), where key is the caller's 32-byte secret (64 hex characters)
 * and the body is the exact bytes sent. The server accepts |now - t| <= the signing window (60 s by default).
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export const CALLER_HEADER = "x-venenum-caller";
export const SIGNATURE_HEADER = "x-venenum-signature";
export const DEFAULT_WINDOW_SECONDS = 60;
export const HEX_KEY = /^[0-9a-f]{64}$/;

export type Body = string | Uint8Array;
export type VerifyResult = { ok: true; caller: string } | { ok: false; reason: "missing-headers" | "unknown-caller" | "bad-signature-format" | "stale" | "mismatch" };

/** Parses `t=<seconds>,v1=<hex>`; null when either part is missing or malformed. */
export function parseSignatureHeader(header: string | undefined): { t: number; v1: string } | null {
  const parts: Record<string, string> = {};
  for (const piece of String(header ?? "").split(",")) {
    const i = piece.indexOf("=");
    if (i > 0) parts[piece.slice(0, i).trim()] = piece.slice(i + 1).trim();
  }
  const t = Number(parts.t);
  const v1 = parts.v1 ?? "";
  if (!/^[0-9]{1,12}$/.test(parts.t ?? "") || !Number.isSafeInteger(t) || !/^[0-9a-f]{64}$/.test(v1)) return null;
  return { t, v1 };
}

export function computeSignature(caller: string, t: number, body: Body, hexKey: string): string {
  const h = createHmac("sha256", Buffer.from(hexKey, "hex"));
  h.update(`${caller}.${t}.`);
  h.update(body);
  return h.digest("hex");
}

/** The two headers for a request whose raw body is `body`. */
export function signHeaders(caller: string, body: Body, hexKey: string, now = Math.floor(Date.now() / 1000)): Record<string, string> {
  return { [CALLER_HEADER]: caller, [SIGNATURE_HEADER]: `t=${now},v1=${computeSignature(caller, now, body, hexKey)}` };
}

export function verifySignature(
  callerHeader: string | undefined,
  signatureHeader: string | undefined,
  body: Body,
  keys: ReadonlyMap<string, string>,
  { now = Math.floor(Date.now() / 1000), windowSeconds = DEFAULT_WINDOW_SECONDS } = {},
): VerifyResult {
  if (!callerHeader || !signatureHeader) return { ok: false, reason: "missing-headers" };
  const key = keys.get(callerHeader);
  if (!key || !HEX_KEY.test(key)) return { ok: false, reason: "unknown-caller" };
  const sig = parseSignatureHeader(signatureHeader);
  if (!sig) return { ok: false, reason: "bad-signature-format" };
  if (Math.abs(now - sig.t) > windowSeconds) return { ok: false, reason: "stale" };
  const expected = Buffer.from(computeSignature(callerHeader, sig.t, body, key), "hex");
  const given = Buffer.from(sig.v1, "hex");
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return { ok: false, reason: "mismatch" };
  return { ok: true, caller: callerHeader };
}
