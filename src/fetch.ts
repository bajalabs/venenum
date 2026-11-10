/** Fetch the object to scan from an allowed origin, with no redirects and a size cap, and check it is what the caller described. */
import { createHash } from "node:crypto";

export class ScanError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message?: string) {
    super(message ?? code);
    this.status = status;
    this.code = code;
  }
}

/** True when `url` is http(s), carries no credentials, and its origin is one of `origins` exactly. */
export function originAllowed(url: string, origins: readonly string[]): boolean {
  try {
    const u = new URL(url);
    return (u.protocol === "https:" || u.protocol === "http:") && !u.username && !u.password && origins.includes(u.origin);
  } catch {
    return false;
  }
}

export async function fetchBytes(url: string, { maxBytes, timeoutMs, fetchImpl = fetch }: { maxBytes: number; timeoutMs: number; fetchImpl?: typeof fetch }): Promise<Uint8Array> {
  let res: Response;
  try {
    res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs), redirect: "error" });
  } catch (e) {
    throw new ScanError(502, "download_failed", e instanceof Error ? e.message : String(e));
  }
  if (!res.ok) throw new ScanError(502, "download_failed", `upstream answered ${res.status}`);
  const declared = Number(res.headers.get("content-length") ?? 0);
  if (declared > maxBytes) {
    await res.body?.cancel().catch(() => undefined);
    throw new ScanError(413, "too_large", `declared ${declared} bytes > ${maxBytes}`);
  }
  const reader = res.body?.getReader();
  if (!reader) {
    const b = new Uint8Array(await res.arrayBuffer());
    if (b.byteLength > maxBytes) throw new ScanError(413, "too_large", `more than ${maxBytes} bytes`);
    return b;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new ScanError(413, "too_large", `more than ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

export const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
