/**
 * End-to-end check of a running venenum with a real clamd (CI runs it against `docker compose up`):
 * an EICAR test string must come back infected and a clean text clean, through POST /v1/scan/bytes and,
 * when SMOKE_FIXTURE_HOST is set, through POST /v1/scan from a fixture server this script runs.
 * EICAR is assembled in memory; no file carries it.
 *
 *   VENENUM_URL       the service (default http://127.0.0.1:3330)
 *   VENENUM_CALLER    a caller name in the service's VENENUM_HMAC_KEYS
 *   VENENUM_KEY       that caller's key (64 hex)
 *   SMOKE_FIXTURE_HOST, SMOKE_FIXTURE_PORT   how the service reaches this script (for example host.docker.internal, 8765)
 */
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { signHeaders } from "../src/signing.ts";

const base = (process.env.VENENUM_URL ?? "http://127.0.0.1:3330").replace(/\/+$/, "");
const caller = process.env.VENENUM_CALLER ?? "";
const key = process.env.VENENUM_KEY ?? "";
const fixtureHost = process.env.SMOKE_FIXTURE_HOST;
const fixturePort = Number(process.env.SMOKE_FIXTURE_PORT ?? 8765);
if (!caller || !/^[0-9a-f]{64}$/.test(key)) {
  console.error("smoke: set VENENUM_CALLER and VENENUM_KEY (64 hex)");
  process.exit(2);
}

const eicar = Buffer.from(["X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD", "-ANTIVIRUS-TEST-FILE!$H+H*"].join(""));
const clean = Buffer.from("a clean document\n");
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
let failures = 0;

function expectVerdict(label: string, status: number, body: { verdict?: string }, want: string) {
  const ok = status === 200 && body.verdict === want;
  console.log(`${ok ? "ok  " : "FAIL"} ${label}: ${status} ${JSON.stringify(body)}`);
  if (!ok) failures++;
}

const health = await fetch(`${base}/health`);
console.log(`health: ${health.status} ${await health.text()}`);
if (!health.ok) process.exit(1);

for (const [name, bytes, want] of [["clean", clean, "clean"], ["eicar", eicar, "infected"]] as const) {
  const res = await fetch(`${base}/v1/scan/bytes`, {
    method: "POST",
    headers: { "content-type": "application/octet-stream", "x-scan-sha256": sha(bytes), "x-scan-size": String(bytes.length), "x-scan-ref": `smoke/${name}`, ...signHeaders(caller, bytes, key) },
    body: bytes,
  });
  expectVerdict(`POST /v1/scan/bytes ${name}`, res.status, (await res.json()) as { verdict?: string }, want);
}

if (fixtureHost) {
  const files: Record<string, Buffer> = { "/clean.txt": clean, "/eicar.com": eicar };
  const server = createServer((req, res) => {
    const b = files[req.url ?? ""];
    res.writeHead(b ? 200 : 404, b ? { "content-type": "application/octet-stream", "content-length": b.length } : {});
    res.end(b);
  });
  await new Promise<void>((r) => server.listen(fixturePort, "0.0.0.0", r));
  try {
    for (const [path, bytes, want] of [["/clean.txt", clean, "clean"], ["/eicar.com", eicar, "infected"]] as const) {
      const raw = JSON.stringify({ url: `http://${fixtureHost}:${fixturePort}${path}`, sha256: sha(bytes), size: bytes.length, ref: `smoke${path}` });
      const res = await fetch(`${base}/v1/scan`, { method: "POST", headers: { "content-type": "application/json", ...signHeaders(caller, raw, key) }, body: raw });
      expectVerdict(`POST /v1/scan ${path}`, res.status, (await res.json()) as { verdict?: string }, want);
    }
  } finally {
    server.close();
  }
}
process.exit(failures ? 1 : 0);
