import { expect, test } from "vitest";
import { parseVersion, scanBytes, version } from "../src/clamd.ts";
import { EICAR, fakeClamd } from "./helpers.ts";

test("VERSION gives the engine, the signature version and its date; INSTREAM answers OK and FOUND", async () => {
  const c = await fakeClamd({ versionDate: "Wed Oct 14 10:00:00 2026" });
  try {
    const v = await version(c.options);
    expect([v.engine, v.signatures, v.signatures_at]).toEqual(["ClamAV 1.4.3", "27600", "2026-10-14T10:00:00.000Z"]);
    expect(await scanBytes(c.options, Buffer.from("hello"))).toEqual({ clean: true, threat: null });
    expect(await scanBytes(c.options, Buffer.from(EICAR))).toEqual({ clean: false, threat: "Win.Test.EICAR_HDB-1" });
    expect((await scanBytes(c.options, Buffer.alloc(200 * 1024, 7))).clean).toBe(true); // more than one 64 KiB chunk
  } finally {
    await c.close();
  }
});

test("an unreadable VERSION reply, an unreachable clamd and a timeout are errors, never a verdict", async () => {
  expect(() => parseVersion("ClamAV 1.4.3/27600/garbage")).toThrow(/unreadable/);
  expect(() => parseVersion("")).toThrow(/unavailable/);
  expect(parseVersion("ClamAV 1.4.3/27600/Wed Oct 14 10:00:00 2026", Date.parse("2026-10-15T10:00:00Z")).age_ms).toBe(24 * 3_600_000);
  await expect(version({ connection: { path: "/nonexistent/clamd.sock" }, timeoutMs: 1_000 })).rejects.toThrow(/connection failed/);
});
