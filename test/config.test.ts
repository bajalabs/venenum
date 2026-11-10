import { describe, expect, test } from "vitest";
import { ConfigError, DEFAULTS, settingsFromEnv } from "../src/config.ts";

const k1 = "a".repeat(64);
const k2 = "B".repeat(64);

describe("settingsFromEnv", () => {
  test("every setting has a default", () => {
    const s = settingsFromEnv({});
    expect(s.host).toBe("0.0.0.0");
    expect(s.port).toBe(3330);
    expect(s.keys.size).toBe(0);
    expect(s.origins).toEqual([]);
    expect(s.maxBytes).toBe(DEFAULTS.VENENUM_MAX_BYTES);
    expect(s.jsonBodyLimit).toBe(65_536);
    expect(s.fetchTimeoutMs).toBe(60_000);
    expect(s.maxSignatureAgeMs).toBe(72 * 3_600_000);
    expect(s.signingWindowSeconds).toBe(60);
    expect(s.logLevel).toBe("info");
    expect(s.clamd).toEqual({ connection: { path: "/tmp/clamd.sock" }, timeoutMs: 90_000 });
  });

  test("keys are caller:hex pairs, origins are normalised, clamd over TCP", () => {
    const s = settingsFromEnv({
      VENENUM_HMAC_KEYS: ` app:${k1} , worker-2:${k2}`,
      VENENUM_FETCH_ORIGINS: "https://files.example.com/, http://127.0.0.1:8000,https://files.example.com",
      CLAMD_HOST: "clamav",
      CLAMD_PORT: "3311",
      PORT: "8080",
      VENENUM_SIGNING_WINDOW_SECONDS: "120",
    });
    expect([...s.keys]).toEqual([["app", k1], ["worker-2", k2.toLowerCase()]]);
    expect(s.origins).toEqual(["https://files.example.com", "http://127.0.0.1:8000"]);
    expect(s.clamd.connection).toEqual({ host: "clamav", port: 3311 });
    expect([s.port, s.signingWindowSeconds]).toEqual([8080, 120]);
  });

  test("every invalid setting is reported at once and the service does not start", () => {
    try {
      settingsFromEnv({
        VENENUM_HMAC_KEYS: `app:short,bad name:${k1},app:${k1},app:${k1}`,
        VENENUM_FETCH_ORIGINS: "https://files.example.com/bucket,ftp://x.example,https://user:pw@x.example",
        VENENUM_MAX_BYTES: "25MB",
        PORT: "70000",
        CLAMD_SOCKET: "/tmp/c.sock",
        CLAMD_HOST: "clamav",
        VENENUM_LOG_LEVEL: "loud",
      });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigError);
      const p = (e as ConfigError).problems;
      expect(p).toContain("VENENUM_HMAC_KEYS: the key for app must be 64 hex characters (32 bytes; openssl rand -hex 32)");
      expect(p.some((x) => x.includes('"bad name" is not a caller name'))).toBe(true);
      expect(p).toContain("VENENUM_HMAC_KEYS: app appears twice");
      expect(p.filter((x) => x.startsWith("VENENUM_FETCH_ORIGINS"))).toHaveLength(3);
      expect(p).toContain("VENENUM_MAX_BYTES must be a whole number from 1 to 9007199254740991 (got 25MB)");
      expect(p.some((x) => x.startsWith("PORT must be"))).toBe(true);
      expect(p).toContain("set CLAMD_SOCKET or CLAMD_HOST, not both");
      expect(p.some((x) => x.startsWith("VENENUM_LOG_LEVEL"))).toBe(true);
    }
  });
});
