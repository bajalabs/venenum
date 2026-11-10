/**
 * Settings, all from environment variables with documented defaults (README.md, Configuration). Invalid values stop the
 * service at start with every problem listed, rather than running with a setting it did not understand.
 */
import type { ClamdOptions } from "./clamd.ts";
import { DEFAULT_WINDOW_SECONDS, HEX_KEY } from "./signing.ts";

export interface Settings {
  host: string;
  port: number;
  logLevel: string;
  keys: Map<string, string>;
  origins: string[];
  maxBytes: number;
  jsonBodyLimit: number;
  fetchTimeoutMs: number;
  maxSignatureAgeMs: number;
  signingWindowSeconds: number;
  clamd: ClamdOptions;
}

export const DEFAULTS = {
  HOST: "0.0.0.0",
  PORT: 3330,
  VENENUM_LOG_LEVEL: "info",
  VENENUM_MAX_BYTES: 26_214_400,
  VENENUM_JSON_BODY_LIMIT: 65_536,
  VENENUM_FETCH_TIMEOUT_MS: 60_000,
  VENENUM_MAX_SIGNATURE_AGE_HOURS: 72,
  VENENUM_SIGNING_WINDOW_SECONDS: DEFAULT_WINDOW_SECONDS,
  CLAMD_SOCKET: "/tmp/clamd.sock",
  CLAMD_PORT: 3310,
  CLAMD_TIMEOUT_MS: 90_000,
} as const;

const LOG_LEVELS = ["fatal", "error", "warn", "info", "debug", "trace", "silent"];
const CALLER = /^[A-Za-z0-9._-]{1,64}$/;

export class ConfigError extends Error {
  problems: string[];
  constructor(problems: string[]) {
    super(`invalid configuration:\n  ${problems.join("\n  ")}`);
    this.problems = problems;
  }
}

type Env = Record<string, string | undefined>;
const value = (env: Env, name: string) => {
  const v = env[name]?.trim();
  return v ? v : undefined;
};

/** `caller:hexkey` pairs separated by commas. A caller name may appear once; rotate a key by adding a second caller name. */
export function parseKeys(raw: string | undefined, problems: string[]): Map<string, string> {
  const keys = new Map<string, string>();
  for (const pair of (raw ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const i = pair.indexOf(":");
    const caller = i > 0 ? pair.slice(0, i).trim() : "";
    const key = i > 0 ? pair.slice(i + 1).trim().toLowerCase() : "";
    if (!CALLER.test(caller)) problems.push(`VENENUM_HMAC_KEYS: "${caller || pair.slice(0, 16)}" is not a caller name (letters, digits, dot, dash, underscore; up to 64)`);
    else if (!HEX_KEY.test(key)) problems.push(`VENENUM_HMAC_KEYS: the key for ${caller} must be 64 hex characters (32 bytes; openssl rand -hex 32)`);
    else if (keys.has(caller)) problems.push(`VENENUM_HMAC_KEYS: ${caller} appears twice`);
    else keys.set(caller, key);
  }
  return keys;
}

/** Comma-separated origins (scheme://host[:port]); a path, query or credentials are refused. */
export function parseOrigins(raw: string | undefined, problems: string[]): string[] {
  const out: string[] = [];
  for (const item of (raw ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    let u: URL;
    try {
      u = new URL(item);
    } catch {
      problems.push(`VENENUM_FETCH_ORIGINS: ${item} is not a URL`);
      continue;
    }
    if (!/^https?:$/.test(u.protocol) || u.username || u.password || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) {
      problems.push(`VENENUM_FETCH_ORIGINS: ${item} must be an origin such as https://files.example.com (no path, query or credentials)`);
      continue;
    }
    out.push(u.origin);
  }
  return [...new Set(out)];
}

function integer(env: Env, name: keyof typeof DEFAULTS, problems: string[], { min = 1, max = Number.MAX_SAFE_INTEGER } = {}): number {
  const raw = value(env, name);
  if (raw === undefined) return DEFAULTS[name] as number;
  const n = Number(raw);
  if (!/^[0-9]+$/.test(raw) || !Number.isSafeInteger(n) || n < min || n > max) {
    problems.push(`${name} must be a whole number from ${min} to ${max} (got ${raw})`);
    return DEFAULTS[name] as number;
  }
  return n;
}

export function settingsFromEnv(env: Env = process.env): Settings {
  const problems: string[] = [];
  const logLevel = value(env, "VENENUM_LOG_LEVEL") ?? DEFAULTS.VENENUM_LOG_LEVEL;
  if (!LOG_LEVELS.includes(logLevel)) problems.push(`VENENUM_LOG_LEVEL must be one of ${LOG_LEVELS.join(", ")}`);
  const socket = value(env, "CLAMD_SOCKET");
  const clamdHost = value(env, "CLAMD_HOST");
  if (socket && clamdHost) problems.push("set CLAMD_SOCKET or CLAMD_HOST, not both");
  const clamdPort = integer(env, "CLAMD_PORT", problems, { max: 65_535 });
  const clamdTimeout = integer(env, "CLAMD_TIMEOUT_MS", problems);
  const settings: Settings = {
    host: value(env, "HOST") ?? DEFAULTS.HOST,
    port: integer(env, "PORT", problems, { min: 0, max: 65_535 }),
    logLevel,
    keys: parseKeys(env.VENENUM_HMAC_KEYS, problems),
    origins: parseOrigins(env.VENENUM_FETCH_ORIGINS, problems),
    maxBytes: integer(env, "VENENUM_MAX_BYTES", problems),
    jsonBodyLimit: integer(env, "VENENUM_JSON_BODY_LIMIT", problems, { min: 256 }),
    fetchTimeoutMs: integer(env, "VENENUM_FETCH_TIMEOUT_MS", problems),
    maxSignatureAgeMs: integer(env, "VENENUM_MAX_SIGNATURE_AGE_HOURS", problems) * 3_600_000,
    signingWindowSeconds: integer(env, "VENENUM_SIGNING_WINDOW_SECONDS", problems, { max: 3_600 }),
    clamd: {
      connection: clamdHost ? { host: clamdHost, port: clamdPort } : { path: socket ?? DEFAULTS.CLAMD_SOCKET },
      timeoutMs: clamdTimeout,
    },
  };
  if (problems.length) throw new ConfigError(problems);
  return settings;
}
