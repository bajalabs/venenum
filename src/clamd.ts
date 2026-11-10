/**
 * A minimal clamd client: one connection per command, zVERSION and zINSTREAM in 64 KiB chunks, bounded replies,
 * a timeout, and the signature database's date read from VERSION.
 */
import { createConnection, type NetConnectOpts } from "node:net";

const MAX_REPLY = 4096;
const CHUNK = 64 * 1024;
const EICAR = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE";

export interface ClamdOptions {
  connection: NetConnectOpts;
  timeoutMs: number;
}
export interface ClamdVersion {
  engine: string;
  signatures: string;
  signatures_at: string;
  age_ms: number;
  raw: string;
}
export type Verdict = { clean: true; threat: null } | { clean: false; threat: string };

const write = (socket: ReturnType<typeof createConnection>, bytes: Uint8Array) =>
  new Promise<void>((resolve, reject) => socket.write(bytes, (e) => (e ? reject(e) : resolve())));

/** Sends zVERSION (no bytes) or zINSTREAM (bytes) and resolves with the NUL-terminated reply. */
export function command(options: ClamdOptions, bytes?: Uint8Array): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(options.connection);
    let reply = Buffer.alloc(0);
    let sent = false;
    let settled = false;
    const finish = (error?: Error, value?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(value ?? "");
    };
    const timer = setTimeout(() => finish(new Error("clamd timed out")), options.timeoutMs);
    socket.on("error", () => finish(new Error("clamd connection failed")));
    socket.on("close", () => finish(new Error("clamd response was incomplete")));
    socket.on("data", (chunk: Buffer) => {
      if (reply.length + chunk.length > MAX_REPLY) return finish(new Error("clamd response exceeded the limit"));
      reply = Buffer.concat([reply, chunk]);
      const end = reply.indexOf(0);
      if (end < 0) return;
      if (!sent || end !== reply.length - 1) return finish(new Error("clamd returned an invalid response"));
      finish(undefined, reply.subarray(0, end).toString("utf8"));
    });
    socket.once("connect", () => {
      void (async () => {
        if (!bytes) {
          sent = true;
          await write(socket, Buffer.from("zVERSION\0"));
          return;
        }
        await write(socket, Buffer.from("zINSTREAM\0"));
        for (let offset = 0; offset < bytes.length; offset += CHUNK) {
          if (settled) return;
          const chunk = bytes.subarray(offset, offset + CHUNK);
          const len = Buffer.alloc(4);
          len.writeUInt32BE(chunk.length);
          await write(socket, len);
          await write(socket, chunk);
        }
        sent = true;
        await write(socket, Buffer.alloc(4));
      })().catch(() => finish(new Error("clamd stream failed")));
    });
  });
}

/** "ClamAV 1.4.3/27600/Wed Oct 14 10:00:00 2026" → engine, signature version, its date and age. */
export function parseVersion(reply: string, now = Date.now()): ClamdVersion {
  const m = /^ClamAV ([0-9]+\.[0-9]+\.[0-9]+[^/\r\n]*)\/([0-9]+)\/([^\r\n]+)$/.exec(reply ?? "");
  if (!m) throw new Error("clamd version is unavailable (no signatures loaded?)");
  const at = Date.parse(`${m[3]} UTC`);
  if (!Number.isFinite(at)) throw new Error("clamd signature date is unreadable");
  return { engine: `ClamAV ${m[1]}`, signatures: m[2] ?? "", signatures_at: new Date(at).toISOString(), age_ms: now - at, raw: reply };
}

export const version = async (options: ClamdOptions) => parseVersion(await command(options));

/** The verdict on `bytes`; throws when clamd does not answer with one. */
export async function scanBytes(options: ClamdOptions, bytes: Uint8Array): Promise<Verdict> {
  const reply = await command(options, bytes);
  if (reply === "stream: OK") return { clean: true, threat: null };
  const m = /^stream: ([A-Za-z0-9_.+(): -]{1,256}) FOUND$/.exec(reply);
  if (!m?.[1]) throw new Error(`clamd did not return a verdict: ${reply.slice(0, 80)}`);
  return { clean: false, threat: m[1] };
}

export const isEicar = (bytes: Uint8Array) => Buffer.from(bytes).includes(EICAR);
