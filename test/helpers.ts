import { createServer as createHttp } from "node:http";
import { createServer as createNet } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type ClamdOptions, isEicar } from "../src/clamd.ts";
import type { Settings } from "../src/config.ts";

/** The EICAR test string, assembled at run time so no file in the repository carries it. */
export const EICAR = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD", "-ANTIVIRUS-TEST-FILE!$H+H*"].join("");

/** A fake clamd on a Unix socket: VERSION with a configurable date, INSTREAM that finds EICAR. */
export async function fakeClamd({ versionDate = new Date().toUTCString().replace(/ GMT$/, ""), engine = "1.4.3", sigs = "27600" } = {}) {
  const path = join(tmpdir(), `venenum-${process.pid}-${Math.random().toString(16).slice(2)}.sock`);
  const server = createNet((socket) => {
    let buf = Buffer.alloc(0);
    let mode: "command" | "stream" | "done" = "command";
    const chunks: Buffer[] = [];
    socket.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      if (mode === "command") {
        const end = buf.indexOf(0);
        if (end < 0) return;
        const cmd = buf.subarray(0, end).toString();
        buf = buf.subarray(end + 1);
        if (cmd === "zVERSION") return void socket.end(Buffer.from(`ClamAV ${engine}/${sigs}/${versionDate}\0`));
        if (cmd !== "zINSTREAM") return void socket.end(Buffer.from("UNKNOWN COMMAND\0"));
        mode = "stream";
      }
      while (mode === "stream" && buf.length >= 4) {
        const len = buf.readUInt32BE(0);
        if (len === 0) {
          socket.end(Buffer.from(isEicar(Buffer.concat(chunks)) ? "stream: Win.Test.EICAR_HDB-1 FOUND\0" : "stream: OK\0"));
          mode = "done";
          return;
        }
        if (buf.length < 4 + len) return;
        chunks.push(buf.subarray(4, 4 + len));
        buf = buf.subarray(4 + len);
      }
    });
  });
  await new Promise<void>((r) => server.listen(path, r));
  const options: ClamdOptions = { connection: { path }, timeoutMs: 5_000 };
  return { options, close: () => new Promise<void>((r) => server.close(() => r())) };
}

/** A file server: GET /<name> answers the bytes registered under that name; GET /redirect answers a 302. */
export async function fileServer(files: Record<string, Buffer>) {
  const server = createHttp((req, res) => {
    if (req.url === "/redirect") {
      res.writeHead(302, { location: "/clean.bin" });
      return void res.end();
    }
    const b = files[(req.url ?? "").slice(1)];
    if (!b) {
      res.writeHead(404);
      return void res.end();
    }
    res.writeHead(200, { "content-type": "application/octet-stream", "content-length": b.length });
    res.end(b);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { origin, close: () => new Promise<void>((r) => server.close(() => r())) };
}

export const KEY = "c".repeat(64);

export function settings(over: Partial<Settings> & { clamd: ClamdOptions }): Settings {
  return {
    host: "127.0.0.1",
    port: 0,
    logLevel: "silent",
    keys: new Map([["app", KEY]]),
    origins: [],
    maxBytes: 1_000_000,
    jsonBodyLimit: 65_536,
    fetchTimeoutMs: 5_000,
    maxSignatureAgeMs: 72 * 3_600_000,
    signingWindowSeconds: 60,
    ...over,
  };
}
