import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { build } from "../src/server.ts";
import { EICAR, fakeClamd, KEY, settings } from "./helpers.ts";
import { VECTOR } from "./vector.ts";

const run = promisify(execFile);
const root = new URL("..", import.meta.url).pathname;
const hasPython = await run("python3", ["--version"]).then(
  () => true,
  () => false,
);
const clients: [string, string, string[]][] = [
  ["Node", process.execPath, [join(root, "examples/client.mjs")]],
  ...(hasPython ? ([["Python", "python3", ["-I", join(root, "examples/client.py")]]] as [string, string, string[]][]) : []),
];

let clamd: Awaited<ReturnType<typeof fakeClamd>>;
let app: ReturnType<typeof build>;
let env: NodeJS.ProcessEnv;
const dir = mkdtempSync(join(tmpdir(), "venenum-clients-"));
writeFileSync(join(dir, "clean.txt"), "a clean document");
writeFileSync(join(dir, "test-virus.txt"), EICAR);

beforeAll(async () => {
  clamd = await fakeClamd();
  app = build(settings({ clamd: clamd.options }), { logger: false });
  await app.listen({ host: "127.0.0.1", port: 0 });
  env = { ...process.env, VENENUM_URL: `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`, VENENUM_CALLER: "app", VENENUM_KEY: KEY };
});
afterAll(async () => {
  await app.close();
  await clamd.close();
});

describe.each(clients)("the %s example client", (_name, bin, args) => {
  test("signs the published test vector", async () => {
    const { stdout } = await run(bin, [...args, "vector"]);
    expect(stdout.trim()).toBe(`t=${VECTOR.t},v1=${VECTOR.v1}`);
  });
  test("gets a clean and an infected verdict from a running service", async () => {
    const c = await run(bin, [...args, "bytes", join(dir, "clean.txt")], { env });
    expect(c.stdout).toMatch(/^200 .*"verdict":"clean"/);
    const i = await run(bin, [...args, "bytes", join(dir, "test-virus.txt")], { env });
    expect(i.stdout).toMatch(/^200 .*"verdict":"infected"/);
  });
});
