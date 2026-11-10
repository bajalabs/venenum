import { expect, test } from "vitest";
import { computeSignature, parseSignatureHeader, signHeaders, verifySignature } from "../src/signing.ts";
import { VECTOR } from "./vector.ts";

const KEY = "a".repeat(64);
const keys = new Map([["app", KEY]]);


test("the signature is HMAC-SHA256 over caller.t.body, as lowercase hex, with the headers named in the docs", () => {
  const h = signHeaders("app", '{"x":1}', KEY, 1_700_000_000);
  expect(h["x-venenum-caller"]).toBe("app");
  expect(h["x-venenum-signature"]).toMatch(/^t=1700000000,v1=[0-9a-f]{64}$/);
  expect(parseSignatureHeader(h["x-venenum-signature"])?.v1).toBe(computeSignature("app", 1_700_000_000, '{"x":1}', KEY));
  // the same bytes as a string or a buffer sign the same
  expect(computeSignature("app", 1, Buffer.from('{"x":1}'), KEY)).toBe(computeSignature("app", 1, '{"x":1}', KEY));
});

test("the published test vector", () => {
  expect(computeSignature(VECTOR.caller, VECTOR.t, VECTOR.body, VECTOR.key)).toBe(VECTOR.v1);
  expect(signHeaders(VECTOR.caller, VECTOR.body, VECTOR.key, VECTOR.t)["x-venenum-signature"]).toBe(`t=${VECTOR.t},v1=${VECTOR.v1}`);
});

test("verification: accepted inside the window, refused stale, changed, unknown, missing or malformed", () => {
  const sig = signHeaders("app", '{"x":1}', KEY, 1_700_000_000)["x-venenum-signature"];
  expect(verifySignature("app", sig, '{"x":1}', keys, { now: 1_700_000_060 })).toEqual({ ok: true, caller: "app" });
  expect(verifySignature("app", sig, '{"x":1}', keys, { now: 1_699_999_940 })).toEqual({ ok: true, caller: "app" });
  expect(verifySignature("app", sig, '{"x":1}', keys, { now: 1_700_000_061 })).toEqual({ ok: false, reason: "stale" });
  expect(verifySignature("app", sig, '{"x":1}', keys, { now: 1_700_000_100, windowSeconds: 120 }).ok).toBe(true);
  expect(verifySignature("app", sig, '{"x":2}', keys, { now: 1_700_000_000 })).toEqual({ ok: false, reason: "mismatch" });
  expect(verifySignature("other", sig, '{"x":1}', keys, { now: 1_700_000_000 })).toEqual({ ok: false, reason: "unknown-caller" });
  expect(verifySignature(undefined, undefined, "", keys)).toEqual({ ok: false, reason: "missing-headers" });
  for (const bad of ["t=abc,v1=zz", `v1=${"a".repeat(64)}`, "t=1700000000", `t=1.5,v1=${"a".repeat(64)}`, `t=1700000000,v1=${"A".repeat(64)}`]) {
    expect(verifySignature("app", bad, "", keys, { now: 1_700_000_000 })).toEqual({ ok: false, reason: "bad-signature-format" });
  }
});

test("the header parser takes the parts in any order and ignores spaces", () => {
  expect(parseSignatureHeader(` v1=${"b".repeat(64)} , t=42 `)).toEqual({ t: 42, v1: "b".repeat(64) });
});
