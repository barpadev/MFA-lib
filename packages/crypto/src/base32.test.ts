import assert from "node:assert/strict";
import { test } from "node:test";

import { base32ToBytes, bytesToBase32 } from "./base32.ts";
import { bytesToHex, bytesToUtf8, hexToBytes, utf8ToBytes } from "./buffer.ts";

void test("bytesToBase32 matches RFC 4648 §10", () => {
  const vectors: Array<[string, string]> = [
    ["", ""],
    ["f", "MY======"],
    ["fo", "MZXQ===="],
    ["foo", "MZXW6==="],
    ["foob", "MZXW6YQ="],
    ["fooba", "MZXW6YTB"],
    ["foobar", "MZXW6YTBOI======"],
  ];
  for (const [text, encoded] of vectors) {
    assert.equal(bytesToBase32(utf8ToBytes(text)), encoded);
    assert.equal(bytesToUtf8(base32ToBytes(encoded)), text);
  }
});

void test("base32ToBytes accepts lowercase and omitted padding", () => {
  const bytes = utf8ToBytes("foobar");
  assert.deepEqual([...base32ToBytes("mzxw6ytboi======")], [...bytes]);
  assert.deepEqual([...base32ToBytes("MZXW6YTBOI")], [...bytes]);
  assert.equal(bytesToHex(base32ToBytes(bytesToBase32(hexToBytes("00ff")))), "00ff");
});

void test("base32ToBytes rejects malformed input", () => {
  assert.throws(() => base32ToBytes("1"), /invalid base32/);
  assert.throws(() => base32ToBytes("MY====="), /invalid base32/);
  assert.throws(() => base32ToBytes("MY=======A"), /invalid base32/);
  assert.throws(() => base32ToBytes("M=======A"), /invalid base32/);
  assert.throws(() => base32ToBytes("MZ======"), /invalid base32/);
});
