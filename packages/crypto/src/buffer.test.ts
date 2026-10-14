import assert from "node:assert/strict";
import { test } from "node:test";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  bytesToUtf8,
  concatBytes,
  constantTimeEqual,
  hexToBytes,
  randomBytes,
  utf8ToBytes,
} from "./buffer.ts";

void test("concatBytes copies into a new buffer", () => {
  const left = Uint8Array.of(1, 2);
  const right = Uint8Array.of(3);
  const joined = concatBytes(left, right, new Uint8Array());
  assert.deepEqual([...joined], [1, 2, 3]);
  left[0] = 9;
  assert.equal(joined[0], 1);
});

void test("constantTimeEqual matches equal bytes and rejects a length mismatch", () => {
  assert.equal(constantTimeEqual(new Uint8Array(), new Uint8Array()), true);
  assert.equal(constantTimeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3)), true);
  assert.equal(constantTimeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4)), false);
  assert.equal(constantTimeEqual(Uint8Array.of(0, 0), Uint8Array.of(0, 0, 0)), false);
});

void test("hex round-trips and rejects malformed input", () => {
  assert.equal(bytesToHex(new Uint8Array()), "");
  assert.equal(bytesToHex(Uint8Array.of(0x0f, 0xab, 0x00)), "0fab00");
  assert.deepEqual([...hexToBytes("0FAB00")], [0x0f, 0xab, 0x00]);
  assert.throws(() => hexToBytes("abc"), /invalid hex/);
  assert.throws(() => hexToBytes("zz"), /invalid hex/);
});

void test("base64url matches RFC 4648 §5 and accepts padding", () => {
  const vectors: Array<[string, string]> = [
    ["", ""],
    ["f", "Zg"],
    ["fo", "Zm8"],
    ["foo", "Zm9v"],
    ["foob", "Zm9vYg"],
    ["fooba", "Zm9vYmE"],
    ["foobar", "Zm9vYmFy"],
  ];
  for (const [text, encoded] of vectors) {
    const bytes = utf8ToBytes(text);
    assert.equal(bytesToBase64Url(bytes), encoded);
    assert.deepEqual([...base64UrlToBytes(encoded)], [...bytes]);
    const pad = encoded.length % 4 === 0 ? "" : "=".repeat(4 - (encoded.length % 4));
    assert.deepEqual([...base64UrlToBytes(`${encoded}${pad}`)], [...bytes]);
  }
  assert.equal(bytesToBase64Url(Uint8Array.of(0xfb, 0xff, 0xbf)), "-_-_");
  assert.throws(() => base64UrlToBytes("Zm9vYg==="), /invalid base64url/);
  assert.throws(() => base64UrlToBytes("ab+c"), /invalid base64url/);
  assert.throws(() => base64UrlToBytes("a"), /invalid base64url/);
});

void test("utf8 round-trips Persian text and rejects invalid bytes", () => {
  const text = "راز";
  assert.equal(bytesToUtf8(utf8ToBytes(text)), text);
  assert.throws(() => bytesToUtf8(Uint8Array.of(0xff)), TypeError);
});

void test("randomBytes uses the platform CSPRNG", () => {
  assert.equal(randomBytes(0).byteLength, 0);
  assert.equal(randomBytes(32).byteLength, 32);
  assert.throws(() => randomBytes(-1), RangeError);
  assert.throws(() => randomBytes(1.5), RangeError);
});
