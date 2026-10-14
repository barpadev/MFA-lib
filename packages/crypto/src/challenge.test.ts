import assert from "node:assert/strict";
import { test } from "node:test";

import { base64UrlToBytes, constantTimeEqual } from "./buffer.ts";
import { createChallenge } from "./challenge.ts";

void test("createChallenge mints 32 bytes and round-trips as base64url", () => {
  const challenge = createChallenge();
  assert.equal(challenge.bytes.byteLength, 32);
  assert.deepEqual([...base64UrlToBytes(challenge.value)], [...challenge.bytes]);
});

void test("verify accepts the bytes once", () => {
  const challenge = createChallenge();
  assert.equal(challenge.verify(challenge.bytes), true);
  assert.equal(challenge.verify(challenge.bytes), false);
});

void test("a mismatch consumes the challenge", () => {
  const challenge = createChallenge(16);
  const wrong = challenge.bytes;
  const first = wrong[0] ?? 0;
  wrong[0] = first ^ 0xff;
  assert.equal(challenge.verify(wrong), false);
  assert.equal(challenge.verify(challenge.bytes), false);
});

void test("a length mismatch consumes the challenge", () => {
  const challenge = createChallenge(16);
  assert.equal(challenge.verify(challenge.bytes.slice(0, 8)), false);
  assert.equal(challenge.verify(challenge.bytes), false);
});

void test("mutating a returned copy does not change the stored challenge", () => {
  const challenge = createChallenge(16);
  const copy = challenge.bytes;
  const first = copy[0] ?? 0;
  copy[0] = first ^ 0xff;
  assert.equal(challenge.verify(challenge.bytes), true);
});

void test("two challenges are independent", () => {
  const first = createChallenge(16);
  const second = createChallenge(16);
  assert.equal(constantTimeEqual(first.bytes, second.bytes), false);
  assert.equal(second.verify(second.bytes), true);
  assert.equal(first.verify(first.bytes), true);
});

void test("createChallenge rejects a short or non-integer length", () => {
  assert.throws(() => createChallenge(15), /invalid challenge/);
  assert.throws(() => createChallenge(0), /invalid challenge/);
  assert.throws(() => createChallenge(-1), /invalid challenge/);
  assert.throws(() => createChallenge(1.5), /invalid challenge/);
});
