import assert from "node:assert/strict";
import { test } from "node:test";

import { utf8ToBytes } from "./buffer.ts";
import { createVault, openVault, rewrapVault, sealVault, vaultPbkdf2Iterations } from "./vault.ts";

const now = new Date("2026-10-11T08:00:00.000Z");
const rounds = 1_000;

void test("the production KDF count is the OWASP PBKDF2-HMAC-SHA-256 figure", () => {
  assert.equal(vaultPbkdf2Iterations, 600_000);
});

void test("a vault round-trips and the returned key cannot be exported", async () => {
  const plaintext = utf8ToBytes("account-secret");
  const created = await createVault("1234", plaintext, now, rounds);
  assert.equal(created.key.extractable, false);
  assert.equal(created.sealed.version, 1);
  assert.equal(created.sealed.cipher, "AES-GCM");
  assert.equal(created.sealed.kdf.kdf, "PBKDF2");
  assert.equal(created.sealed.kdf.hash, "SHA-256");
  assert.equal(created.sealed.kdf.iterations, rounds);
  assert.equal(created.sealed.iv.byteLength, 12);
  assert.equal(created.sealed.kdf.salt.byteLength, 16);
  assert.equal(created.sealed.wrappedKey.byteLength, 40);
  assert.equal(created.sealed.createdAt, "2026-10-11T08:00:00.000Z");
  await assert.rejects(crypto.subtle.exportKey("raw", created.key));

  const opened = await openVault(created.sealed, "1234");
  assert.equal(opened.key.extractable, false);
  assert.deepEqual([...opened.plaintext], [...plaintext]);
  opened.plaintext.fill(0);
});

void test("a wrong PIN or a swapped byte fails closed", async () => {
  const created = await createVault("1234", utf8ToBytes("super-secret"), now, rounds);
  await assert.rejects(openVault(created.sealed, "9999"), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, "invalid request");
    assert.equal(error.message.includes("9999"), false);
    assert.equal(error.message.includes("super-secret"), false);
    return true;
  });
  const flipped = new Uint8Array(created.sealed.ciphertext);
  flipped[0] = (flipped[0] ?? 0) ^ 0xff;
  await assert.rejects(openVault({ ...created.sealed, ciphertext: flipped }, "1234"), /invalid request/);
  await assert.rejects(createVault("12", utf8ToBytes("x"), now, rounds), /invalid request/);
  await assert.rejects(createVault("1234", utf8ToBytes("x"), now, 1), /invalid request/);
});

void test("sealing keeps the wrap and rewrapping drops the old PIN", async () => {
  const created = await createVault("1234", utf8ToBytes("one"), now, rounds);
  const later = new Date("2026-10-11T09:00:00.000Z");
  const sealed = await sealVault(created.sealed, created.key, utf8ToBytes("two"), later);
  assert.deepEqual([...sealed.wrappedKey], [...created.sealed.wrappedKey]);
  assert.equal(sealed.updatedAt, "2026-10-11T09:00:00.000Z");
  assert.equal(sealed.createdAt, created.sealed.createdAt);
  const opened = await openVault(sealed, "1234");
  assert.equal(new TextDecoder().decode(opened.plaintext), "two");

  const changed = await rewrapVault(sealed, opened.plaintext, "5678", later, rounds);
  assert.equal(changed.key.extractable, false);
  assert.equal(changed.sealed.id, sealed.id);
  assert.notDeepEqual([...changed.sealed.wrappedKey], [...sealed.wrappedKey]);
  await assert.rejects(openVault(changed.sealed, "1234"), /invalid request/);
  const restored = await openVault(changed.sealed, "5678");
  assert.equal(new TextDecoder().decode(restored.plaintext), "two");
  opened.plaintext.fill(0);
  restored.plaintext.fill(0);
});
