import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { backupPbkdf2Iterations, createBackup, encodeMnemonic, openBackup } from "./backup.ts";
import { utf8ToBytes } from "./buffer.ts";

const now = new Date("2026-10-11T08:00:00.000Z");
const vectorPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const vectorSeed =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

async function bip39Seed(phrase: string): Promise<Uint8Array> {
  const raw = utf8ToBytes(phrase.normalize("NFKD"));
  const key = await crypto.subtle.importKey("raw", raw, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-512", salt: utf8ToBytes("mnemonic"), iterations: 2048 },
      key,
      512,
    ),
  );
}

void test("the backup KDF is the BIP-39 seed function", () => {
  assert.equal(backupPbkdf2Iterations, 2048);
  const source = readFileSync(new URL("./backup.ts", import.meta.url), "utf8");
  assert.equal(source.includes("exportKey"), false);
});

void test("zero entropy is the published 12-word phrase and seed", async () => {
  const phrase = await encodeMnemonic(new Uint8Array(16));
  assert.equal(phrase, vectorPhrase);
  const seed = await bip39Seed(phrase);
  assert.equal(Buffer.from(seed).toString("hex"), vectorSeed);
  seed.fill(0);
});

void test("a backup round-trips under the BIP-39 seed and omits the phrase", async () => {
  const plaintext = utf8ToBytes("account-secret");
  const created = await createBackup(plaintext, now);
  assert.equal(created.mnemonic.split(" ").length, 12);
  assert.equal(created.backup.version, 1);
  assert.equal(created.backup.wrapping, "seed");
  assert.equal(created.backup.cipher, "AES-GCM");
  assert.equal(created.backup.kdf.kdf, "PBKDF2");
  assert.equal(created.backup.kdf.hash, "SHA-512");
  assert.equal(created.backup.kdf.iterations, 2048);
  assert.equal(created.backup.iv.byteLength, 12);
  assert.deepEqual([...created.backup.kdf.salt], [...utf8ToBytes("mnemonic")]);
  assert.equal(created.backup.createdAt, "2026-10-11T08:00:00.000Z");
  assert.equal(Object.hasOwn(created.backup, "mnemonic"), false);
  assert.equal(JSON.stringify(created.backup).includes(created.mnemonic), false);

  const seed = await bip39Seed(created.mnemonic);
  const key = await crypto.subtle.importKey("raw", seed.subarray(0, 32), { name: "AES-GCM" }, false, ["decrypt"]);
  const openedBySeed = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: created.backup.iv,
        additionalData: utf8ToBytes(`${created.backup.id}.1`),
      },
      key,
      created.backup.ciphertext,
    ),
  );
  assert.deepEqual([...openedBySeed], [...plaintext]);
  seed.fill(0);
  openedBySeed.fill(0);

  const opened = await openBackup(created.backup, created.mnemonic);
  assert.deepEqual([...opened], [...plaintext]);
  opened.fill(0);
});

void test("a bad phrase or a swapped byte fails closed", async () => {
  const created = await createBackup(utf8ToBytes("super-secret"), now);
  const wrong = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
  await assert.rejects(openBackup(created.backup, wrong), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, "invalid request");
    assert.equal(error.message.includes("abandon"), false);
    assert.equal(error.message.includes("super-secret"), false);
    return true;
  });
  const flipped = new Uint8Array(created.backup.ciphertext);
  flipped[0] = (flipped[0] ?? 0) ^ 0xff;
  await assert.rejects(openBackup({ ...created.backup, ciphertext: flipped }, created.mnemonic), /invalid request/);
  await assert.rejects(openBackup({ ...created.backup, kdf: { ...created.backup.kdf, iterations: 600_000 } }, created.mnemonic), /invalid request/);
  await assert.rejects(encodeMnemonic(new Uint8Array(32)), /invalid request/);
});
