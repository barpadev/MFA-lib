import { bytesToHex, constantTimeEqual, randomBytes, utf8ToBytes } from "./buffer.ts";
import { bip39English } from "./wordlist.ts";

type BackupKey = Awaited<ReturnType<typeof crypto.subtle.deriveKey>>;

/**
 * BIP-39 mnemonic-to-seed count. The phrase is 128 bits of CSPRNG entropy,
 * so this is not the PIN's 600,000-iteration stretch.
 */
export const backupPbkdf2Iterations = 2048;

const wordCount = 12;
const entropyBytes = 16;
const formatVersion = 1;
const seedSalt = utf8ToBytes("mnemonic");

const wordIndex = new Map<string, number>(bip39English.map((word, index) => [word, index]));

export interface SealedBackup {
  id: string;
  version: number;
  wrapping: "seed";
  cipher: "AES-GCM";
  iv: Uint8Array;
  ciphertext: Uint8Array;
  kdf: {
    kdf: "PBKDF2";
    hash: "SHA-512";
    salt: Uint8Array;
    iterations: number;
  };
  createdAt: string;
}

function invalid(): never {
  throw new Error("invalid request");
}

function copyBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy;
}

function byteAt(bytes: Uint8Array, index: number): number {
  const byte = bytes[index];
  if (byte === undefined) {
    return invalid();
  }
  return byte;
}

function stamp(now: Date): string {
  if (Number.isNaN(now.getTime())) {
    return invalid();
  }
  return now.toISOString();
}

function wordAt(index: number): string {
  const word = bip39English[index];
  if (word === undefined) {
    return invalid();
  }
  return word;
}

function readIndex(indexes: readonly number[], position: number): number {
  const index = indexes[position];
  if (index === undefined) {
    return invalid();
  }
  return index;
}

/** 12-word BIP-39 phrase from 16 bytes of entropy. */
export async function encodeMnemonic(entropy: Uint8Array): Promise<string> {
  if (entropy.byteLength !== entropyBytes) {
    return invalid();
  }
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", copyBytes(entropy)));
  const combined = new Uint8Array(17);
  combined.set(entropy);
  combined[16] = byteAt(digest, 0) & 0xf0;
  const words: string[] = [];
  for (let word = 0; word < wordCount; word += 1) {
    let index = 0;
    for (let bit = 0; bit < 11; bit += 1) {
      const position = word * 11 + bit;
      index = (index << 1) | ((byteAt(combined, position >> 3) >> (7 - (position & 7))) & 1);
    }
    words.push(wordAt(index));
  }
  return words.join(" ");
}

function indexesFromPhrase(phrase: string): number[] {
  const words = phrase.normalize("NFKD").trim().toLowerCase().split(/\s+/u);
  if (words.length !== wordCount) {
    return invalid();
  }
  const indexes: number[] = [];
  for (const word of words) {
    const index = wordIndex.get(word);
    if (index === undefined) {
      return invalid();
    }
    indexes.push(index);
  }
  return indexes;
}

async function checksumMatches(indexes: readonly number[]): Promise<boolean> {
  const combined = new Uint8Array(17);
  let position = 0;
  for (let word = 0; word < wordCount; word += 1) {
    const index = readIndex(indexes, word);
    for (let bit = 10; bit >= 0; bit -= 1) {
      const value = (index >> bit) & 1;
      const offset = position >> 3;
      combined[offset] = byteAt(combined, offset) | (value << (7 - (position & 7)));
      position += 1;
    }
  }
  const entropy = combined.subarray(0, entropyBytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", entropy));
  return (byteAt(combined, 16) >> 4) === (byteAt(digest, 0) >> 4);
}

async function canonicalMnemonic(phrase: string): Promise<string> {
  const indexes = indexesFromPhrase(phrase);
  if (!(await checksumMatches(indexes))) {
    return invalid();
  }
  return indexes.map((index) => wordAt(index)).join(" ");
}

async function deriveBackupKey(phrase: string): Promise<BackupKey> {
  const mnemonic = await canonicalMnemonic(phrase);
  const encoded = utf8ToBytes(mnemonic);
  const raw = copyBytes(encoded);
  encoded.fill(0);
  let mnemonicKey: BackupKey;
  try {
    mnemonicKey = await crypto.subtle.importKey("raw", raw, "PBKDF2", false, ["deriveKey"]);
  } finally {
    raw.fill(0);
  }
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-512", salt: copyBytes(seedSalt), iterations: backupPbkdf2Iterations },
    mnemonicKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function associated(id: string, version: number): Uint8Array {
  return utf8ToBytes(`${id}.${String(version)}`);
}

function readBackup(backup: {
  readonly id: string;
  readonly version: number;
  readonly wrapping: string;
  readonly cipher: string;
  readonly iv: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly kdf: {
    readonly kdf: string;
    readonly hash: string;
    readonly salt: Uint8Array;
    readonly iterations: number;
  };
  readonly createdAt: string;
}): void {
  if (backup.version !== formatVersion || backup.wrapping !== "seed" || backup.cipher !== "AES-GCM") {
    return invalid();
  }
  if (backup.kdf.kdf !== "PBKDF2" || backup.kdf.hash !== "SHA-512") {
    return invalid();
  }
  if (backup.kdf.iterations !== backupPbkdf2Iterations || backup.iv.byteLength !== 12) {
    return invalid();
  }
  if (!constantTimeEqual(backup.kdf.salt, seedSalt) || backup.ciphertext.byteLength < 16 || backup.id.length === 0) {
    return invalid();
  }
  if (!backup.createdAt.endsWith("Z") || Number.isNaN(Date.parse(backup.createdAt))) {
    return invalid();
  }
}

async function sealWithMnemonic(plaintext: Uint8Array, phrase: string, now: Date): Promise<SealedBackup> {
  const createdAt = stamp(now);
  const key = await deriveBackupKey(phrase);
  const id = bytesToHex(randomBytes(16));
  const iv = copyBytes(randomBytes(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: copyBytes(associated(id, formatVersion)) },
      key,
      copyBytes(plaintext),
    ),
  );
  return {
    id,
    version: formatVersion,
    wrapping: "seed",
    cipher: "AES-GCM",
    iv,
    ciphertext,
    kdf: {
      kdf: "PBKDF2",
      hash: "SHA-512",
      salt: copyBytes(seedSalt),
      iterations: backupPbkdf2Iterations,
    },
    createdAt,
  };
}

/**
 * Encrypt `plaintext` under a new 12-word BIP-39 mnemonic.
 * The mnemonic is returned once and is not part of the blob.
 */
export async function createBackup(
  plaintext: Uint8Array,
  now: Date,
): Promise<{ readonly backup: SealedBackup; readonly mnemonic: string }> {
  const mnemonic = await encodeMnemonic(randomBytes(entropyBytes));
  const backup = await sealWithMnemonic(plaintext, mnemonic, now);
  return { backup, mnemonic };
}

/** Decrypt a seed-wrapped blob. The phrase is not retained. */
export async function openBackup(backup: SealedBackup, phrase: string): Promise<Uint8Array> {
  readBackup(backup);
  const key = await deriveBackupKey(phrase);
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: copyBytes(backup.iv),
          additionalData: copyBytes(associated(backup.id, backup.version)),
        },
        key,
        copyBytes(backup.ciphertext),
      ),
    );
  } catch {
    return invalid();
  }
}
