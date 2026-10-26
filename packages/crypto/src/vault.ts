import { bytesToHex, randomBytes, utf8ToBytes } from "./buffer.ts";

type VaultKey = Awaited<ReturnType<typeof crypto.subtle.deriveKey>>;

/** OWASP 2023 PBKDF2-HMAC-SHA-256 iteration count. */
export const vaultPbkdf2Iterations = 600_000;

const minimumIterations = 1_000;
const maximumIterations = 1_000_000;
const formatVersion = 1;

export interface SealedVault {
  id: string;
  version: number;
  cipher: "AES-GCM";
  iv: Uint8Array;
  ciphertext: Uint8Array;
  wrappedKey: Uint8Array;
  kdf: {
    kdf: "PBKDF2";
    hash: "SHA-256";
    salt: Uint8Array;
    iterations: number;
  };
  createdAt: string;
  updatedAt: string;
}

export interface OpenVault {
  readonly key: VaultKey;
  readonly plaintext: Uint8Array;
}

function invalid(): never {
  throw new Error("invalid request");
}

function copyBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy;
}

function stamp(now: Date): string {
  if (Number.isNaN(now.getTime())) {
    return invalid();
  }
  return now.toISOString();
}

function readIterations(iterations: number): number {
  if (!Number.isInteger(iterations) || iterations < minimumIterations || iterations > maximumIterations) {
    return invalid();
  }
  return iterations;
}

async function importPin(pin: string): Promise<VaultKey> {
  if (!/^[0-9]{4,8}$/u.test(pin)) {
    return invalid();
  }
  const encoded = utf8ToBytes(pin);
  const raw = copyBytes(encoded);
  encoded.fill(0);
  try {
    return await crypto.subtle.importKey("raw", raw, "PBKDF2", false, ["deriveKey"]);
  } finally {
    raw.fill(0);
  }
}

async function deriveKek(pinKey: VaultKey, salt: Uint8Array, iterations: number): Promise<VaultKey> {
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: copyBytes(salt), iterations },
    pinKey,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

function associated(id: string, version: number): Uint8Array {
  return utf8ToBytes(`${id}.${String(version)}`);
}

async function encryptPayload(id: string, key: VaultKey, plaintext: Uint8Array): Promise<{
  readonly iv: Uint8Array;
  readonly ciphertext: Uint8Array;
}> {
  const iv = copyBytes(randomBytes(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: copyBytes(associated(id, formatVersion)) },
      key,
      copyBytes(plaintext),
    ),
  );
  return { iv, ciphertext };
}

/**
 * Mint a vault key, wrap it, and return only the non-extractable unwrap.
 * `wrapKey` rejects a non-extractable key, so the extractable key lives
 * only for that wrap and is not returned.
 */
async function mintWrappedKey(kek: VaultKey, id: string, plaintext: Uint8Array): Promise<{
  readonly key: VaultKey;
  readonly wrappedKey: Uint8Array;
  readonly iv: Uint8Array;
  readonly ciphertext: Uint8Array;
}> {
  const extractable = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const wrappedKey = new Uint8Array(await crypto.subtle.wrapKey("raw", extractable, kek, "AES-KW"));
  const key = await crypto.subtle.unwrapKey(
    "raw",
    wrappedKey,
    kek,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const payload = await encryptPayload(id, key, plaintext);
  return { key, wrappedKey, iv: payload.iv, ciphertext: payload.ciphertext };
}

function sealedRecord(
  id: string,
  wrappedKey: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  createdAt: string,
  updatedAt: string,
): SealedVault {
  return {
    id,
    version: formatVersion,
    cipher: "AES-GCM",
    iv,
    ciphertext,
    wrappedKey,
    kdf: { kdf: "PBKDF2", hash: "SHA-256", salt, iterations },
    createdAt,
    updatedAt,
  };
}

export async function createVault(
  pin: string,
  plaintext: Uint8Array,
  now: Date,
  iterations = vaultPbkdf2Iterations,
): Promise<{ readonly sealed: SealedVault; readonly key: VaultKey }> {
  const rounds = readIterations(iterations);
  const createdAt = stamp(now);
  const pinKey = await importPin(pin);
  const salt = randomBytes(16);
  const kek = await deriveKek(pinKey, salt, rounds);
  const id = bytesToHex(randomBytes(16));
  const minted = await mintWrappedKey(kek, id, plaintext);
  return {
    sealed: sealedRecord(id, minted.wrappedKey, minted.iv, minted.ciphertext, salt, rounds, createdAt, createdAt),
    key: minted.key,
  };
}

function readSealed(sealed: {
  readonly id: string;
  readonly version: number;
  readonly cipher: string;
  readonly iv: Uint8Array;
  readonly wrappedKey: Uint8Array;
  readonly kdf: {
    readonly kdf: string;
    readonly hash: string;
    readonly salt: Uint8Array;
    readonly iterations: number;
  };
}): { readonly salt: Uint8Array; readonly iterations: number } {
  if (sealed.version !== formatVersion || sealed.cipher !== "AES-GCM" || sealed.kdf.kdf !== "PBKDF2") {
    return invalid();
  }
  if (sealed.kdf.hash !== "SHA-256" || sealed.iv.byteLength !== 12 || sealed.kdf.salt.byteLength !== 16) {
    return invalid();
  }
  if (sealed.wrappedKey.byteLength !== 40 || sealed.id.length === 0) {
    return invalid();
  }
  return { salt: sealed.kdf.salt, iterations: readIterations(sealed.kdf.iterations) };
}

async function unwrapVaultKey(sealed: SealedVault, pin: string): Promise<VaultKey> {
  const checked = readSealed(sealed);
  const pinKey = await importPin(pin);
  const kek = await deriveKek(pinKey, checked.salt, checked.iterations);
  try {
    return await crypto.subtle.unwrapKey(
      "raw",
      copyBytes(sealed.wrappedKey),
      kek,
      "AES-KW",
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } catch {
    return invalid();
  }
}

export async function openVault(sealed: SealedVault, pin: string): Promise<OpenVault> {
  const key = await unwrapVaultKey(sealed, pin);
  try {
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: copyBytes(sealed.iv),
          additionalData: copyBytes(associated(sealed.id, sealed.version)),
        },
        key,
        copyBytes(sealed.ciphertext),
      ),
    );
    return { key, plaintext };
  } catch {
    return invalid();
  }
}

export async function sealVault(sealed: SealedVault, key: VaultKey, plaintext: Uint8Array, now: Date): Promise<SealedVault> {
  readSealed(sealed);
  if (key.extractable || key.algorithm.name !== "AES-GCM") {
    return invalid();
  }
  const payload = await encryptPayload(sealed.id, key, plaintext);
  return sealedRecord(
    sealed.id,
    sealed.wrappedKey,
    payload.iv,
    payload.ciphertext,
    sealed.kdf.salt,
    sealed.kdf.iterations,
    sealed.createdAt,
    stamp(now),
  );
}

export async function rewrapVault(
  sealed: SealedVault,
  plaintext: Uint8Array,
  pin: string,
  now: Date,
  iterations = vaultPbkdf2Iterations,
): Promise<{ readonly sealed: SealedVault; readonly key: VaultKey }> {
  readSealed(sealed);
  const rounds = readIterations(iterations);
  const pinKey = await importPin(pin);
  const salt = randomBytes(16);
  const kek = await deriveKek(pinKey, salt, rounds);
  const minted = await mintWrappedKey(kek, sealed.id, plaintext);
  return {
    sealed: sealedRecord(
      sealed.id,
      minted.wrappedKey,
      minted.iv,
      minted.ciphertext,
      salt,
      rounds,
      sealed.createdAt,
      stamp(now),
    ),
    key: minted.key,
  };
}

/** Device-bound vault: ciphertext plus a non-extractable AES-GCM key (no user PIN). */
export interface DeviceSealedVault {
  id: string;
  version: number;
  cipher: "AES-GCM";
  iv: Uint8Array;
  ciphertext: Uint8Array;
  key: VaultKey;
  createdAt: string;
  updatedAt: string;
}

function readDeviceSealed(sealed: {
  readonly id: string;
  readonly version: number;
  readonly cipher: string;
  readonly iv: Uint8Array;
  readonly key: VaultKey;
}): void {
  if (sealed.version !== formatVersion || sealed.cipher !== "AES-GCM" || sealed.id.length === 0) {
    return invalid();
  }
  if (sealed.iv.byteLength !== 12 || sealed.key.extractable || sealed.key.algorithm.name !== "AES-GCM") {
    return invalid();
  }
}

export async function createDeviceVault(
  plaintext: Uint8Array,
  now: Date,
): Promise<DeviceSealedVault> {
  const createdAt = stamp(now);
  const id = bytesToHex(randomBytes(16));
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const payload = await encryptPayload(id, key, plaintext);
  return {
    id,
    version: formatVersion,
    cipher: "AES-GCM",
    iv: payload.iv,
    ciphertext: payload.ciphertext,
    key,
    createdAt,
    updatedAt: createdAt,
  };
}

export async function sealDeviceVault(
  sealed: DeviceSealedVault,
  plaintext: Uint8Array,
  now: Date,
): Promise<DeviceSealedVault> {
  readDeviceSealed(sealed);
  const payload = await encryptPayload(sealed.id, sealed.key, plaintext);
  return {
    ...sealed,
    iv: payload.iv,
    ciphertext: payload.ciphertext,
    updatedAt: stamp(now),
  };
}

export async function openDeviceVault(sealed: DeviceSealedVault): Promise<Uint8Array> {
  readDeviceSealed(sealed);
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: copyBytes(sealed.iv),
          additionalData: copyBytes(associated(sealed.id, sealed.version)),
        },
        sealed.key,
        copyBytes(sealed.ciphertext),
      ),
    );
  } catch {
    return invalid();
  }
}
