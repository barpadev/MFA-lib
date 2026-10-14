import type { OtpAlgorithm } from "./otpauth.ts";

const hashes = {
  SHA1: "SHA-1",
  SHA256: "SHA-256",
  SHA512: "SHA-512",
} as const satisfies Record<OtpAlgorithm, string>;

export interface OtpOptions {
  algorithm?: OtpAlgorithm;
  digits?: 6 | 8;
}

export interface TotpOptions extends OtpOptions {
  period?: number;
}

function invalid(message: string): never {
  throw new Error(message);
}

function byteAt(bytes: Uint8Array, index: number): number {
  const byte = bytes[index];
  if (byte === undefined) {
    return invalid("invalid otp");
  }
  return byte;
}

function readAlgorithm(algorithm: string | undefined): OtpAlgorithm {
  const selected = algorithm ?? "SHA1";
  if (selected === "SHA1" || selected === "SHA256" || selected === "SHA512") {
    return selected;
  }
  return invalid("invalid otp");
}

function readDigits(digits: number | undefined): 6 | 8 {
  if (digits === undefined || digits === 6) {
    return 6;
  }
  if (digits === 8) {
    return 8;
  }
  return invalid("invalid otp");
}

function readCounter(counter: number): number {
  if (!Number.isSafeInteger(counter) || counter < 0) {
    return invalid("invalid counter");
  }
  return counter;
}

function movingFactor(counter: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(readCounter(counter)));
  return bytes;
}

function truncate(mac: Uint8Array, digits: 6 | 8): string {
  const offset = byteAt(mac, mac.byteLength - 1) & 0x0f;
  const binary =
    ((byteAt(mac, offset) & 0x7f) << 24) |
    (byteAt(mac, offset + 1) << 16) |
    (byteAt(mac, offset + 2) << 8) |
    byteAt(mac, offset + 3);
  const modulus = digits === 8 ? 100_000_000 : 1_000_000;
  return (binary % modulus).toString().padStart(digits, "0");
}

async function hmac(secret: Uint8Array, counter: number, algorithm: OtpAlgorithm): Promise<Uint8Array> {
  if (secret.byteLength === 0) {
    return invalid("invalid secret");
  }
  const raw = new Uint8Array(secret.byteLength);
  raw.set(secret);
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    raw,
    { name: "HMAC", hash: hashes[algorithm] },
    false,
    ["sign"],
  );
  const mac = await globalThis.crypto.subtle.sign("HMAC", key, movingFactor(counter));
  return new Uint8Array(mac);
}

/** RFC 4226 HOTP. The code is decimal and zero-padded. */
export async function hotp(
  secret: Uint8Array,
  counter: number,
  options: OtpOptions = {},
): Promise<string> {
  const algorithm = readAlgorithm(options.algorithm);
  const digits = readDigits(options.digits);
  return truncate(await hmac(secret, counter, algorithm), digits);
}

/** RFC 6238 TOTP. `unixSeconds` is the time step input, not the system clock. */
export async function totp(
  secret: Uint8Array,
  unixSeconds: number,
  options: TotpOptions = {},
): Promise<string> {
  const period = options.period ?? 30;
  if (!Number.isSafeInteger(period) || period < 1) {
    return invalid("invalid period");
  }
  const time = readCounter(unixSeconds);
  return hotp(secret, Math.floor(time / period), options);
}
