const hexAlphabet = "0123456789abcdef";
const base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const base64UrlDecode = new Uint8Array(128).fill(255);
for (let index = 0; index < base64UrlAlphabet.length; index += 1) {
  base64UrlDecode[base64UrlAlphabet.charCodeAt(index)] = index;
}

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

function alphabetChar(alphabet: string, index: number): string {
  const char = alphabet[index];
  if (char === undefined) {
    throw new RangeError("alphabet index out of range");
  }
  return char;
}

function byteAt(bytes: Uint8Array, index: number): number {
  const byte = bytes[index];
  if (byte === undefined) {
    throw new RangeError("byte index out of range");
  }
  return byte;
}

/** Join byte sequences without sharing the inputs' buffers. */
export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) {
    length += part.byteLength;
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

/**
 * Compare two byte strings in constant time relative to their contents.
 * Length mismatch is not secret and returns false.
 */
export function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  const length = Math.max(left.byteLength, right.byteLength);
  let diff = left.byteLength === right.byteLength ? 0 : 1;
  for (let index = 0; index < length; index += 1) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return diff === 0;
}

/** Lowercase hex. Empty input returns an empty string. */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += alphabetChar(hexAlphabet, byte >> 4);
    hex += alphabetChar(hexAlphabet, byte & 0x0f);
  }
  return hex;
}

/** Case-insensitive hex. Odd length and non-hex characters throw. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    const pair = hex.slice(index * 2, index * 2 + 2);
    if (!/^[0-9a-f]{2}$/iu.test(pair)) {
      throw new Error("invalid hex");
    }
    out[index] = Number.parseInt(pair, 16);
  }
  return out;
}

/** Unpadded base64url (RFC 4648 §5). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let index = 0; index < bytes.byteLength; index += 3) {
    const first = byteAt(bytes, index);
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    const chunk = (first << 16) | ((second ?? 0) << 8) | (third ?? 0);
    out += alphabetChar(base64UrlAlphabet, (chunk >> 18) & 63);
    out += alphabetChar(base64UrlAlphabet, (chunk >> 12) & 63);
    if (second !== undefined) {
      out += alphabetChar(base64UrlAlphabet, (chunk >> 6) & 63);
    }
    if (third !== undefined) {
      out += alphabetChar(base64UrlAlphabet, chunk & 63);
    }
  }
  return out;
}

/** Accepts padded or unpadded base64url. Standard base64 (`+` `/`) is rejected. */
export function base64UrlToBytes(value: string): Uint8Array {
  let end = value.length;
  while (end > 0 && value[end - 1] === "=") {
    end -= 1;
  }
  if (value.length - end > 2 || end % 4 === 1) {
    throw new Error("invalid base64url");
  }
  const out = new Uint8Array(Math.floor((end * 3) / 4));
  let outIndex = 0;
  for (let index = 0; index < end; index += 4) {
    const remaining = end - index;
    if (remaining < 2) {
      throw new Error("invalid base64url");
    }
    const c0 = decodeBase64UrlChar(value, index);
    const c1 = decodeBase64UrlChar(value, index + 1);
    const c2 = remaining > 2 ? decodeBase64UrlChar(value, index + 2) : 0;
    const c3 = remaining > 3 ? decodeBase64UrlChar(value, index + 3) : 0;
    const chunk = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    out[outIndex] = (chunk >> 16) & 0xff;
    outIndex += 1;
    if (remaining > 2) {
      out[outIndex] = (chunk >> 8) & 0xff;
      outIndex += 1;
    }
    if (remaining > 3) {
      out[outIndex] = chunk & 0xff;
      outIndex += 1;
    }
  }
  return out;
}

function decodeBase64UrlChar(value: string, index: number): number {
  const char = value.charCodeAt(index);
  const decoded = char < base64UrlDecode.length ? base64UrlDecode[char] : undefined;
  if (decoded === undefined || decoded === 255) {
    throw new Error("invalid base64url");
  }
  return decoded;
}

export function utf8ToBytes(value: string): Uint8Array {
  return utf8Encoder.encode(value);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

/** Platform CSPRNG. `Math.random` is never used. */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0) {
    throw new RangeError("length must be a non-negative integer");
  }
  const bytes = new Uint8Array(length);
  if (length > 0) {
    globalThis.crypto.getRandomValues(bytes);
  }
  return bytes;
}
