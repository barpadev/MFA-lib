const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function alphabetChar(index: number): string {
  const char = base32Alphabet[index];
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

function quantumLength(remaining: number): number {
  if (remaining >= 5) {
    return 8;
  }
  if (remaining === 4) {
    return 7;
  }
  if (remaining === 3) {
    return 5;
  }
  if (remaining === 2) {
    return 4;
  }
  return 2;
}

/** RFC 4648 §6, uppercase, with `=` padding. */
export function bytesToBase32(bytes: Uint8Array): string {
  let out = "";
  for (let index = 0; index < bytes.byteLength; index += 5) {
    const remaining = bytes.byteLength - index;
    const b0 = byteAt(bytes, index);
    const b1 = remaining > 1 ? byteAt(bytes, index + 1) : 0;
    const b2 = remaining > 2 ? byteAt(bytes, index + 2) : 0;
    const b3 = remaining > 3 ? byteAt(bytes, index + 3) : 0;
    const b4 = remaining > 4 ? byteAt(bytes, index + 4) : 0;
    const symbols = [
      b0 >> 3,
      ((b0 & 0x07) << 2) | (b1 >> 6),
      (b1 >> 1) & 0x1f,
      ((b1 & 0x01) << 4) | (b2 >> 4),
      ((b2 & 0x0f) << 1) | (b3 >> 7),
      (b3 >> 2) & 0x1f,
      ((b3 & 0x03) << 3) | (b4 >> 5),
      b4 & 0x1f,
    ];
    const count = quantumLength(remaining);
    for (let symbol = 0; symbol < count; symbol += 1) {
      out += alphabetChar(symbols[symbol] ?? 0);
    }
    out += "=".repeat(8 - count);
  }
  return out;
}

function isValidBodyLength(length: number): boolean {
  const mod = length % 8;
  return mod === 0 || mod === 2 || mod === 4 || mod === 5 || mod === 7;
}

function expectedPadding(bodyLength: number): number {
  switch (bodyLength % 8) {
    case 2:
      return 6;
    case 4:
      return 4;
    case 5:
      return 3;
    case 7:
      return 1;
    default:
      return 0;
  }
}

function decodeChar(value: string, index: number): number {
  const code = value.charCodeAt(index);
  if (code >= 65 && code <= 90) {
    return code - 65;
  }
  if (code >= 97 && code <= 122) {
    return code - 97;
  }
  if (code >= 50 && code <= 55) {
    return code - 50 + 26;
  }
  throw new Error("invalid base32");
}

function appendQuantum(symbols: readonly number[], out: number[]): void {
  const at = (index: number): number => {
    const symbol = symbols[index];
    if (symbol === undefined) {
      throw new Error("invalid base32");
    }
    return symbol;
  };
  const count = symbols.length;
  out.push((at(0) << 3) | (at(1) >> 2));
  if (count === 2) {
    if ((at(1) & 0x03) !== 0) {
      throw new Error("invalid base32");
    }
    return;
  }
  out.push(((at(1) & 0x03) << 6) | (at(2) << 1) | (at(3) >> 4));
  if (count === 4) {
    if ((at(3) & 0x0f) !== 0) {
      throw new Error("invalid base32");
    }
    return;
  }
  out.push(((at(3) & 0x0f) << 4) | (at(4) >> 1));
  if (count === 5) {
    if ((at(4) & 0x01) !== 0) {
      throw new Error("invalid base32");
    }
    return;
  }
  out.push(((at(4) & 0x01) << 7) | (at(5) << 2) | (at(6) >> 3));
  if (count === 7) {
    if ((at(6) & 0x07) !== 0) {
      throw new Error("invalid base32");
    }
    return;
  }
  if (count !== 8) {
    throw new Error("invalid base32");
  }
  out.push(((at(6) & 0x07) << 5) | at(7));
}

/**
 * Decode RFC 4648 Base32.
 * Upper and lower case are accepted. Padding may be omitted.
 * Non-zero unused bits are rejected.
 */
export function base32ToBytes(value: string): Uint8Array {
  let end = value.length;
  while (end > 0 && value[end - 1] === "=") {
    end -= 1;
  }
  const padding = value.length - end;
  if (padding > 6 || !isValidBodyLength(end) || (padding > 0 && value.length % 8 !== 0)) {
    throw new Error("invalid base32");
  }
  if (padding !== 0 && padding !== expectedPadding(end)) {
    throw new Error("invalid base32");
  }
  const bytes: number[] = [];
  for (let index = 0; index < end; ) {
    const count = Math.min(8, end - index);
    const symbols: number[] = [];
    for (let offset = 0; offset < count; offset += 1) {
      symbols.push(decodeChar(value, index + offset));
    }
    appendQuantum(symbols, bytes);
    index += count;
  }
  return Uint8Array.from(bytes);
}
