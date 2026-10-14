import { base32ToBytes } from "./base32.ts";

export const otpAlgorithms = ["SHA1", "SHA256", "SHA512"] as const;

export type OtpAlgorithm = (typeof otpAlgorithms)[number];

interface OtpauthFields {
  issuer: string;
  account: string;
  secret: Uint8Array;
  algorithm: OtpAlgorithm;
  digits: 6 | 8;
}

export interface TotpAuth extends OtpauthFields {
  type: "totp";
  period: number;
}

export interface HotpAuth extends OtpauthFields {
  type: "hotp";
  counter: number;
}

export type Otpauth = TotpAuth | HotpAuth;

const invalid = (): never => {
  throw new Error("invalid otpauth");
};

function sole(params: URLSearchParams, key: string): string | undefined {
  const values = params.getAll(key);
  const value = values[0];
  if (values.length > 1 || value === undefined) {
    return values.length > 1 ? invalid() : undefined;
  }
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

function readLabel(pathname: string): { issuer: string; account: string } {
  let label: string;
  try {
    label = decodeURIComponent(pathname.replace(/^\/+/u, ""));
  } catch {
    return invalid();
  }
  const colon = label.indexOf(":");
  if (colon === -1) {
    return { issuer: "", account: label.trim() };
  }
  return {
    issuer: label.slice(0, colon).trim(),
    account: label.slice(colon + 1).trim(),
  };
}

function readAlgorithm(value: string | undefined): OtpAlgorithm {
  const algorithm = (value ?? "SHA1").toUpperCase();
  if (algorithm === "SHA1" || algorithm === "SHA256" || algorithm === "SHA512") {
    return algorithm;
  }
  return invalid();
}

function readDigits(value: string | undefined): 6 | 8 {
  if (value === undefined || value === "6") {
    return 6;
  }
  if (value === "8") {
    return 8;
  }
  return invalid();
}

function readCount(value: string): number {
  if (!/^[0-9]+$/u.test(value)) {
    return invalid();
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    return invalid();
  }
  return parsed;
}

function readSecret(value: string | undefined): Uint8Array {
  if (value === undefined) {
    return invalid();
  }
  const normalized = value.replace(/[\s-]/gu, "").toUpperCase();
  if (normalized.length === 0) {
    return invalid();
  }
  try {
    const secret = base32ToBytes(normalized);
    if (secret.byteLength === 0) {
      return invalid();
    }
    return secret;
  } catch {
    return invalid();
  }
}

/** Parse a Key URI (`otpauth://totp/...` or `otpauth://hotp/...`). */
export function parseOtpauth(uri: string): Otpauth {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return invalid();
  }
  if (url.protocol !== "otpauth:" || url.username !== "" || url.password !== "" || url.port !== "") {
    return invalid();
  }
  const type = url.hostname.toLowerCase();
  if (type !== "totp" && type !== "hotp") {
    return invalid();
  }

  const params = new URLSearchParams(url.search);
  const label = readLabel(url.pathname);
  if (label.account === "") {
    return invalid();
  }
  const queryIssuer = sole(params, "issuer");
  if (queryIssuer !== undefined && label.issuer !== "" && queryIssuer !== label.issuer) {
    return invalid();
  }

  const secret = readSecret(sole(params, "secret"));
  const algorithm = readAlgorithm(sole(params, "algorithm"));
  const digits = readDigits(sole(params, "digits"));
  const issuer = queryIssuer ?? label.issuer;
  const periodText = sole(params, "period");
  const counterText = sole(params, "counter");

  if (type === "totp") {
    if (counterText !== undefined) {
      return invalid();
    }
    const period = periodText === undefined ? 30 : readCount(periodText);
    if (period < 1) {
      return invalid();
    }
    return { type, issuer, account: label.account, secret, algorithm, digits, period };
  }

  if (periodText !== undefined || counterText === undefined) {
    return invalid();
  }
  return {
    type,
    issuer,
    account: label.account,
    secret,
    algorithm,
    digits,
    counter: readCount(counterText),
  };
}
