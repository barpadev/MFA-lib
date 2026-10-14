import assert from "node:assert/strict";
import { test } from "node:test";

import { utf8ToBytes } from "./buffer.ts";
import { hotp, totp } from "./otp.ts";

const sha1Secret = utf8ToBytes("12345678901234567890");
const sha256Secret = utf8ToBytes("12345678901234567890123456789012");
const sha512Secret = utf8ToBytes(
  "1234567890123456789012345678901234567890123456789012345678901234",
);

const rfc4226 = [
  "755224",
  "287082",
  "359152",
  "969429",
  "338314",
  "254676",
  "287922",
  "162583",
  "399871",
  "520489",
] as const;

const rfc6238 = [
  { time: 59, sha1: "94287082", sha256: "46119246", sha512: "90693936" },
  { time: 1_111_111_109, sha1: "07081804", sha256: "68084774", sha512: "25091201" },
  { time: 1_111_111_111, sha1: "14050471", sha256: "67062674", sha512: "99943326" },
  { time: 1_234_567_890, sha1: "89005924", sha256: "91819424", sha512: "93441116" },
  { time: 2_000_000_000, sha1: "69279037", sha256: "90698825", sha512: "38618901" },
  { time: 20_000_000_000, sha1: "65353130", sha256: "77737706", sha512: "47863826" },
] as const;

void test("hotp matches RFC 4226 appendix D", async () => {
  for (const [counter, code] of rfc4226.entries()) {
    assert.equal(await hotp(sha1Secret, counter), code);
  }
});

void test("totp matches RFC 6238 appendix B", async () => {
  for (const row of rfc6238) {
    assert.equal(await totp(sha1Secret, row.time, { digits: 8 }), row.sha1);
    assert.equal(
      await totp(sha256Secret, row.time, { algorithm: "SHA256", digits: 8 }),
      row.sha256,
    );
    assert.equal(
      await totp(sha512Secret, row.time, { algorithm: "SHA512", digits: 8 }),
      row.sha512,
    );
  }
});

void test("totp is hotp at floor(unixSeconds / period)", async () => {
  assert.equal(await totp(sha1Secret, 59), await hotp(sha1Secret, 1));
  assert.equal(await totp(sha1Secret, 59, { period: 60 }), await hotp(sha1Secret, 0));
});

void test("otp rejects inputs that are not a code", async () => {
  await assert.rejects(hotp(new Uint8Array(), 0), /invalid secret/u);
  await assert.rejects(hotp(sha1Secret, -1), /invalid counter/u);
  await assert.rejects(hotp(sha1Secret, 1.5), /invalid counter/u);
  await assert.rejects(totp(sha1Secret, 0, { period: 0 }), /invalid period/u);
  await assert.rejects(
    hotp(sha1Secret, 0, { algorithm: "MD5" as "SHA1" }),
    /invalid otp/u,
  );
});
