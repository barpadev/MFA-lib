import assert from "node:assert/strict";
import { test } from "node:test";

import { base32ToBytes } from "./base32.ts";
import { parseOtpauth } from "./otpauth.ts";

const secret = "JBSWY3DPEHPK3PXP";

void test("parseOtpauth reads a TOTP key URI", () => {
  const parsed = parseOtpauth(
    `otpauth://totp/${encodeURIComponent("بانک:علی")}?secret=${secret}&issuer=${encodeURIComponent("بانک")}&algorithm=SHA256&digits=8&period=45`,
  );
  assert.equal(parsed.type, "totp");
  assert.equal(parsed.issuer, "بانک");
  assert.equal(parsed.account, "علی");
  assert.deepEqual([...parsed.secret], [...base32ToBytes(secret)]);
  assert.equal(parsed.algorithm, "SHA256");
  assert.equal(parsed.digits, 8);
  assert.equal(parsed.period, 45);
});

void test("parseOtpauth applies TOTP defaults and strips secret padding characters", () => {
  const parsed = parseOtpauth(
    "otpauth://TOTP/Example:alice@google.com?secret=jbsw%20y3dp-ehpk-3pxp",
  );
  assert.equal(parsed.type, "totp");
  assert.equal(parsed.issuer, "Example");
  assert.equal(parsed.account, "alice@google.com");
  assert.deepEqual([...parsed.secret], [...base32ToBytes(secret)]);
  assert.equal(parsed.algorithm, "SHA1");
  assert.equal(parsed.digits, 6);
  assert.equal(parsed.period, 30);
});

void test("parseOtpauth reads an HOTP counter", () => {
  const parsed = parseOtpauth(
    `otpauth://hotp/alice@google.com?secret=${secret}&counter=0`,
  );
  assert.equal(parsed.type, "hotp");
  assert.equal(parsed.issuer, "");
  assert.equal(parsed.account, "alice@google.com");
  assert.equal(parsed.counter, 0);
});

void test("parseOtpauth rejects malformed URIs", () => {
  const samples = [
    "https://example.com",
    "otpauth://totp/alice",
    "otpauth://hotp/alice?secret=" + secret,
    "otpauth://totp/alice?secret=" + secret + "&counter=1",
    "otpauth://hotp/alice?secret=" + secret + "&counter=1&period=30",
    "otpauth://totp/alice?secret=" + secret + "&digits=7",
    "otpauth://totp/alice?secret=" + secret + "&algorithm=MD5",
    "otpauth://totp/alice?secret=" + secret + "&period=0",
    "otpauth://totp/Example:alice?secret=" + secret + "&issuer=Other",
    "otpauth://totp/?secret=" + secret,
    "otpauth://totp/alice?secret=!!!!",
  ];
  for (const sample of samples) {
    assert.throws(() => parseOtpauth(sample), /invalid otpauth/);
  }
});
