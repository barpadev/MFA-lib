# @themystery/crypto

Version `0.1.0`. Apache-2.0. The licence text is [`LICENSE`](LICENSE) in this package, copied from the repository root.

This is a library for developers. It wraps WebCrypto for TOTP, HOTP, a PIN-wrapped vault, and a seed-wrapped backup. It has no UI, no network calls, and no runtime dependencies. `@themystery/totp` depends on `workspace:^0.1.0` and imports this package. It does not copy these algorithms.

While the major version is 0, a new minor version may change the API. A patch stays compatible. There is no independent audit of this package.

## Install

From this repository:

```json
{
  "dependencies": {
    "@themystery/crypto": "workspace:^0.1.0"
  }
}
```

Outside the repository, build the tarball and add that file:

```bash
pnpm --dir packages/crypto build
pnpm --dir packages/crypto pack
pnpm add ./packages/crypto/themystery-crypto-0.1.0.tgz
```

The public entry is the package root. Import from `@themystery/crypto`. The published files are `dist/`, this README, and `LICENSE`.

Node.js 22 or newer. The runtime is `globalThis.crypto` (WebCrypto). `totp` does not read the clock. Pass the Unix seconds yourself.

## Codes

`parseOtpauth` returns the issuer, the account label, the secret bytes, the algorithm, the digits, and either `period` (TOTP, default 30) or `counter` (HOTP). A malformed URI throws `invalid otpauth`. The message does not include the URI.

`totp` and `hotp` return a zero-padded decimal string. The algorithm is `SHA1`, `SHA256`, or `SHA512`. Digits are 6 or 8. A failure is `invalid secret`, `invalid period`, `invalid counter`, or `invalid otp`. The message does not include the secret or the code.

```ts
import { parseOtpauth, totp } from "@themystery/crypto";

const parsed = parseOtpauth(uri);
if (parsed.type !== "totp") {
  throw new Error("invalid otpauth");
}
const code = await totp(parsed.secret, unixSeconds, {
  algorithm: parsed.algorithm,
  digits: parsed.digits,
  period: parsed.period,
});
```

That sample is illustrative. It is not a real enrollment URI, and it has no secret value.

Replay prevention stays with the server that checks the code.

## Vault and backup

`createVault` seals plaintext with a PIN of 4 to 8 digits. The KDF is PBKDF2-HMAC-SHA-256, 600,000 iterations, unless the caller passes another count inside 1,000–1,000,000. The vault key is AES-GCM-256, wrapped with AES-KW, and is not extractable. `openVault`, `sealVault`, and `rewrapVault` use that same record. A failure is `invalid request`.

`createBackup` seals plaintext under a new 12-word BIP-39 mnemonic and returns the phrase once. The blob uses PBKDF2-HMAC-SHA-512, salt `mnemonic`, 2048 iterations. `openBackup` decrypts with the phrase. The phrase is not a field of the blob.

## Other exports

Buffer helpers: `concatBytes`, `constantTimeEqual`, `bytesToHex`, `hexToBytes`, `bytesToBase64Url`, `base64UrlToBytes`, `utf8ToBytes`, `bytesToUtf8`, `randomBytes`.

Base32: `bytesToBase32`, `base32ToBytes`.

`createChallenge` mints at least 16 bytes (default 32). `verify` accepts the challenge once.

`constantTimeEqual` walks the longer input and does not branch on byte values.
