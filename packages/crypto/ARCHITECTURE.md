# packages/crypto — Architecture

Business rules for `@themystery/crypto` 0.1.0. Root `ARCHITECTURE.md` wins on conflict.

## 1. Mission

This package is the versioned open-core library. Developers consume it. It is not an app and not a service. `@themystery/totp` is the consumer in this repository. `apps/passkey` may import it as a test harness. That harness is not this package's supported product consumer.

## 2. What ships

The package version is `0.1.0`, licence Apache-2.0. `pnpm build` writes `dist/` from `src/` and copies the repository `LICENSE` next to this file. `package.json` `exports` point at `dist/index.js` and `dist/index.d.ts`. Tests stay on the TypeScript sources and run with Node's type stripper. There are no runtime dependencies.

While the major version is 0, a minor bump may change the public entry. A patch does not. `@themystery/totp` depends on `workspace:^0.1.0`.

The public entry is the names re-exported from `src/index.ts`:

- Codes: `parseOtpauth`, `totp`, `hotp`.
- Vault: `createVault`, `openVault`, `sealVault`, `rewrapVault`, `vaultPbkdf2Iterations`.
- Backup: `createBackup`, `openBackup`, `encodeMnemonic`, `backupPbkdf2Iterations`.
- Challenge: `createChallenge`.
- Bytes: Base32, hex, unpadded base64url, UTF-8, `concatBytes`, `constantTimeEqual`, `randomBytes`.

`randomBytes` uses `globalThis.crypto`. `totp` takes explicit Unix seconds and does not read the clock.

## 3. Codes

`parseOtpauth` accepts an `otpauth://` URI. The result is issuer, account, secret bytes, algorithm (`SHA1`, `SHA256`, or `SHA512`), digits (6 or 8), and either `period` (TOTP, default 30) or `counter` (HOTP). A malformed URI throws `invalid otpauth` with no URI in the message.

`hotp` follows RFC 4226. `totp` follows RFC 6238. Both return a zero-padded decimal code via WebCrypto HMAC. Failures are `invalid secret`, `invalid period`, `invalid counter`, or `invalid otp`, with no secret and no code in the message. Replay prevention is not this package.

## 4. Vault

Format version is 1. The PIN is 4–8 digits. The KDF is PBKDF2-HMAC-SHA-256. The default is 600,000 iterations. A caller-supplied count must be an integer from 1,000 through 1,000,000. WebCrypto has no Argon2id, so PBKDF2 stays inside the audited primitive set. The vault key is AES-GCM-256. AES-KW wraps it. The key returned by create, open, or rewrap has `extractable: false`. Payload encryption uses a 12-byte IV and additional data bound to the vault id and format version. A failed open is `invalid request`. This package does not write IndexedDB and does not call `exportKey`.

## 5. Backup

`createBackup` returns a versioned AES-GCM blob, `wrapping: "seed"`, and a 12-word BIP-39 mnemonic from 128 bits of CSPRNG entropy. The seed function is PBKDF2-HMAC-SHA-512, salt `mnemonic`, empty passphrase, 2048 iterations. That count is the BIP-39 seed function, not the PIN stretch. The AES-GCM key is the first 256 bits of the 512-bit seed and is not returned. The mnemonic is not a field of the blob. `openBackup` decrypts and does not retain the phrase. A failure is `invalid request`.

## 6. Challenge

`createChallenge` mints at least 16 bytes, default 32, and exposes unpadded base64url. `verify` compares in constant time and consumes the challenge on the first call. A later call returns false.

## 7. Never

- No telemetry, network, UI, or app storage.
- No `Math.random` on a security path.
- No `exportKey` on a vault key or a backup key.
- No secret, PIN, seed, URI, or code in an error message.
- No runtime dependency. No copyleft dependency.
- No claim of an independent audit.

## 8. Cross-references

Root invariants: `/ARCHITECTURE.md`. The TOTP app that consumes this version: `apps/totp/ARCHITECTURE.md`. Account shapes stay in `packages/types` and are not imported here.
