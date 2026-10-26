import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const readme = readFileSync(join(root, "README.md"), "utf8");
const architecture = readFileSync(join(root, "ARCHITECTURE.md"), "utf8");
const license = readFileSync(join(root, "LICENSE"));
const repositoryLicense = readFileSync(join(root, "../../LICENSE"));

const runtimeExports = [
  "backupPbkdf2Iterations",
  "base32ToBytes",
  "base64UrlToBytes",
  "bytesToBase32",
  "bytesToBase64Url",
  "bytesToHex",
  "bytesToUtf8",
  "concatBytes",
  "constantTimeEqual",
  "createBackup",
  "createChallenge",
  "createDeviceVault",
  "createVault",
  "encodeMnemonic",
  "hexToBytes",
  "hotp",
  "openBackup",
  "openDeviceVault",
  "openVault",
  "parseOtpauth",
  "randomBytes",
  "rewrapVault",
  "sealDeviceVault",
  "sealVault",
  "totp",
  "utf8ToBytes",
  "vaultPbkdf2Iterations",
];

test("the package is version 0.1.0 and publishes the built entry", () => {
  assert.equal(manifest.name, "@crypto/Barpa-MFA");
  assert.equal(manifest.version, "0.1.0");
  assert.equal(manifest.license, "Apache-2.0");
  assert.equal(manifest.private, undefined);
  assert.deepEqual(manifest.files, ["dist", "README.md", "LICENSE"]);
  assert.equal(manifest.exports["."].import, "./dist/index.js");
  assert.equal(manifest.exports["."].types, "./dist/index.d.ts");
  assert.equal(Object.keys(manifest.dependencies ?? {}).length, 0);
  assert.equal(license.equals(repositoryLicense), true);
});

test("a stranger can follow the README", () => {
  assert.match(readme, /workspace:\^0\.1\.0/);
  assert.match(readme, /pnpm add \.\/packages\/crypto\/crypto-Barpa-MFA-0\.1\.0\.tgz/);
  assert.match(readme, /parseOtpauth/);
  assert.match(readme, /from "@crypto\/Barpa-MFA"/);
  assert.match(architecture, /0\.1\.0/);
  assert.doesNotMatch(readme, /otpauth:\/\/|secret=|mnemonic:/i);
});

test("the built entry is the public surface", async () => {
  const built = await import("../dist/index.js");
  assert.deepEqual(Object.keys(built).sort(), runtimeExports);
  const declarations = readdirSync(join(root, "dist"))
    .filter((name) => name.endsWith(".d.ts"))
    .map((name) => readFileSync(join(root, "dist", name), "utf8"))
    .join("\n");
  assert.doesNotMatch(declarations, /from\s+["'][^"']+\.ts["']/);
  assert.match(readFileSync(join(root, "dist/index.d.ts"), "utf8"), /from "\.\/otp\.js"/);
});
