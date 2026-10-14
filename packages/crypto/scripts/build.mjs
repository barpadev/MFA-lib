import { spawnSync } from "node:child_process";
import { copyFileSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(import.meta.url);

rmSync(join(packageRoot, "dist"), { recursive: true, force: true });
copyFileSync(join(packageRoot, "../../LICENSE"), join(packageRoot, "LICENSE"));

const tsc = require.resolve("typescript/lib/tsc.js");
const result = spawnSync(process.execPath, [tsc, "-p", "tsconfig.build.json"], {
  cwd: packageRoot,
  stdio: "inherit",
});

if ((result.status ?? 1) !== 0) {
  process.exit(result.status ?? 1);
}

const dist = join(packageRoot, "dist");
for (const name of readdirSync(dist)) {
  if (!name.endsWith(".d.ts")) {
    continue;
  }
  const path = join(dist, name);
  const source = readFileSync(path, "utf8");
  const rewritten = source.replaceAll(/(\bfrom\s+["']\.[^"']+)\.ts(["'])/gu, "$1.js$2");
  if (rewritten !== source) {
    writeFileSync(path, rewritten);
  }
}
