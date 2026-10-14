import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

const ignores = {
  ignores: ["**/dist/**", "**/.next/**", "**/coverage/**", "**/.turbo/**"],
};

/**
 * Shared flat config. Apps pass `typeChecked` once they have a tsconfig
 * that includes sources. This package itself stays syntax-only.
 *
 * @param {{
 *   typeChecked?: boolean,
 *   tsconfigRootDir?: string,
 *   environment?: "neutral" | "node" | "browser"
 * }} [options]
 */
export function createConfig(options = {}) {
  const environment = options.environment ?? "neutral";
  const languageGlobals =
    environment === "node" ? globals.node : environment === "browser" ? globals.browser : {};

  const tsFiles = ["**/*.{ts,tsx,mts,cts}"];
  const typeAware = options.typeChecked
    ? tseslint.configs.strictTypeChecked.map((config) => ({
        ...config,
        files: tsFiles,
      }))
    : tseslint.configs.strict;

  return tseslint.config(
    ignores,
    eslint.configs.recommended,
    typeAware,
    {
      files: tsFiles,
      languageOptions: {
        globals: languageGlobals,
        parserOptions: options.typeChecked
          ? {
              projectService: true,
              tsconfigRootDir: options.tsconfigRootDir,
            }
          : {},
      },
    },
    {
      files: ["**/*.{js,mjs,cjs}"],
      languageOptions: {
        globals: languageGlobals,
      },
    },
  );
}

export default createConfig();
