import { createConfig } from "@themystery/config/eslint";

export default createConfig({
  typeChecked: true,
  tsconfigRootDir: import.meta.dirname,
  environment: "node",
});
