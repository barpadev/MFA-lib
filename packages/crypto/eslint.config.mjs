import { createConfig } from "@crypto/Barpa-config/eslint";

export default createConfig({
  typeChecked: true,
  tsconfigRootDir: import.meta.dirname,
  environment: "node",
});
