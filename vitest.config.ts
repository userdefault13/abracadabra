import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    env: {
      ABRA_SKIP_BIOMETRICS: "1",
    },
  },
});
