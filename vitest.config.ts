import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    env: {
      ABRA_SKIP_BIOMETRICS: "1",
      // Isolate from a real/user abra-agent socket (macOS + Linux CI).
      ABRA_AGENT: "0",
    },
  },
});
