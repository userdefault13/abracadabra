import os from "node:os";
import path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    env: {
      ABRA_SKIP_BIOMETRICS: "1",
      // Isolate from a real/user abra-agent socket (macOS + Linux CI).
      ABRA_AGENT: "0",
      // A test that forgets its own temp ABRA_DIR / keystore must never reach the
      // user's ~/.abracadabra or OS keychain.
      ABRA_DIR: path.join(os.tmpdir(), `abra-vitest-unisolated-${process.pid}`),
      ABRA_KEYSTORE: "passphrase-file",
    },
  },
});
