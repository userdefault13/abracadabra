#!/usr/bin/env node
if (process.platform !== "darwin") {
  console.warn(
    "abracadabra requires macOS (Touch ID + Keychain). Install may succeed but the CLI will not work fully.",
  );
}
