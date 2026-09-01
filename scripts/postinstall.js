#!/usr/bin/env node
import { existsSync } from "node:fs";
import { execSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const helper = path.join(root, "vendor", "auth-helper");

if (process.platform === "darwin" && !existsSync(helper)) {
  try {
    execSync("npm run setup", { cwd: root, stdio: "inherit" });
  } catch {
    console.warn(
      "abracadabra: failed to compile Touch ID helper — run `npm run setup` manually (requires Xcode CLT).",
    );
  }
}

if (process.platform === "linux" || process.platform === "win32") {
  try {
    execSync("npm rebuild keytar", { cwd: root, stdio: "ignore" });
  } catch {
    console.warn(
      "abracadabra: keytar native build failed — install OS deps or set ABRA_KEYSTORE=passphrase-file (see docs/CROSS-PLATFORM.md).",
    );
  }
}
