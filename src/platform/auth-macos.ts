import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { AuthRequest, PlatformAuth } from "./types.js";
import { biometricsSkipped } from "./env.js";

const execFileAsync = promisify(execFile);

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const HELPER_BIN = path.join(ROOT, "vendor", "auth-helper");
const HELPER_SRC = path.join(ROOT, "src", "auth", "auth-helper.swift");

async function compileHelper(): Promise<void> {
  await execFileAsync("swiftc", ["-O", HELPER_SRC, "-o", HELPER_BIN], {
    timeout: 120_000,
  });
}

async function ensureHelper(): Promise<void> {
  if (existsSync(HELPER_BIN)) return;
  await compileHelper();
}

export class MacOSTouchIdAuth implements PlatformAuth {
  readonly id = "macos-touchid";

  supportsBiometrics(): boolean {
    return !biometricsSkipped();
  }

  async authenticate(req: AuthRequest): Promise<void> {
    if (biometricsSkipped()) return;
    const timeoutSeconds = req.timeoutSeconds ?? 30;
    await ensureHelper();
    try {
      await execFileAsync(HELPER_BIN, [req.reason, String(timeoutSeconds)], {
        timeout: (timeoutSeconds + 10) * 1000,
      });
    } catch (err) {
      const detail =
        err instanceof Error && "stdout" in err && typeof err.stdout === "string"
          ? err.stdout.replace(/^DENY\s*/, "").trim()
          : "";
      throw new Error(detail || "Biometric authentication failed or was cancelled");
    }
  }
}
