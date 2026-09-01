import { execFile } from "node:child_process";
import crypto from "node:crypto";
import os from "node:os";
import { promisify } from "node:util";
import type { PlatformKeystore } from "./types.js";

const execFileAsync = promisify(execFile);

const SERVICE = "abracadabra-master-key";
const ACCOUNT = os.userInfo().username;

async function runSecurity(args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("security", args);
  return stdout;
}

export class MacOSKeychainKeystore implements PlatformKeystore {
  readonly id = "macos-keychain";

  async getOrCreateMasterKey(): Promise<Buffer> {
    try {
      const stdout = await runSecurity([
        "find-generic-password",
        "-s",
        SERVICE,
        "-a",
        ACCOUNT,
        "-w",
      ]);
      return Buffer.from(stdout.trim(), "base64");
    } catch {
      const key = crypto.randomBytes(32);
      await this.storeMasterKey(key);
      return key;
    }
  }

  async storeMasterKey(key: Buffer): Promise<void> {
    await runSecurity([
      "add-generic-password",
      "-s",
      SERVICE,
      "-a",
      ACCOUNT,
      "-w",
      key.toString("base64"),
      "-U",
    ]);
    const stdout = await runSecurity([
      "find-generic-password",
      "-s",
      SERVICE,
      "-a",
      ACCOUNT,
      "-w",
    ]);
    const stored = Buffer.from(stdout.trim(), "base64");
    if (!stored.equals(key)) {
      throw new Error("Failed to store master key in Keychain");
    }
  }
}
