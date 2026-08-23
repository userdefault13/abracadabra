import { execFile } from "node:child_process";
import crypto from "node:crypto";
import { promisify } from "node:util";
import os from "node:os";

const execFileAsync = promisify(execFile);

const SERVICE = "abracadabra-master-key";
const ACCOUNT = os.userInfo().username;

async function runSecurity(args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("security", args);
  return stdout;
}

export async function getMasterKey(): Promise<Buffer> {
  try {
    const stdout = await runSecurity([
      "find-generic-password",
      "-s", SERVICE,
      "-a", ACCOUNT,
      "-w",
    ]);
    return Buffer.from(stdout.trim(), "base64");
  } catch {
    return await createMasterKey();
  }
}

async function createMasterKey(): Promise<Buffer> {
  const key = crypto.randomBytes(32);
  // -U updates the item if it exists
  await runSecurity([
    "add-generic-password",
    "-s", SERVICE,
    "-a", ACCOUNT,
    "-w", key.toString("base64"),
    "-U",
  ]);
  // verify readback so we never lose the only copy of the key
  const stdout = await runSecurity([
    "find-generic-password",
    "-s", SERVICE,
    "-a", ACCOUNT,
    "-w",
  ]);
  const stored = Buffer.from(stdout.trim(), "base64");
  if (!stored.equals(key)) {
    throw new Error("Failed to store master key in Keychain");
  }
  return key;
}
