import os from "node:os";
import path from "node:path";
import fs from "node:fs";

export const ABRA_DIR = path.join(os.homedir(), ".abracadabra");
export const VAULT_FILE = path.join(ABRA_DIR, "vault.enc");

export function ensureDir(): void {
  fs.mkdirSync(ABRA_DIR, { recursive: true, mode: 0o700 });
}
