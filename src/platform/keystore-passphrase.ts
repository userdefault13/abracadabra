import crypto from "node:crypto";
import type { PlatformKeystore } from "./types.js";
import { promptHidden } from "../core/prompt.js";
import {
  masterKeyFileExists,
  readMasterKeyFile,
  writeMasterKeyFile,
} from "./master-key-file.js";
import { headlessPassphrase } from "./env.js";
import {
  getSessionMasterKey,
  getSessionPassphrase,
  unlockSession,
} from "./session.js";

export class VaultLockedError extends Error {
  constructor() {
    super("Vault locked — run: abra unlock");
    this.name = "VaultLockedError";
  }
}

export class PassphraseFileKeystore implements PlatformKeystore {
  readonly id = "passphrase-file";

  async getOrCreateMasterKey(): Promise<Buffer> {
    const cached = getSessionMasterKey();
    if (cached) return cached;

    if (masterKeyFileExists()) {
      const headless = headlessPassphrase();
      if (headless) return this.unlockWithPassphrase(headless);
      throw new VaultLockedError();
    }

    return this.initializeNewMasterKey();
  }

  async storeMasterKey(key: Buffer): Promise<void> {
    if (key.length !== 32) throw new Error("Master key must be 32 bytes");
    const passphrase = getSessionPassphrase();
    if (!passphrase) {
      throw new Error("Vault locked — run: abra unlock before restoring a master key");
    }
    writeMasterKeyFile(key, passphrase);
    unlockSession(key, passphrase);
  }

  async initializeNewMasterKey(): Promise<Buffer> {
    const p1 = await promptHidden("Set vault passphrase (new): ");
    const p2 = await promptHidden("Confirm passphrase: ");
    if (!p1 || p1 !== p2) throw new Error("Passphrases do not match");
    const key = crypto.randomBytes(32);
    writeMasterKeyFile(key, p1);
    unlockSession(key, p1);
    return key;
  }

  async unlockWithPassphrase(passphrase: string): Promise<Buffer> {
    if (!masterKeyFileExists()) {
      throw new Error("No master key file — run any vault command to initialize, or restore from USB");
    }
    const key = readMasterKeyFile(passphrase);
    unlockSession(key, passphrase);
    return key;
  }
}

export function isPassphraseVaultLocked(): boolean {
  return masterKeyFileExists() && !getSessionMasterKey();
}
