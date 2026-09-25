import crypto from "node:crypto";
import type { PlatformKeystore } from "./types.js";
import { promptHidden } from "../core/prompt.js";
import {
  assertVaultPassphraseMin,
  masterKeyFileExists,
  openMasterKeyFile,
  loadMasterKeyFileRaw,
  readMasterKeyFile,
  writeMasterKeyFile,
  WrongPassphraseError,
  VAULT_PASSPHRASE_MIN,
} from "./master-key-file.js";
import { headlessPassphrase } from "./env.js";
import { getSessionMasterKey, unlockSession } from "./session.js";
import {
  assertUnlockAllowed,
  recordUnlockFailure,
  resetUnlockAttempts,
} from "./unlock-attempts.js";

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

  /**
   * Re-wrap the master key. Prompts on the tty (passphrase is never cached).
   * If a file already exists, verifies the passphrase opens it before rewriting.
   */
  async storeMasterKey(key: Buffer): Promise<void> {
    if (key.length !== 32) throw new Error("Master key must be 32 bytes");

    if (masterKeyFileExists()) {
      const passphrase = await promptHidden("Vault passphrase: ");
      if (!passphrase) throw new Error("Empty passphrase");
      // Verify before overwrite (wrong passphrase → WrongPassphraseError).
      try {
        openMasterKeyFile(loadMasterKeyFileRaw(), passphrase);
      } catch (err) {
        if (err instanceof WrongPassphraseError) throw err;
        throw err;
      }
      // Existing secrets may be < 12 chars — allow re-wrap with warning.
      if ([...passphrase.normalize("NFKC")].length < VAULT_PASSPHRASE_MIN) {
        process.stderr.write(
          `abracadabra: vault passphrase is shorter than ${VAULT_PASSPHRASE_MIN} characters — consider changing it\n`,
        );
      }
      writeMasterKeyFile(key, passphrase);
      unlockSession(key);
      return;
    }

    const p1 = await promptHidden("Set vault passphrase (new): ");
    const p2 = await promptHidden("Confirm passphrase: ");
    if (!p1 || p1 !== p2) throw new Error("Passphrases do not match");
    assertVaultPassphraseMin(p1);
    writeMasterKeyFile(key, p1);
    unlockSession(key);
  }

  async initializeNewMasterKey(): Promise<Buffer> {
    const p1 = await promptHidden("Set vault passphrase (new): ");
    const p2 = await promptHidden("Confirm passphrase: ");
    if (!p1 || p1 !== p2) throw new Error("Passphrases do not match");
    assertVaultPassphraseMin(p1);
    const key = crypto.randomBytes(32);
    writeMasterKeyFile(key, p1);
    unlockSession(key);
    return key;
  }

  async unlockWithPassphrase(passphrase: string): Promise<Buffer> {
    if (!masterKeyFileExists()) {
      throw new Error("No master key file — run any vault command to initialize, or restore from USB");
    }
    assertUnlockAllowed();
    let key: Buffer;
    try {
      key = readMasterKeyFile(passphrase);
    } catch (err) {
      if (err instanceof WrongPassphraseError) {
        recordUnlockFailure();
        throw err;
      }
      // I/O / format errors — do not increment the counter.
      throw err;
    }
    resetUnlockAttempts();
    unlockSession(key);
    return key;
  }
}

export function isPassphraseVaultLocked(): boolean {
  return masterKeyFileExists() && !getSessionMasterKey();
}
