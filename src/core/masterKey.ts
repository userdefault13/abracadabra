import crypto from "node:crypto";
import fs from "node:fs";
import type { PlatformKeystore } from "../platform/types.js";
import { KeystoreError } from "../platform/types.js";
import { vaultFile } from "./paths.js";

export interface ResolveMasterKeyOpts {
  /** Injectable vault-exists check (defaults to `fs.existsSync(vaultFile())`). */
  vaultExists?: () => boolean;
}

function defaultVaultExists(): boolean {
  return fs.existsSync(vaultFile());
}

/**
 * Resolve the vault master key without minting over an existing vault.
 *
 * Backends that implement `getMasterKey` only mint on `KeystoreError` kind
 * `not_found` when no vault.enc exists. Locked / denied / unavailable / mismatch
 * (and any non-KeystoreError) never mint.
 *
 * Backends without `getMasterKey` fall back to `getOrCreateMasterKey()` unchanged
 * (macOS keychain, passphrase-file).
 */
export async function resolveMasterKey(
  keystore: PlatformKeystore,
  opts?: ResolveMasterKeyOpts,
): Promise<Buffer> {
  if (!keystore.getMasterKey) {
    return keystore.getOrCreateMasterKey();
  }

  const vaultExists = opts?.vaultExists ?? defaultVaultExists;

  try {
    return await keystore.getMasterKey();
  } catch (e) {
    const err =
      e instanceof KeystoreError
        ? e
        : new KeystoreError(
            "unavailable",
            e instanceof Error ? e.message : String(e),
          );

    if (err.kind === "not_found" && !vaultExists()) {
      if (keystore.createMasterKey) {
        return keystore.createMasterKey();
      }
      const key = crypto.randomBytes(32);
      await keystore.storeMasterKey(key);
      return key;
    }

    throw err;
  }
}
