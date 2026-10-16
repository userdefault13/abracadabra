import path from "node:path";
import { saveVault, withVaultLock, writeEncryptedVaultFile, type Vault } from "../../src/core/vault.js";

/** Test setup: overwrite the vault under the vault lock (no read-modify-write). */
export function seedVault(vault: Vault): Promise<void> {
  return withVaultLock(() => saveVault(vault));
}

/** Test setup: write an already-encrypted vault.enc under the lock beside `file`. */
export function seedVaultFile(enc: Buffer, file?: string): Promise<void> {
  return withVaultLock(() => writeEncryptedVaultFile(enc, file), file ? { dir: path.dirname(file) } : {});
}
