import { promptHidden } from "../core/prompt.js";
import {
  lockSession,
  isSessionUnlocked,
  platformInfo,
  unlockPassphraseVault,
} from "../platform/index.js";
import { resolveKeystoreBackend } from "../platform/env.js";

export async function cmdUnlock(): Promise<void> {
  const backend = resolveKeystoreBackend();
  if (backend !== "passphrase-file") {
    console.log(`Keystore "${backend}" does not use abra unlock (OS credential store).`);
    if (isSessionUnlocked()) lockSession();
    return;
  }
  const passphrase = await promptHidden("Vault passphrase: ");
  if (!passphrase) {
    throw new Error("Empty passphrase");
  }
  await unlockPassphraseVault(passphrase);
  console.log("✓ Vault unlocked");
}

export function cmdLock(): void {
  lockSession();
  console.log("✓ Vault locked");
}

export async function cmdUnlockStatus(): Promise<void> {
  const info = platformInfo();
  if (info.keystore !== "passphrase-file") {
    console.log(`unlock: not applicable (keystore=${info.keystore})`);
    return;
  }
  if (info.vaultLocked) {
    console.log("unlock: locked — run: abra unlock");
    process.exit(1);
  }
  console.log("unlock: session active");
}
