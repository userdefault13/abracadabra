import type { PlatformAuth, PlatformKeystore } from "./types.js";
import { MacOSKeychainKeystore } from "./keystore-macos.js";
import { KeytarKeystore } from "./keystore-keytar.js";
import { PassphraseFileKeystore } from "./keystore-passphrase.js";
import { MacOSTouchIdAuth } from "./auth-macos.js";
import { PasswordPromptAuth } from "./auth-password.js";
import { NoAuth } from "./auth-none.js";
import {
  biometricsSkipped,
  resolveAuthBackend,
  resolveKeystoreBackend,
  UNSUPPORTED_PLATFORM_HINT,
} from "./env.js";
import { resetSessionForTests, isSessionUnlocked, lockSession } from "./session.js";
import { isPassphraseVaultLocked } from "./keystore-passphrase.js";
import { writeMasterKeyFile } from "./master-key-file.js";
import { unlockSession } from "./session.js";
import { probeKeytar } from "./keystore-keytar.js";

export type { AuthRequest, PlatformAuth, PlatformKeystore } from "./types.js";
export { biometricsSkipped, resolveAuthBackend, resolveKeystoreBackend } from "./env.js";
export { lockSession, isSessionUnlocked } from "./session.js";
export { VaultLockedError } from "./keystore-passphrase.js";
export { probeKeytar } from "./keystore-keytar.js";

let keystoreSingleton: PlatformKeystore | null = null;
let authSingleton: PlatformAuth | null = null;

/** Test hook — reset cached platform backends. */
export function resetPlatformForTests(): void {
  keystoreSingleton = null;
  authSingleton = null;
  resetSessionForTests();
}

export function createKeystore(): PlatformKeystore {
  const backend = resolveKeystoreBackend();
  switch (backend) {
    case "macos-keychain":
      if (process.platform !== "darwin") {
        throw new Error(`ABRA_KEYSTORE=macos-keychain requires macOS. ${UNSUPPORTED_PLATFORM_HINT}`);
      }
      return new MacOSKeychainKeystore();
    case "keytar":
      return new KeytarKeystore();
    case "passphrase-file":
      return new PassphraseFileKeystore();
    default:
      throw new Error(`Unknown ABRA_KEYSTORE="${backend}". ${UNSUPPORTED_PLATFORM_HINT}`);
  }
}

export function createAuth(): PlatformAuth {
  const backend = resolveAuthBackend();
  switch (backend) {
    case "macos-touchid":
      if (process.platform !== "darwin") {
        throw new Error(`ABRA_AUTH=macos-touchid requires macOS. ${UNSUPPORTED_PLATFORM_HINT}`);
      }
      return new MacOSTouchIdAuth();
    case "password":
      return new PasswordPromptAuth();
    case "none":
      return new NoAuth();
    default:
      throw new Error(`Unknown ABRA_AUTH="${backend}". ${UNSUPPORTED_PLATFORM_HINT}`);
  }
}

export function getKeystore(): PlatformKeystore {
  keystoreSingleton ??= createKeystore();
  return keystoreSingleton;
}

export function getAuth(): PlatformAuth {
  authSingleton ??= createAuth();
  return authSingleton;
}

export async function getMasterKey(): Promise<Buffer> {
  return getKeystore().getOrCreateMasterKey();
}

export async function storeMasterKey(key: Buffer): Promise<void> {
  return getKeystore().storeMasterKey(key);
}

/**
 * USB restore / migration: persist master key on this machine's keystore.
 * Pass the bundle passphrase when using ABRA_KEYSTORE=passphrase-file.
 */
export async function restoreMasterKey(key: Buffer, bundlePassphrase?: string): Promise<void> {
  if (key.length !== 32) throw new Error("Master key must be 32 bytes");
  const backend = resolveKeystoreBackend();
  if (backend === "passphrase-file") {
    if (!bundlePassphrase) {
      throw new Error("USB restore on passphrase-file keystore requires the bundle passphrase");
    }
    writeMasterKeyFile(key, bundlePassphrase);
    unlockSession(key, bundlePassphrase);
    keystoreSingleton = createKeystore();
    return;
  }
  await getKeystore().storeMasterKey(key);
}

export async function authenticate(reason: string, timeoutSeconds = 30): Promise<void> {
  await getAuth().authenticate({ reason, timeoutSeconds });
}

export function platformInfo(): {
  platform: NodeJS.Platform;
  keystore: string;
  auth: string;
  biometricsSkipped: boolean;
  vaultLocked: boolean;
} {
  return {
    platform: process.platform,
    keystore: resolveKeystoreBackend(),
    auth: resolveAuthBackend(),
    biometricsSkipped: biometricsSkipped(),
    vaultLocked: resolveKeystoreBackend() === "passphrase-file" && isPassphraseVaultLocked(),
  };
}

export async function platformHealth(): Promise<{
  keytar?: { ok: boolean; detail?: string };
}> {
  const out: { keytar?: { ok: boolean; detail?: string } } = {};
  if (resolveKeystoreBackend() === "keytar") {
    out.keytar = await probeKeytar();
  }
  return out;
}

export async function unlockPassphraseVault(passphrase: string): Promise<void> {
  const ks = createKeystore();
  if (!(ks instanceof PassphraseFileKeystore)) {
    throw new Error(`abra unlock is only for ABRA_KEYSTORE=passphrase-file (current: ${ks.id})`);
  }
  await ks.unlockWithPassphrase(passphrase);
}
