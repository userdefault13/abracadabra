import type { PlatformAuth, PlatformKeystore } from "./types.js";
import { MacOSKeychainKeystore } from "./keystore-macos.js";
import { KeytarKeystore } from "./keystore-keytar.js";
import { PassphraseFileKeystore } from "./keystore-passphrase.js";
import { MacOSTouchIdAuth } from "./auth-macos.js";
import { PasswordPromptAuth } from "./auth-password.js";
import { PolkitAuth, probePolkit, setProbePolkitForTests } from "./auth-polkit.js";
import { PassphraseAuth } from "./auth-passphrase.js";
import { NoAuth } from "./auth-none.js";
import {
  authSelectionReason,
  biometricsSkipped,
  detectHeadlessSession,
  keystoreSelectionReason,
  resolveAbraDirFromEnv,
  resolveAuthBackend,
  resolveKeystoreBackend,
  UNSUPPORTED_PLATFORM_HINT,
  VALID_AUTH_BACKENDS,
  type HeadlessDetection,
} from "./env.js";
import { resetSessionForTests, isSessionUnlocked, lockSession } from "./session.js";
import { isPassphraseVaultLocked } from "./keystore-passphrase.js";
import { writeMasterKeyFile } from "./master-key-file.js";
import { unlockSession } from "./session.js";
import { VAULT_PASSPHRASE_MIN } from "./master-key-file.js";
import { probeKeytar } from "./keystore-keytar.js";
import { resolveMasterKey } from "../core/masterKey.js";

export type { AuthRequest, PlatformAuth, PlatformKeystore } from "./types.js";
export { KeystoreError } from "./types.js";
export {
  authSelectionReason,
  biometricsSkipped,
  detectHeadlessSession,
  keystoreSelectionReason,
  resolveAuthBackend,
  resolveKeystoreBackend,
  VALID_AUTH_BACKENDS,
} from "./env.js";
export type { HeadlessDetection, KeystoreResolveOpts } from "./env.js";
export { lockSession, isSessionUnlocked } from "./session.js";
export { VaultLockedError } from "./keystore-passphrase.js";
export { probeKeytar } from "./keystore-keytar.js";
export { probePolkit, setProbePolkitForTests } from "./auth-polkit.js";

let keystoreSingleton: PlatformKeystore | null = null;
let authSingleton: PlatformAuth | null = null;
let autoDetectNoticeEmitted = false;

/** Injectable deps for hermetic auto-detect stderr notice tests. */
export type KeystoreAutoDetectNoticeDeps = {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  isTTY?: boolean | null;
  stderrWrite?: (chunk: string) => void;
  abraDir?: () => string;
  selectionReason?: () => string;
};

/**
 * Once per process: warn on stderr when Linux auto-detected passphrase-file
 * in a non-interactive process (systemd / pipes). Never stdout (abra get/env).
 * Suppress with ABRA_QUIET=1.
 */
export function maybeWarnKeystoreAutoDetect(
  deps: KeystoreAutoDetectNoticeDeps = {},
): void {
  if (autoDetectNoticeEmitted) return;
  const env = deps.env ?? process.env;
  if (env.ABRA_QUIET === "1") return;
  const platform = deps.platform ?? process.platform;
  if (platform !== "linux") return;
  if (env.ABRA_KEYSTORE) return;
  const reason =
    deps.selectionReason?.() ?? keystoreSelectionReason(env, platform);
  if (!reason.startsWith("auto-detected")) return;
  const isTTY =
    deps.isTTY !== undefined ? deps.isTTY : process.stdin.isTTY;
  if (isTTY) return;

  autoDetectNoticeEmitted = true;
  const dir = deps.abraDir?.() ?? resolveAbraDirFromEnv(env);
  const write =
    deps.stderrWrite ??
    ((chunk: string) => {
      process.stderr.write(chunk);
    });
  write(
    `abra: keystore auto-detected as passphrase-file (master.key.enc in ${dir}); ` +
      `set ABRA_KEYSTORE explicitly in units — see docs/LINUX-HEADLESS.md#upgrading-existing-units\n`,
  );
}

/** Test hook — reset cached platform backends. */
export function resetPlatformForTests(): void {
  keystoreSingleton = null;
  authSingleton = null;
  autoDetectNoticeEmitted = false;
  resetSessionForTests();
  setProbePolkitForTests(null);
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
    case "polkit":
      if (process.platform !== "linux") {
        throw new Error(`ABRA_AUTH=polkit requires Linux. ${UNSUPPORTED_PLATFORM_HINT}`);
      }
      return new PolkitAuth();
    case "passphrase":
      return new PassphraseAuth();
    case "password":
      return new PasswordPromptAuth();
    case "none":
      return new NoAuth();
    default:
      throw new Error(
        `Unknown ABRA_AUTH="${backend}". Valid values: ${VALID_AUTH_BACKENDS.join(", ")}. ${UNSUPPORTED_PLATFORM_HINT}`,
      );
  }
}

export function getKeystore(): PlatformKeystore {
  if (!keystoreSingleton) {
    // Notice only on real instantiation (not resolveKeystoreBackend / doctor).
    maybeWarnKeystoreAutoDetect();
    keystoreSingleton = createKeystore();
  }
  return keystoreSingleton;
}

export function getAuth(): PlatformAuth {
  authSingleton ??= createAuth();
  return authSingleton;
}

export async function getMasterKey(): Promise<Buffer> {
  return resolveMasterKey(getKeystore());
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
    // Bundle passphrase is an existing secret — allow < 12 chars but warn.
    // Enforcing the new minimum would brick restores of older USB/cloud bundles.
    if ([...bundlePassphrase.normalize("NFKC")].length < VAULT_PASSPHRASE_MIN) {
      process.stderr.write(
        `abracadabra: bundle passphrase is shorter than ${VAULT_PASSPHRASE_MIN} characters — vault wrap will use it anyway; consider changing the vault passphrase after restore\n`,
      );
    }
    writeMasterKeyFile(key, bundlePassphrase);
    unlockSession(key);
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
  authSelectionReason: string;
  keystoreSelectionReason: string;
  biometricsSkipped: boolean;
  vaultLocked: boolean;
  headless: HeadlessDetection;
} {
  return {
    platform: process.platform,
    keystore: resolveKeystoreBackend(),
    auth: resolveAuthBackend(),
    authSelectionReason: authSelectionReason(),
    keystoreSelectionReason: keystoreSelectionReason(),
    biometricsSkipped: biometricsSkipped(),
    vaultLocked: resolveKeystoreBackend() === "passphrase-file" && isPassphraseVaultLocked(),
    headless: detectHeadlessSession(),
  };
}

export async function platformHealth(): Promise<{
  keytar?: { ok: boolean; detail?: string };
  polkit?: { ok: boolean; pkcheck?: string; policy?: string; detail?: string };
}> {
  const out: {
    keytar?: { ok: boolean; detail?: string };
    polkit?: { ok: boolean; pkcheck?: string; policy?: string; detail?: string };
  } = {};
  if (resolveKeystoreBackend() === "keytar") {
    out.keytar = await probeKeytar();
  }
  const auth = resolveAuthBackend();
  // PolKit not needed when passphrase auth is selected.
  if (auth !== "passphrase" && (process.platform === "linux" || auth === "polkit")) {
    out.polkit = probePolkit();
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
