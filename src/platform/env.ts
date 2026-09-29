import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { masterKeyFile, vaultFile } from "../core/paths.js";

export type HeadlessDetection = {
  headless: boolean;
  reasons: string[];
};

/**
 * Resolve vault directory from an env map (hermetic for tests).
 * ABRA_DIR (trimmed) → else HOME/.abracadabra → else os.homedir()/.abracadabra.
 */
export function resolveAbraDirFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  const fromEnv = env.ABRA_DIR?.trim();
  if (fromEnv) return fromEnv;
  const home = env.HOME?.trim();
  if (home) return path.join(home, ".abracadabra");
  return path.join(os.homedir(), ".abracadabra");
}

/**
 * Detect whether this Linux session can show a graphical approval dialog.
 * Non-Linux → not headless (reasons explain the skip).
 *
 * Headless when:
 * - SSH_CONNECTION or SSH_TTY is non-empty, OR
 * - neither WAYLAND_DISPLAY nor DISPLAY is set AND XDG_SESSION_TYPE is not wayland/x11
 */
export function detectHeadlessSession(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): HeadlessDetection {
  if (platform !== "linux") {
    return { headless: false, reasons: [`not linux (${platform})`] };
  }

  const reasons: string[] = [];
  const sshConnection = (env.SSH_CONNECTION ?? "").trim();
  const sshTty = (env.SSH_TTY ?? "").trim();
  if (sshConnection) reasons.push("SSH_CONNECTION set");
  if (sshTty) reasons.push("SSH_TTY set");

  const display = (env.DISPLAY ?? "").trim();
  const wayland = (env.WAYLAND_DISPLAY ?? "").trim();
  const sessionType = (env.XDG_SESSION_TYPE ?? "").trim().toLowerCase();
  const graphicalSessionType = sessionType === "wayland" || sessionType === "x11";
  const hasDisplay = Boolean(display || wayland);

  if (!hasDisplay && !graphicalSessionType) {
    const typeLabel = sessionType || "unset";
    reasons.push(`no DISPLAY/WAYLAND_DISPLAY and XDG_SESSION_TYPE=${typeLabel}`);
  }

  if (reasons.some((r) => r.startsWith("SSH_") || r.startsWith("no DISPLAY"))) {
    return { headless: true, reasons };
  }

  // Graphical: explain why.
  const graphicalReasons: string[] = [];
  if (wayland) graphicalReasons.push("WAYLAND_DISPLAY set");
  if (display) graphicalReasons.push("DISPLAY set");
  if (graphicalSessionType) graphicalReasons.push(`XDG_SESSION_TYPE=${sessionType}`);
  if (graphicalReasons.length === 0) graphicalReasons.push("graphical session");
  return { headless: false, reasons: graphicalReasons };
}

export function biometricsSkipped(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.ABRA_SKIP_BIOMETRICS === "1" || env.ABRA_AUTH === "none";
}

/** CI/smoke only — requires ABRA_SKIP_BIOMETRICS=1 (or ABRA_AUTH=none). */
export function headlessPassphrase(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (!biometricsSkipped(env)) return undefined;
  const p = env.ABRA_HEADLESS_PASSPHRASE?.trim();
  return p || undefined;
}

let keytarLoadableCache: boolean | undefined;

/** Whether keytar's native addon loads. Newer npm skips install scripts, leaving it unbuilt. */
export function keytarLoadable(): boolean {
  if (keytarLoadableCache === undefined) {
    try {
      createRequire(import.meta.url)("keytar");
      keytarLoadableCache = true;
    } catch {
      keytarLoadableCache = false;
    }
  }
  return keytarLoadableCache;
}

/**
 * True → use passphrase-file instead of keytar. Only when keytar can't load AND
 * the vault is new or already passphrase-wrapped: a vault whose key lives in the
 * OS keyring must stay on keytar so the user gets the rebuild hint, not "not found".
 */
export function shouldFallBackFromKeytar(s: {
  keytarLoadable: boolean;
  vaultExists: boolean;
  masterKeyFileExists: boolean;
}): boolean {
  if (s.keytarLoadable) return false;
  return s.masterKeyFileExists || !s.vaultExists;
}

function defaultKeytarFallback(): boolean {
  if (keytarLoadable()) return false;
  return shouldFallBackFromKeytar({
    keytarLoadable: false,
    vaultExists: existsSync(vaultFile()),
    masterKeyFileExists: existsSync(masterKeyFile()),
  });
}

let keytarFallbackProbe: () => boolean = defaultKeytarFallback;

/** Test hook — null restores the real probe. */
export function setKeytarFallbackProbeForTests(fn: (() => boolean) | null): void {
  keytarFallbackProbe = fn ?? defaultKeytarFallback;
}

let masterKeyFileProbe: () => boolean = () => existsSync(masterKeyFile());

/** Test hook — null restores the real probe. */
export function setMasterKeyFileProbeForTests(fn: (() => boolean) | null): void {
  masterKeyFileProbe = fn ?? (() => existsSync(masterKeyFile()));
}

/**
 * Linux/Windows: master.key.enc means the vault is passphrase-wrapped (new install
 * fallback or `abra keystore migrate`), so the CLI and abra-agent both pick
 * passphrase-file without ABRA_KEYSTORE — even when keytar loads.
 */
export function resolveKeystoreBackend(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  if (env.ABRA_KEYSTORE) return env.ABRA_KEYSTORE;
  if (platform === "darwin") return "macos-keychain";
  if (platform === "linux" || platform === "win32") {
    return keytarFallbackProbe() || masterKeyFileProbe() ? "passphrase-file" : "keytar";
  }
  return "passphrase-file";
}

/**
 * Human-readable why resolveKeystoreBackend picked its value (for doctor).
 * Only the master.key.enc case starts with "auto-detected".
 */
export function keystoreSelectionReason(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  if (env.ABRA_KEYSTORE) return "explicit ABRA_KEYSTORE";
  if (platform === "linux" || platform === "win32") {
    if (masterKeyFileProbe()) return "auto-detected master.key.enc";
    if (keytarFallbackProbe()) return "keytar addon not built";
  }
  return "platform default";
}

/** Linux/Windows picked passphrase-file only because keytar's addon isn't built. */
export function keystoreFellBackFromKeytar(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): boolean {
  return (
    !env.ABRA_KEYSTORE &&
    (platform === "linux" || platform === "win32") &&
    keytarFallbackProbe()
  );
}

/**
 * Auth backend selection.
 *
 * Order: explicit ABRA_AUTH → skip flags → darwin Touch ID → linux headless/
 * graphical rules → win32 password → other password.
 * Linux never auto-resolves to "password".
 */
export function resolveAuthBackend(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  if (env.ABRA_AUTH) return env.ABRA_AUTH;
  if (biometricsSkipped(env)) return "none";
  if (platform === "darwin") return "macos-touchid";
  if (platform === "linux") {
    const { headless } = detectHeadlessSession(env, platform);
    const keystore = resolveKeystoreBackend(env, platform);
    if (headless && keystore === "passphrase-file") return "passphrase";
    // Headless + keytar (or other): still "polkit" — PolkitAuth denies with a
    // headless hint (no dialog). Never auto-select "password" on Linux.
    return "polkit";
  }
  // Pre-existing: win32 defaults to the console password confirm prompt.
  if (platform === "win32") return "password";
  return "password";
}

/** Human-readable why resolveAuthBackend picked its value (for doctor). */
export function authSelectionReason(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  if (env.ABRA_AUTH) return "explicit ABRA_AUTH";
  if (biometricsSkipped(env)) return "ABRA_SKIP_BIOMETRICS / ABRA_AUTH=none";
  if (platform === "darwin") return "darwin default (macos-touchid)";
  if (platform === "linux") {
    const { headless } = detectHeadlessSession(env, platform);
    const keystore = resolveKeystoreBackend(env, platform);
    if (headless && keystore === "passphrase-file") return "headless + passphrase-file";
    if (headless) return "headless + keytar → polkit denies";
    return "graphical session";
  }
  if (platform === "win32") return "win32 default (password)";
  return "platform default (password)";
}

export const UNSUPPORTED_PLATFORM_HINT =
  "Set ABRA_KEYSTORE=passphrase-file if the OS credential store is unavailable — see docs/CROSS-PLATFORM.md";

export const VALID_AUTH_BACKENDS = [
  "macos-touchid",
  "polkit",
  "passphrase",
  "password",
  "none",
] as const;
