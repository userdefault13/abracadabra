export function biometricsSkipped(): boolean {
  return process.env.ABRA_SKIP_BIOMETRICS === "1" || process.env.ABRA_AUTH === "none";
}

/** CI/smoke only — requires ABRA_SKIP_BIOMETRICS=1. */
export function headlessPassphrase(): string | undefined {
  if (!biometricsSkipped()) return undefined;
  const p = process.env.ABRA_HEADLESS_PASSPHRASE?.trim();
  return p || undefined;
}

export function resolveKeystoreBackend(): string {
  if (process.env.ABRA_KEYSTORE) return process.env.ABRA_KEYSTORE;
  if (process.platform === "darwin") return "macos-keychain";
  if (process.platform === "linux" || process.platform === "win32") return "keytar";
  return "passphrase-file";
}

export function resolveAuthBackend(): string {
  if (process.env.ABRA_AUTH) return process.env.ABRA_AUTH;
  if (biometricsSkipped()) return "none";
  if (process.platform === "darwin") return "macos-touchid";
  if (process.platform === "linux" || process.platform === "win32") return "password";
  return "password";
}

export const UNSUPPORTED_PLATFORM_HINT =
  "Set ABRA_KEYSTORE=passphrase-file if the OS credential store is unavailable — see docs/CROSS-PLATFORM.md";
