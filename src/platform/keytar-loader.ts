let keytarModule: {
  getPassword: (service: string, account: string) => Promise<string | null>;
  setPassword: (service: string, account: string, password: string) => Promise<void>;
  deletePassword: (service: string, account: string) => Promise<boolean>;
} | null = null;

export async function loadKeytar() {
  if (keytarModule) return keytarModule;
  try {
    const mod = await import("keytar");
    const kt = mod.default ?? mod;
    keytarModule = kt;
    return kt;
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(
      `keytar native module unavailable (${detail}). ` +
        "Install build tools and run: npm rebuild keytar. " +
        "Or set ABRA_KEYSTORE=passphrase-file — see docs/CROSS-PLATFORM.md",
    );
  }
}
