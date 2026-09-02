import crypto from "node:crypto";

/** USB local stick backups (device in your pocket). */
export const USB_PASSPHRASE_MIN = 8;

/**
 * Cloud `--full` checkpoints are offline-attackable if the sealed blob is fetched.
 * Require longer, mixed passphrases.
 */
export const CLOUD_PASSPHRASE_MIN = 16;

const COMMON_WEAK = new Set(
  [
    "password",
    "password123",
    "password1234",
    "passphrase",
    "abracadabra",
    "12345678",
    "1234567890123456",
    "qwertyuiop",
    "letmein12345678",
    "changeme1234567",
  ].map((s) => s.toLowerCase()),
);

export function assertUsbPassphrase(passphrase: string): void {
  if (passphrase.length < USB_PASSPHRASE_MIN) {
    throw new Error(`Passphrase must be at least ${USB_PASSPHRASE_MIN} characters`);
  }
}

/**
 * Reject weak passphrases for cloud-sealed full vaults.
 * Requires length ≥ 16 and at least 3 of: lower, upper, digit, symbol.
 */
export function assertCloudPassphrase(passphrase: string): void {
  const p = passphrase.normalize("NFKC");
  if (p.length < CLOUD_PASSPHRASE_MIN) {
    throw new Error(
      `Cloud full-vault passphrase must be at least ${CLOUD_PASSPHRASE_MIN} characters ` +
        `(sealed checkpoints can be fetched and attacked offline)`,
    );
  }
  if (COMMON_WEAK.has(p.toLowerCase())) {
    throw new Error("Passphrase is too common — choose a stronger one");
  }
  // Reject long runs of a single character / trivial sequences
  if (/^(.)\1+$/.test(p) || /^0123456789abcdef+$/i.test(p) || /^abcdefghijklmnop/i.test(p)) {
    throw new Error("Passphrase is too predictable — mix unrelated words and symbols");
  }

  let classes = 0;
  if (/[a-z]/.test(p)) classes++;
  if (/[A-Z]/.test(p)) classes++;
  if (/[0-9]/.test(p)) classes++;
  if (/[^a-zA-Z0-9]/.test(p)) classes++;
  if (classes < 3) {
    throw new Error(
      "Cloud passphrase must use at least 3 of: lowercase, uppercase, digits, symbols",
    );
  }

  // Rough entropy floor: unique charset × length
  const unique = new Set(p).size;
  if (unique < 8) {
    throw new Error("Cloud passphrase has too little character variety");
  }
}

/** Stronger scrypt params for cloud-bound BackupBundles. */
export const CLOUD_SCRYPT = {
  N: 262144, // 2^18 — slower offline crack vs USB default 2^14
  r: 8,
  p: 1,
  keyLen: 32,
} as const;

export function randomSalt(bytes = 16): string {
  return crypto.randomBytes(bytes).toString("base64");
}
