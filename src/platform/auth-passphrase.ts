import type { AuthRequest, PlatformAuth } from "./types.js";
import { promptHidden, isNoTerminalError } from "../core/prompt.js";
import { resolveKeystoreBackend } from "./env.js";
import { masterKeyFileExists, WrongPassphraseError } from "./master-key-file.js";
import { assertUnlockAllowed } from "./unlock-attempts.js";
import {
  isPassphraseVaultLocked,
  verifyVaultPassphrase,
} from "./keystore-passphrase.js";
import { unlockSession } from "./session.js";

const NO_TTY_DENIAL =
  "abracadabra: approval denied — passphrase approval needs a terminal: use ssh -t (MCP/API access while headless comes with `abra grant`)";

const REASON_MAX = 200;

/**
 * Sanitize a reason string before writing it to a tty: strip ANSI escapes and
 * C0/C1 control chars (newlines → spaces), then truncate.
 */
export function sanitizeAuthReason(reason: string): string {
  let s = reason
    // CSI / OSC / other ESC sequences
    .replace(/\x1b(?:\[[0-9;?]*[ -/]*[@-~]|].*?(?:\x07|\x1b\\)|[@-Z\\-_])/g, "")
    // Newlines → spaces (keep readable single-line prompt context)
    .replace(/[\r\n]+/g, " ")
    // Remaining C0 (0x00–0x1F, 0x7F) and C1 (0x80–0x9F)
    .replace(/[\u0000-\u001F\u007F\u0080-\u009F]/g, "");
  s = s.trim();
  if (s.length > REASON_MAX) s = `${s.slice(0, REASON_MAX)}…`;
  return s;
}

export class PassphraseAuth implements PlatformAuth {
  readonly id = "passphrase";

  supportsBiometrics(): boolean {
    return false;
  }

  async authenticate(req: AuthRequest): Promise<void> {
    const keystore = resolveKeystoreBackend();
    if (keystore !== "passphrase-file") {
      throw new Error(
        `abracadabra: approval denied — ABRA_AUTH=passphrase requires ABRA_KEYSTORE=passphrase-file (current keystore: ${keystore}). Migration from keytar is coming via \`abra keystore migrate\`.`,
      );
    }

    if (!masterKeyFileExists()) {
      throw new Error(
        "abracadabra: approval denied — no vault master key file (initialize the vault or restore from USB)",
      );
    }

    // Refuse before any prompt or scrypt when backoff is active.
    assertUnlockAllowed();

    const reason = sanitizeAuthReason(req.reason);
    const prompt = `abracadabra: ${reason}\nVault passphrase to approve: `;

    let passphrase: string;
    try {
      passphrase = await promptHidden(prompt);
    } catch (err) {
      if (isNoTerminalError(err)) {
        throw new Error(NO_TTY_DENIAL);
      }
      throw err;
    }

    if (!passphrase) {
      throw new Error("abracadabra: approval denied — empty passphrase");
    }

    let key: Buffer;
    try {
      key = verifyVaultPassphrase(passphrase);
    } catch (err) {
      if (err instanceof WrongPassphraseError) {
        throw new Error("abracadabra: approval denied — wrong passphrase");
      }
      throw err;
    }

    // Unlock a locked session so the subsequent reveal can read the master key.
    // The approval itself is never cached — next authenticate() prompts again.
    // unlockSession keeps its own copy, so always zero the derived key here.
    try {
      if (isPassphraseVaultLocked()) unlockSession(key);
    } finally {
      key.fill(0);
    }
  }
}
