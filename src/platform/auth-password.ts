import type { AuthRequest, PlatformAuth } from "./types.js";
import { promptHidden } from "../core/prompt.js";

export class PasswordPromptAuth implements PlatformAuth {
  readonly id = "password";

  supportsBiometrics(): boolean {
    return false;
  }

  async authenticate(req: AuthRequest): Promise<void> {
    if (!process.stdin.isTTY) {
      throw new Error(
        `abracadabra: approval required — ${req.reason}. Run from a TTY or set ABRA_AUTH=none for CI (unsafe).`,
      );
    }
    await promptHidden(`abracadabra: ${req.reason}\nPress Enter after reading (type anything to confirm): `);
  }
}
