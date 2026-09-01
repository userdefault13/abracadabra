import type { PlatformAuth } from "./types.js";

/** Skips human approval — dev/CI only (`ABRA_SKIP_BIOMETRICS=1` or `ABRA_AUTH=none`). */
export class NoAuth implements PlatformAuth {
  readonly id = "none";

  supportsBiometrics(): boolean {
    return false;
  }

  async authenticate(): Promise<void> {}
}
