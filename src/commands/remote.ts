import type { Command } from "commander";
import { abraDir } from "../core/paths.js";
import { getOrCreatePublicDeviceKey } from "../remote/device-key.js";

/**
 * Hidden preview commands for remote unlock (PR 1/7).
 * Feature is off by default — nothing listens until later PRs + ABRA_REMOTE_UNLOCK=1.
 */

export function cmdRemoteWhoami(opts: { base?: string } = {}): void {
  const pub = getOrCreatePublicDeviceKey({ base: opts.base ?? abraDir() });
  // Fingerprint only — never print private keys or raw key material.
  console.log(pub.fingerprint);
}

export function registerRemoteCommands(program: Command): void {
  const remote = program
    .command("remote", { hidden: true })
    .description("(preview) Remote fleet unlock from the hub");

  remote
    .command("whoami", { hidden: true })
    .description("Print this device's remote public-key fingerprint (creates the device key if missing)")
    .action(() => {
      try {
        cmdRemoteWhoami();
      } catch (err) {
        console.error(`\x1b[31m✗ ${err instanceof Error ? err.message : String(err)}\x1b[0m`);
        process.exit(1);
      }
    });
}
