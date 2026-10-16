import type { Command } from "commander";
import { loadVault, updateVault } from "../core/vault.js";
import { abraDir } from "../core/paths.js";
import { authenticate } from "../platform/index.js";
import { getOrCreatePublicDeviceKey } from "../remote/device-key.js";
import { isRemoteUnlockEnabled } from "../remote/feature.js";
import {
  completeHubEnroll,
  type EnrollHubDeps,
  type EnrollOffer,
} from "../remote/enroll.js";

/**
 * Hidden preview commands for remote unlock (PR 1–2/7).
 * Feature is off by default — nothing listens until later PRs + ABRA_REMOTE_UNLOCK=1.
 */

const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;

export function cmdRemoteWhoami(opts: { base?: string } = {}): void {
  const pub = getOrCreatePublicDeviceKey({ base: opts.base ?? abraDir() });
  // Fingerprint only — never print private keys or raw key material.
  console.log(pub.fingerprint);
}

export interface RemoteEnrollDeps extends EnrollHubDeps {
  /**
   * Fetch a sealed enroll offer from the receiver peer.
   * Network wiring is PR 3; inject a loopback/in-process transport in tests.
   */
  fetchOffer: (peerNameOrId: string) => Promise<EnrollOffer>;
}

export function defaultRemoteEnrollDeps(): RemoteEnrollDeps {
  return {
    authenticate: (reason) => authenticate(reason),
    loadVault,
    updateVault: (mutator) => updateVault(mutator),
    now: () => Date.now(),
    log: (line) => console.log(green(`✓ ${line}`)),
    fetchOffer: async () => {
      throw new Error(
        "remote enroll network transport is not wired yet (PR 3) — use the loopback enroll harness in tests",
      );
    },
  };
}

/**
 * Hub: `abra remote enroll <peer>` — require feature flag, fetch sealed offer,
 * Touch ID, store unlockWrap. Never logs wrap keys or master-key material.
 */
export async function cmdRemoteEnroll(
  peerNameOrId: string,
  deps: RemoteEnrollDeps = defaultRemoteEnrollDeps(),
): Promise<void> {
  if (!isRemoteUnlockEnabled()) {
    throw new Error("remote unlock is disabled — set ABRA_REMOTE_UNLOCK=1 to enable enroll");
  }
  const offer = await deps.fetchOffer(peerNameOrId);
  const { peerName } = await completeHubEnroll(offer, peerNameOrId, deps);
  deps.log?.(`enrolled remote unlock for "${peerName}"`);
}

function fail(err: unknown): never {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(red(`✗ ${msg}`));
  process.exit(1);
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
        fail(err);
      }
    });

  remote
    .command("enroll <peer>", { hidden: true })
    .description(
      "Enroll a paired receiver for remote unlock (hub stores wrap key; requires ABRA_REMOTE_UNLOCK=1)",
    )
    .action(async (peer: string) => {
      try {
        await cmdRemoteEnroll(peer);
        process.exit(0);
      } catch (err) {
        fail(err);
      }
    });
}
