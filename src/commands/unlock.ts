import { promptHidden, isNoTerminalError, NoTerminalError } from "../core/prompt.js";
import {
  lockSession,
  isSessionUnlocked,
  platformInfo,
  authenticate,
} from "../platform/index.js";
import { resolveKeystoreBackend, resolveAuthBackend } from "../platform/env.js";
import { verifyVaultPassphrase } from "../platform/keystore-passphrase.js";
import { unlockSession } from "../platform/session.js";
import {
  shouldTryAgent,
  agentUnlockKey,
  AgentClientError,
  resolveAgentSocketPath,
} from "../agent/index.js";
import { abraDir } from "../core/paths.js";
import fs from "node:fs";

function nonPassphraseUnlockMessage(backend: string): string {
  return (
    `Keystore "${backend}" does not use abra unlock (OS credential store). ` +
    `If you migrated to passphrase-file, master.key.enc was not found in ${abraDir()}; ` +
    `set ABRA_DIR or ABRA_KEYSTORE=passphrase-file.`
  );
}

/**
 * Unlock the passphrase-file vault for this process, and push the master key
 * into abra-agent when reachable.
 *
 * Approval:
 * - When `resolveAuthBackend() === "passphrase"`, the unlock passphrase prompt
 *   IS the approval (single prompt; same verifyVaultPassphrase path incl. backoff).
 * - Otherwise authenticate() runs first (Touch ID / PolKit / password), then the
 *   vault passphrase is prompted separately.
 *
 * The agent never prompts — it only accepts `unlock.key` from the abra CLI peer.
 */
export async function cmdUnlock(): Promise<void> {
  const backend = resolveKeystoreBackend();
  if (backend !== "passphrase-file") {
    console.log(nonPassphraseUnlockMessage(backend));
    if (isSessionUnlocked()) lockSession();
    return;
  }

  const authBackend = resolveAuthBackend();
  if (authBackend !== "passphrase") {
    await authenticate(
      "abracadabra: unlock vault (passphrase-file) and load the key into abra-agent",
    );
  }

  let passphrase: string;
  try {
    passphrase = await promptHidden("Vault passphrase: ");
  } catch (err) {
    if (isNoTerminalError(err) || err instanceof NoTerminalError) {
      throw err instanceof NoTerminalError ? err : new NoTerminalError();
    }
    throw err;
  }
  if (!passphrase) {
    throw new Error("Empty passphrase");
  }

  // Shared verify path (#13): counts failures, resets on success.
  const key = verifyVaultPassphrase(passphrase);

  // Local session unlock (same effect as unlockPassphraseVault).
  unlockSession(key);

  let agentHoldsKey = false;
  if (shouldTryAgent()) {
    let socketPath: string | undefined;
    try {
      socketPath = resolveAgentSocketPath();
    } catch {
      socketPath = undefined;
    }
    if (socketPath && fs.existsSync(socketPath)) {
      try {
        await agentUnlockKey(key, { socketPath });
        agentHoldsKey = true;
      } catch (e) {
        const code = e instanceof AgentClientError ? e.code : "error";
        const msg = e instanceof Error ? e.message : String(e);
        console.error(`⚠ abra-agent unlock.key failed (${code}): ${msg}`);
        console.error(
          "  Local session is unlocked for this process; start/fix abra-agent and retry unlock to share the key.",
        );
      }
    }
  }

  key.fill(0);

  if (agentHoldsKey) {
    console.log(
      "✓ Vault unlocked (abra-agent holds the key: idle 15m, max 8h)",
    );
  } else {
    console.log(
      "✓ Vault unlocked for this process only — start abra-agent (systemctl --user start abra-agent) to keep it unlocked between commands",
    );
  }
}

/** Clear the local passphrase session. Agent lock is handled by the CLI wrapper. */
export function cmdLock(): void {
  lockSession();
  console.log("✓ Vault session locked");
}

export async function cmdUnlockStatus(): Promise<void> {
  const info = platformInfo();
  if (info.keystore !== "passphrase-file") {
    console.log(
      `unlock: not applicable (keystore=${info.keystore}). ` +
        `If you migrated to passphrase-file, master.key.enc was not found in ${abraDir()}; ` +
        `set ABRA_DIR or ABRA_KEYSTORE=passphrase-file.`,
    );
    return;
  }
  if (info.vaultLocked) {
    console.log("unlock: locked — run: abra unlock");
    process.exit(1);
  }
  console.log("unlock: session active");
}
