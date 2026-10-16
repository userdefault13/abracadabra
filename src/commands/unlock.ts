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
  agentStatus,
  agentUnlockKey,
  AgentClientError,
  resolveAgentSocketPath,
} from "../agent/index.js";
import fs from "node:fs";

/**
 * `abra unlock` exit code when the passphrase was correct but abra-agent did
 * not take the key (refused peer, timeout, mismatch, …). Distinct from 1
 * (wrong passphrase / generic error) so scripts and units can tell them apart.
 */
export const EXIT_AGENT_REFUSED = 3;

/**
 * Stderr lines for a failed unlock.key push. Static agent reason + hint only —
 * the agent never sends peer cmdline/env, and neither do we.
 */
export function formatAgentUnlockFailure(
  err: unknown,
  opts: { color?: boolean } = {},
): string[] {
  const red = (s: string) => (opts.color ? `\x1b[31m${s}\x1b[0m` : s);
  const code = err instanceof AgentClientError ? err.code : "error";
  const reason =
    err instanceof AgentClientError && err.reason ? err.reason : code;
  const hint = err instanceof AgentClientError ? err.hint : undefined;
  const msg = err instanceof Error ? err.message : String(err);

  const head =
    code === "forbidden_peer"
      ? `✗ abra-agent REFUSED unlock (reason: ${reason})`
      : `✗ abra-agent unlock FAILED (reason: ${reason}: ${msg})`;
  const lines = [
    red(
      `${head} — vault NOT shared with the agent; other processes/units will still see it locked.`,
    ),
  ];
  if (hint) lines.push(red(`  hint: ${hint}`));
  if (!hint || !/Rerun:|retry:/i.test(hint)) {
    lines.push(red("  Rerun: abra unlock   (after fixing the cause above)"));
  }
  lines.push(
    "  Passphrase was correct: this abra process alone was unlocked, and that ends when it exits.",
  );
  return lines;
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
    console.log(`Keystore "${backend}" does not use abra unlock (OS credential store).`);
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
  let agentError: unknown = null;
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
        agentError = e;
      }
    }
  }

  key.fill(0);

  if (agentError !== null) {
    // Never a ✓ here: the user would believe other processes/units are unlocked.
    const color = Boolean(process.stderr.isTTY) && !process.env.NO_COLOR;
    for (const line of formatAgentUnlockFailure(agentError, { color })) {
      console.error(line);
    }
    process.exitCode = EXIT_AGENT_REFUSED;
    return;
  }

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

export type UnlockState = "not-applicable" | "session" | "agent" | "locked";

/**
 * Whether vault I/O can proceed without a prompt: this process holds the key,
 * or abra-agent does. A fresh process (systemd ExecStartPre) never has its own
 * session, so the agent is what counts there.
 */
export async function resolveUnlockState(
  deps: {
    info?: () => { keystore: string; vaultLocked: boolean };
    tryAgent?: () => boolean;
    status?: () => Promise<{ locked: boolean }>;
  } = {},
): Promise<{ state: UnlockState; keystore: string }> {
  const info = (deps.info ?? platformInfo)();
  if (info.keystore !== "passphrase-file") return { state: "not-applicable", keystore: info.keystore };
  if (!info.vaultLocked) return { state: "session", keystore: info.keystore };
  if ((deps.tryAgent ?? shouldTryAgent)()) {
    try {
      const st = await (deps.status ?? agentStatus)();
      if (!st.locked) return { state: "agent", keystore: info.keystore };
    } catch {
      /* agent down → locked */
    }
  }
  return { state: "locked", keystore: info.keystore };
}

export async function cmdUnlockStatus(): Promise<void> {
  const { state, keystore } = await resolveUnlockState();
  if (state === "not-applicable") {
    console.log(`unlock: not applicable (keystore=${keystore})`);
    return;
  }
  if (state === "locked") {
    console.log("unlock: locked — run: abra unlock");
    process.exit(1);
  }
  console.log(state === "agent" ? "unlock: abra-agent holds the key" : "unlock: session active");
}
