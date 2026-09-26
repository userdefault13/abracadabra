import type { CallerIdentity } from "../core/caller-identity.js";
import { authenticate as platformAuthenticate } from "./index.js";
import { resolveAuthBackend } from "./env.js";
import { isNoTtyApprovalDenial } from "./auth-passphrase.js";
import {
  agentGrantCheck,
  AgentClientError,
  type AgentClientOpts,
} from "../agent/client.js";
import type { GrantCaller } from "../agent/grants.js";

export type RevealVia = "auth" | "grant";

export interface AuthorizeRevealResult {
  via: RevealVia;
  grantId?: string;
}

export interface AuthorizeRevealDeps {
  resolveAuthBackend?: () => string;
  authenticate?: (reason: string) => Promise<void>;
  isNoTtyDenial?: (err: unknown) => boolean;
  grantCheck?: (
    project: string,
    caller: GrantCaller,
    opts?: AgentClientOpts,
  ) => Promise<{ granted: boolean; grantId?: string; remainingMs?: number }>;
  agentOpts?: AgentClientOpts;
}

function grantHint(project: string, callerExe?: string | null): string {
  const exeHint = callerExe
    ? callerExe
    : "<exe path>";
  return (
    `abracadabra: approval denied — no terminal and no matching grant for this caller. ` +
    `Run on a terminal: abra grant --project ${project} --caller ${exeHint} --ttl <≤8h>` +
    (callerExe
      ? ` (detected caller: ${callerExe}). If the agent is locked, run: abra unlock`
      : `. If the agent is locked or unreachable, run: abra unlock`)
  );
}

/**
 * Gate secret reveals for MCP/API.
 *
 * Non-passphrase backends: authenticate() only (Touch ID / PolKit / …).
 * Passphrase backend: try authenticate(); on no-TTY denial, fall back to an
 * agent-held caller-bound grant. Other auth errors propagate (grants not consulted).
 * Payments/signing must NOT use this — they keep calling authenticate() directly.
 */
export async function authorizeReveal(opts: {
  reason: string;
  project: string;
  caller: () => Promise<CallerIdentity | null>;
  deps?: AuthorizeRevealDeps;
}): Promise<AuthorizeRevealResult> {
  const resolveBackend = opts.deps?.resolveAuthBackend ?? resolveAuthBackend;
  const auth = opts.deps?.authenticate ?? platformAuthenticate;
  const isNoTty = opts.deps?.isNoTtyDenial ?? isNoTtyApprovalDenial;
  const check =
    opts.deps?.grantCheck ??
    ((project: string, caller: GrantCaller, clientOpts?: AgentClientOpts) =>
      agentGrantCheck(project, caller, clientOpts));

  const backend = resolveBackend();
  if (backend !== "passphrase") {
    await auth(opts.reason);
    return { via: "auth" };
  }

  try {
    await auth(opts.reason);
    return { via: "auth" };
  } catch (err) {
    if (!isNoTty(err)) throw err;
  }

  // No TTY under passphrase — try a matching agent grant.
  let identity: CallerIdentity | null = null;
  try {
    identity = await opts.caller();
  } catch {
    identity = null;
  }

  if (!identity) {
    throw new Error(grantHint(opts.project, null));
  }

  try {
    const result = await check(
      opts.project,
      {
        exe: identity.exe,
        dev: identity.dev,
        ino: identity.ino,
      },
      opts.deps?.agentOpts,
    );
    if (result.granted) {
      return { via: "grant", grantId: result.grantId };
    }
  } catch (e) {
    const lockedOrDown =
      e instanceof AgentClientError &&
      (e.code === "locked" ||
        e.code === "connect" ||
        e.code === "timeout" ||
        e.code === "unavailable");
    if (lockedOrDown) {
      throw new Error(
        `${grantHint(opts.project, identity.exe)} (abra-agent locked or unreachable — run: abra unlock)`,
      );
    }
    // forbidden_peer / other → treat as no grant
  }

  throw new Error(grantHint(opts.project, identity.exe));
}
