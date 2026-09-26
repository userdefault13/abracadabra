import fs from "node:fs";
import {
  agentStatus,
  AgentClientError,
  resolveAgentSocketPath,
} from "../agent/index.js";
import type { AgentStatusBody } from "../agent/protocol.js";

export type AgentStatusState = "unlocked" | "locked" | "not_running";

export type AgentStatusCliOpts = {
  json?: boolean;
  wait?: boolean;
  /** Seconds; default 300 when --wait. 0 = wait forever. */
  timeout?: number;
};

export type AgentStatusCliDeps = {
  status?: () => Promise<AgentStatusBody>;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  resolveSocketPath?: () => string;
  existsSync?: (path: string) => boolean;
  log?: (msg: string) => void;
  /** Called instead of process.exit (tests). */
  exit?: (code: number) => void;
};

function msToSecondsLeft(ms: number | null): number {
  if (ms === null || !Number.isFinite(ms)) return 0;
  return Math.max(0, Math.ceil(ms / 1000));
}

export function formatAgentStatusLine(
  state: AgentStatusState,
  status: AgentStatusBody | null,
  socketPath: string,
): string {
  if (state === "not_running") {
    return `abra-agent: not running (${socketPath})`;
  }
  if (state === "locked" || !status || status.locked) {
    return "abra-agent: locked";
  }
  const idle = msToSecondsLeft(status.idleRemainingMs);
  const maxAge = msToSecondsLeft(status.maxAgeRemainingMs);
  return `abra-agent: unlocked (idle ${idle}s left, max-age ${maxAge}s left)`;
}

async function probeOnce(
  deps: AgentStatusCliDeps,
): Promise<{ state: AgentStatusState; status: AgentStatusBody | null; socketPath: string }> {
  const resolveSocket =
    deps.resolveSocketPath ?? (() => resolveAgentSocketPath());
  const exists = deps.existsSync ?? ((p: string) => fs.existsSync(p));
  let socketPath: string;
  try {
    socketPath = resolveSocket();
  } catch {
    socketPath = "(unavailable)";
    return { state: "not_running", status: null, socketPath };
  }
  if (!exists(socketPath)) {
    return { state: "not_running", status: null, socketPath };
  }

  const getStatus = deps.status ?? (() => agentStatus({ socketPath }));
  try {
    const status = await getStatus();
    if (status.locked) return { state: "locked", status, socketPath };
    return { state: "unlocked", status, socketPath };
  } catch (e) {
    if (
      e instanceof AgentClientError &&
      (e.code === "connect" || e.code === "timeout" || e.code === "unavailable")
    ) {
      return { state: "not_running", status: null, socketPath };
    }
    throw e;
  }
}

function exitCodeForState(state: AgentStatusState): number {
  if (state === "unlocked") return 0;
  if (state === "locked") return 1;
  return 2;
}

/**
 * `abra agent status` — non-secret agent probe (no peer check on status op).
 * Exit: 0 unlocked, 1 locked, 2 not running.
 * `--wait`: poll until unlocked (default timeout 300s; 0 = forever) → 0 / 1.
 */
export async function cmdAgentStatus(
  opts: AgentStatusCliOpts = {},
  deps: AgentStatusCliDeps = {},
): Promise<void> {
  const log = deps.log ?? ((msg: string) => console.log(msg));
  const exit = deps.exit ?? ((code: number) => process.exit(code));
  const sleep =
    deps.sleep ??
    ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = deps.now ?? (() => Date.now());

  if (opts.wait) {
    const timeoutSec = opts.timeout ?? 300;
    const deadline =
      timeoutSec <= 0 ? Number.POSITIVE_INFINITY : now() + timeoutSec * 1000;

    for (;;) {
      const { state, status, socketPath } = await probeOnce(deps);
      if (state === "unlocked") {
        if (opts.json) {
          log(
            JSON.stringify({
              state,
              locked: false,
              idleRemainingMs: status?.idleRemainingMs ?? null,
              maxAgeRemainingMs: status?.maxAgeRemainingMs ?? null,
              socketPath,
            }),
          );
        } else {
          log(formatAgentStatusLine(state, status, socketPath));
        }
        exit(0);
        return;
      }
      if (now() >= deadline) {
        if (opts.json) {
          log(
            JSON.stringify({
              state,
              locked: state === "locked",
              idleRemainingMs: status?.idleRemainingMs ?? null,
              maxAgeRemainingMs: status?.maxAgeRemainingMs ?? null,
              socketPath,
              timedOut: true,
            }),
          );
        } else {
          log(formatAgentStatusLine(state, status, socketPath));
        }
        exit(1);
        return;
      }
      await sleep(1000);
    }
  }

  const { state, status, socketPath } = await probeOnce(deps);
  if (opts.json) {
    log(
      JSON.stringify({
        state,
        locked: state === "locked" ? true : state === "unlocked" ? false : null,
        idleRemainingMs: status?.idleRemainingMs ?? null,
        maxAgeRemainingMs: status?.maxAgeRemainingMs ?? null,
        socketPath,
      }),
    );
  } else {
    log(formatAgentStatusLine(state, status, socketPath));
  }
  exit(exitCodeForState(state));
}
