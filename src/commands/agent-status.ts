import fs from "node:fs";
import {
  agentStatus,
  AgentClientError,
  resolveAgentSocketPath,
  resolveAgentRuntimeBase,
  formatAgentSocketVia,
  type AgentRuntimeSource,
  type AgentPathDeps,
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
  resolveRuntimeBase?: () => {
    source: AgentRuntimeSource;
    reason: string;
  };
  pathDeps?: AgentPathDeps;
  existsSync?: (path: string) => boolean;
  log?: (msg: string) => void;
  /** Called instead of process.exit (tests). */
  exit?: (code: number) => void;
};

function msToSecondsLeft(ms: number | null): number {
  if (ms === null || !Number.isFinite(ms)) return 0;
  return Math.max(0, Math.ceil(ms / 1000));
}

function socketAnnotation(
  socketPath: string,
  source: AgentRuntimeSource,
  reason: string,
): string {
  return `socket ${socketPath} ${formatAgentSocketVia(source, reason)}`;
}

export function formatAgentStatusLine(
  state: AgentStatusState,
  status: AgentStatusBody | null,
  socketPath: string,
  source: AgentRuntimeSource = "none",
  reason = "",
): string {
  const sock = socketAnnotation(socketPath, source, reason);
  if (state === "not_running") {
    return `abra-agent: not running (${sock})`;
  }
  if (state === "locked" || !status || status.locked) {
    return `abra-agent: locked (${sock})`;
  }
  const idle = msToSecondsLeft(status.idleRemainingMs);
  const maxAge = msToSecondsLeft(status.maxAgeRemainingMs);
  return `abra-agent: unlocked (idle ${idle}s left, max-age ${maxAge}s left; ${sock})`;
}

type ProbeResult = {
  state: AgentStatusState;
  status: AgentStatusBody | null;
  socketPath: string;
  socketSource: AgentRuntimeSource;
  socketReason: string;
};

/**
 * One-shot agent probe (no secrets). Errors / missing socket → `not_running`.
 * Used by `abra agent status` and `abra doctor`.
 */
export async function probeAgentStatusState(
  deps: AgentStatusCliDeps = {},
): Promise<AgentStatusState> {
  try {
    const { state } = await probeOnce(deps);
    return state;
  } catch {
    return "not_running";
  }
}

async function probeOnce(deps: AgentStatusCliDeps): Promise<ProbeResult> {
  const runtime =
    deps.resolveRuntimeBase?.() ?? resolveAgentRuntimeBase(deps.pathDeps);
  const socketSource = runtime.source;
  const socketReason = runtime.reason;

  const resolveSocket =
    deps.resolveSocketPath ??
    (() => resolveAgentSocketPath(deps.pathDeps));
  const exists = deps.existsSync ?? ((p: string) => fs.existsSync(p));
  let socketPath: string;
  try {
    socketPath = resolveSocket();
  } catch {
    socketPath = "(unavailable)";
    return {
      state: "not_running",
      status: null,
      socketPath,
      socketSource,
      socketReason,
    };
  }
  if (!exists(socketPath)) {
    return {
      state: "not_running",
      status: null,
      socketPath,
      socketSource,
      socketReason,
    };
  }

  const getStatus = deps.status ?? (() => agentStatus({ socketPath }));
  try {
    const status = await getStatus();
    if (status.locked) {
      return {
        state: "locked",
        status,
        socketPath,
        socketSource,
        socketReason,
      };
    }
    return {
      state: "unlocked",
      status,
      socketPath,
      socketSource,
      socketReason,
    };
  } catch (e) {
    if (
      e instanceof AgentClientError &&
      (e.code === "connect" || e.code === "timeout" || e.code === "unavailable")
    ) {
      return {
        state: "not_running",
        status: null,
        socketPath,
        socketSource,
        socketReason,
      };
    }
    throw e;
  }
}

function exitCodeForState(state: AgentStatusState): number {
  if (state === "unlocked") return 0;
  if (state === "locked") return 1;
  return 2;
}

function jsonPayload(
  state: AgentStatusState,
  status: AgentStatusBody | null,
  socketPath: string,
  socketSource: AgentRuntimeSource,
  socketReason: string,
  extra?: Record<string, unknown>,
): string {
  return JSON.stringify({
    state,
    locked: state === "locked" ? true : state === "unlocked" ? false : null,
    idleRemainingMs: status?.idleRemainingMs ?? null,
    maxAgeRemainingMs: status?.maxAgeRemainingMs ?? null,
    socketPath,
    socketSource,
    socketReason,
    ...extra,
  });
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
      const { state, status, socketPath, socketSource, socketReason } =
        await probeOnce(deps);
      if (state === "unlocked") {
        if (opts.json) {
          log(
            jsonPayload(state, status, socketPath, socketSource, socketReason),
          );
        } else {
          log(
            formatAgentStatusLine(
              state,
              status,
              socketPath,
              socketSource,
              socketReason,
            ),
          );
        }
        exit(0);
        return;
      }
      if (now() >= deadline) {
        if (opts.json) {
          log(
            jsonPayload(state, status, socketPath, socketSource, socketReason, {
              timedOut: true,
            }),
          );
        } else {
          log(
            formatAgentStatusLine(
              state,
              status,
              socketPath,
              socketSource,
              socketReason,
            ),
          );
        }
        exit(1);
        return;
      }
      await sleep(1000);
    }
  }

  const { state, status, socketPath, socketSource, socketReason } =
    await probeOnce(deps);
  if (opts.json) {
    log(jsonPayload(state, status, socketPath, socketSource, socketReason));
  } else {
    log(
      formatAgentStatusLine(
        state,
        status,
        socketPath,
        socketSource,
        socketReason,
      ),
    );
  }
  exit(exitCodeForState(state));
}
