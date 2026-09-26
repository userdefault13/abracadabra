import fs from "node:fs";
import path from "node:path";

/** Default idle lock: 15 minutes. Override with ABRA_AGENT_IDLE_SECONDS. */
export const DEFAULT_IDLE_SECONDS = 15 * 60;

/** Absolute max unlock age: 8 hours (hard ceiling). Override with ABRA_AGENT_MAX_AGE_SECONDS. */
export const DEFAULT_MAX_AGE_SECONDS = 8 * 60 * 60;

export type AgentRuntimeSource =
  | "ABRA_AGENT_SOCKET"
  | "XDG_RUNTIME_DIR"
  | "run-user-fallback"
  | "none";

export type AgentRuntimeBase = {
  dir: string | null;
  source: AgentRuntimeSource;
  reason: string;
};

/** Injectable deps for hermetic tests (no real fs / getuid). */
export type AgentPathDeps = {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  getuid?: () => number | undefined;
  lstatSync?: (p: string) => fs.Stats;
};

function readEnv(deps?: AgentPathDeps): NodeJS.ProcessEnv {
  return deps?.env ?? process.env;
}

function readPlatform(deps?: AgentPathDeps): NodeJS.Platform {
  return deps?.platform ?? process.platform;
}

function readUid(deps?: AgentPathDeps): number | undefined {
  if (deps?.getuid) return deps.getuid();
  return process.getuid?.();
}

function readLstat(deps?: AgentPathDeps): (p: string) => fs.Stats {
  return deps?.lstatSync ?? ((p) => fs.lstatSync(p));
}

/**
 * XDG_RUNTIME_DIR or a validated `/run/user/<uid>` fallback (Linux only).
 * Does not consider `ABRA_AGENT_SOCKET` — that is layered in
 * `resolveAgentRuntimeBase` / `resolveAgentSocketPath`.
 */
function resolveXdgOrRunUser(deps?: AgentPathDeps): AgentRuntimeBase {
  const env = readEnv(deps);
  const platform = readPlatform(deps);
  const xdg = env.XDG_RUNTIME_DIR?.trim();
  if (xdg) {
    return {
      dir: xdg,
      source: "XDG_RUNTIME_DIR",
      reason: "XDG_RUNTIME_DIR set",
    };
  }

  if (platform !== "linux") {
    return {
      dir: null,
      source: "none",
      reason: "XDG_RUNTIME_DIR unset",
    };
  }

  const uid = readUid(deps);
  if (uid === undefined) {
    return {
      dir: null,
      source: "none",
      reason: "getuid unavailable",
    };
  }

  const candidate = path.posix.join("/run/user", String(uid));
  const lstat = readLstat(deps);
  let st: fs.Stats;
  try {
    st = lstat(candidate);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === "ENOENT") {
      return { dir: null, source: "none", reason: "missing" };
    }
    return {
      dir: null,
      source: "none",
      reason: err.code ? `lstat ${err.code}` : "missing",
    };
  }

  if (st.isSymbolicLink()) {
    return { dir: null, source: "none", reason: "symlink" };
  }
  if (!st.isDirectory()) {
    return { dir: null, source: "none", reason: "not a directory" };
  }
  if (st.uid !== uid) {
    return {
      dir: null,
      source: "none",
      reason: `owner uid ${st.uid} != ${uid}`,
    };
  }
  const mode = st.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    return {
      dir: null,
      source: "none",
      reason: `mode 0o${mode.toString(8)} has group/other bits`,
    };
  }

  return {
    dir: candidate,
    source: "run-user-fallback",
    reason: "XDG_RUNTIME_DIR unset",
  };
}

/**
 * Resolve the agent runtime base directory and how it was chosen.
 *
 * - `ABRA_AGENT_SOCKET` set → source override (dir = dirname of resolved socket)
 * - else `XDG_RUNTIME_DIR` (non-empty trimmed) → use it
 * - else Linux only: accept `/run/user/<uid>` when it is a real directory,
 *   owned by uid, not a symlink, and mode has no group/other bits (0700)
 * - else none
 */
export function resolveAgentRuntimeBase(deps?: AgentPathDeps): AgentRuntimeBase {
  const env = readEnv(deps);
  const override = env.ABRA_AGENT_SOCKET?.trim();
  if (override) {
    return {
      dir: path.dirname(path.resolve(override)),
      source: "ABRA_AGENT_SOCKET",
      reason: "ABRA_AGENT_SOCKET set",
    };
  }
  return resolveXdgOrRunUser(deps);
}

/**
 * Whether vault I/O should try the background agent.
 *
 * - `ABRA_AGENT=0` — always off
 * - win32 — always off (unsupported: no POSIX uid/modes; unix sockets differ)
 * - `ABRA_AGENT=1` — opt-in on darwin/linux (pair with `ABRA_AGENT_SOCKET` in tests)
 * - default — on only on Linux when `XDG_RUNTIME_DIR` is set or a valid
 *   `/run/user/<uid>` fallback resolves (`ABRA_AGENT_SOCKET` alone does not enable)
 */
export function isAgentEnabled(deps?: AgentPathDeps): boolean {
  const env = readEnv(deps);
  const platform = readPlatform(deps);
  const flag = env.ABRA_AGENT?.trim();
  if (flag === "0") return false;
  if (platform === "win32") return false;
  if (flag === "1") return true;
  if (platform !== "linux") return false;
  // Default enablement ignores ABRA_AGENT_SOCKET (path override ≠ opt-in).
  return resolveXdgOrRunUser(deps).dir != null;
}

export function resolveIdleSeconds(): number {
  const raw = process.env.ABRA_AGENT_IDLE_SECONDS?.trim();
  if (!raw) return DEFAULT_IDLE_SECONDS;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_IDLE_SECONDS;
  return Math.floor(n);
}

/**
 * Absolute unlock lifetime (seconds). Invalid → default 8h.
 * Values above 8h are clamped to 8h. Activity does not extend this.
 */
export function resolveMaxAgeSeconds(): number {
  const raw = process.env.ABRA_AGENT_MAX_AGE_SECONDS?.trim();
  if (!raw) return DEFAULT_MAX_AGE_SECONDS;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_MAX_AGE_SECONDS;
  return Math.min(DEFAULT_MAX_AGE_SECONDS, Math.floor(n));
}

/**
 * Socket path: `ABRA_AGENT_SOCKET` override, else `$runtime/abra/agent.sock`
 * where runtime is `XDG_RUNTIME_DIR` or a validated `/run/user/<uid>` fallback.
 */
export function resolveAgentSocketPath(deps?: AgentPathDeps): string {
  const env = readEnv(deps);
  const override = env.ABRA_AGENT_SOCKET?.trim();
  if (override) return path.resolve(override);

  const base = resolveXdgOrRunUser(deps);
  if (!base.dir) {
    throw new Error(
      `Agent socket path unset: set ABRA_AGENT_SOCKET or XDG_RUNTIME_DIR, or ensure /run/user/<uid> is a 0700 directory owned by you (${base.reason})`,
    );
  }
  return path.posix.join(base.dir, "abra", "agent.sock");
}

export function agentRuntimeDir(socketPath: string): string {
  return path.dirname(socketPath);
}

/**
 * Ensure the runtime directory exists with mode 0700 and is owned by us.
 * Refuses symlinks and dirs with group/other bits.
 */
export function ensureAgentRuntimeDir(dir: string, uid = process.getuid?.()): void {
  if (uid === undefined) {
    throw new Error("Agent requires a POSIX uid (process.getuid)");
  }

  let st: fs.Stats;
  try {
    st = fs.lstatSync(dir);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code !== "ENOENT") throw e;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    st = fs.lstatSync(dir);
  }

  if (st.isSymbolicLink()) {
    throw new Error(`Agent runtime dir must not be a symlink: ${dir}`);
  }
  if (!st.isDirectory()) {
    throw new Error(`Agent runtime path is not a directory: ${dir}`);
  }
  if (st.uid !== uid) {
    throw new Error(
      `Agent runtime dir owner mismatch (uid ${st.uid} != ${uid}): ${dir}`,
    );
  }
  const mode = st.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(
      `Agent runtime dir must be mode 0700 (got 0o${mode.toString(8)}): ${dir}`,
    );
  }
}

/** Short temp dir under /tmp for tests (avoids macOS socket path length limits). */
export function mkAgentTestDir(prefix = "abra-ag-"): string {
  return fs.mkdtempSync(path.join("/tmp", prefix));
}

/** Human-readable "via …" clause for status / doctor lines. */
export function formatAgentSocketVia(
  source: AgentRuntimeSource,
  reason: string,
): string {
  switch (source) {
    case "ABRA_AGENT_SOCKET":
      return `via ABRA_AGENT_SOCKET: ${reason}`;
    case "XDG_RUNTIME_DIR":
      return `via XDG_RUNTIME_DIR: ${reason}`;
    case "run-user-fallback":
      return `via /run/user/<uid> fallback: ${reason}`;
    case "none":
      return reason;
  }
}
