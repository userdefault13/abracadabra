import fs from "node:fs";
import path from "node:path";

/** Default idle lock: 15 minutes. Override with ABRA_AGENT_IDLE_SECONDS. */
export const DEFAULT_IDLE_SECONDS = 15 * 60;

/**
 * Whether vault I/O should try the background agent.
 *
 * - `ABRA_AGENT=0` — always off
 * - `ABRA_AGENT=1` — opt-in (any platform; pair with `ABRA_AGENT_SOCKET` in tests)
 * - default — on only on Linux when `XDG_RUNTIME_DIR` is set
 */
export function isAgentEnabled(): boolean {
  const flag = process.env.ABRA_AGENT?.trim();
  if (flag === "0") return false;
  if (flag === "1") return true;
  return process.platform === "linux" && !!process.env.XDG_RUNTIME_DIR?.trim();
}

export function resolveIdleSeconds(): number {
  const raw = process.env.ABRA_AGENT_IDLE_SECONDS?.trim();
  if (!raw) return DEFAULT_IDLE_SECONDS;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_IDLE_SECONDS;
  return Math.floor(n);
}

/**
 * Socket path: `ABRA_AGENT_SOCKET` override, else `$XDG_RUNTIME_DIR/abra/agent.sock`.
 * Unix path length limits are ~104 (macOS) / ~108 (Linux) — keep temp dirs short.
 */
export function resolveAgentSocketPath(): string {
  const override = process.env.ABRA_AGENT_SOCKET?.trim();
  if (override) return path.resolve(override);
  const runtime = process.env.XDG_RUNTIME_DIR?.trim();
  if (!runtime) {
    throw new Error(
      "Agent socket path unset: set ABRA_AGENT_SOCKET or XDG_RUNTIME_DIR",
    );
  }
  return path.join(runtime, "abra", "agent.sock");
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
