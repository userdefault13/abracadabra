/**
 * Linux: before prompting for the vault passphrase, re-exec once under the
 * agent's node binary when process.execPath's realpath differs — so unlock.key
 * peer checks pass without a second passphrase prompt.
 */
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { resolveAbraCliEntrypoint } from "../agent/peer.js";
import { agentStatus, shouldTryAgent, resolveAgentSocketPath } from "../agent/index.js";
import type { AgentStatusBody } from "../agent/protocol.js";

export const ABRA_REEXEC_ENV = "ABRA_REEXEC";

export type UnlockReexecDeps = {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  execPath?: string;
  argv?: string[];
  getuid?: () => number;
  /** Our package dist/index.js (pre-realpath). */
  entryPath?: string;
  realpathSync?: (p: string) => string;
  statSync?: (p: string) => fs.Stats;
  existsSync?: (p: string) => boolean;
  tryAgent?: () => boolean;
  resolveSocket?: () => string;
  status?: () => Promise<AgentStatusBody>;
  spawnSync?: (
    command: string,
    args: string[],
    opts: { stdio: "inherit"; env: NodeJS.ProcessEnv },
  ) => SpawnSyncReturns<Buffer>;
  exit?: (code: number) => never;
};

/**
 * True when `agentNode` is safe to exec: absolute path, regular file, owned by
 * current uid or root, not group/world-writable.
 */
export function isTrustedAgentNode(
  agentNode: string,
  deps: {
    getuid?: () => number;
    statSync?: (p: string) => fs.Stats;
  } = {},
): boolean {
  if (!path.isAbsolute(agentNode)) return false;
  const statSync = deps.statSync ?? ((p) => fs.statSync(p));
  let st: fs.Stats;
  try {
    st = statSync(agentNode);
  } catch {
    return false;
  }
  if (!st.isFile()) return false;
  const mode = st.mode;
  // group-writable or world-writable → reject
  if (mode & 0o022) return false;
  const getuid = deps.getuid ?? (() => {
    if (typeof process.getuid === "function") return process.getuid();
    return -1;
  });
  const uid = getuid();
  if (uid < 0) return false;
  // owner is self or root
  if (st.uid !== uid && st.uid !== 0) return false;
  return true;
}

/**
 * If needed, spawnSync the agent node + our entry + argv.slice(2) and exit.
 * No-op when already matching, not Linux, ABRA_REEXEC set, or validation fails.
 */
export async function maybeReexecForAgentNode(
  deps: UnlockReexecDeps = {},
): Promise<void> {
  const platform = deps.platform ?? process.platform;
  if (platform !== "linux") return;

  const env = deps.env ?? process.env;
  if (env[ABRA_REEXEC_ENV] === "1") return;

  if (!(deps.tryAgent ?? shouldTryAgent)()) return;

  const existsSync = deps.existsSync ?? ((p) => fs.existsSync(p));
  let socketPath: string | undefined;
  try {
    socketPath = (deps.resolveSocket ?? resolveAgentSocketPath)();
  } catch {
    return;
  }
  if (!socketPath || !existsSync(socketPath)) return;

  let st: AgentStatusBody;
  try {
    st = await (deps.status ?? (() => agentStatus({ socketPath })))();
  } catch {
    return;
  }

  const agentNodeRaw = st.nodePath;
  const agentEntryRaw = st.entryPath;
  if (typeof agentNodeRaw !== "string" || !agentNodeRaw) return;
  if (typeof agentEntryRaw !== "string" || !agentEntryRaw) return;

  const realpath = deps.realpathSync ?? ((p) => fs.realpathSync(p));
  let ourExec: string;
  let agentNode: string;
  let ourEntry: string;
  let agentEntry: string;
  try {
    ourExec = realpath(deps.execPath ?? process.execPath);
    agentNode = realpath(agentNodeRaw);
    ourEntry = realpath(deps.entryPath ?? resolveAbraCliEntrypoint());
    agentEntry = realpath(agentEntryRaw);
  } catch {
    return;
  }

  if (ourExec === agentNode) return;
  if (ourEntry !== agentEntry) return;

  if (!isTrustedAgentNode(agentNode, { getuid: deps.getuid, statSync: deps.statSync })) {
    return;
  }

  const argv = deps.argv ?? process.argv;
  const args = [ourEntry, ...argv.slice(2)];
  const childEnv = { ...env, [ABRA_REEXEC_ENV]: "1" };
  const spawn = deps.spawnSync ?? spawnSync;
  const result = spawn(agentNode, args, { stdio: "inherit", env: childEnv });
  const code =
    typeof result.status === "number"
      ? result.status
      : result.signal
        ? 1
        : 1;
  const exit = deps.exit ?? ((c: number) => process.exit(c));
  exit(code);
}
