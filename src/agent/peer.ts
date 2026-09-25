/**
 * Fail-closed peer authorization for sensitive agent ops.
 *
 * Linux: resolve the connecting peer via the accepted socket inode + `ss -xpn`
 * (iproute2 sock_diag / UNIX_DIAG_PEER), then allow only the abra CLI running
 * under the same node binary with a clean argv / NODE_OPTIONS.
 *
 * Non-Linux: reject unless a test-only `authorizePeer` override is supplied
 * (no /proc, no reliable equivalent without native addons).
 */
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type net from "node:net";

const execFileAsync = promisify(execFile);

const SS_CANDIDATES = ["/usr/bin/ss", "/usr/sbin/ss", "/bin/ss"] as const;
const SS_TIMEOUT_MS = 1500;

/** Node flags that can inject code or a debugger before the script runs. */
const DANGEROUS_NODE_FLAG =
  /^(?:--require|--import|--loader|--experimental-loader|--eval|--inspect(?:-brk|-port|-publish-uid)?(?:=|$)|-e|-r)$/;

const DANGEROUS_NODE_OPTIONS =
  /(?:^|\s)(--require|--import|--loader|--experimental-loader|--eval|--inspect(?:-brk|-port|-publish-uid)?(?:=|\s|$)|-e\b|-r\b)/;

export type PeerAuthOk = { ok: true; pid: number; exe: string };
export type PeerAuthFail = { ok: false; reason: string };
export type PeerAuthResult = PeerAuthOk | PeerAuthFail;

export interface SsUnixEntry {
  localInode: number;
  peerInode: number;
  /** Owning pid of this endpoint, if `users:(...)` present. */
  pid: number | null;
}

export interface PeerCheckDeps {
  platform?: NodeJS.Platform;
  /** Absolute path to the node binary this agent runs under. */
  execPath?: string;
  /** Absolute path to this package's CLI entry (`dist/index.js`). */
  cliEntrypoint?: string;
  getSocketFd?: (socket: net.Socket) => number | null;
  readlinkSync?: (p: string) => string;
  readFileSync?: (p: string) => Buffer;
  realpathSync?: (p: string) => string;
  /** Return stdout of `ss -xpn` (injected in tests). */
  runSs?: () => Promise<string>;
  existsSync?: (p: string) => boolean;
}

/** Resolve this package's `dist/index.js` from the agent module location. */
export function resolveAbraCliEntrypoint(
  fromUrl: string = import.meta.url,
): string {
  const here = path.dirname(fileURLToPath(fromUrl));
  return path.resolve(here, "..", "index.js");
}

export function getSocketFd(socket: net.Socket): number | null {
  const handle = (socket as unknown as { _handle?: { fd?: number } })._handle;
  if (!handle || typeof handle.fd !== "number" || handle.fd < 0) return null;
  return handle.fd;
}

/** Parse `socket:[12345]` from readlink `/proc/self/fd/<fd>`. */
export function parseSocketInode(readlinkTarget: string): number | null {
  const m = /^socket:\[(\d+)\]$/.exec(readlinkTarget.trim());
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/**
 * Parse `ss -xpn` unix ESTAB lines. Fail-closed: skip unparseable rows.
 *
 * Expected shape (iproute2):
 *   u_str ESTAB 0 0 /run/user/1000/abra/agent.sock 40321 * 40322 users:(("node",pid=1111,fd=20))
 *   u_str ESTAB 0 0 * 40322 * 40321 users:(("node",pid=2222,fd=3))
 *
 * The inode pair is the last `LOCAL_INODE * PEER_INODE` on the line (earlier
 * `0 * N` matches can hit Recv-Q/Send-Q columns when Local Address is `*`).
 */
export function parseSsUnixXpn(stdout: string): SsUnixEntry[] {
  const out: SsUnixEntry[] = [];
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("Netid")) continue;
    if (!line.startsWith("u_str")) continue;
    // Require ESTAB (connected). LISTEN rows have peer `*` without a peer inode pair.
    if (!/\bESTAB\b/.test(line)) continue;

    const beforeUsers = (line.split(/\susers:/)[0] ?? line).trimEnd();
    // Rightmost `LOCAL_INODE * PEER_INODE` only — earlier `0 * N` can match Send-Q
    // when Local Address is `*` (e.g. `ESTAB 0 0 * 40322 * 40321`).
    const inodePair = beforeUsers.match(/(\d+)\s+\*\s+(\d+)\s*$/);
    if (!inodePair) continue;
    const localInode = Number(inodePair[1]);
    const peerInode = Number(inodePair[2]);
    if (
      !Number.isSafeInteger(localInode) ||
      !Number.isSafeInteger(peerInode) ||
      localInode <= 0 ||
      peerInode <= 0
    ) {
      continue;
    }

    let pid: number | null = null;
    const usersMatch = line.match(
      /users:\(\("(?:[^"\\]|\\.)*",pid=(\d+),fd=\d+\)/,
    );
    if (usersMatch) {
      const p = Number(usersMatch[1]);
      if (Number.isSafeInteger(p) && p > 0) pid = p;
    }
    // Multiple users:(...) groups on one line → ambiguous; drop pid.
    const userGroups = line.match(/users:\(/g);
    if (userGroups && userGroups.length > 1) pid = null;

    out.push({ localInode, peerInode, pid });
  }
  return out;
}

/**
 * Given our accepted-socket local inode, find the unique peer pid.
 * Any ambiguity or missing data → null (caller rejects).
 */
export function resolvePeerPidFromSs(
  entries: SsUnixEntry[],
  localInode: number,
): number | null {
  const ours = entries.filter((e) => e.localInode === localInode);
  if (ours.length !== 1) return null;
  const peerInode = ours[0].peerInode;
  if (peerInode === localInode) return null;

  const peers = entries.filter((e) => e.localInode === peerInode);
  if (peers.length !== 1) return null;
  const pid = peers[0].pid;
  if (pid === null || pid <= 0) return null;

  // Ambiguity: another row also claims this pid for a different pairing.
  const samePid = entries.filter((e) => e.pid === pid);
  if (samePid.length !== 1) return null;

  return pid;
}

export function parseProcCmdline(buf: Buffer): string[] {
  const parts: string[] = [];
  let start = 0;
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0) {
      if (i > start) parts.push(buf.subarray(start, i).toString("utf8"));
      start = i + 1;
    }
  }
  if (start < buf.length) {
    parts.push(buf.subarray(start).toString("utf8"));
  }
  return parts.filter((s) => s.length > 0);
}

export function parseProcEnviron(buf: Buffer): Map<string, string> {
  const map = new Map<string, string>();
  const text = buf.toString("utf8");
  for (const entry of text.split("\0")) {
    if (!entry) continue;
    const eq = entry.indexOf("=");
    if (eq <= 0) continue;
    map.set(entry.slice(0, eq), entry.slice(eq + 1));
  }
  return map;
}

/** True when argv has dangerous node flags before the script path at scriptIndex. */
export function argvHasDangerousFlagsBeforeScript(
  argv: string[],
  scriptIndex: number,
): boolean {
  // argv[0] is the node binary (or symlink name); flags live in (0, scriptIndex).
  for (let i = 1; i < scriptIndex; i++) {
    const a = argv[i];
    if (!a) continue;
    const flag = a.includes("=") ? a.slice(0, a.indexOf("=") + 1).replace(/=$/, "") : a;
    // Normalize: check full token and token before '='
    const base = a.startsWith("-") ? a.split("=")[0] : a;
    if (DANGEROUS_NODE_FLAG.test(base) || DANGEROUS_NODE_FLAG.test(flag)) {
      return true;
    }
    // `--require=foo` / `-r=foo` already covered; also bare `--inspect=9229`
    if (
      base.startsWith("--inspect") ||
      base === "--require" ||
      base === "--import" ||
      base === "--loader" ||
      base === "--experimental-loader" ||
      base === "--eval" ||
      base === "-e" ||
      base === "-r"
    ) {
      return true;
    }
  }
  return false;
}

export function nodeOptionsAreDangerous(nodeOptions: string | undefined): boolean {
  if (!nodeOptions || !nodeOptions.trim()) return false;
  return DANGEROUS_NODE_OPTIONS.test(nodeOptions);
}

/**
 * Allow when:
 * - peer exe realpath == agent execPath realpath (same node binary)
 * - peer argv[1] realpath == this package's dist/index.js (Node puts the script
 *   at argv[1] for both `node dist/index.js` and shebang `abra`; an installed
 *   `abra` bin that realpaths to the same file is therefore allowed)
 * - no node flags before the script (argv[1] must not start with `-`)
 * - NODE_OPTIONS contains none of the dangerous inject/debug flags
 */
export function isAllowedAbraCliPeer(
  opts: {
    peerExeRealpath: string;
    agentExecRealpath: string;
    peerArgv: string[];
    cliEntrypointRealpath: string;
    nodeOptions?: string;
    realpathSync?: (p: string) => string;
  },
): { allowed: true } | { allowed: false; reason: string } {
  const realpath = opts.realpathSync ?? ((p: string) => fs.realpathSync(p));

  if (opts.peerExeRealpath !== opts.agentExecRealpath) {
    return { allowed: false, reason: "exe_mismatch" };
  }
  if (nodeOptionsAreDangerous(opts.nodeOptions)) {
    return { allowed: false, reason: "dangerous_node_options" };
  }
  if (opts.peerArgv.length < 2) {
    return { allowed: false, reason: "argv_too_short" };
  }

  // Any flag before the script shifts it off argv[1] — reject.
  if (argvHasDangerousFlagsBeforeScript(opts.peerArgv, /* scriptIndex */ 1)) {
    return { allowed: false, reason: "node_flags_in_argv" };
  }

  const scriptArg = opts.peerArgv[1];
  if (!scriptArg || scriptArg.startsWith("-")) {
    return { allowed: false, reason: "node_flags_in_argv" };
  }

  let scriptReal: string;
  try {
    scriptReal = realpath(scriptArg);
  } catch {
    return { allowed: false, reason: "script_realpath_failed" };
  }

  if (scriptReal !== opts.cliEntrypointRealpath) {
    return { allowed: false, reason: "argv_script_mismatch" };
  }

  return { allowed: true };
}

async function defaultRunSs(existsSync: (p: string) => boolean): Promise<string> {
  let ssPath: string | null = null;
  for (const c of SS_CANDIDATES) {
    if (existsSync(c)) {
      ssPath = c;
      break;
    }
  }
  if (!ssPath) {
    throw new Error("ss_not_found");
  }
  const { stdout } = await execFileAsync(ssPath, ["-xpn"], {
    timeout: SS_TIMEOUT_MS,
    maxBuffer: 4 * 1024 * 1024,
    encoding: "utf8",
  });
  return typeof stdout === "string" ? stdout : String(stdout);
}

/**
 * Authorize the process on the other end of `socket` for sensitive ops.
 * Always fail-closed on ambiguity, missing tools, or non-Linux (unless overridden).
 */
export async function authorizePeer(
  socket: net.Socket,
  deps: PeerCheckDeps = {},
): Promise<PeerAuthResult> {
  const platform = deps.platform ?? process.platform;
  if (platform !== "linux") {
    return { ok: false, reason: "peer_check_linux_only" };
  }

  const readlinkSync = deps.readlinkSync ?? ((p: string) => fs.readlinkSync(p));
  const readFileSync = deps.readFileSync ?? ((p: string) => fs.readFileSync(p));
  const realpathSync = deps.realpathSync ?? ((p: string) => fs.realpathSync(p));
  const existsSync = deps.existsSync ?? ((p: string) => fs.existsSync(p));
  const getFd = deps.getSocketFd ?? getSocketFd;
  const runSs = deps.runSs ?? (() => defaultRunSs(existsSync));

  const fd = getFd(socket);
  if (fd === null) {
    return { ok: false, reason: "no_socket_fd" };
  }

  let inode: number | null = null;
  try {
    inode = parseSocketInode(readlinkSync(`/proc/self/fd/${fd}`));
  } catch {
    return { ok: false, reason: "fd_readlink_failed" };
  }
  if (inode === null) {
    return { ok: false, reason: "bad_socket_inode" };
  }

  let ssOut: string;
  try {
    ssOut = await runSs();
  } catch {
    return { ok: false, reason: "ss_failed" };
  }

  const entries = parseSsUnixXpn(ssOut);
  const pid = resolvePeerPidFromSs(entries, inode);
  if (pid === null) {
    return { ok: false, reason: "peer_pid_unresolved" };
  }

  let peerExe: string;
  try {
    peerExe = realpathSync(`/proc/${pid}/exe`);
  } catch {
    return { ok: false, reason: "exe_read_failed" };
  }

  let agentExec: string;
  try {
    agentExec = realpathSync(deps.execPath ?? process.execPath);
  } catch {
    return { ok: false, reason: "agent_exec_realpath_failed" };
  }

  let cliEntrypoint: string;
  try {
    cliEntrypoint = realpathSync(
      deps.cliEntrypoint ?? resolveAbraCliEntrypoint(),
    );
  } catch {
    return { ok: false, reason: "cli_entrypoint_realpath_failed" };
  }

  let argv: string[];
  try {
    argv = parseProcCmdline(readFileSync(`/proc/${pid}/cmdline`));
  } catch {
    return { ok: false, reason: "cmdline_read_failed" };
  }

  let nodeOptions: string | undefined;
  try {
    const env = parseProcEnviron(readFileSync(`/proc/${pid}/environ`));
    nodeOptions = env.get("NODE_OPTIONS");
  } catch {
    return { ok: false, reason: "environ_read_failed" };
  }

  const verdict = isAllowedAbraCliPeer({
    peerExeRealpath: peerExe,
    agentExecRealpath: agentExec,
    peerArgv: argv,
    cliEntrypointRealpath: cliEntrypoint,
    nodeOptions,
    realpathSync,
  });

  if (!verdict.allowed) {
    return { ok: false, reason: verdict.reason };
  }

  return { ok: true, pid, exe: peerExe };
}
