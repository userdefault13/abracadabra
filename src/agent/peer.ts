/**
 * Fail-closed peer authorization for sensitive agent ops.
 *
 * Linux: resolve the connecting peer via the accepted socket inode + `ss -xpn`
 * (iproute2 sock_diag / UNIX_DIAG_PEER), then allow only the abra CLI running
 * under the same node binary with a clean argv / NODE_OPTIONS.
 *
 * Non-Linux: reject unless a test-only `authorizePeer` override is supplied
 * (no /proc, no reliable equivalent without native addons).
 *
 * Why `ss` and not something cheaper:
 * - SO_PEERCRED would hand us the peer pid straight from the kernel, but Node
 *   exposes no getsockopt on net.Socket; it needs a native addon. Not used.
 * - /proc/net/unix lists each socket's inode but never its peer inode, so it
 *   cannot pair our accepted socket with the client end. Only sock_diag
 *   (UNIX_DIAG_PEER, i.e. netlink) can — hence ss, hence AF_NETLINK in the unit.
 * - `ss -p` builds its pid map by walking every /proc/<pid>/fd before applying
 *   any filter, so `ss -xpn src <path>` would not make the expensive part
 *   cheaper (and unix filters see only the server-side path). We run the full
 *   listing, with a generous timeout and a few retries under load.
 */
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type net from "node:net";

const execFileAsync = promisify(execFile);

const SS_CANDIDATES = ["/usr/bin/ss", "/usr/sbin/ss", "/bin/ss"] as const;
/** Per-attempt ss timeout. `-p` scans every /proc/<pid>/fd and spikes under load. */
export const SS_TIMEOUT_MS = 5000;
export const SS_MAX_ATTEMPTS = 3;
/** Sleep before attempt 2, 3, … */
export const SS_RETRY_BACKOFF_MS = [100, 300] as const;
/** Upper bound for the whole ss phase (all attempts + backoff). */
export const PEER_CHECK_BUDGET_MS = 12_000;

/** ss stderr when sock_diag is blocked (RestrictAddressFamilies / seccomp / LSM). */
const SS_NETLINK_STDERR =
  /Cannot open netlink socket|Operation not permitted|Address family not supported|EAFNOSUPPORT|EPERM/i;

export const SS_NETLINK_HINT =
  "ss could not use sock_diag (netlink). If abra-agent runs as a systemd unit, " +
  "set RestrictAddressFamilies=AF_UNIX AF_NETLINK, then: " +
  "systemctl --user daemon-reload && systemctl --user restart abra-agent";
export const SS_RETRY_HINT = "ss timed out (system load?) — retry: abra unlock";
export const SS_GENERIC_RETRY_HINT = "peer lookup via ss failed — retry: abra unlock";

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
  /** Return stdout of `ss -xpn` (injected in tests). Throw SsRunError to classify. */
  runSs?: (opts: { timeoutMs: number }) => Promise<string>;
  existsSync?: (p: string) => boolean;
  /** Backoff sleep between ss attempts (tests inject a no-op). */
  sleep?: (ms: number) => Promise<void>;
  /** Monotonic clock in ms (tests). */
  now?: () => number;
  /** Diagnostic log line sink. Never receives peer cmdline / env. */
  log?: (msg: string) => void;
}

export type SsFailureKind =
  | "timeout"
  | "exit"
  | "not_found"
  | "maxbuffer"
  | "spawn"
  | "netlink";

export class SsRunError extends Error {
  constructor(
    readonly kind: SsFailureKind,
    readonly exitCode: number | null = null,
  ) {
    super(`ss_failed:${kind}`);
    this.name = "SsRunError";
  }
}

/** Map an execFile rejection (or anything thrown by runSs) to a failure kind. */
export function classifySsError(err: unknown): SsRunError {
  if (err instanceof SsRunError) return err;
  const e = (err ?? {}) as {
    code?: unknown;
    killed?: boolean;
    signal?: unknown;
    stderr?: unknown;
  };
  if (e.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
    return new SsRunError("maxbuffer");
  }
  // execFile's timeout kills the child (killed=true, signal=SIGTERM).
  if (e.killed === true || e.code === "ETIMEDOUT") {
    return new SsRunError("timeout");
  }
  const stderr = typeof e.stderr === "string" ? e.stderr : "";
  if (stderr && SS_NETLINK_STDERR.test(stderr)) {
    return new SsRunError("netlink", typeof e.code === "number" ? e.code : null);
  }
  if (typeof e.code === "number") return new SsRunError("exit", e.code);
  if (e.code === "ENOENT") return new SsRunError("not_found");
  return new SsRunError("spawn");
}

/** `ss_failed:timeout`, `ss_failed:exit_1`, … */
export function ssFailureReason(err: SsRunError): string {
  if (err.kind === "exit" && err.exitCode !== null) {
    return `ss_failed:exit_${err.exitCode}`;
  }
  return `ss_failed:${err.kind}`;
}

function isRetryableSsError(err: SsRunError): boolean {
  // Missing binary / blocked netlink will not fix themselves in 300ms.
  return err.kind !== "not_found" && err.kind !== "netlink";
}

/**
 * Static, non-sensitive remediation text for a peer-check failure reason.
 * Uses only the agent's own node path + CLI entrypoint — never peer data.
 */
export function peerFailureHint(
  reason: string,
  agent: { execPath: string; cliEntrypoint: string },
): string | undefined {
  if (reason === "exe_mismatch") {
    return (
      `abra-agent runs under node ${agent.execPath}; the CLI must use the same node binary ` +
      `(a #!/usr/bin/env node shebang picks the first node on PATH). ` +
      `Rerun: ${agent.execPath} ${agent.cliEntrypoint} unlock`
    );
  }
  if (reason === "ss_failed:netlink" || reason === "ss_no_peer_info") {
    return SS_NETLINK_HINT;
  }
  if (reason === "ss_failed:timeout") return SS_RETRY_HINT;
  if (reason === "ss_failed:not_found") {
    return "ss (iproute2) not found in /usr/bin, /usr/sbin or /bin — install iproute2";
  }
  if (reason.startsWith("ss_failed") || reason.startsWith("peer_pid_unresolved")) {
    return SS_GENERIC_RETRY_HINT;
  }
  return undefined;
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
    // Multiple users:(...) groups, or several holders inside one group
    // (`users:(("a",pid=1,fd=3),("b",pid=2,fd=4))` — inherited / passed fd)
    // → ambiguous; drop pid.
    const userGroups = line.match(/users:\(/g);
    if (userGroups && userGroups.length > 1) pid = null;
    const pidFields = line.match(/[(,]pid=\d+/g);
    if (pidFields && pidFields.length > 1) pid = null;

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
  const r = resolvePeerFromSs(entries, localInode);
  return r.ok ? r.pid : null;
}

export type SsPeerResolution =
  | { ok: true; pid: number }
  | {
      ok: false;
      /** local_not_found / peer_not_found / peer_pid_missing may be a race. */
      detail:
        | "local_not_found"
        | "peer_not_found"
        | "peer_pid_missing"
        | "ambiguous";
      retryable: boolean;
    };

/**
 * Same as resolvePeerPidFromSs, but says why it failed. "Not visible yet"
 * outcomes are retryable (the client's row can lag the accept, or the fd
 * scan can miss a just-created fd); ambiguity never is.
 */
export function resolvePeerFromSs(
  entries: SsUnixEntry[],
  localInode: number,
): SsPeerResolution {
  const ours = entries.filter((e) => e.localInode === localInode);
  if (ours.length === 0) {
    return { ok: false, detail: "local_not_found", retryable: true };
  }
  if (ours.length !== 1) {
    return { ok: false, detail: "ambiguous", retryable: false };
  }
  const peerInode = ours[0].peerInode;
  if (peerInode === localInode) {
    return { ok: false, detail: "ambiguous", retryable: false };
  }

  const peers = entries.filter((e) => e.localInode === peerInode);
  if (peers.length === 0) {
    return { ok: false, detail: "peer_not_found", retryable: true };
  }
  if (peers.length !== 1) {
    return { ok: false, detail: "ambiguous", retryable: false };
  }
  const pid = peers[0].pid;
  if (pid === null || pid <= 0) {
    return { ok: false, detail: "peer_pid_missing", retryable: true };
  }

  // Pairing is uniquely determined by inode uniqueness above. Do not reject
  // when the same pid appears on other ESTAB rows (e.g. D-Bus / Secret Service).
  return { ok: true, pid };
}

/**
 * True when ss printed connected unix rows but none carry a peer inode — ss
 * fell back to /proc/net/unix because netlink (sock_diag) was unavailable.
 */
export function ssOutputLacksPeerInfo(stdout: string): boolean {
  let estab = 0;
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line.startsWith("u_str") || !/\bESTAB\b/.test(line)) continue;
    const beforeUsers = (line.split(/\susers:/)[0] ?? line).trimEnd();
    const m = beforeUsers.match(/(\d+)\s+\*\s+(\d+)\s*$/);
    if (!m) continue;
    estab++;
    if (Number(m[2]) > 0) return false;
  }
  return estab > 0;
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
 * - relative argv[1] is resolved against the peer's cwd (not the agent's) before
 *   realpath; missing peer cwd with a relative script → `peer_cwd_unreadable`
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
    /** Peer process cwd from `/proc/<pid>/cwd`; required when argv[1] is relative. */
    peerCwd?: string;
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

  let scriptAbs = scriptArg;
  if (!path.isAbsolute(scriptArg)) {
    if (!opts.peerCwd) {
      return { allowed: false, reason: "peer_cwd_unreadable" };
    }
    scriptAbs = path.resolve(opts.peerCwd, scriptArg);
  }

  let scriptReal: string;
  try {
    scriptReal = realpath(scriptAbs);
  } catch {
    return { allowed: false, reason: "script_realpath_failed" };
  }

  if (scriptReal !== opts.cliEntrypointRealpath) {
    return { allowed: false, reason: "argv_script_mismatch" };
  }

  return { allowed: true };
}

async function defaultRunSs(
  existsSync: (p: string) => boolean,
  timeoutMs: number,
): Promise<string> {
  let ssPath: string | null = null;
  for (const c of SS_CANDIDATES) {
    if (existsSync(c)) {
      ssPath = c;
      break;
    }
  }
  if (!ssPath) {
    throw new SsRunError("not_found");
  }
  try {
    const { stdout } = await execFileAsync(ssPath, ["-xpn"], {
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
      encoding: "utf8",
    });
    return typeof stdout === "string" ? stdout : String(stdout);
  } catch (e) {
    throw classifySsError(e);
  }
}

function defaultPeerLog(msg: string): void {
  process.stderr.write(`abra-agent: peer ${msg}\n`);
}

/**
 * Run ss until our socket's peer resolves to exactly one pid, or give up.
 * Each attempt is resolved from its own snapshot — retries never merge data
 * across snapshots, so a retry can only fail closed or find the same unique pid.
 */
async function resolvePeerPidWithRetry(
  localInode: number,
  deps: {
    runSs: (opts: { timeoutMs: number }) => Promise<string>;
    sleep: (ms: number) => Promise<void>;
    now: () => number;
    log: (msg: string) => void;
  },
): Promise<{ ok: true; pid: number } | { ok: false; reason: string }> {
  const deadline = deps.now() + PEER_CHECK_BUDGET_MS;
  let lastReason = "ss_failed:spawn";

  for (let attempt = 1; attempt <= SS_MAX_ATTEMPTS; attempt++) {
    if (attempt > 1) {
      const backoff =
        SS_RETRY_BACKOFF_MS[Math.min(attempt - 2, SS_RETRY_BACKOFF_MS.length - 1)];
      if (deps.now() + backoff >= deadline) break;
      await deps.sleep(backoff);
    }
    const timeoutMs = Math.min(SS_TIMEOUT_MS, deadline - deps.now());
    if (timeoutMs <= 0) break;

    let out: string;
    try {
      out = await deps.runSs({ timeoutMs });
    } catch (e) {
      const err = classifySsError(e);
      lastReason = ssFailureReason(err);
      deps.log(`${lastReason} attempt=${attempt}/${SS_MAX_ATTEMPTS}`);
      if (!isRetryableSsError(err)) return { ok: false, reason: lastReason };
      continue;
    }

    if (ssOutputLacksPeerInfo(out)) {
      deps.log(`ss_no_peer_info attempt=${attempt}/${SS_MAX_ATTEMPTS}`);
      return { ok: false, reason: "ss_no_peer_info" };
    }

    const r = resolvePeerFromSs(parseSsUnixXpn(out), localInode);
    if (r.ok) {
      if (attempt > 1) deps.log(`resolved attempt=${attempt}/${SS_MAX_ATTEMPTS}`);
      return r;
    }
    lastReason = `peer_pid_unresolved:${r.detail}`;
    deps.log(`${lastReason} attempt=${attempt}/${SS_MAX_ATTEMPTS}`);
    if (!r.retryable) return { ok: false, reason: lastReason };
  }
  return { ok: false, reason: lastReason };
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
  const runSs =
    deps.runSs ??
    ((o: { timeoutMs: number }) => defaultRunSs(existsSync, o.timeoutMs));
  const sleep =
    deps.sleep ??
    ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = deps.now ?? (() => performance.now());
  const log = deps.log ?? defaultPeerLog;

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

  const resolved = await resolvePeerPidWithRetry(inode, {
    runSs,
    sleep,
    now,
    log,
  });
  if (!resolved.ok) {
    return { ok: false, reason: resolved.reason };
  }
  const pid = resolved.pid;

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

  // Relative argv[1] must be resolved against the peer's cwd, not the agent's.
  // Otherwise a peer can run `node usr/lib/.../index.js` from an attacker cwd
  // that collides when realpath'd from the agent process.
  let peerCwd: string | undefined;
  try {
    peerCwd = readlinkSync(`/proc/${pid}/cwd`);
  } catch {
    peerCwd = undefined;
  }
  const scriptArg = argv[1];
  if (scriptArg && !path.isAbsolute(scriptArg) && peerCwd === undefined) {
    return { ok: false, reason: "peer_cwd_unreadable" };
  }

  const verdict = isAllowedAbraCliPeer({
    peerExeRealpath: peerExe,
    agentExecRealpath: agentExec,
    peerArgv: argv,
    cliEntrypointRealpath: cliEntrypoint,
    nodeOptions,
    peerCwd,
    realpathSync,
  });

  if (!verdict.allowed) {
    return { ok: false, reason: verdict.reason };
  }

  return { ok: true, pid, exe: peerExe };
}
