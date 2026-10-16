import { AsyncLocalStorage } from "node:async_hooks";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { abraDir } from "./paths.js";

/**
 * Cross-process write lock for vault.enc — `<vault dir>/vault.lock`.
 *
 * - Acquire: exclusive create (`open(…, "wx")`), atomic on macOS, Linux and
 *   Windows. Content: {pid, hostname, createdAt, token}.
 * - Stale: holder pid is dead on this host (EPERM counts as alive), a pid of
 *   this process that no live holder here owns (pid reuse), or the lock is
 *   older than `maxHoldMs`. Stale locks are renamed to a unique name, the moved
 *   file's token is re-checked, and only then is it discarded — so two waiters
 *   that judged the same lock stale can't both break it and both win (the loser
 *   moves the winner's fresh lock, sees the token differ, and puts it back).
 * - Wait: exponential backoff with jitter up to `timeoutMs`, then
 *   VaultLockTimeoutError naming the holder pid + age.
 * - Release: only when the on-disk token is ours (same rename-and-verify dance),
 *   in `finally`, plus best-effort on process 'exit'. Signals that kill the
 *   process without 'exit' leave a lock that the dead-pid check breaks.
 * - Re-entrancy: re-entrant within one async call chain (AsyncLocalStorage), so
 *   nested withVaultLock/updateVault calls never deadlock. Independent async
 *   flows in the same process do NOT share the lock — they queue on the
 *   lockfile exactly like separate processes.
 * - A holder whose lock was broken (held past `maxHoldMs`) loses it:
 *   assertVaultLockHeld() re-reads the file before every vault.enc write and
 *   throws instead of writing.
 */

export const VAULT_LOCK_FILE = "vault.lock";
export const DEFAULT_LOCK_TIMEOUT_MS = 10_000;
export const DEFAULT_LOCK_MAX_HOLD_MS = 30_000;
const MIN_BACKOFF_MS = 5;
const MAX_BACKOFF_MS = 250;

export interface VaultLockInfo {
  pid: number;
  hostname: string;
  createdAt: number;
  token: string;
}

export interface VaultLockOptions {
  /** Directory holding vault.enc (the lockfile sits beside it). Default: abraDir(). */
  dir?: string;
  /** Give up waiting after this long. Default 10 s. */
  timeoutMs?: number;
  /** A lock older than this is stale and may be broken. Default 30 s. */
  maxHoldMs?: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  isPidAlive?: (pid: number) => boolean;
  hostname?: () => string;
  pid?: number;
}

export class VaultLockTimeoutError extends Error {
  constructor(
    readonly lockPath: string,
    readonly holder: VaultLockInfo | null,
    readonly ageMs: number | null,
  ) {
    const who = holder ? `pid ${holder.pid} on ${holder.hostname}` : "an unknown process";
    const age = ageMs === null ? "" : `, held for ${(ageMs / 1000).toFixed(1)}s`;
    super(
      `Timed out waiting for the vault write lock (${lockPath}) — held by ${who}${age}. ` +
        `Retry once that command finishes; if no abra process is running, delete the lock file.`,
    );
    this.name = "VaultLockTimeoutError";
  }
}

export class VaultLockNotHeldError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultLockNotHeldError";
  }
}

export function vaultLockPath(dir: string = abraDir()): string {
  return path.join(path.resolve(dir), VAULT_LOCK_FILE);
}

/** Lock path → token, for the current async call chain. */
const context = new AsyncLocalStorage<ReadonlyMap<string, string>>();
/** Every lock this process currently holds (token → lock path), for exit cleanup + pid-reuse checks. */
const heldHere = new Map<string, string>();
let exitHookInstalled = false;

export function defaultIsPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

interface Resolved {
  timeoutMs: number;
  maxHoldMs: number;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  isPidAlive: (pid: number) => boolean;
  hostname: string;
  pid: number;
}

function resolve(opts: VaultLockOptions): Resolved {
  return {
    timeoutMs: opts.timeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS,
    maxHoldMs: opts.maxHoldMs ?? DEFAULT_LOCK_MAX_HOLD_MS,
    now: opts.now ?? Date.now,
    sleep: opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))),
    isPidAlive: opts.isPidAlive ?? defaultIsPidAlive,
    hostname: (opts.hostname ?? os.hostname)(),
    pid: opts.pid ?? process.pid,
  };
}

interface Observed {
  /** null when the file is empty / mid-write / garbage. */
  info: VaultLockInfo | null;
  mtimeMs: number;
}

function parseInfo(raw: string): VaultLockInfo | null {
  try {
    const v = JSON.parse(raw) as Partial<VaultLockInfo>;
    if (
      Number.isInteger(v.pid) &&
      (v.pid as number) > 0 &&
      typeof v.hostname === "string" &&
      typeof v.createdAt === "number" &&
      typeof v.token === "string" &&
      v.token.length > 0
    ) {
      return v as VaultLockInfo;
    }
  } catch {
    /* partial write or garbage */
  }
  return null;
}

/** null = no lock file. Windows sharing errors while another process renames it read as "held, unknown". */
function readLock(file: string): Observed | null {
  try {
    const raw = fs.readFileSync(file, "utf8");
    let mtimeMs = Date.now();
    try {
      mtimeMs = fs.statSync(file).mtimeMs;
    } catch {
      /* raced with a rename */
    }
    return { info: parseInfo(raw), mtimeMs };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    if (code === "EPERM" || code === "EBUSY" || code === "EACCES") return { info: null, mtimeMs: Date.now() };
    throw err;
  }
}

export function readVaultLock(dir?: string): VaultLockInfo | null {
  return readLock(vaultLockPath(dir))?.info ?? null;
}

function tryCreate(file: string, info: VaultLockInfo): boolean {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  let fd: number;
  try {
    fd = fs.openSync(file, "wx", 0o600);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EEXIST") return false;
    // Windows: a lock file pending delete/rename refuses new handles.
    if (process.platform === "win32" && (code === "EPERM" || code === "EBUSY" || code === "EACCES")) return false;
    throw err;
  }
  try {
    fs.writeSync(fd, JSON.stringify(info));
  } catch (err) {
    fs.closeSync(fd);
    fs.rmSync(file, { force: true });
    throw err;
  }
  fs.closeSync(fd);
  return true;
}

function ageOf(o: Observed, now: number): number {
  return now - (o.info?.createdAt ?? o.mtimeMs);
}

function isStale(o: Observed, r: Resolved): boolean {
  if (ageOf(o, r.now()) > r.maxHoldMs) return true;
  const info = o.info;
  if (!info || info.hostname !== r.hostname) return false;
  if (info.pid === r.pid) return !heldHere.has(info.token);
  return !r.isPidAlive(info.pid);
}

function sameLock(a: Observed, b: Observed | null): boolean {
  if (!b) return false;
  if (a.info && b.info) return a.info.token === b.info.token;
  return !a.info && !b.info && a.mtimeMs === b.mtimeMs;
}

/**
 * Move the lock aside, and discard it only if it is the lock `expected`
 * describes; otherwise put it back (if the slot is still free).
 * Returns true when the expected lock was removed.
 */
function removeIfSame(file: string, expected: Observed): boolean {
  const grave = `${file}.${crypto.randomBytes(6).toString("hex")}.stale`;
  try {
    fs.renameSync(file, grave);
  } catch {
    return false; // gone already (ENOENT) or Windows sharing violation — caller retries
  }
  const moved = readLock(grave);
  if (sameLock(expected, moved)) {
    fs.rmSync(grave, { force: true });
    return true;
  }
  try {
    fs.linkSync(grave, file);
  } catch {
    try {
      if (!fs.existsSync(file)) fs.renameSync(grave, file);
    } catch {
      /* best effort */
    }
  }
  fs.rmSync(grave, { force: true });
  return false;
}

function releaseFile(file: string, token: string): boolean {
  const cur = readLock(file);
  if (!cur?.info || cur.info.token !== token) return false;
  return removeIfSame(file, cur);
}

/**
 * Release a lock only if `token` still owns it. Returns false (no-op) on a
 * token mismatch or when no lock exists.
 */
export function releaseVaultLock(token: string, dir?: string): boolean {
  heldHere.delete(token);
  return releaseFile(vaultLockPath(dir), token);
}

function installExitHook(): void {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  process.on("exit", () => {
    for (const [token, file] of heldHere) {
      try {
        releaseFile(file, token);
      } catch {
        /* best effort */
      }
    }
    heldHere.clear();
  });
}

/**
 * Acquire the lock file directly (no re-entrancy). Prefer withVaultLock; this
 * is exported for tests and for callers that must hand the token elsewhere.
 */
export async function acquireVaultLock(opts: VaultLockOptions = {}): Promise<VaultLockInfo> {
  const r = resolve(opts);
  const file = vaultLockPath(opts.dir);
  const deadline = r.now() + r.timeoutMs;
  let backoff = MIN_BACKOFF_MS;
  let vanished = 0;
  for (;;) {
    const info: VaultLockInfo = {
      pid: r.pid,
      hostname: r.hostname,
      createdAt: r.now(),
      token: crypto.randomBytes(16).toString("hex"),
    };
    if (tryCreate(file, info)) {
      heldHere.set(info.token, file);
      installExitHook();
      return info;
    }
    const holder = readLock(file);
    // Released between our create and read: retry at once, a few times.
    if (holder === null && vanished++ < 3) continue;
    if (holder && isStale(holder, r) && removeIfSame(file, holder)) continue;
    const now = r.now();
    if (now >= deadline) {
      throw new VaultLockTimeoutError(file, holder?.info ?? null, holder ? ageOf(holder, now) : null);
    }
    const jitter = Math.random() * backoff;
    await r.sleep(Math.min(backoff + jitter, deadline - now));
    backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
  }
}

/** Token of the lock held by the current async call chain, if any. */
export function currentVaultLockToken(dir?: string): string | undefined {
  return context.getStore()?.get(vaultLockPath(dir));
}

export function isVaultLockHeld(dir?: string): boolean {
  return currentVaultLockToken(dir) !== undefined;
}

/**
 * Throw unless the lock for `dir` is held — by the current async call chain,
 * or (agent side) by the client that sent `token` — and the on-disk lock still
 * carries that token.
 */
export function assertVaultLockHeld(dir?: string, token?: string): void {
  const file = vaultLockPath(dir);
  const mine = token ?? currentVaultLockToken(dir);
  if (!mine) {
    throw new VaultLockNotHeldError(
      `vault.enc write outside the vault lock (${file}) — use updateVault() or withVaultLock()`,
    );
  }
  const onDisk = readLock(file);
  if (onDisk?.info?.token !== mine) {
    throw new VaultLockNotHeldError(
      `lost the vault lock (${file}) — it was held past its max age and broken by another process; nothing written`,
    );
  }
}

/**
 * Run `fn` holding the vault write lock. Re-entrant within one async call
 * chain: a nested call just runs `fn`. Never hold it across prompts or network.
 */
export async function withVaultLock<T>(fn: () => Promise<T> | T, opts: VaultLockOptions = {}): Promise<T> {
  const file = vaultLockPath(opts.dir);
  const held = context.getStore();
  if (held?.has(file)) return fn();
  const info = await acquireVaultLock(opts);
  try {
    return await context.run(new Map(held ?? []).set(file, info.token), fn);
  } finally {
    heldHere.delete(info.token);
    releaseFile(file, info.token);
  }
}
