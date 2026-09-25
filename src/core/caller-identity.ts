import fs from "node:fs";
import path from "node:path";

/** Real caller binary identity: absolute exe path + inode (dev, ino). */
export interface CallerIdentity {
  exe: string;
  dev: number;
  ino: number;
}

export interface CallerIdentityFs {
  readlink(target: string): string | Promise<string>;
  realpath(target: string): string | Promise<string>;
  stat(target: string): { dev: number; ino: number } | Promise<{ dev: number; ino: number }>;
}

async function asPromise<T>(v: T | Promise<T>): Promise<T> {
  return v;
}

const defaultFs: CallerIdentityFs = {
  readlink: (p) => fs.readlinkSync(p),
  realpath: (p) => fs.realpathSync(p),
  stat: (p) => {
    const s = fs.statSync(p);
    return { dev: s.dev, ino: s.ino };
  },
};

/**
 * Resolve the real executable identity for a Linux process via /proc.
 * Returns null on any failure, non-Linux, or if the exe link is "(deleted)".
 */
export async function identityForPid(
  pid: number,
  deps?: {
    platform?: NodeJS.Platform;
    fs?: CallerIdentityFs;
  },
): Promise<CallerIdentity | null> {
  const platform = deps?.platform ?? process.platform;
  if (platform !== "linux") return null;
  if (!Number.isInteger(pid) || pid <= 0) return null;

  const io = deps?.fs ?? defaultFs;
  try {
    const linkPath = path.posix.join("/proc", String(pid), "exe");
    const target = await asPromise(io.readlink(linkPath));
    if (typeof target !== "string" || !target) return null;
    if (target.endsWith(" (deleted)")) return null;
    const exe = await asPromise(io.realpath(target));
    if (typeof exe !== "string" || !exe) return null;
    const st = await asPromise(io.stat(exe));
    if (
      typeof st?.dev !== "number" ||
      typeof st?.ino !== "number" ||
      !Number.isFinite(st.dev) ||
      !Number.isFinite(st.ino)
    ) {
      return null;
    }
    return { exe, dev: st.dev, ino: st.ino };
  } catch {
    return null;
  }
}

/**
 * Identity of the process that spawned `abra mcp` (the MCP client).
 * Uses process.ppid — never the self-reported `requestedBy` string.
 */
export async function identifyMcpCaller(deps?: {
  platform?: NodeJS.Platform;
  fs?: CallerIdentityFs;
  ppid?: number;
}): Promise<CallerIdentity | null> {
  const ppid = deps?.ppid ?? process.ppid;
  return identityForPid(ppid, deps);
}
