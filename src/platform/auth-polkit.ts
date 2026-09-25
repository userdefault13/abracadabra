import { execFile as execFileCb } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { promisify } from "node:util";
import type { AuthRequest, PlatformAuth } from "./types.js";
import { detectHeadlessSession } from "./env.js";

const DEFAULT_EXEC = promisify(execFileCb);

/** Absolute paths only — never rely on PATH for a relative `pkcheck`. */
export const PKCHECK_CANDIDATES = ["/usr/bin/pkcheck", "/usr/local/bin/pkcheck"] as const;

export const POLKIT_ACTION_ID = "dev.abracadabra.reveal";

/** Canonical package location; also accept /etc for local installs. */
export const POLICY_CANDIDATES = [
  "/usr/share/polkit-1/actions/dev.abracadabra.policy",
  "/etc/polkit-1/actions/dev.abracadabra.policy",
] as const;

/**
 * Minimum wall-clock for pkcheck when the user may type a password.
 * Effective timeout = max(req.timeoutSeconds ?? 30, MIN_PKCHECK_TIMEOUT_SECONDS).
 */
export const MIN_PKCHECK_TIMEOUT_SECONDS = 120;

export type ExecFileFn = (
  file: string,
  args: readonly string[],
  options: { timeout: number },
) => Promise<{ stdout: string; stderr: string }>;

export type ExistsFn = (path: string) => boolean;
export type ReadFileFn = (path: string, encoding: "utf8") => string;

export interface PolkitAuthDeps {
  execFile?: ExecFileFn;
  existsSync?: ExistsFn;
  readFileSync?: ReadFileFn;
  getuid?: () => number;
  pid?: number;
  /** Injectable env for headless detection / ABRA_AUTH (tests). */
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
}

export interface PolkitProbeResult {
  ok: boolean;
  pkcheck?: string;
  policy?: string;
  detail?: string;
}

let probeOverride: (() => PolkitProbeResult) | null = null;

/** Test hook — inject probe result; pass null to restore. */
export function setProbePolkitForTests(fn: (() => PolkitProbeResult) | null): void {
  probeOverride = fn;
}

function resolvePkcheck(exists: ExistsFn = existsSync): string | undefined {
  for (const p of PKCHECK_CANDIDATES) {
    if (exists(p)) return p;
  }
  return undefined;
}

function resolvePolicy(exists: ExistsFn = existsSync): string | undefined {
  for (const p of POLICY_CANDIDATES) {
    if (exists(p)) return p;
  }
  return undefined;
}

/**
 * Prefer `pid,start_time,uid` (polkit ≥ 0.112) to avoid the CVE-2013-4288 race
 * on bare-pid subjects. start_time is /proc/self/stat field 22; fall back to
 * plain pid only if /proc cannot be parsed (no uid required for that path).
 */
export function resolvePolkitSubject(
  deps: Pick<PolkitAuthDeps, "readFileSync" | "getuid" | "pid"> = {},
): string {
  const pid = deps.pid ?? process.pid;
  const read = deps.readFileSync ?? readFileSync;
  let startTime: string | undefined;
  try {
    const stat = read("/proc/self/stat", "utf8");
    const closeParen = stat.lastIndexOf(")");
    if (closeParen < 0) return String(pid);
    // Fields after comm (field 2): index 0 = field 3 … index 19 = field 22 (starttime).
    const afterComm = stat.slice(closeParen + 2).trimStart().split(/\s+/);
    const field = afterComm[19];
    if (!field || !/^\d+$/.test(field)) return String(pid);
    startTime = field;
  } catch {
    return String(pid);
  }
  const getuidFn = deps.getuid ?? process.getuid;
  if (typeof getuidFn !== "function") {
    throw new Error("process.getuid is unavailable");
  }
  return `${pid},${startTime},${getuidFn()}`;
}

export const POLKIT_INSTALL_HINT = "sudo scripts/install-polkit.sh";

export function headlessPolkitHint(reasons: string[]): string {
  return (
    `Headless session (${reasons.join("; ")}): PolKit can't show an approval dialog. ` +
    `Headless use needs ABRA_KEYSTORE=passphrase-file (then approvals prompt for the vault passphrase on the terminal; use ssh -t). ` +
    `Run: abra keystore migrate --to passphrase-file`
  );
}

export function probePolkit(deps: Pick<PolkitAuthDeps, "existsSync"> = {}): PolkitProbeResult {
  if (probeOverride) return probeOverride();
  return probeWith(deps.existsSync ?? existsSync);
}

function probeWith(exists: ExistsFn): PolkitProbeResult {
  const pkcheck = resolvePkcheck(exists);
  const policy = resolvePolicy(exists);
  if (!pkcheck && !policy) {
    return { ok: false, detail: "pkcheck and polkit policy not found" };
  }
  if (!pkcheck) {
    return { ok: false, policy, detail: "pkcheck not found at /usr/bin/pkcheck or /usr/local/bin/pkcheck" };
  }
  if (!policy) {
    return {
      ok: false,
      pkcheck,
      detail:
        "polkit policy missing — install with: sudo scripts/install-polkit.sh (places file in /usr/share/polkit-1/actions/)",
    };
  }
  return { ok: true, pkcheck, policy };
}

export class PolkitAuth implements PlatformAuth {
  readonly id = "polkit";
  private readonly deps: PolkitAuthDeps;

  constructor(deps: PolkitAuthDeps = {}) {
    this.deps = deps;
  }

  supportsBiometrics(): boolean {
    return false;
  }

  async authenticate(req: AuthRequest): Promise<void> {
    const env = this.deps.env ?? process.env;
    const platform = this.deps.platform ?? process.platform;
    const headless = detectHeadlessSession(env, platform);
    const authExplicit = Boolean(env.ABRA_AUTH);

    // Auto-selected polkit on a headless session cannot show a dialog — deny
    // before pkcheck. Explicit ABRA_AUTH=polkit still attempts pkcheck.
    if (headless.headless && !authExplicit) {
      throw new Error(
        `abracadabra: approval denied — ${req.reason}. ${headlessPolkitHint(headless.reasons)}`,
      );
    }

    // Check the (injectable) filesystem, never the test probe override:
    // a missing pkcheck or policy denies before any exec.
    const probe = probeWith(this.deps.existsSync ?? existsSync);
    const pkcheck = probe.pkcheck;
    if (!probe.ok || !pkcheck) {
      throw denyWithOptionalHeadlessHint(
        `abracadabra: PolKit approval denied — ${req.reason}. ` +
          `PolKit is not set up (${probe.detail ?? "unknown"}). ` +
          `Install the policy: ${POLKIT_INSTALL_HINT} ` +
          `(ABRA_AUTH=password is an explicit, less-safe opt-in that skips the identity check).`,
        headless.headless && authExplicit ? headless.reasons : null,
      );
    }

    const getuid = this.deps.getuid ?? process.getuid;
    if (typeof getuid !== "function") {
      throw denyWithOptionalHeadlessHint(
        `abracadabra: PolKit approval denied — ${req.reason}. process.getuid is unavailable.`,
        headless.headless && authExplicit ? headless.reasons : null,
      );
    }

    const subject = resolvePolkitSubject({ ...this.deps, getuid });
    const timeoutSeconds = Math.max(req.timeoutSeconds ?? 30, MIN_PKCHECK_TIMEOUT_SECONDS);
    const execFile = this.deps.execFile ?? (DEFAULT_EXEC as ExecFileFn);
    const args = [
      "--action-id",
      POLKIT_ACTION_ID,
      "--process",
      subject,
      "--allow-user-interaction",
    ] as const;

    try {
      await execFile(pkcheck, args, { timeout: timeoutSeconds * 1000 });
    } catch (err) {
      const base = denyError(req.reason, err);
      if (headless.headless && authExplicit) {
        throw new Error(`${base.message} ${headlessPolkitHint(headless.reasons)}`);
      }
      throw base;
    }
  }
}

function denyWithOptionalHeadlessHint(message: string, reasons: string[] | null): Error {
  if (reasons) return new Error(`${message} ${headlessPolkitHint(reasons)}`);
  return new Error(message);
}

function denyError(reason: string, err: unknown): Error {
  const prefix = `abracadabra: PolKit approval denied — ${reason}`;
  if (!err || typeof err !== "object") {
    return new Error(`${prefix}. ${String(err)}`);
  }
  const e = err as NodeJS.ErrnoException & {
    code?: string | number;
    signal?: string;
    killed?: boolean;
    status?: number;
  };
  if (e.code === "ENOENT") {
    return new Error(`${prefix}. pkcheck binary missing (ENOENT).`);
  }
  if (e.code === "EACCES") {
    return new Error(`${prefix}. cannot execute pkcheck (EACCES).`);
  }
  if (e.killed || e.signal || e.code === "ETIMEDOUT") {
    return new Error(`${prefix}. timed out or interrupted${e.signal ? ` (${e.signal})` : ""}.`);
  }
  const status = typeof e.status === "number" ? e.status : typeof e.code === "number" ? e.code : undefined;
  if (status === 1) {
    return new Error(`${prefix}. not authorized (pkcheck exit 1).`);
  }
  if (status === 2) {
    return new Error(
      `${prefix}. authorization requires a challenge but user interaction was not allowed (pkcheck exit 2).`,
    );
  }
  if (status === 3) {
    return new Error(`${prefix}. the authentication dialog was dismissed (pkcheck exit 3).`);
  }
  if (status === 126) {
    return new Error(`${prefix}. pkcheck could not be executed (exit 126).`);
  }
  if (status === 127) {
    return new Error(
      `${prefix}. an error occurred while checking authorization (pkcheck exit 127).`,
    );
  }
  const msg = err instanceof Error ? err.message : String(err);
  return new Error(`${prefix}. ${msg}`);
}
