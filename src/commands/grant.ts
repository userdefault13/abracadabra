import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { authenticate, resolveAuthBackend } from "../platform/index.js";
import { loadVault } from "../core/vault.js";
import {
  agentGrantAdd,
  agentGrantList,
  agentGrantRevoke,
  agentStatus,
  AgentClientError,
  shouldTryAgent,
  resolveAgentSocketPath,
  GRANT_TTL_MIN_SECONDS,
  GRANT_TTL_MAX_SECONDS,
} from "../agent/index.js";

/** Basenames refused as grant callers unless --allow-interpreter. */
const INTERPRETER_BASENAMES = new Set([
  "node",
  "nodejs",
  "bun",
  "deno",
  "python",
  "python3",
  "perl",
  "ruby",
  "php",
  "bash",
  "sh",
  "dash",
  "zsh",
  "fish",
  "ksh",
  "env",
  "busybox",
  "npx",
]);

const PYTHON3_DOT = /^python3\.\d+$/;

export function isInterpreterBasename(base: string): boolean {
  const b = base.toLowerCase();
  return INTERPRETER_BASENAMES.has(b) || PYTHON3_DOT.test(b);
}

/**
 * Parse TTL: `90s`, `30m`, `2h`, `8h`, or plain seconds.
 * Returns seconds; throws on invalid / out of range.
 */
export function parseGrantTtl(raw: string): number {
  const s = raw.trim().toLowerCase();
  if (!s) throw new Error("ttl is required");

  let seconds: number;
  const m = s.match(/^(\d+(?:\.\d+)?)(s|m|h)?$/);
  if (!m) {
    throw new Error(
      `invalid ttl "${raw}" — use e.g. 90s, 30m, 2h, 8h, or plain seconds`,
    );
  }
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`invalid ttl "${raw}"`);
  }
  const unit = m[2] ?? "s";
  switch (unit) {
    case "s":
      seconds = Math.floor(n);
      break;
    case "m":
      seconds = Math.floor(n * 60);
      break;
    case "h":
      seconds = Math.floor(n * 3600);
      break;
    default:
      throw new Error(`invalid ttl unit in "${raw}"`);
  }

  if (seconds < GRANT_TTL_MIN_SECONDS) {
    throw new Error(
      `ttl must be at least ${GRANT_TTL_MIN_SECONDS}s (got ${seconds}s)`,
    );
  }
  if (seconds > GRANT_TTL_MAX_SECONDS) {
    throw new Error(
      `ttl must be at most ${GRANT_TTL_MAX_SECONDS / 3600}h / ${GRANT_TTL_MAX_SECONDS}s (got ${seconds}s)`,
    );
  }
  return seconds;
}

function formatLocalExpiry(expiresAt: number): string {
  return new Date(expiresAt).toLocaleString();
}

function requireAgentUnlocked(): void {
  if (!shouldTryAgent()) {
    throw new Error(
      "run abra unlock first (abra-agent must be running)",
    );
  }
  let socketPath: string;
  try {
    socketPath = resolveAgentSocketPath();
  } catch {
    throw new Error(
      "run abra unlock first (abra-agent must be running)",
    );
  }
  if (!fs.existsSync(socketPath)) {
    throw new Error(
      "run abra unlock first (abra-agent must be running)",
    );
  }
}

async function assertAgentUnlocked(): Promise<void> {
  requireAgentUnlocked();
  try {
    const st = await agentStatus();
    if (st.locked) {
      throw new Error(
        "run abra unlock first (abra-agent must be running)",
      );
    }
  } catch (e) {
    if (
      e instanceof Error &&
      e.message.includes("run abra unlock first")
    ) {
      throw e;
    }
    throw new Error(
      "run abra unlock first (abra-agent must be running)",
    );
  }
}

export async function cmdGrantAdd(opts: {
  project: string;
  caller: string;
  ttl: string;
  allowInterpreter?: boolean;
}): Promise<void> {
  // Terminal requirement: under the passphrase backend, authenticate() below
  // prompts on /dev/tty and denies with no terminal.

  const ttlSeconds = parseGrantTtl(opts.ttl);
  const project = opts.project.trim();
  if (!project) throw new Error("--project is required");

  let exe: string;
  try {
    exe = fs.realpathSync(path.resolve(opts.caller));
  } catch {
    throw new Error(`caller path not found: ${opts.caller}`);
  }
  let st: fs.Stats;
  try {
    st = fs.statSync(exe);
  } catch {
    throw new Error(`caller path not readable: ${exe}`);
  }
  if (!st.isFile()) {
    throw new Error(`caller must be a regular file: ${exe}`);
  }
  // Executable bit (owner/group/other) — refuse non-executables.
  if ((st.mode & 0o111) === 0) {
    throw new Error(`caller is not executable: ${exe}`);
  }

  const base = path.basename(exe);
  if (isInterpreterBasename(base) && !opts.allowInterpreter) {
    throw new Error(
      `refusing to grant access to interpreter/shell "${base}" — a grant to an interpreter covers ANY script it runs. ` +
        `Pass --allow-interpreter if you really intend that (broad). Prefer granting the real client binary when possible.`,
    );
  }

  await assertAgentUnlocked();

  const vault = await loadVault();
  if (!(project in vault.projects)) {
    throw new Error(`project not found: ${project}`);
  }

  const ttlLabel =
    ttlSeconds >= 3600
      ? `${(ttlSeconds / 3600).toFixed(ttlSeconds % 3600 === 0 ? 0 : 1)}h`
      : ttlSeconds >= 60
        ? `${Math.round(ttlSeconds / 60)}m`
        : `${ttlSeconds}s`;

  await authenticate(
    `abracadabra: grant ${exe} access to "${project}" for ${ttlLabel} (headless MCP/API)`,
  );

  let grant;
  try {
    grant = await agentGrantAdd({
      project,
      caller: { exe, dev: st.dev, ino: st.ino },
      ttlSeconds,
    });
  } catch (e) {
    if (e instanceof AgentClientError && e.code === "locked") {
      throw new Error(
        "run abra unlock first (abra-agent must be running)",
      );
    }
    throw e;
  }

  console.log(`✓ grant ${grant.id}`);
  console.log(`  project:  ${grant.project}`);
  console.log(`  caller:   ${grant.caller.exe}`);
  console.log(`  expires:  ${formatLocalExpiry(grant.expiresAt)}`);
  console.log(
    `  note:    cleared on lock/sleep/expiry; only this exact binary (same inode) matches — a package upgrade invalidates it`,
  );

  if (resolveAuthBackend() !== "passphrase") {
    console.log(
      `  note:    grants are only consulted under the passphrase backend (headless Linux)`,
    );
  }
}

export async function cmdGrantList(): Promise<void> {
  await assertAgentUnlocked();
  const grants = await agentGrantList();
  if (grants.length === 0) {
    console.log("(no active grants)");
    return;
  }
  for (const g of grants) {
    const remSec = Math.round(g.remainingMs / 1000);
    console.log(
      `${g.id}  ${g.project}  ${g.caller.exe}  remaining ${remSec}s`,
    );
  }
}

export async function cmdGrantRevoke(target: string): Promise<void> {
  await assertAgentUnlocked();
  if (target === "all") {
    const n = await agentGrantRevoke({ all: true });
    console.log(`✓ revoked ${n} grant(s)`);
    return;
  }
  const n = await agentGrantRevoke({ grantId: target });
  if (n === 0) {
    console.log(`(no grant with id ${target})`);
    return;
  }
  console.log(`✓ revoked ${n} grant(s)`);
}

export function registerGrantCommand(program: Command): void {
  program
    .command("grant")
    .description(
      "Pre-approve a caller binary for headless MCP/API reveals (passphrase backend)",
    )
    .option("--project <name>", "vault project to grant")
    .option("--caller <path>", "absolute or relative path to the caller executable")
    .option("--ttl <duration>", "grant lifetime (90s, 30m, 2h, 8h, or seconds)")
    .option(
      "--allow-interpreter",
      "allow granting node/python/shell/etc. (covers any script they run)",
    )
    .option("--list", "list active grants (metadata only)")
    .option("--revoke <id|all>", "revoke a grant id or all")
    .action(
      async (opts: {
        project?: string;
        caller?: string;
        ttl?: string;
        allowInterpreter?: boolean;
        list?: boolean;
        revoke?: string;
      }) => {
        if (opts.list) {
          await cmdGrantList();
          return;
        }
        if (opts.revoke) {
          await cmdGrantRevoke(opts.revoke);
          return;
        }
        if (!opts.project || !opts.caller || !opts.ttl) {
          throw new Error(
            "usage: abra grant --project <P> --caller <path> --ttl <dur> [--allow-interpreter]\n" +
              "       abra grant --list\n" +
              "       abra grant --revoke <id|all>",
          );
        }
        await cmdGrantAdd({
          project: opts.project,
          caller: opts.caller,
          ttl: opts.ttl,
          allowInterpreter: opts.allowInterpreter,
        });
      },
    );
}
