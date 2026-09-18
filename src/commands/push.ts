import { Command } from "commander";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadVault, assertProject, assertConnection } from "../core/vault.js";
import type { Connection, VarEntry } from "../core/vault.js";
import { authenticate } from "../platform/index.js";
import { assertLicensed } from "../license/index.js";

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;

function fail(err: unknown): never {
  console.error(red(`✗ ${err instanceof Error ? err.message : String(err)}`));
  process.exit(1);
}

const VERCEL_API = "https://api.vercel.com";

export const VERCEL_TARGETS = ["production", "preview", "development"] as const;
export type VercelTarget = (typeof VERCEL_TARGETS)[number];

/** Parse `--env production,preview` into a validated, de-duplicated target list. */
export function parseTargets(raw?: string): VercelTarget[] {
  const list = (raw ?? "production,preview")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (list.length === 0) throw new Error("--env needs at least one target");
  for (const t of list) {
    if (!(VERCEL_TARGETS as readonly string[]).includes(t)) {
      throw new Error(`Unknown Vercel target "${t}" (use ${VERCEL_TARGETS.join(", ")})`);
    }
  }
  return [...new Set(list)] as VercelTarget[];
}

export interface VercelLink {
  projectId?: string;
  orgId?: string;
}

/** `vercel link` writes .vercel/project.json — reuse it so the caller need not repeat ids. */
export function readVercelLink(cwd = process.cwd()): VercelLink | null {
  try {
    const raw = JSON.parse(readFileSync(join(cwd, ".vercel", "project.json"), "utf8")) as Record<
      string,
      unknown
    >;
    return {
      projectId: typeof raw.projectId === "string" ? raw.projectId : undefined,
      orgId: typeof raw.orgId === "string" ? raw.orgId : undefined,
    };
  } catch {
    return null;
  }
}

export interface VercelTargetRef {
  project: string;
  teamId?: string;
  source: "flag" | "link" | "connection";
}

/**
 * Pick the Vercel project + team: explicit flags win, then the linked
 * .vercel/project.json, then the ids stored on the connection.
 * Personal-scope orgIds (`user_…`) are not teams and are dropped.
 */
export function resolveVercelTarget(opts: {
  flagProject?: string;
  flagTeam?: string;
  link: VercelLink | null;
  conn: Pick<Connection, "vars">;
}): VercelTargetRef {
  const project =
    opts.flagProject || opts.link?.projectId || opts.conn.vars.VERCEL_PROJECT_ID?.value;
  if (!project) {
    throw new Error(
      "No Vercel project: pass --project <id|name>, run from a `vercel link`ed directory, or store VERCEL_PROJECT_ID via `abra connect vercel`",
    );
  }
  const teamCandidate =
    opts.flagTeam || opts.link?.orgId || opts.conn.vars.VERCEL_ORG_ID?.value || "";
  const teamId = teamCandidate.startsWith("team_") ? teamCandidate : undefined;
  const source: VercelTargetRef["source"] = opts.flagProject
    ? "flag"
    : opts.link?.projectId
      ? "link"
      : "connection";
  return { project, teamId, source };
}

export interface VercelEnvBody {
  key: string;
  value: string;
  type: "encrypted" | "plain";
  target: VercelTarget[];
}

export function buildVercelEnvBody(key: string, entry: VarEntry, targets: VercelTarget[]): VercelEnvBody {
  return { key, value: entry.value, type: entry.secret ? "encrypted" : "plain", target: targets };
}

async function upsertEnv(token: string, ref: VercelTargetRef, body: VercelEnvBody): Promise<void> {
  const url = new URL(`${VERCEL_API}/v10/projects/${encodeURIComponent(ref.project)}/env`);
  url.searchParams.set("upsert", "true");
  if (ref.teamId) url.searchParams.set("teamId", ref.teamId);
  const res = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.ok) return;
  let message = `HTTP ${res.status}`;
  try {
    const j = (await res.json()) as { error?: { message?: string; code?: string } };
    if (j?.error?.message) message = `${j.error.message}${j.error.code ? ` (${j.error.code})` : ""}`;
  } catch {
    /* non-JSON error body — keep the status line */
  }
  throw new Error(message);
}

interface PushVercelOptions {
  env?: string;
  project?: string;
  team?: string;
  all?: boolean;
  dryRun?: boolean;
}

export async function pushVercel(
  projectName: string,
  keys: string[],
  opts: PushVercelOptions,
): Promise<void> {
  try {
    const vault = await loadVault();
    const project = assertProject(vault, projectName);
    const conn = assertConnection(vault, "vercel");
    const token = conn.vars.VERCEL_TOKEN?.value;
    if (!token) throw new Error("Vercel connection has no VERCEL_TOKEN — run: abra connect vercel");

    const targets = parseTargets(opts.env);
    const selected = opts.all ? Object.keys(project.vars).sort() : keys;
    if (selected.length === 0) throw new Error("Pass one or more KEY names, or --all");
    for (const k of selected) {
      if (!(k in project.vars)) throw new Error(`Var not found in ${projectName}: ${k}`);
    }
    const ref = resolveVercelTarget({
      flagProject: opts.project,
      flagTeam: opts.team,
      link: readVercelLink(),
      conn,
    });

    console.log(
      `${bold(projectName)} → Vercel ${bold(ref.project)}${ref.teamId ? dim(` (team ${ref.teamId})`) : ""} ${dim(`[${ref.source}]`)} · ${targets.join(", ")}`,
    );
    if (opts.dryRun) {
      for (const k of selected) console.log(`  ${k}${project.vars[k].secret ? dim(" (secret)") : ""}`);
      console.log(dim("dry run — nothing sent"));
      return;
    }

    // materializing vault values into a third-party store is gated like `get` / `env`
    await assertLicensed();
    await authenticate(
      `abracadabra: push ${selected.length} var(s) from "${projectName}" to Vercel ${ref.project}`,
    );

    let ok = 0;
    for (const k of selected) {
      try {
        await upsertEnv(token, ref, buildVercelEnvBody(k, project.vars[k], targets));
        console.log(green(`  ✓ ${k}`));
        ok++;
      } catch (err) {
        console.error(red(`  ✗ ${k}: ${err instanceof Error ? err.message : String(err)}`));
      }
    }
    if (ok === selected.length) console.log(green(`✓ Pushed ${ok} var(s) to Vercel`));
    else console.log(`Pushed ${ok}/${selected.length} var(s)`);
    console.log(dim("Env changes apply to the next deployment — redeploy to pick them up."));
    if (ok !== selected.length) process.exit(1);
  } catch (err) {
    fail(err);
  }
}

// ---------------------------------------------------------------------------
// push ssh — upsert vault vars into a remote .env over ssh (values travel on stdin)
// ---------------------------------------------------------------------------

export interface KeyMapping {
  local: string;
  remote: string;
}

/** `KEY` or `LOCAL:REMOTE` → { local, remote }. */
export function parseKeyMapping(spec: string): KeyMapping {
  const [local, remote] = spec.split(":");
  if (!local) throw new Error(`Bad key spec "${spec}" — use KEY or LOCAL_KEY:REMOTE_KEY`);
  const bad = [local, remote].filter((k) => k && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(k));
  if (bad.length) throw new Error(`Invalid env var name "${bad[0]}"`);
  return { local, remote: remote || local };
}

/** Parse `user@host[:port]` and reject anything that could smuggle ssh options. */
export function parseSshTarget(target: string): { user: string; host: string; port?: number } {
  const m = target.match(/^([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+)(?::(\d{1,5}))?$/);
  if (!m) throw new Error(`Bad ssh target "${target}" — use user@host[:port]`);
  return { user: m[1], host: m[2], port: m[3] ? Number(m[3]) : undefined };
}

/**
 * The remote side: reads KEY=VALUE lines from stdin and upserts them into the env file
 * (replacing an existing KEY= line, else appending). Values are never in argv or logs.
 */
export function remoteUpsertScript(envPath: string): string {
  if (!/^[A-Za-z0-9_./~-]+$/.test(envPath)) throw new Error(`Bad remote path "${envPath}"`);
  return [
    `set -e`,
    `f=${envPath}`,
    `mkdir -p "$(dirname "$f")"; touch "$f"; chmod 600 "$f"`,
    `while IFS= read -r line; do`,
    `  k="\${line%%=*}"`,
    `  if grep -q "^\${k}=" "$f"; then`,
    `    tmp="$(mktemp)"; grep -v "^\${k}=" "$f" > "$tmp"; printf '%s\\n' "$line" >> "$tmp"; cat "$tmp" > "$f"; rm -f "$tmp"`,
    `  else`,
    `    printf '%s\\n' "$line" >> "$f"`,
    `  fi`,
    `  echo "  ✓ $k"`,
    `done`,
  ].join("\n");
}

function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

interface PushSshOptions {
  env?: string;
  dryRun?: boolean;
  /** Vault project holding the SSH private key to authenticate with (abra keygen ssh). */
  identityProject?: string;
  /** Var name of that key (default SSH_PRIVATE_KEY). */
  identityKey?: string;
  /** Remote command to run after the upsert (same identity), e.g. a rebuild + health check. */
  run?: string;
}

/** Write a vault-held private key to a 0600 temp file for `ssh -i`; caller removes it. */
async function materializeIdentity(pem: string): Promise<string> {
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "abra-ssh-"));
  const file = join(dir, "id");
  writeFileSync(file, pem.endsWith("\n") ? pem : `${pem}\n`, { mode: 0o600 });
  return file;
}

export async function pushSsh(
  projectName: string,
  target: string,
  keys: string[],
  opts: PushSshOptions,
): Promise<void> {
  try {
    const vault = await loadVault();
    const project = assertProject(vault, projectName);
    const { user, host, port } = parseSshTarget(target);
    const envPath = opts.env || ".env";
    const mappings = keys.map(parseKeyMapping);
    if (mappings.length === 0) throw new Error("Pass one or more KEY or LOCAL:REMOTE names");
    for (const m of mappings) {
      if (!(m.local in project.vars)) throw new Error(`Var not found in ${projectName}: ${m.local}`);
    }
    // Optional vault-held identity (e.g. `abra keygen ssh gotchibot` → SSH_PRIVATE_KEY).
    const identityKeyName = opts.identityKey || "SSH_PRIVATE_KEY";
    const identityProject = opts.identityProject ? assertProject(vault, opts.identityProject) : null;
    if (identityProject && !(identityKeyName in identityProject.vars)) {
      throw new Error(`Var not found in ${opts.identityProject}: ${identityKeyName}`);
    }

    console.log(
      `${bold(projectName)} → ssh ${bold(`${user}@${host}`)}${port ? `:${port}` : ""} ${dim(envPath)}` +
        (identityProject ? dim(`  (identity ${opts.identityProject}/${identityKeyName})`) : ""),
    );
    if (opts.dryRun) {
      for (const m of mappings) console.log(`  ${m.remote}${m.remote !== m.local ? dim(` ← ${m.local}`) : ""}`);
      console.log(dim("dry run — nothing sent"));
      return;
    }

    await assertLicensed();
    await authenticate(`abracadabra: push ${mappings.length} var(s) from "${projectName}" to ${user}@${host}`);

    // Values ride on stdin as KEY=VALUE lines; the remote script upserts them one by one.
    const payload = mappings.map((m) => `${m.remote}=${project.vars[m.local].value}`).join("\n") + "\n";
    const { spawn } = await import("node:child_process");
    const args = ["-o", "BatchMode=yes"];
    if (port) args.push("-p", String(port));
    let identityFile: string | null = null;
    if (identityProject) {
      identityFile = await materializeIdentity(identityProject.vars[identityKeyName].value);
      args.push("-o", "IdentitiesOnly=yes", "-i", identityFile);
    }
    const sshArgs = [...args, `${user}@${host}`];
    let code: number;
    try {
      code = await new Promise((resolve, reject) => {
        const child = spawn("ssh", [...sshArgs, `bash -c ${shellSingleQuote(remoteUpsertScript(envPath))}`], {
          stdio: ["pipe", "inherit", "inherit"],
        });
        child.on("error", reject);
        child.on("close", (c) => resolve(c ?? 1));
        child.stdin.end(payload);
      });
      if (code === 0 && opts.run) {
        console.log(dim(`▸ ${opts.run}`));
        code = await new Promise((resolve, reject) => {
          const child = spawn("ssh", [...sshArgs, `bash -lc ${shellSingleQuote(opts.run!)}`], { stdio: "inherit" });
          child.on("error", reject);
          child.on("close", (c) => resolve(c ?? 1));
        });
      }
    } finally {
      if (identityFile) {
        const { rmSync } = await import("node:fs");
        const { dirname } = await import("node:path");
        rmSync(dirname(identityFile), { recursive: true, force: true });
      }
    }
    if (code !== 0) throw new Error(`ssh exited with ${code}`);
    console.log(green(`✓ Pushed ${mappings.length} var(s) to ${user}@${host}:${envPath}`));
    console.log(dim("Restart the remote service to pick them up (e.g. docker compose up -d --build)."));
  } catch (err) {
    fail(err);
  }
}

export function registerPushCommands(program: Command): void {
  const push = program
    .command("push")
    .description("Push vault vars into a hosting provider's env (Touch ID gated)");

  push
    .command("vercel <project> [keys...]")
    .description(
      "Upsert project vars into Vercel env via the vercel connection (project from --project, .vercel/project.json, or VERCEL_PROJECT_ID)",
    )
    .option("-e, --env <targets>", "comma-separated: production,preview,development", "production,preview")
    .option("-p, --project <idOrName>", "Vercel project id or name")
    .option("-t, --team <teamId>", "Vercel team id (team_…)")
    .option("--all", "push every var in the project")
    .option("--dry-run", "list what would be pushed (names only); send nothing")
    .action(pushVercel);

  push
    .command("ssh <project> <target> [keys...]")
    .description(
      "Upsert project vars into a remote .env over ssh (user@host[:port]); KEY or LOCAL_KEY:REMOTE_KEY; values travel on stdin",
    )
    .option("-e, --env <path>", "remote env file path", ".env")
    .option("--identity-project <project>", "vault project holding the SSH private key to use (abra keygen ssh)")
    .option("--identity-key <name>", "var name of that key", "SSH_PRIVATE_KEY")
    .option("--run <command>", "remote command to run after the upsert (e.g. 'cd app && docker compose up -d --build')")
    .option("--dry-run", "list what would be pushed (names only); send nothing")
    .action(pushSsh);
}
