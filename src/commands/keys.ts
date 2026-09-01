import { Command } from "commander";
import { loadVault, saveVault } from "../core/vault.js";
import type { ApiKey } from "../core/vault.js";
import { generateApiKey } from "../core/apikeys.js";
import { prompt } from "../core/prompt.js";
import { authenticate } from "../platform/index.js";

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;

function fail(err: unknown): never {
  console.error(`\x1b[31m✗ ${err instanceof Error ? err.message : String(err)}\x1b[0m`);
  process.exit(1);
}

function describeKey(k: ApiKey, vaultProjects: Set<string>): string {
  const scope = k.projects === null ? "all projects" : k.projects.join(",");
  const unknown = (k.projects ?? []).filter((p) => !vaultProjects.has(p));
  const warn = unknown.length > 0 ? dim(` (unknown: ${unknown.join(",")})`) : "";
  const expiry = k.expiresAt ? ` · expires ${new Date(k.expiresAt).toLocaleDateString()}` : "";
  return `${bold(k.prefix)}…  ${k.name} ${dim(`[${scope}${warn}]${expiry} · id ${k.id}`)}`;
}

export function registerKeyCommands(program: Command): void {
  const keys = program
    .command("keys")
    .description("Manage API keys for the local abra HTTP API (POST /secret)");

  keys
    .command("new <name>")
    .description("Issue a new API key — prints the full key ONCE")
    .option("-p, --projects <projects>", "comma-separated project scope (default: all projects)")
    .option("--expires-in <days>", "expire after N days", "0")
    .action(async (name: string, opts: { projects?: string; expiresIn: string }) => {
      try {
        if (!/^[\w.-]{2,64}$/.test(name)) fail("Name must be 2-64 chars: letters, digits, . _ -");
        await authenticate(`abracadabra: issue API key "${name}"`);
        const vault = await loadVault();
        const projects = opts.projects
          ? opts.projects.split(",").map((p) => p.trim()).filter(Boolean)
          : null;
        for (const p of projects ?? []) {
          if (!vault.projects[p]) console.error(dim(`⚠ project "${p}" does not exist yet`));
        }
        const days = Number(opts.expiresIn);
        const { record, fullKey } = generateApiKey(name, projects, {
          expiresInDays: days > 0 ? days : undefined,
        });
        vault.apiKeys![record.id] = record;
        await saveVault(vault);
        console.log(green(`✓ API key "${name}" created (${record.id})`));
        console.log();
        console.log(`  ${fullKey}`);
        console.log();
        console.log(dim("  Copy it now — it will NOT be shown again."));
        console.log(dim("  Use it as:  curl -H 'Authorization: Bearer <key>' http://127.0.0.1:7331/secret ..."));
      } catch (err) {
        fail(err);
      }
    });

  keys
    .command("ls")
    .description("List API keys (full keys are never shown)")
    .action(async () => {
      try {
        const vault = await loadVault();
        const all = Object.values(vault.apiKeys ?? {}).sort((a, b) => a.createdAt - b.createdAt);
        if (all.length === 0) {
          console.log(dim("No API keys yet. Try: abra keys new my-agent"));
          return;
        }
        const projects = new Set(Object.keys(vault.projects));
        for (const k of all) {
          const expired = k.expiresAt && Date.now() > k.expiresAt;
          console.log(`${describeKey(k, projects)}${expired ? dim(" [EXPIRED]") : ""}`);
        }
      } catch (err) {
        fail(err);
      }
    });

  keys
    .command("rm <id>")
    .description("Revoke an API key by id or prefix")
    .action(async (idOrPrefix: string) => {
      try {
        await authenticate("abracadabra: revoke an API key");
        const vault = await loadVault();
        const all = Object.values(vault.apiKeys ?? {});
        const match =
          all.find((k) => k.id === idOrPrefix) ??
          all.find((k) => k.prefix.startsWith(idOrPrefix));
        if (!match) fail(`No API key matching "${idOrPrefix}" (see: abra keys ls)`);
        const answer = await prompt(`Revoke key "${match.name}" (${match.id})? [y/N] `);
        if (answer.trim().toLowerCase() !== "y") {
          console.log(dim("Aborted"));
          return;
        }
        delete vault.apiKeys![match.id];
        await saveVault(vault);
        console.log(green(`✓ Revoked API key "${match.name}"`));
      } catch (err) {
        fail(err);
      }
    });
}
