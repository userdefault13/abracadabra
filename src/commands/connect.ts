import { Command } from "commander";
import { loadVault, saveVault, assertProject, assertConnection } from "../core/vault.js";
import type { Vault } from "../core/vault.js";
import { prompt, promptHidden } from "../core/prompt.js";
import { authenticate } from "../platform/index.js";
import { getProvider, providers } from "../connectors/providers.js";
import type { Provider } from "../connectors/providers.js";

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;

function fail(err: unknown): never {
  console.error(`\x1b[31m✗ ${err instanceof Error ? err.message : String(err)}\x1b[0m`);
  process.exit(1);
}

export function listProviders(): void {
  console.log(bold("Available providers:"));
  for (const p of Object.values(providers)) {
    const credNames = p.fields.filter((f) => f.required ?? true).map((f) => f.varName);
    console.log(`  ${bold(p.id.padEnd(12))} ${p.label}${dim(`\n${" ".repeat(15)}creds: ${credNames.join(", ")}`)}`);
  }
  console.log(dim("\nConnect: abra connect <provider>   Issue: abra issue <provider> <project>"));
}

export async function connect(providerId?: string, opts?: { json?: string }): Promise<void> {
  if (!providerId) {
    listProviders();
    return;
  }
  try {
    const provider = getProvider(providerId);
    const vault = await loadVault();

    // ── non-interactive import from a downloaded key file ─────────────
    if (opts?.json) {
      const { readFileSync } = await import("node:fs");
      let raw: Record<string, string>;
      try {
        raw = JSON.parse(readFileSync(opts.json, "utf8"));
      } catch {
        fail(`Cannot read JSON file: ${opts.json}`);
      }
      let importedVars: Record<string, { value: string; secret: boolean; updatedAt: number }>;

      if (provider.importFromFile) {
        let derived: Record<string, { value: string; secret: boolean }>;
        try {
          derived = await provider.importFromFile(raw);
        } catch (err) {
          fail(err);
        }
        importedVars = Object.fromEntries(
          Object.entries(derived).map(([k, v]) => [k, { ...v, updatedAt: Date.now() }]),
        );
      } else {
        // generic shape: {id|name|apiKeyId, privateKey|apiKeySecret}
        const keyId = raw.id ?? raw.name ?? raw.apiKeyId;
        const keySecret = raw.privateKey ?? raw.apiKeySecret;
        if (!keyId || !keySecret) {
          fail("Unrecognized key file — expected {id, privateKey}, {name, privateKey} or {apiKeyId, apiKeySecret}");
        }
        const fieldNames = provider.fields.map((f) => f.varName);
        if (fieldNames.length < 2) fail(`Provider ${provider.id} does not support JSON import`);
        importedVars = {
          [fieldNames[0]]: { value: keyId, secret: false, updatedAt: Date.now() },
          [fieldNames[1]]: { value: keySecret, secret: true, updatedAt: Date.now() },
        };
      }

      vault.connections ??= {};
      vault.connections[provider.id] = {
        provider: provider.id,
        label: "imported",
        createdAt: Date.now(),
        meta: { importedFrom: opts.json },
        vars: importedVars,
      };
      await saveVault(vault);
      console.log(green(`✓ Connected ${bold(provider.label)} from ${opts.json}`));
      for (const name of Object.keys(importedVars).sort()) {
        console.log(`  ${name}${importedVars[name].secret ? dim(" (secret)") : ""}`);
      }
      console.log(dim(`Issue into a project with: abra issue ${provider.id} <project>`));
      return;
    }

    if (vault.connections?.[provider.id]) {
      const answer = await prompt(
        `Already connected to ${provider.id}. Re-connect and overwrite? [y/N] `,
      );
      if (answer.trim().toLowerCase() !== "y") return;
    }

    if (provider.portalUrl) {
      console.log(`Opening ${bold(provider.label)} portal…`);
      console.log(dim(`  ${provider.portalUrl}`));
      console.log(
        dim("Create an admin API key there (name it e.g. \"abracadabra\"), then paste the details below."),
      );
      const { execFile } = await import("node:child_process");
      execFile("open", [provider.portalUrl]);
    }

    const meta: Record<string, string> = {};
    if (provider.fields.some((f) => !f.secret)) {
      meta.keyName = await prompt(`Label for this connection (e.g. abracadabra-admin): `);
    }

    const vars: Record<string, { value: string; secret: boolean; updatedAt: number }> = {};
    for (const field of provider.fields) {
      let value = "";
      while (!value) {
        value = field.secret
          ? await promptHidden(`${field.prompt}\n> `)
          : await prompt(`${field.prompt}: `);
        if (!value && !field.required) break;
        if (!value) console.log(dim("this field is required"));
      }
      if (!value) continue;
      vars[field.varName] = { value, secret: field.secret, updatedAt: Date.now() };
    }

    vault.connections ??= {};
    vault.connections[provider.id] = {
      provider: provider.id,
      label: meta.keyName,
      createdAt: Date.now(),
      meta,
      vars,
    };
    await saveVault(vault);
    console.log(green(`✓ Connected ${bold(provider.label)} — stored encrypted in your vault`));
    console.log(dim(`Issue into a project with: abra issue ${provider.id} --project <name>`));
  } catch (err) {
    fail(err);
  }
}

export async function listConnections(): Promise<void> {
  try {
    const vault = await loadVault();
    const conns = Object.values(vault.connections ?? {});
    if (conns.length === 0) {
      console.log(dim("No connections yet. Try: abra connect cdp | cloudflare | vercel"));
      return;
    }
    for (const conn of conns.sort((a, b) => a.provider.localeCompare(b.provider))) {
      console.log(
        `${bold(conn.provider)}  ${dim(conn.label ?? "")}  ${dim(`(${Object.keys(conn.vars).length} creds)`)}`,
      );
    }
  } catch (err) {
    fail(err);
  }
}

export async function removeConnection(providerId: string): Promise<void> {
  try {
    const vault = await loadVault();
    assertConnection(vault, providerId);
    const answer = await prompt(`Disconnect "${providerId}"? [y/N] `);
    if (answer.trim().toLowerCase() !== "y") return;
    delete vault.connections![providerId];
    await saveVault(vault);
    console.log(green(`✓ Disconnected ${providerId}`));
  } catch (err) {
    fail(err);
  }
}

interface IssueOptions {
  project?: string;
}

export async function issueCreds(
  providerId: string,
  targetProject: string,
  _opts: IssueOptions,
  command?: Command,
): Promise<void> {
  void command;
  try {
    const vault: Vault = await loadVault();
    const provider = getProvider(providerId);
    const conn = assertConnection(vault, providerId);
    const project = assertProject(vault, targetProject);

    // materializing provider secrets into a project is Touch ID gated
    await authenticate(`abracadabra: issue ${providerId} credentials to "${targetProject}"`);

    const issued = provider.issueVars(conn);
    const now = Date.now();
    for (const [key, value] of Object.entries(issued)) {
      project.vars[key] = { value, secret: true, updatedAt: now };
    }
    await saveVault(vault);

    console.log(green(`✓ Issued ${Object.keys(issued).length} var(s) from ${providerId} to ${bold(targetProject)}:`));
    for (const key of Object.keys(issued).sort()) console.log(`  ${key}`);
    console.log(dim(`Use them: abra run ${targetProject} -- <cmd>`));
  } catch (err) {
    fail(err);
  }
}

export function registerConnectCommands(program: Command): void {
  program
    .command("connect [provider]")
    .description(`Connect a third-party account (${Object.keys(providers).join(", ")}) — no arg lists providers`)
    .option("--json <path>", "import credentials from a downloaded key file (non-interactive)")
    .action(connect);

  program
    .command("connections")
    .description("List connected accounts")
    .action(listConnections);

  program
    .command("disconnect <provider>")
    .description("Remove a stored connection")
    .action(removeConnection);

  program
    .command("issue <provider> <project>")
    .description("Provision provider credentials as vars in a project (Touch ID gated)")
    .action(issueCreds);
}
