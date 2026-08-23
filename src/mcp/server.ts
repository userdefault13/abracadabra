import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { loadVault, saveVault, assertProject } from "../core/vault.js";
import type { Vault } from "../core/vault.js";
import { authenticate } from "../auth/touchid.js";
import { generateWalletsIntoProject } from "../commands/keygen.js";

const MAX_TTL_SECONDS = 24 * 60 * 60;

function textResult(payload: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    isError,
  };
}

/** Discover projects and key names. Values are never included. */
async function listProjects() {
  const vault = await loadVault();
  const projects = Object.fromEntries(
    Object.entries(vault.projects).map(([name, project]) => [
      name,
      Object.fromEntries(
        Object.entries(project.vars).map(([key, entry]) => [
          key,
          { secret: entry.secret },
        ]),
      ),
    ]),
  );
  return textResult({
    tool: "list_projects",
    format:
      '{ "projects": { "<name>": { "<KEY>": { "secret": boolean } } } } — values are never returned by this tool',
    projects,
  });
}

/**
 * Request secret values. Pops a Touch ID dialog on the user's machine;
 * returns values ONLY after biometric approval.
 */
async function getSecrets(args: {
  project: string;
  keys: string[];
  ttl?: number;
  requestedBy?: string;
}) {
  const vault: Vault = await loadVault();
  let proj;
  try {
    proj = assertProject(vault, args.project);
  } catch {
    return textResult({ error: `project not found: ${args.project}` }, true);
  }

  const missing = args.keys.filter((k) => !(k in proj.vars));
  if (missing.length > 0) {
    return textResult(
      { error: `keys not found in ${args.project}: ${missing.join(", ")}` },
      true,
    );
  }

  const who = args.requestedBy ? `${args.requestedBy} (MCP agent)` : "MCP agent";
  try {
    await authenticate(
      `abracadabra: ${who} requests ${args.keys.join(", ")} from "${args.project}"`,
    );
  } catch {
    return textResult(
      { error: "user denied or timed out biometric approval", approved: false },
      true,
    );
  }

  const vars = Object.fromEntries(
    args.keys.map((k) => [k, proj.vars[k].value]),
  );

  return textResult({
    tool: "get_secrets",
    format:
      'parse with JSON.parse(result.content[0].text) → { vars: { "<KEY>": "<value>" }, approved: true }',
    project: args.project,
    approved: true,
    grantedVia: "touch-id",
    vars,
    note: "treat these values as secrets; do not log or echo them",
  });
}

/** Generate a fresh EVM wallet via local Foundry and store it in the vault. */
async function generateWallet(args: { project: string; payTo?: boolean }) {
  try {
    const vault = await loadVault();
    const wallets = await generateWalletsIntoProject(vault, args.project, {
      count: "1",
      payTo: args.payTo,
    });
    return textResult({
      tool: "generate_wallet",
      format:
        '{ wallets: [{ address, varPrefix }] } — private key stored encrypted as EVM_PRIVATE_KEY<varPrefix>',
      project: args.project,
      wallets: wallets.map((w) => ({
        address: w.address,
        varSuffix: w.varSuffix,
        payToSet: w.setPayTo,
      })),
    });
  } catch (err) {
    return textResult(
      { error: err instanceof Error ? err.message : String(err) },
      true,
    );
  }
}

export async function startMcpServer(): Promise<void> {
  const server = new McpServer({
    name: "abracadabra",
    version: "0.1.0",
  });

  server.tool("list_projects", "List abracadabra projects and their KEY names (no values). Call this first to discover what is available.", {}, async () =>
    listProjects(),
  );

  server.tool(
    "get_secrets",
    `Request secret env vars from a project. Pops a Touch ID dialog the user must approve.
Args: { project: string, keys: string[], ttl?: number, requestedBy?: string }
Returns JSON in content[0].text: { approved: true, vars: { "<KEY>": "<value>" } }
On denial you receive isError=true with { approved: false }. Never log returned values.`,
    {
      project: z.string().describe("abracadabra project name"),
      keys: z.array(z.string()).min(1).max(50).describe("KEY names to request"),
      ttl: z.number().int().positive().max(MAX_TTL_SECONDS).optional()
        .describe("seconds of silent re-access after this approval"),
      requestedBy: z.string().optional().describe("your agent/app name, shown in the approval dialog"),
    },
    async (args) => getSecrets(args),
  );

  server.tool(
    "generate_wallet",
    `Generate a fresh EVM wallet with local Foundry (cast) and store it encrypted in a project.
Args: { project: string, payTo?: boolean }
Returns { wallets: [{ address, varSuffix, payToSet }] }; private key lands as EVM_PRIVATE_KEY<varSuffix>.`,
    {
      project: z.string().describe("project to store the wallet in"),
      payTo: z.boolean().optional().describe("also set PAY_TO_ADDRESS to the new address"),
    },
    async (args) => generateWallet(args),
  );

  await server.connect(new StdioServerTransport());
  // stderr only — stdout carries the MCP protocol
  console.error(`✦ abracadabra MCP server ready (stdio)`);
}
