import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { loadVault, saveVault, assertProject } from "../core/vault.js";
import type { Vault } from "../core/vault.js";
import { authenticate } from "../platform/index.js";
import {
  generateWalletsIntoProject,
  mintCloudflareTokenIntoProject,
  generateSshKeysIntoProject,
} from "../commands/keygen.js";
import { providers } from "../connectors/providers.js";
import {
  findMcpGrant,
  issueMcpGrant,
  listMcpGrants,
} from "./grants.js";

const MAX_TTL_SECONDS = 24 * 60 * 60;

/** Testnet chains the agent can request wallets for, with funding hints. */
const CHAINS: Record<string, { chainId: number; usdc?: string; faucet: string }> = {
  "base-sepolia": {
    chainId: 84532,
    usdc: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    faucet: "https://faucet.circle.com (USDC) · https://www.alchemy.com/faucets/base-sepolia (ETH gas)",
  },
};

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

  const agentId = args.requestedBy?.trim() || "MCP agent";
  const who = args.requestedBy ? `${args.requestedBy} (MCP agent)` : "MCP agent";

  const ttl =
    typeof args.ttl === "number" && args.ttl > 0
      ? Math.min(Math.floor(args.ttl), MAX_TTL_SECONDS)
      : 0;

  if (ttl > 0) {
    const grant = findMcpGrant(agentId, args.project);
    if (grant) {
      const vars = Object.fromEntries(
        args.keys.map((k) => [k, proj.vars[k].value]),
      );
      return textResult({
        tool: "get_secrets",
        project: args.project,
        approved: true,
        grantedVia: "session-grant",
        remainingSec: Math.max(0, Math.round((grant.expiresAt - Date.now()) / 1000)),
        vars,
        note: "treat these values as secrets; do not log or echo them",
      });
    }
  }

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

  if (ttl > 0) {
    issueMcpGrant(agentId, args.project, ttl);
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
async function generateWallet(args: { project: string; payTo?: boolean; chain?: string }) {
  try {
    const vault = await loadVault();
    const chain = args.chain ? CHAINS[args.chain] : undefined;
    if (args.chain && !chain) {
      return textResult(
        { error: `unknown chain "${args.chain}". Supported: ${Object.keys(CHAINS).join(", ")}` },
        true,
      );
    }
    const wallets = await generateWalletsIntoProject(vault, args.project, {
      count: "1",
      payTo: args.payTo,
    });
    return textResult({
      tool: "generate_wallet",
      format:
        '{ wallets: [{ address, varPrefix }] } — private key stored encrypted as EVM_PRIVATE_KEY<varPrefix>',
      project: args.project,
      chain: chain
        ? {
            name: args.chain,
            chainId: chain.chainId,
            usdcAddress: chain.usdc,
            funding: `fund with testnet USDC + ETH for gas — ${chain.faucet}`,
          }
        : undefined,
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

/** Mint a fresh scoped Cloudflare Account Owned API token and store it in a project. */
async function generateCloudflareToken(args: {
  project: string;
  perms?: string[];
  expiresInDays?: number;
  requestedBy?: string;
}) {
  try {
    const who = args.requestedBy ? `${args.requestedBy} (MCP agent)` : "MCP agent";
    await authenticate(
      `abracadabra: ${who} mints a fresh Cloudflare API token for "${args.project}"`,
    );
    const vault = await loadVault();
    const result = await mintCloudflareTokenIntoProject(vault, args.project, {
      perms: args.perms?.join(","),
      expiresIn: args.expiresInDays && args.expiresInDays > 0 ? String(args.expiresInDays) : undefined,
    });
    return textResult({
      tool: "generate_cloudflare_token",
      format:
        '{ tokenId, tokenName, scopes, expiresOn } — the token VALUE is stored encrypted in the vault as CLOUDFLARE_API_TOKEN; fetch via get_secrets',
      project: args.project,
      ...result,
      note: "token value never returned here — request CLOUDFLARE_API_TOKEN via get_secrets",
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("denied") || msg.includes("cancel") || msg.includes("biometric")) {
      return textResult(
        { error: "user denied or timed out biometric approval", approved: false },
        true,
      );
    }
    return textResult({ error: msg, approved: false }, true);
  }
}

/** Generate a fresh SSH ed25519 keypair locally and store it in the vault. */
async function generateSshKey(args: { project: string; count?: number; comment?: string }) {
  try {
    const vault = await loadVault();
    const keys = await generateSshKeysIntoProject(vault, args.project, {
      count: String(args.count ?? 1),
      comment: args.comment,
    });
    return textResult({
      tool: "generate_ssh_key",
      format:
        '{ keys: [{ varSuffix, publicKey, comment }] } — private key stored encrypted as SSH_PRIVATE_KEY<varSuffix>; fetch via get_secrets',
      project: args.project,
      keys: keys.map((k) => ({
        varSuffix: k.varSuffix,
        publicKey: k.publicKey,
        comment: k.comment,
      })),
      note: "public keys are safe to share; never log the private key",
    });
  } catch (err) {
    return textResult(
      { error: err instanceof Error ? err.message : String(err) },
      true,
    );
  }
}

/**
 * Check a provider connection and return setup instructions when missing.
 * Read-only: the human runs `abra connect` / `abra issue` themselves —
 * connecting a provider always requires interactive secret entry.
 */
async function requestConnection(args: { provider: string; project?: string }) {
  const provider = providers[args.provider];
  if (!provider) {
    return textResult(
      { error: `unknown provider "${args.provider}". Available: ${Object.keys(providers).join(", ")}` },
      true,
    );
  }

  const payload: Record<string, unknown> = {
    tool: "request_connection",
    provider: provider.id,
    label: provider.label,
    varsIssued: provider.fields.filter((f) => f.required !== false).map((f) => f.varName),
  };

  // Connection metadata only — key names and labels, never secret values.
  const vault = await loadVault();
  const conn = vault.connections?.[provider.id];
  if (conn) {
    payload.connected = true;
    if (conn.label) payload.connectionLabel = conn.label;
    payload.note =
      "Provider is connected. Request the issued vars via get_secrets after storing them in a project " +
      `(user runs: abra issue ${provider.id} ${args.project ?? "<project>"}).`;
  } else {
    payload.connected = false;
    payload.setup = {
      portalUrl: provider.portalUrl,
      steps: [
        `User creates the credential${provider.portalUrl ? ` at ${provider.portalUrl}` : ""} (dashboard — agents cannot do this step)`,
        `User runs: abra connect ${provider.id}   # pastes the credential once, stored AES-256-GCM`,
        args.project
          ? `User runs: abra issue ${provider.id} ${args.project}   # Touch ID gate → vars into project "${args.project}"`
          : `User runs: abra issue ${provider.id} <project>   # Touch ID gate → vars into a project`,
        "Agent then calls get_secrets({ project, keys }) — Touch ID approval still required per read",
      ],
      fields: provider.fields.map((f) => ({
        varName: f.varName,
        prompt: f.prompt,
        required: f.required ?? false,
      })),
    };
    if (args.project) {
      const proj = vault.projects[args.project];
      payload.projectStatus = proj
        ? {
            exists: true,
            hasVars: Object.keys(proj.vars).filter((k) =>
              provider.fields.some((f) => f.varName === k),
            ),
          }
        : { exists: false, createWith: `abra project new ${args.project}` };
    }
  }
  return textResult(payload);
}

async function listGrants() {
  return textResult({
    tool: "list_grants",
    grants: listMcpGrants().map((g) => ({
      agentId: g.agentId,
      project: g.project,
      remainingSec: g.remainingSec,
    })),
    note: "MCP session grants are in-memory for this abra mcp process only — separate from HTTP grants on abra serve",
  });
}

export async function startMcpServer(): Promise<void> {
  const server = new McpServer({
    name: "abracadabra",
    version: "1.0.0",
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
    "list_grants",
    "List active MCP session grants (silent re-access windows issued via get_secrets with ttl). Read-only, no Touch ID.",
    {},
    async () => listGrants(),
  );

  server.tool(
    "generate_wallet",
    `Generate a fresh EVM wallet with local Foundry (cast) and store it encrypted in a project.
Args: { project: string, payTo?: boolean, chain?: string }
Returns { wallets: [{ address, varSuffix, payToSet }] }; private key lands as EVM_PRIVATE_KEY<varSuffix>.
Pass chain (e.g. "base-sepolia") to get chainId + USDC contract + faucet info for funding the wallet.`,
    {
      project: z.string().describe("project to store the wallet in"),
      payTo: z.boolean().optional().describe("also set PAY_TO_ADDRESS to the new address"),
      chain: z.enum(["base-sepolia"]).optional()
        .describe("target chain — response includes chainId, USDC address and faucet hints"),
    },
    async (args) => generateWallet(args),
  );

  server.tool(
    "request_connection",
    `Check whether a provider (cloudflare, cdp, digitalocean, nvidia, openrouter, vercel) is connected to the vault.
If connected: tells you which vars it issues so you can get_secrets them.
If not: returns exact setup steps + portal URL for the user to connect it.
Read-only — connecting always requires the user's interactive action.`,
    {
      provider: z.string().describe("provider id, e.g. cloudflare"),
      project: z.string().optional()
        .describe("project the issued vars would land in — response includes its status"),
    },
    async (args) => requestConnection(args),
  );

  server.tool(
    "generate_cloudflare_token",
    `Mint a FRESH Cloudflare Account Owned API token scoped to Workers deploys and store it encrypted in a project as CLOUDFLARE_API_TOKEN.
Requires the vault's cloudflare connection to be an Account Owned Token with "API Tokens Write".
Pops a Touch ID dialog the user must approve. The token VALUE is never returned here —
afterwards call get_secrets({ project, keys: ["CLOUDFLARE_API_TOKEN"] }) to use it.`,
    {
      project: z.string().describe("project to store the token in"),
      perms: z.array(z.string()).optional()
        .describe('Cloudflare permission-group names (default: ["Workers Scripts Edit", "Account Settings Read"])'),
      expiresInDays: z.number().int().positive().optional()
        .describe("expire the minted token after N days"),
      requestedBy: z.string().optional().describe("your agent/app name, shown in the approval dialog"),
    },
    async (args) => generateCloudflareToken(args),
  );

  server.tool(
    "generate_ssh_key",
    `Generate a fresh SSH ed25519 keypair with the system ssh-keygen and store it encrypted in a project.
Args: { project: string, count?: number, comment?: string }
Returns { keys: [{ varSuffix, publicKey, comment }] }; the private key lands as SSH_PRIVATE_KEY<varSuffix> —
request it via get_secrets when needed. Add the public key to a host's ~/.ssh/authorized_keys to grant access.`,
    {
      project: z.string().describe("project to store the keypair in"),
      count: z.number().int().positive().max(20).optional().describe("number of keypairs (suffixes _1…_n)"),
      comment: z.string().optional().describe("key comment/label (default: <project>@<hostname>)"),
    },
    async (args) => generateSshKey(args),
  );

  await server.connect(new StdioServerTransport());
  // stderr only — stdout carries the MCP protocol
  console.error(`✦ abracadabra MCP server ready (stdio)`);
}
