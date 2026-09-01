import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadVault, saveVault, assertProject, assertConnection } from "../core/vault.js";
import type { Vault } from "../core/vault.js";
import { authenticate } from "../platform/index.js";

const execFileAsync = promisify(execFile);

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;

interface KeygenWallet {
  address: string;
  private_key: string;
}

async function castNewWallet(): Promise<KeygenWallet> {
  try {
    const { stdout } = await execFileAsync("cast", ["wallet", "new", "--json"]);
    const parsed = JSON.parse(stdout) as KeygenWallet[];
    if (!Array.isArray(parsed) || parsed.length === 0 || !parsed[0].address) {
      throw new Error("unexpected cast output");
    }
    return parsed[0];
  } catch (err) {
    if (err instanceof Error && "code" in err && (err as { code?: string }).code === "ENOENT") {
      throw new Error(
        "foundry's `cast` not found on PATH. Install: curl -L https://foundry.paradigm.xyz | sh && foundryup",
      );
    }
    throw err;
  }
}

interface KeygenOptions {
  payTo?: boolean;
  count?: string;
  perms?: string;
  expiresIn?: string;
  account?: string;
  comment?: string;
}

const keygens: Record<string, (projectName: string, opts: KeygenOptions) => Promise<void>> = {
  foundry: keygenFoundry,
  cloudflare: keygenCloudflare,
  ssh: keygenSsh,
};

export async function keygen(provider: string, projectName: string, opts: KeygenOptions): Promise<void> {
  const fn = keygens[provider];
  if (!fn) {
    console.error(`\x1b[31m✗ Unknown keygen provider "${provider}". Available: ${Object.keys(keygens).join(", ")}\x1b[0m`);
    process.exit(1);
  }
  await fn(projectName, opts);
}

export interface GeneratedWallet {
  varSuffix: string;
  address: string;
  setPayTo: boolean;
}

/**
 * Core wallet generation: writes to the vault and RETURNS results.
 * No printing — safe for reuse inside the MCP stdio server.
 */
export async function generateWalletsIntoProject(
  vault: import("../core/vault.js").Vault,
  projectName: string,
  opts: KeygenOptions,
): Promise<GeneratedWallet[]> {
  const project = assertProject(vault, projectName);
  const count = Math.max(1, Math.min(Number(opts.count ?? 1) || 1, 20));
  const results: GeneratedWallet[] = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    const wallet = await castNewWallet();
    const suffix = count > 1 ? `_${i + 1}` : "";
    project.vars[`EVM_ADDRESS${suffix}`] = {
      value: wallet.address,
      secret: false,
      updatedAt: now,
    };
    project.vars[`EVM_PRIVATE_KEY${suffix}`] = {
      value: wallet.private_key,
      secret: true,
      updatedAt: now,
    };
    const setPayTo = opts.payTo === true && i === 0;
    if (setPayTo) {
      project.vars.PAY_TO_ADDRESS = {
        value: wallet.address,
        secret: false,
        updatedAt: now,
      };
    }
    results.push({ varSuffix: suffix, address: wallet.address, setPayTo });
  }

  await saveVault(vault);
  return results;
}

export async function keygenFoundry(projectName: string, opts: KeygenOptions): Promise<void> {
  try {
    const vault = await loadVault();
    const wallets = await generateWalletsIntoProject(vault, projectName, opts);
    for (const w of wallets) {
      console.log(green(`✓ generated wallet ${bold(w.address)} → ${projectName}`));
      console.log(dim(`  EVM_ADDRESS${w.varSuffix} (plain), EVM_PRIVATE_KEY${w.varSuffix} (secret)`));
      if (w.setPayTo) console.log(dim(`  PAY_TO_ADDRESS set`));
    }
    console.log(dim(`Private keys are stored encrypted — reveal with: abra get ${projectName} EVM_PRIVATE_KEY`));
  } catch (err) {
    console.error(`\x1b[31m✗ ${err instanceof Error ? err.message : String(err)}\x1b[0m`);
    process.exit(1);
  }
}

// ── ssh: local Ed25519 keypairs via the system ssh-keygen ───────────────────

export interface GeneratedSshKey {
  varSuffix: string;
  publicKey: string;
  comment: string;
}

/**
 * Core SSH key generation: writes to the vault and RETURNS results.
 * No printing — safe for reuse inside the MCP stdio server.
 */
export async function generateSshKeysIntoProject(
  vault: Vault,
  projectName: string,
  opts: KeygenOptions,
): Promise<GeneratedSshKey[]> {
  const project = assertProject(vault, projectName);
  const count = Math.max(1, Math.min(Number(opts.count ?? 1) || 1, 20));
  const results: GeneratedSshKey[] = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    const suffix = count > 1 ? `_${i + 1}` : "";
    const comment = opts.comment ?? `${projectName}${suffix}@${os.hostname()}`;
    const { publicKey, privateKey } = await sshKeygenPair(comment);
    project.vars[`SSH_PRIVATE_KEY${suffix}`] = { value: privateKey, secret: true, updatedAt: now };
    project.vars[`SSH_PUBLIC_KEY${suffix}`] = { value: publicKey, secret: false, updatedAt: now };
    results.push({ varSuffix: suffix, publicKey, comment });
  }

  await saveVault(vault);
  return results;
}

async function sshKeygenPair(comment: string): Promise<{ publicKey: string; privateKey: string }> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "abra-ssh-"));
  const file = path.join(dir, "id_ed25519");
  try {
    try {
      await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", file]);
    } catch (err) {
      if (err instanceof Error && "code" in err && (err as { code?: string }).code === "ENOENT") {
        throw new Error("ssh-keygen not found on PATH (comes with macOS / OpenSSH)");
      }
      throw err;
    }
    return {
      privateKey: fs.readFileSync(file, "utf8"),
      publicKey: fs.readFileSync(`${file}.pub`, "utf8").trim(),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

export async function keygenSsh(projectName: string, opts: KeygenOptions): Promise<void> {
  try {
    const vault = await loadVault();
    const keys = await generateSshKeysIntoProject(vault, projectName, opts);
    for (const k of keys) {
      console.log(green(`✓ generated ed25519 key (${k.comment}) → ${projectName}`));
      console.log(dim(`  ${k.publicKey}`));
      console.log(dim(`  SSH_PRIVATE_KEY${k.varSuffix} (secret), SSH_PUBLIC_KEY${k.varSuffix} (plain)`));
    }
    console.log(dim(`Private keys are stored encrypted — reveal with: abra get ${projectName} SSH_PRIVATE_KEY`));
  } catch (err) {
    console.error(`\x1b[31m✗ ${err instanceof Error ? err.message : String(err)}\x1b[0m`);
    process.exit(1);
  }
}

// ── cloudflare: mint a fresh account-owned API token per project ───────────

export interface CloudflareTokenResult {
  tokenId: string;
  tokenName: string;
  scopes: string[];
  expiresOn?: string;
}

const CF_API = "https://api.cloudflare.com/client/v4";

/**
 * Mint a fresh Cloudflare Account Owned API token via the API and store it in
 * the project as CLOUDFLARE_API_TOKEN (+ CLOUDFLARE_ACCOUNT_ID). Requires the
 * connected cloudflare credential to itself be an Account Owned Token with the
 * "API Tokens Write" permission — user tokens cannot mint user tokens.
 */
export async function mintCloudflareTokenIntoProject(
  vault: Vault,
  projectName: string,
  opts: { perms?: string; expiresIn?: string; account?: string },
): Promise<CloudflareTokenResult> {
  const project = assertProject(vault, projectName);
  const conn = assertConnection(vault, "cloudflare");
  const adminToken = conn.vars.CLOUDFLARE_API_TOKEN?.value;
  if (!adminToken) throw new Error("cloudflare connection has no CLOUDFLARE_API_TOKEN stored");
  const accountId = opts.account || conn.vars.CLOUDFLARE_ACCOUNT_ID?.value || "";
  if (!accountId) throw new Error("No Cloudflare account ID known — pass --account <id>");

  const wanted = (opts.perms ?? "Workers Scripts Edit,Account Settings Read")
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);

  // resolve human-readable permission names → group ids
  const gRes = await fetch(`${CF_API}/accounts/${accountId}/tokens/permission_groups`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  const gData = (await gRes.json()) as {
    success?: boolean;
    result?: { id: string; name: string }[];
    errors?: { message: string }[];
  };
  if (!gRes.ok || !gData.success || !gData.result) {
    throw new Error(
      `Cannot list Cloudflare permission groups: ${gData.errors?.[0]?.message ?? gRes.status}`,
    );
  }
  const groupIds: string[] = [];
  for (const want of wanted) {
    const match = gData.result.find((g) => g.name.toLowerCase() === want.toLowerCase());
    if (!match) {
      throw new Error(
        `Unknown Cloudflare permission "${want}". Available groups: ${gData.result.map((g) => g.name).join(", ")}`,
      );
    }
    groupIds.push(match.id);
  }

  const body: Record<string, unknown> = {
    name: `abra-${projectName}`,
    policies: [
      {
        effect: "allow",
        resources: { "com.cloudflare.edge.account": accountId },
        permission_groups: groupIds,
      },
    ],
  };
  const days = Number(opts.expiresIn ?? 0);
  if (days > 0) body.expires_on = new Date(Date.now() + days * 86_400_000).toISOString();

  const res = await fetch(`${CF_API}/accounts/${accountId}/tokens`, {
    method: "POST",
    headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = (await res.json()) as {
    success?: boolean;
    result?: { id: string; value?: string; expires_on?: string };
    errors?: { code: number; message: string }[];
  };
  if (!res.ok || !data.success || !data.result?.value) {
    const msg = data.errors?.map((e) => `[${e.code}] ${e.message}`).join("; ") ?? `HTTP ${res.status}`;
    throw new Error(
      `Cloudflare token creation failed: ${msg}\n` +
        `  The connected CLOUDFLARE_API_TOKEN must be an Account Owned Token with\n` +
        `  "API Tokens Write" permission — create one at dash.cloudflare.com →\n` +
        `  your account → Manage Account → Account API Tokens, then: abra connect cloudflare`,
    );
  }

  const now = Date.now();
  project.vars.CLOUDFLARE_API_TOKEN = { value: data.result.value, secret: true, updatedAt: now };
  project.vars.CLOUDFLARE_ACCOUNT_ID = { value: accountId, secret: false, updatedAt: now };
  await saveVault(vault);
  return {
    tokenId: data.result.id,
    tokenName: `abra-${projectName}`,
    scopes: wanted,
    expiresOn: data.result.expires_on,
  };
}

export async function keygenCloudflare(projectName: string, opts: KeygenOptions): Promise<void> {
  try {
    await authenticate(`abracadabra: mint a fresh Cloudflare API token for "${projectName}"`);
    const vault = await loadVault();
    const result = await mintCloudflareTokenIntoProject(vault, projectName, opts);
    console.log(green(`✓ minted Cloudflare token ${bold(result.tokenName)} (${result.tokenId}) → ${projectName}`));
    console.log(dim(`  scope: ${result.scopes.join(", ")}`));
    if (result.expiresOn) console.log(dim(`  expires: ${new Date(result.expiresOn).toLocaleString()}`));
    console.log(dim(`  stored as CLOUDFLARE_API_TOKEN (secret) + CLOUDFLARE_ACCOUNT_ID`));
    console.log(dim(`  deploy with: abra run ${projectName} -- npx wrangler deploy`));
  } catch (err) {
    console.error(`\x1b[31m✗ ${err instanceof Error ? err.message : String(err)}\x1b[0m`);
    process.exit(1);
  }
}
