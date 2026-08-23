import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { loadVault, saveVault, assertProject } from "../core/vault.js";

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
}

const keygens: Record<string, (projectName: string, opts: KeygenOptions) => Promise<void>> = {
  foundry: keygenFoundry,
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
