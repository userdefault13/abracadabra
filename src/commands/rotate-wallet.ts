/**
 * Interactive / scripted EVM deployer key rotation.
 *
 *   abra rotate-wallet <project> [--dry-run] [--no-transfer] [--rpc-url …]
 *   abra rotate-wallet <project> --purge-legacy [--key …]
 *
 * Never prints private keys. Touch ID gates mutate steps.
 */
import { Command } from "commander";
import { loadVault, saveVault, assertProject, type Project, type Vault } from "../core/vault.js";
import { authenticate } from "../platform/index.js";
import { prompt } from "../core/prompt.js";
import { castNewWallet } from "./keygen.js";
import {
  castBalanceEth,
  castBalanceWei,
  castSend,
  formatEthWei,
  BASE_RPC,
} from "./treasury.js";

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`;

/** Leave enough ETH for one more self-transfer if needed. */
const GAS_RESERVE_WEI = 50_000n * 5_000_000_000n; // 50k gas * 5 gwei

export interface WalletPair {
  id: string;
  addressVar: string;
  privateKeyVar: string;
  address: string;
  legacyAddressVar: string;
  legacyPrivateKeyVar: string;
  /** Project-specific aliases to rewrite to the new address (same value as old). */
  aliasAddressVars: string[];
}

function fail(err: unknown): never {
  console.error(red(`✗ ${err instanceof Error ? err.message : String(err)}`));
  process.exit(1);
}

function shortAddr(a: string): string {
  if (!a || a.length < 12) return a || "(none)";
  return `${a.slice(0, 6)}…${a.slice(-4)}`;
}

/** Detect rotatable EVM key pairs in a project (never returns key values). */
export function detectWalletPairs(project: Project): WalletPair[] {
  const keys = Object.keys(project.vars);
  const pairs: WalletPair[] = [];
  const seenPk = new Set<string>();

  const add = (
    addressVar: string,
    privateKeyVar: string,
    aliasAddressVars: string[] = [],
  ) => {
    if (seenPk.has(privateKeyVar)) return;
    if (!project.vars[privateKeyVar]?.value) return;
    const address = String(project.vars[addressVar]?.value || "").trim();
    seenPk.add(privateKeyVar);

    let legacyAddressVar: string;
    let legacyPrivateKeyVar: string;
    if (privateKeyVar === "EVM_PRIVATE_KEY") {
      legacyAddressVar = "EVM_ADDRESS_LEGACY";
      legacyPrivateKeyVar = "EVM_PRIVATE_KEY_LEGACY";
    } else if (/^EVM_PRIVATE_KEY(_\d+)$/.test(privateKeyVar)) {
      const num = RegExp.$1;
      legacyAddressVar = `EVM_ADDRESS${num}_LEGACY`;
      legacyPrivateKeyVar = `EVM_PRIVATE_KEY${num}_LEGACY`;
    } else {
      const prefix = privateKeyVar.replace(/_PRIVATE_KEY(_\d+)?$/i, "");
      const num = (/(_\d+)$/.exec(privateKeyVar) || [])[1] || "";
      legacyAddressVar = `${prefix}_ADDRESS${num}_LEGACY`;
      legacyPrivateKeyVar = `${prefix}_PRIVATE_KEY${num}_LEGACY`;
    }

    pairs.push({
      id: privateKeyVar,
      addressVar,
      privateKeyVar,
      address,
      legacyAddressVar,
      legacyPrivateKeyVar,
      aliasAddressVars: aliasAddressVars.filter((v) => v !== addressVar),
    });
  };

  if (project.vars.EVM_PRIVATE_KEY) {
    add("EVM_ADDRESS", "EVM_PRIVATE_KEY", ["PAY_TO_ADDRESS"]);
  }

  for (const k of keys) {
    const m = /^EVM_PRIVATE_KEY(_\d+)$/.exec(k);
    if (m) add(`EVM_ADDRESS${m[1]}`, k);
  }

  for (const k of keys) {
    if (k === "EVM_PRIVATE_KEY" || /^EVM_PRIVATE_KEY_/.test(k)) continue;
    if (k === "TREASURY_PRIVATE_KEY" || k === "SSH_PRIVATE_KEY") continue;
    if (/_LEGACY$/i.test(k)) continue;
    if (!/_PRIVATE_KEY$/i.test(k) && !/_PRIVATE_KEY_\d+$/i.test(k)) continue;

    const prefix = k.replace(/_PRIVATE_KEY(_\d+)?$/i, "");
    const num = (/(_\d+)$/.exec(k) || [])[1] || "";
    const candidates = [
      `${prefix}_WALLET_ADDRESS${num}`,
      `${prefix}_ADDRESS${num}`,
      `${prefix}_WALLET${num}`,
      "EVM_ADDRESS",
    ];
    const addressVar = candidates.find((c) => project.vars[c]?.value) || candidates[0];
    add(addressVar, k, candidates.filter((c) => c !== addressVar));
  }

  return pairs;
}

async function pickPair(pairs: WalletPair[], preferId?: string): Promise<WalletPair> {
  if (preferId) {
    const hit = pairs.find((p) => p.id === preferId || p.privateKeyVar === preferId);
    if (hit) return hit;
  }
  if (pairs.length === 1) return pairs[0];
  console.log(bold("Rotatable wallets in this project:"));
  pairs.forEach((p, i) => {
    console.log(`  ${i + 1}) ${p.privateKeyVar}  →  ${shortAddr(p.address) || "(no address var)"}`);
  });
  const ans = (await prompt("Pick number (or q to cancel): ")).trim();
  if (ans.toLowerCase() === "q") {
    console.log("Cancelled.");
    process.exit(0);
  }
  const n = Number(ans);
  if (!Number.isFinite(n) || n < 1 || n > pairs.length) fail("Invalid pick");
  return pairs[n - 1];
}

export async function rotateWalletIntoProject(
  vault: Vault,
  projectName: string,
  pair: WalletPair,
  opts: {
    rpcUrl?: string;
    transferEth?: boolean;
    dryRun?: boolean;
  } = {},
): Promise<{ oldAddress: string; newAddress: string; ethMovedWei: string }> {
  const project = assertProject(vault, projectName);
  const oldPk = project.vars[pair.privateKeyVar]?.value;
  if (!oldPk) throw new Error(`Missing ${pair.privateKeyVar}`);
  const oldAddress = String(project.vars[pair.addressVar]?.value || pair.address || "").trim();

  const rpc = opts.rpcUrl || process.env.ABRA_ROTATE_RPC || BASE_RPC;
  // treasury castBalance* reads ABRA_TREASURY_RPC / BASE_RPC
  if (opts.rpcUrl || process.env.ABRA_ROTATE_RPC) {
    process.env.ABRA_TREASURY_RPC = rpc;
  }

  if (opts.dryRun) {
    return { oldAddress, newAddress: "(dry-run)", ethMovedWei: "0" };
  }

  await authenticate(
    `abracadabra: rotate wallet ${projectName} ${pair.privateKeyVar} (${shortAddr(oldAddress) || "new"})`,
  );

  const wallet = await castNewWallet();
  const now = Date.now();

  if (oldPk) {
    project.vars[pair.legacyPrivateKeyVar] = {
      value: oldPk,
      secret: true,
      updatedAt: now,
    };
  }
  if (oldAddress) {
    project.vars[pair.legacyAddressVar] = {
      value: oldAddress,
      secret: false,
      updatedAt: now,
    };
  }

  project.vars[pair.privateKeyVar] = {
    value: wallet.private_key,
    secret: true,
    updatedAt: now,
  };
  project.vars[pair.addressVar] = {
    value: wallet.address,
    secret: false,
    updatedAt: now,
  };

  for (const alias of pair.aliasAddressVars) {
    const cur = String(project.vars[alias]?.value || "").trim();
    if (cur && oldAddress && cur.toLowerCase() === oldAddress.toLowerCase()) {
      project.vars[alias] = { value: wallet.address, secret: false, updatedAt: now };
    }
  }
  const payTo = String(project.vars.PAY_TO_ADDRESS?.value || "").trim();
  if (payTo && oldAddress && payTo.toLowerCase() === oldAddress.toLowerCase()) {
    project.vars.PAY_TO_ADDRESS = {
      value: wallet.address,
      secret: false,
      updatedAt: now,
    };
  }

  await saveVault(vault);

  let ethMovedWei = 0n;
  if (opts.transferEth !== false && oldAddress && oldPk) {
    try {
      const wei = await castBalanceWei(oldAddress);
      if (wei > GAS_RESERVE_WEI) {
        const sendWei = wei - GAS_RESERVE_WEI;
        await castSend(
          [wallet.address, "--value", `${sendWei}wei`, "--rpc-url", rpc],
          oldPk,
        );
        ethMovedWei = sendWei;
      }
    } catch (e) {
      console.log(
        yellow(
          `⚠ ETH sweep skipped: ${e instanceof Error ? e.message : e} — move funds manually from ${shortAddr(oldAddress)} → ${shortAddr(wallet.address)}`,
        ),
      );
    }
  }

  return {
    oldAddress,
    newAddress: wallet.address,
    ethMovedWei: ethMovedWei.toString(),
  };
}

export async function purgeLegacyPair(
  vault: Vault,
  projectName: string,
  pair: WalletPair,
): Promise<void> {
  const project = assertProject(vault, projectName);
  await authenticate(
    `abracadabra: purge legacy wallet keys ${projectName} ${pair.legacyPrivateKeyVar}`,
  );
  delete project.vars[pair.legacyPrivateKeyVar];
  delete project.vars[pair.legacyAddressVar];
  await saveVault(vault);
}

async function rotateWalletCli(
  projectName: string,
  opts: {
    dryRun?: boolean;
    noTransfer?: boolean;
    rpcUrl?: string;
    key?: string;
    purgeLegacy?: boolean;
  },
): Promise<void> {
  try {
    const vault = await loadVault();
    const project = assertProject(vault, projectName);
    const pairs = detectWalletPairs(project);
    if (!pairs.length) {
      fail(
        `No EVM private keys found in ${projectName}. Generate one with: abra keygen foundry ${projectName}`,
      );
    }

    const pair = await pickPair(pairs, opts.key);

    if (opts.purgeLegacy) {
      if (!project.vars[pair.legacyPrivateKeyVar]) {
        fail(`No ${pair.legacyPrivateKeyVar} to purge`);
      }
      const ans = (
        await prompt(
          `Delete ${pair.legacyPrivateKeyVar} + ${pair.legacyAddressVar}? This cannot be undone. [y/N] `,
        )
      )
        .trim()
        .toLowerCase();
      if (ans !== "y") {
        console.log("Cancelled.");
        return;
      }
      await purgeLegacyPair(vault, projectName, pair);
      console.log(green(`✓ purged legacy keys for ${pair.privateKeyVar}`));
      return;
    }

    let balNote = "";
    if (pair.address) {
      try {
        const b = await castBalanceEth(pair.address);
        balNote = ` · ${b.eth} ETH`;
      } catch {
        balNote = " · (balance n/a)";
      }
    }

    console.log("");
    console.log(bold(`Rotate wallet in ${projectName}`));
    console.log(`  key      ${pair.privateKeyVar}`);
    console.log(`  address  ${pair.addressVar} = ${pair.address || "(missing)"}${balNote}`);
    console.log(`  legacy → ${pair.legacyPrivateKeyVar} / ${pair.legacyAddressVar}`);
    console.log(
      dim(
        "  After rotate: transfer contract ownership from old → new on-chain, then purge legacy.",
      ),
    );
    console.log("");

    if (opts.dryRun) {
      console.log(yellow("Dry run — no Touch ID, no vault writes."));
      return;
    }

    const ans = (await prompt("Generate new key, archive old as *_LEGACY, update vault? [y/N] "))
      .trim()
      .toLowerCase();
    if (ans !== "y") {
      console.log("Cancelled.");
      return;
    }

    const result = await rotateWalletIntoProject(vault, projectName, pair, {
      rpcUrl: opts.rpcUrl,
      transferEth: !opts.noTransfer,
      dryRun: false,
    });

    console.log(green(`✓ rotated ${pair.privateKeyVar}`));
    console.log(`  old  ${result.oldAddress || "(none)"}  →  ${pair.legacyAddressVar}`);
    console.log(`  new  ${bold(result.newAddress)}`);
    if (result.ethMovedWei !== "0") {
      console.log(dim(`  moved ${formatEthWei(BigInt(result.ethMovedWei))} ETH to new address`));
    }
    console.log("");
    console.log(bold("Next (on-chain — abra cannot do this for you):"));
    console.log(`  1. Transfer diamond/minter owner from old → ${result.newAddress}`);
    console.log(`  2. Fund new address with gas`);
    console.log(
      `  3. When safe: abra rotate-wallet ${projectName} --purge-legacy --key ${pair.privateKeyVar}`,
    );
    console.log(dim(`  Deploy keeps working via abra run (injects the new key).`));
  } catch (e) {
    fail(e);
  }
}

export function registerRotateWalletCommands(program: Command): void {
  program
    .command("rotate-wallet <project>")
    .description(
      "Rotate an EVM deployer key: archive old as *_LEGACY, generate new (Touch ID). Optional ETH sweep.",
    )
    .option("--dry-run", "List pair + balance; no auth, no writes")
    .option("--no-transfer", "Do not move remaining ETH from old → new")
    .option("--rpc-url <url>", "RPC for balance/sweep (default Base mainnet)")
    .option("--key <var>", "Private key var name to rotate (skip picker)")
    .option("--purge-legacy", "Delete *_LEGACY keys after ownership transfer is done")
    .action(
      async (
        project: string,
        opts: {
          dryRun?: boolean;
          noTransfer?: boolean;
          rpcUrl?: string;
          key?: string;
          purgeLegacy?: boolean;
        },
      ) => {
        await rotateWalletCli(project, opts);
      },
    );
}
