import { execFileSync } from "node:child_process";
import { prompt } from "../core/prompt.js";
import { readActivation } from "../license/store.js";
import { isEthAddress } from "../license/config.js";
import { buildCheckpointState } from "../cartridge/checkpoint.js";
import { buildCheckpointSignMessage } from "../cartridge/checkpoint-crypto.js";
import {
  ensureCartridge,
  fetchRules,
  getCartridge,
  readCartridgeMeta,
  saveCheckpoint,
} from "../cartridge/client.js";

const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;

function fail(msg: string): never {
  console.error(red(`✗ ${msg}`));
  process.exit(1);
}

async function resolveOwnerWallet(explicit?: string): Promise<string> {
  const fromArg = explicit?.trim();
  if (fromArg) {
    if (!isEthAddress(fromArg)) fail("Invalid wallet address");
    return fromArg.toLowerCase();
  }
  const activation = readActivation();
  if (activation?.wallet) return activation.wallet.toLowerCase();
  const entered = (await prompt("Wallet (Abra License holder, 0x…): ")).trim();
  if (!isEthAddress(entered)) fail("Invalid wallet address");
  return entered.toLowerCase();
}

async function signCheckpointMessage(wallet: string, message: string, signatureArg?: string): Promise<string> {
  if (signatureArg?.trim()) return signatureArg.trim();

  const pk = process.env.ABRA_CHECKPOINT_PRIVATE_KEY?.trim();
  if (pk) {
    try {
      return execFileSync("cast", ["wallet", "sign", message, "--private-key", pk], {
        encoding: "utf8",
      }).trim();
    } catch {
      fail("cast wallet sign failed with ABRA_CHECKPOINT_PRIVATE_KEY");
    }
  }

  console.log(dim("Sign this message in your wallet (personal_sign / cast wallet sign):"));
  console.log(message);
  console.log("");
  const pasted = (await prompt("Paste signature (0x…): ")).trim();
  if (!pasted.startsWith("0x")) fail("Invalid signature");
  return pasted;
}

export async function cmdCartridgeRules(): Promise<void> {
  const rules = await fetchRules();
  console.log(JSON.stringify(rules, null, 2));
}

export async function cmdCartridgeEnsure(walletArg?: string): Promise<void> {
  const owner = await resolveOwnerWallet(walletArg);
  console.error(dim(`▸ ensuring abracadabra cartridge for ${owner}…`));
  const snap = await ensureCartridge(owner);
  console.log(green(`✓ cartridge ${String(snap.cartridgeId || "?")}`));
}

export async function cmdCartridgeStatus(): Promise<void> {
  const meta = readCartridgeMeta();
  if (!meta) {
    console.log(dim("No local cartridge — run: abra cartridge ensure"));
    return;
  }
  const snap = await getCartridge(meta.cartridgeId);
  console.log(JSON.stringify({ local: meta, remote: snap }, null, 2));
}

export async function cmdCartridgeCheckpoint(opts: {
  wallet?: string;
  label?: string;
  signature?: string;
  dryRun?: boolean;
}): Promise<void> {
  const owner = await resolveOwnerWallet(opts.wallet);
  let meta = readCartridgeMeta();
  if (!meta || meta.owner !== owner) {
    await cmdCartridgeEnsure(owner);
    meta = readCartridgeMeta();
  }
  if (!meta) fail("cartridge ensure did not persist metadata");

  const remote = await getCartridge(meta.cartridgeId);
  const nonce = Number((remote.checkpoint as { nonce?: number } | undefined)?.nonce || 0) + 1;
  const gameState = await buildCheckpointState(owner);
  const gameStateRecord = gameState as unknown as Record<string, unknown>;
  const message = buildCheckpointSignMessage({
    cartridgeId: meta.cartridgeId,
    nonce,
    gameState: gameStateRecord,
  });

  if (opts.dryRun) {
    console.log(JSON.stringify({ gameState, message }, null, 2));
    return;
  }

  const signature = await signCheckpointMessage(owner, message, opts.signature);
  const result = await saveCheckpoint({
    cartridgeId: meta.cartridgeId,
    gameState: gameStateRecord,
    message,
    signature,
    label: opts.label,
  });
  console.log(green(`✓ checkpoint nonce ${nonce}`));
  console.log(dim(JSON.stringify(result.checkpoint ?? result, null, 2)));
}
