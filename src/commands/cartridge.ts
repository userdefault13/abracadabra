import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { prompt, promptHidden } from "../core/prompt.js";
import { readActivation } from "../license/store.js";
import { isEthAddress } from "../license/config.js";
import {
  buildCheckpointState,
  buildFullCheckpointState,
  extractSealedVault,
} from "../cartridge/checkpoint.js";
import { buildCheckpointSignMessage } from "../cartridge/checkpoint-crypto.js";
import {
  ensureCartridge,
  fetchRules,
  getCartridge,
  readCartridgeMeta,
  saveCheckpoint,
} from "../cartridge/client.js";
import { openBundle } from "../core/backup.js";
import { decryptEnvelope, writeEncryptedFile } from "../core/vault.js";
import { restoreMasterKey, authenticate } from "../platform/index.js";
import { syncStateFile } from "../core/paths.js";

const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;

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
  const gameState = (snap.checkpoint as { gameState?: unknown } | undefined)?.gameState;
  const sealed = extractSealedVault(gameState);
  console.log(
    JSON.stringify(
      {
        local: meta,
        remote: snap,
        hasSealedVault: Boolean(sealed),
      },
      null,
      2,
    ),
  );
}

export async function cmdCartridgeCheckpoint(opts: {
  wallet?: string;
  label?: string;
  signature?: string;
  dryRun?: boolean;
  full?: boolean;
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

  let gameState;
  if (opts.full) {
    const pass1 = await promptHidden("Passphrase to seal full vault for cartridge (min 8, hidden): ");
    if (pass1.length < 8) fail("Passphrase must be at least 8 characters");
    if ((await promptHidden("Repeat passphrase: ")) !== pass1) fail("Passphrases do not match");
    await authenticate("abracadabra: export sealed vault to cartridge checkpoint");
    gameState = await buildFullCheckpointState(owner, pass1);
  } else {
    gameState = await buildCheckpointState(owner);
  }

  const gameStateRecord = gameState as unknown as Record<string, unknown>;
  const message = buildCheckpointSignMessage({
    cartridgeId: meta.cartridgeId,
    nonce,
    gameState: gameStateRecord,
  });

  if (opts.dryRun) {
    // Never dump sealed vault ciphertext into dry-run stdout in full — summarize
    if (opts.full && gameState.schemaVersion === 2 && gameState.sealedVault) {
      const { sealedVault, ...rest } = gameState;
      console.log(
        JSON.stringify(
          {
            gameState: { ...rest, sealedVault: { format: sealedVault.format, present: true } },
            message,
          },
          null,
          2,
        ),
      );
    } else {
      console.log(JSON.stringify({ gameState, message }, null, 2));
    }
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
  console.log(green(`✓ checkpoint nonce ${nonce}${opts.full ? " (full vault sealed)" : ""}`));
  console.log(dim(JSON.stringify(result.checkpoint ?? result, null, 2)));
}

export async function cmdCartridgeRestore(opts: { wallet?: string }): Promise<void> {
  const owner = await resolveOwnerWallet(opts.wallet);
  let meta = readCartridgeMeta();
  if (!meta || meta.owner !== owner) {
    await cmdCartridgeEnsure(owner);
    meta = readCartridgeMeta();
  }
  if (!meta) fail("cartridge ensure did not persist metadata");

  const remote = await getCartridge(meta.cartridgeId);
  const gameState = (remote.checkpoint as { gameState?: unknown } | undefined)?.gameState;
  const sealed = extractSealedVault(gameState);
  if (!sealed) {
    fail("Latest checkpoint has no sealed vault — create one with: abra cartridge checkpoint --full");
  }

  let payload;
  for (let attempt = 1; attempt <= 3; attempt++) {
    const pass = await promptHidden(
      `Sealed vault passphrase (hidden)${attempt > 1 ? `, attempt ${attempt}/3` : ""}: `,
    );
    try {
      payload = openBundle(sealed, pass);
      break;
    } catch {
      if (attempt === 3) fail("Wrong passphrase (3 attempts)");
      console.error(red("✗ Wrong passphrase"));
    }
  }
  if (!payload) fail("Failed to open sealed vault");

  const vault = decryptEnvelope(payload.vaultEnc, Buffer.from(payload.masterKey, "base64"));
  const nVars = Object.values(vault.projects).reduce((n, p) => n + Object.keys(p.vars).length, 0);
  console.log(
    `\nCartridge vault from ${bold(payload.meta.hostname)} — ${new Date(payload.meta.createdAt).toLocaleString()}`,
  );
  console.log(`  ${Object.keys(vault.projects).length} project(s), ${nVars} var(s)`);

  const answer = await prompt(
    red("This OVERWRITES your local vault AND master key. Type 'yes' to continue: "),
  );
  if (answer.trim().toLowerCase() !== "yes") {
    console.log(dim("Aborted"));
    return;
  }
  await authenticate("abracadabra: restore vault from cartridge checkpoint");
  await restoreMasterKey(Buffer.from(payload.masterKey, "base64"));
  writeEncryptedFile(payload.vaultEnc);
  fs.rmSync(syncStateFile(), { force: true });
  console.log(green("✓ Restored vault and master key from cartridge"));
}
