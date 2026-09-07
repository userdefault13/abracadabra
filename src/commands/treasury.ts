import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Command } from "commander";
import {
  loadVault,
  saveVault,
  TREASURY_PROJECT,
  type Vault,
} from "../core/vault.js";
import { authenticate } from "../platform/index.js";
import { isEthAddress, normalizeAddress } from "../license/config.js";

const execFileAsync = promisify(execFile);

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;

function fail(err: unknown): never {
  console.error(red(`✗ ${err instanceof Error ? err.message : String(err)}`));
  process.exit(1);
}

/** Base mainnet USDC (Circle). */
export const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
export const BASE_RPC =
  process.env.ABRA_TREASURY_RPC?.trim() ||
  process.env.ABRA_LICENSE_RPC?.trim() ||
  "https://mainnet.base.org";
export const USDC_DECIMALS = 6;

const ADDRESS_VAR = "TREASURY_ADDRESS";
const PRIVATE_KEY_VAR = "TREASURY_PRIVATE_KEY";

interface CastWallet {
  address: string;
  private_key: string;
}

async function castNewWallet(): Promise<CastWallet> {
  try {
    const { stdout } = await execFileAsync("cast", ["wallet", "new", "--json"]);
    const parsed = JSON.parse(stdout) as CastWallet[];
    if (!Array.isArray(parsed) || parsed.length === 0 || !parsed[0].address) {
      throw new Error("unexpected cast wallet new output");
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

function ensureCastAvailable(err: unknown): never {
  if (err instanceof Error && "code" in err && (err as { code?: string }).code === "ENOENT") {
    throw new Error(
      "foundry's `cast` not found on PATH. Install: curl -L https://foundry.paradigm.xyz | sh && foundryup",
    );
  }
  throw err instanceof Error ? err : new Error(String(err));
}

/** Parse a human USDC amount (e.g. "0.008") into base units (6 decimals). */
export function parseUsdcAmount(amount: string): bigint {
  const raw = amount.trim();
  if (!/^\d+(\.\d+)?$/.test(raw)) {
    throw new Error(`Invalid USDC amount: ${amount}`);
  }
  const [whole, frac = ""] = raw.split(".");
  if (frac.length > USDC_DECIMALS) {
    throw new Error(`USDC amount has more than ${USDC_DECIMALS} decimal places: ${amount}`);
  }
  const padded = frac.padEnd(USDC_DECIMALS, "0");
  const units = BigInt(whole) * 10n ** BigInt(USDC_DECIMALS) + BigInt(padded || "0");
  if (units <= 0n) throw new Error("Amount must be greater than zero");
  return units;
}

export function formatUsdcUnits(units: bigint): string {
  const neg = units < 0n;
  const abs = neg ? -units : units;
  const whole = abs / 10n ** BigInt(USDC_DECIMALS);
  const frac = (abs % 10n ** BigInt(USDC_DECIMALS)).toString().padStart(USDC_DECIMALS, "0");
  const trimmed = frac.replace(/0+$/, "") || "0";
  return `${neg ? "-" : ""}${whole}.${trimmed}`;
}

function treasuryExists(vault: Vault): boolean {
  const p = vault.projects[TREASURY_PROJECT];
  return Boolean(p?.vars[ADDRESS_VAR]?.value && p?.vars[PRIVATE_KEY_VAR]?.value);
}

export function readTreasuryAddress(vault: Vault): string {
  const p = vault.projects[TREASURY_PROJECT];
  const addr = p?.vars[ADDRESS_VAR]?.value;
  if (!addr) {
    throw new Error(`Treasury not initialized. Run: abra treasury init`);
  }
  return addr;
}

/** Load private key after caller has already authenticated. Never log this. */
function readTreasuryPrivateKey(vault: Vault): string {
  const p = vault.projects[TREASURY_PROJECT];
  const pk = p?.vars[PRIVATE_KEY_VAR]?.value;
  if (!pk) {
    throw new Error(`Treasury not initialized. Run: abra treasury init`);
  }
  return pk;
}

export async function initTreasury(opts: { force?: boolean } = {}): Promise<{
  address: string;
  created: boolean;
}> {
  const vault = await loadVault();
  if (treasuryExists(vault) && !opts.force) {
    const address = readTreasuryAddress(vault);
    return { address, created: false };
  }

  if (treasuryExists(vault) && opts.force) {
    await authenticate(
      `abracadabra: regenerate abra treasury wallet (replaces ${readTreasuryAddress(vault)})`,
    );
  }

  const wallet = await castNewWallet();
  const now = Date.now();
  if (!vault.projects[TREASURY_PROJECT]) {
    vault.projects[TREASURY_PROJECT] = { createdAt: now, vars: {} };
  }
  const project = vault.projects[TREASURY_PROJECT];
  project.vars[ADDRESS_VAR] = { value: wallet.address, secret: false, updatedAt: now };
  project.vars[PRIVATE_KEY_VAR] = { value: wallet.private_key, secret: true, updatedAt: now };
  await saveVault(vault);
  return { address: wallet.address, created: true };
}

export interface TreasuryStatus {
  address: string;
  usdc: string;
  usdcRaw: string;
  eth: string;
  ethWei: string;
  rpc: string;
  usdcContract: string;
}

async function castBalanceEth(address: string): Promise<{ eth: string; wei: string }> {
  try {
    const { stdout } = await execFileAsync("cast", [
      "balance",
      address,
      "--ether",
      "--rpc-url",
      BASE_RPC,
    ]);
    const eth = stdout.trim();
    const { stdout: weiOut } = await execFileAsync("cast", [
      "balance",
      address,
      "--rpc-url",
      BASE_RPC,
    ]);
    return { eth, wei: weiOut.trim() };
  } catch (err) {
    ensureCastAvailable(err);
  }
}

async function castUsdcBalance(address: string): Promise<bigint> {
  try {
    const { stdout } = await execFileAsync("cast", [
      "call",
      BASE_USDC,
      "balanceOf(address)(uint256)",
      address,
      "--rpc-url",
      BASE_RPC,
    ]);
    const raw = stdout.trim().split(/\s+/)[0] ?? "0";
    // cast may print "123 [1.23e2]" or plain integer / hex
    if (raw.startsWith("0x")) return BigInt(raw);
    return BigInt(raw.replace(/_/g, ""));
  } catch (err) {
    ensureCastAvailable(err);
  }
}

export async function getTreasuryStatus(): Promise<TreasuryStatus> {
  const vault = await loadVault();
  const address = readTreasuryAddress(vault);
  const [ethBal, usdcRaw] = await Promise.all([
    castBalanceEth(address),
    castUsdcBalance(address),
  ]);
  return {
    address,
    usdc: formatUsdcUnits(usdcRaw),
    usdcRaw: usdcRaw.toString(),
    eth: ethBal.eth,
    ethWei: ethBal.wei,
    rpc: BASE_RPC,
    usdcContract: BASE_USDC,
  };
}

export function paymentAuthReason(args: {
  to: string;
  amountUsdc: string;
  reason: string;
}): string {
  return `abracadabra treasury: pay ${args.amountUsdc} USDC to ${args.to} — ${args.reason}`;
}

export interface TreasuryPaymentResult {
  approved: true;
  txHash: string;
  from: string;
  to: string;
  amountUsdc: string;
}

/**
 * Biometric-gated Base USDC transfer from the abra treasury.
 * Never returns or logs the private key.
 */
export async function payFromTreasury(args: {
  to: string;
  amountUsdc: string;
  reason: string;
}): Promise<TreasuryPaymentResult> {
  const to = normalizeAddress(args.to);
  const amountUsdc = args.amountUsdc.trim();
  const reason = args.reason.trim();
  if (!reason) throw new Error("--reason is required");
  const units = parseUsdcAmount(amountUsdc);

  await authenticate(paymentAuthReason({ to, amountUsdc, reason }));

  const vault = await loadVault();
  const from = readTreasuryAddress(vault);
  const privateKey = readTreasuryPrivateKey(vault);

  let stdout: string;
  try {
    const result = await execFileAsync(
      "cast",
      [
        "send",
        BASE_USDC,
        "transfer(address,uint256)",
        to,
        units.toString(),
        "--private-key",
        privateKey,
        "--rpc-url",
        BASE_RPC,
        "--json",
      ],
      { maxBuffer: 2 * 1024 * 1024 },
    );
    stdout = result.stdout;
  } catch (err) {
    if (err instanceof Error && "code" in err && (err as { code?: string }).code === "ENOENT") {
      throw new Error(
        "foundry's `cast` not found on PATH. Install: curl -L https://foundry.paradigm.xyz | sh && foundryup",
      );
    }
    const stderr =
      err && typeof err === "object" && "stderr" in err
        ? String((err as { stderr: unknown }).stderr)
        : "";
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(stderr.trim() || msg);
  } finally {
    // best-effort: drop local ref (GC); never print
    void privateKey;
  }

  let txHash = "";
  try {
    const parsed = JSON.parse(stdout) as { transactionHash?: string; hash?: string };
    txHash = parsed.transactionHash || parsed.hash || "";
  } catch {
    // fall through to regex
  }
  if (!txHash) {
    const m = stdout.match(/0x[a-fA-F0-9]{64}/);
    if (m) txHash = m[0];
  }
  if (!txHash) {
    throw new Error("cast send succeeded but no transaction hash was returned");
  }

  return { approved: true, txHash, from, to, amountUsdc };
}

export function registerTreasuryCommands(program: Command): void {
  const treasury = program
    .command("treasury")
    .description("User-funded abra treasury wallet (Base USDC) — biometric-gated spends");

  treasury
    .command("init")
    .description("Create the reserved __abra_treasury__ wallet if missing")
    .option("--force", "regenerate wallet (Touch ID; orphaned on-chain funds)")
    .action(async (opts: { force?: boolean }) => {
      try {
        const result = await initTreasury({ force: opts.force });
        if (!result.created) {
          console.log(green(`✓ treasury already initialized`));
          console.log(`  ${bold(result.address)}`);
          console.log(dim("  re-run with --force to regenerate (requires Touch ID)"));
        } else {
          console.log(green(`✓ abra treasury wallet created → ${TREASURY_PROJECT}`));
          console.log(`  ${bold(result.address)}`);
          console.log(dim(`  ${ADDRESS_VAR} (public), ${PRIVATE_KEY_VAR} (secret)`));
        }
        console.log();
        console.log(dim("Fund this address on Base mainnet with:"));
        console.log(dim(`  • USDC (${BASE_USDC})`));
        console.log(dim("  • a tiny amount of ETH for gas"));
        console.log(dim("Then: abra treasury status"));
      } catch (err) {
        fail(err);
      }
    });

  treasury
    .command("address")
    .description("Print the treasury public address")
    .action(async () => {
      try {
        const vault = await loadVault();
        console.log(readTreasuryAddress(vault));
      } catch (err) {
        fail(err);
      }
    });

  treasury
    .command("status")
    .description("Show treasury address + Base USDC + ETH balances")
    .action(async () => {
      try {
        const status = await getTreasuryStatus();
        console.log(`${bold("address")}  ${status.address}`);
        console.log(`${bold("USDC")}     ${status.usdc}  ${dim(`(Base ${BASE_USDC})`)}`);
        console.log(`${bold("ETH")}      ${status.eth}  ${dim("(gas)")}`);
        console.log(dim(`rpc ${status.rpc}`));
      } catch (err) {
        fail(err);
      }
    });

  treasury
    .command("pay")
    .description("Send Base USDC from treasury (Touch ID: amount + destination + reason)")
    .requiredOption("--to <address>", "destination 0x address")
    .requiredOption("--amount <usdc>", "USDC amount, e.g. 0.008")
    .requiredOption("--reason <text>", "human-readable reason shown in Touch ID prompt")
    .action(async (opts: { to: string; amount: string; reason: string }) => {
      try {
        if (!isEthAddress(opts.to.trim())) {
          fail(`Invalid destination address: ${opts.to}`);
        }
        const result = await payFromTreasury({
          to: opts.to,
          amountUsdc: opts.amount,
          reason: opts.reason,
        });
        console.log(green(`✓ paid ${result.amountUsdc} USDC`));
        console.log(dim(`  from ${result.from}`));
        console.log(dim(`  to   ${result.to}`));
        console.log(`  tx   ${bold(result.txHash)}`);
      } catch (err) {
        fail(err);
      }
    });
}
