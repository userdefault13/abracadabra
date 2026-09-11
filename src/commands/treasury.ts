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
export const ETH_DECIMALS = 18;

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

/** Parse a human decimal amount (e.g. "0.008") into base units with `decimals` places. */
export function parseDecimalAmount(amount: string, decimals: number, label: string): bigint {
  const raw = amount.trim();
  if (!/^\d+(\.\d+)?$/.test(raw)) {
    throw new Error(`Invalid ${label} amount: ${amount}`);
  }
  const [whole, frac = ""] = raw.split(".");
  if (frac.length > decimals) {
    throw new Error(`${label} amount has more than ${decimals} decimal places: ${amount}`);
  }
  const padded = frac.padEnd(decimals, "0");
  const units = BigInt(whole) * 10n ** BigInt(decimals) + BigInt(padded || "0");
  if (units <= 0n) throw new Error("Amount must be greater than zero");
  return units;
}

/** Parse a human USDC amount (e.g. "0.008") into base units (6 decimals). */
export function parseUsdcAmount(amount: string): bigint {
  return parseDecimalAmount(amount, USDC_DECIMALS, "USDC");
}

/** Parse a human ETH amount (e.g. "0.00002") into wei. */
export function parseEthAmount(amount: string): bigint {
  return parseDecimalAmount(amount, ETH_DECIMALS, "ETH");
}

export function formatUnits(units: bigint, decimals: number): string {
  const neg = units < 0n;
  const abs = neg ? -units : units;
  const whole = abs / 10n ** BigInt(decimals);
  const frac = (abs % 10n ** BigInt(decimals)).toString().padStart(decimals, "0");
  const trimmed = frac.replace(/0+$/, "") || "0";
  return `${neg ? "-" : ""}${whole}.${trimmed}`;
}

export function formatUsdcUnits(units: bigint): string {
  return formatUnits(units, USDC_DECIMALS);
}

export function formatEthWei(wei: bigint): string {
  return formatUnits(wei, ETH_DECIMALS);
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

async function castBalanceWei(address: string): Promise<bigint> {
  const { wei } = await castBalanceEth(address);
  return BigInt(wei.trim().split(/\s+/)[0] ?? "0");
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

/**
 * Run `cast send <args…> --private-key <key> --rpc-url <rpc> --json` and return the tx hash.
 * The key is passed as a process argument only; it is never logged or echoed.
 */
async function castSend(args: string[], privateKey: string): Promise<string> {
  let stdout: string;
  try {
    const result = await execFileAsync(
      "cast",
      ["send", ...args, "--private-key", privateKey, "--rpc-url", BASE_RPC, "--json"],
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
  }

  let txHash = "";
  try {
    const parsed = JSON.parse(stdout) as {
      transactionHash?: string;
      hash?: string;
      status?: string | number;
    };
    txHash = parsed.transactionHash || parsed.hash || "";
    const st = parsed.status;
    if (st !== undefined && st !== 1 && st !== "0x1" && !String(st).startsWith("1")) {
      throw new Error(`transaction ${txHash || "(unknown)"} reverted (status ${String(st)})`);
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes("reverted")) throw err;
    // fall through to regex
  }
  if (!txHash) {
    const m = stdout.match(/0x[a-fA-F0-9]{64}/);
    if (m) txHash = m[0];
  }
  if (!txHash) {
    throw new Error("cast send succeeded but no transaction hash was returned");
  }
  return txHash;
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

  const txHash = await castSend(
    [BASE_USDC, "transfer(address,uint256)", to, units.toString()],
    privateKey,
  );

  return { approved: true, txHash, from, to, amountUsdc };
}

/** Source wallet must hold at least this much ETH to pay for one USDC transfer on Base. */
export const MIN_SOURCE_GAS_WEI = 5_000_000_000_000n; // 0.000005 ETH
/** Default gas top-up sent from the treasury when the source wallet is under MIN_SOURCE_GAS_WEI. */
export const DEFAULT_GAS_TOPUP_ETH = "0.00002";

export interface RefillPlanInput {
  sourceUsdc: bigint;
  sourceEthWei: bigint;
  treasuryEthWei: bigint;
  /** Human USDC amount; omit to sweep the full balance. */
  amountUsdc?: string;
  /** Human ETH amount for the gas top-up; omit to disable top-ups. */
  gasTopupEth?: string;
}

export interface RefillPlan {
  amountUnits: bigint;
  needsTopup: boolean;
  topupWei: bigint;
}

/** Pure planning step for `abra treasury refill` (no I/O, no keys). */
export function planRefill(input: RefillPlanInput): RefillPlan {
  const amountUnits = input.amountUsdc ? parseUsdcAmount(input.amountUsdc) : input.sourceUsdc;
  if (amountUnits > input.sourceUsdc) {
    throw new Error(
      `Source wallet holds ${formatUsdcUnits(input.sourceUsdc)} USDC, cannot refill ${formatUsdcUnits(amountUnits)}`,
    );
  }
  const needsTopup = input.sourceEthWei < MIN_SOURCE_GAS_WEI;
  if (!needsTopup) return { amountUnits, needsTopup: false, topupWei: 0n };
  if (!input.gasTopupEth) {
    throw new Error(
      `Source wallet holds ${formatEthWei(input.sourceEthWei)} ETH (< ${formatEthWei(MIN_SOURCE_GAS_WEI)}) and gas top-up is disabled`,
    );
  }
  const topupWei = parseEthAmount(input.gasTopupEth);
  // keep a matching reserve in the treasury so it can still pay for its own top-up tx
  if (input.treasuryEthWei < topupWei * 2n) {
    throw new Error(
      `Treasury holds ${formatEthWei(input.treasuryEthWei)} ETH, not enough to send a ${formatEthWei(topupWei)} ETH gas top-up`,
    );
  }
  return { amountUnits, needsTopup: true, topupWei };
}

export interface RefillResult {
  project: string;
  from: string;
  to: string;
  amountUsdc: string;
  sourceUsdcBefore: string;
  sourceEthBefore: string;
  treasuryUsdcBefore: string;
  treasuryUsdcAfter?: string;
  gasTopupEth?: string;
  gasTopupTx?: string;
  txHash?: string;
  dryRun: boolean;
}

export function refillAuthReason(args: {
  project: string;
  from: string;
  amountUsdc: string;
  topupEth?: string;
}): string {
  const gas = args.topupEth ? ` (+${args.topupEth} ETH gas top-up from treasury)` : "";
  return `abracadabra treasury: refill ${args.amountUsdc} USDC from ${args.project} ${args.from}${gas}`;
}

/**
 * Sweep Base USDC from a project wallet (EVM_ADDRESS / EVM_PRIVATE_KEY, optional suffix)
 * into the abra treasury. One Touch ID prompt covers the optional gas top-up and the transfer.
 * Private keys are handed to `cast` as process arguments only and are never logged.
 */
export async function refillTreasury(args: {
  project: string;
  suffix?: string;
  amountUsdc?: string;
  gasTopupEth?: string;
  dryRun?: boolean;
}): Promise<RefillResult> {
  const project = args.project.trim();
  const suffix = args.suffix?.trim() ?? "";
  const addressVar = `EVM_ADDRESS${suffix}`;
  const keyVar = `EVM_PRIVATE_KEY${suffix}`;

  const vault = await loadVault();
  if (project === TREASURY_PROJECT) throw new Error("Cannot refill the treasury from itself");
  const p = vault.projects[project];
  if (!p) throw new Error(`Project "${project}" not found`);
  const fromRaw = p.vars[addressVar]?.value;
  if (!fromRaw) throw new Error(`Project "${project}" has no ${addressVar}`);
  if (!p.vars[keyVar]?.value) throw new Error(`Project "${project}" has no ${keyVar}`);
  const from = fromRaw.trim();
  if (!isEthAddress(from)) throw new Error(`Project "${project}" ${addressVar} is not a 0x address`);
  const to = readTreasuryAddress(vault).trim();

  // sequential: the public Base RPC rate-limits bursts of parallel calls
  const sourceUsdc = await castUsdcBalance(from);
  const sourceEthWei = await castBalanceWei(from);
  const treasuryUsdc = await castUsdcBalance(to);
  const treasuryEthWei = await castBalanceWei(to);

  const base: RefillResult = {
    project,
    from,
    to,
    amountUsdc: formatUsdcUnits(0n),
    sourceUsdcBefore: formatUsdcUnits(sourceUsdc),
    sourceEthBefore: formatEthWei(sourceEthWei),
    treasuryUsdcBefore: formatUsdcUnits(treasuryUsdc),
    dryRun: Boolean(args.dryRun),
  };

  if (sourceUsdc === 0n && !args.amountUsdc) {
    return base; // nothing to sweep
  }

  const plan = planRefill({
    sourceUsdc,
    sourceEthWei,
    treasuryEthWei,
    amountUsdc: args.amountUsdc,
    gasTopupEth: args.gasTopupEth,
  });
  const amountUsdc = formatUsdcUnits(plan.amountUnits);
  const gasTopupEth = plan.needsTopup ? formatEthWei(plan.topupWei) : undefined;

  if (args.dryRun) {
    return { ...base, amountUsdc, gasTopupEth };
  }

  await authenticate(refillAuthReason({ project, from, amountUsdc, topupEth: gasTopupEth }));

  // re-read after auth so the keys are only held for the duration of the sends
  const fresh = await loadVault();
  const sourceKey = fresh.projects[project]?.vars[keyVar]?.value;
  if (!sourceKey) throw new Error(`Project "${project}" has no ${keyVar}`);

  let gasTopupTx: string | undefined;
  if (plan.needsTopup) {
    const treasuryKey = readTreasuryPrivateKey(fresh);
    gasTopupTx = await castSend([from, "--value", plan.topupWei.toString()], treasuryKey);
  }

  const txHash = await castSend(
    [BASE_USDC, "transfer(address,uint256)", to, plan.amountUnits.toString()],
    sourceKey,
  );

  const treasuryUsdcAfter = formatUsdcUnits(await castUsdcBalance(to));
  return { ...base, amountUsdc, gasTopupEth, gasTopupTx, txHash, treasuryUsdcAfter };
}

interface RefillCliOpts {
  suffix?: string;
  amount?: string;
  gasTopup?: string | boolean;
  dryRun?: boolean;
  json?: boolean;
}

async function runRefillCli(project: string, opts: RefillCliOpts): Promise<void> {
  try {
    const gasTopupEth =
      opts.gasTopup === false
        ? undefined
        : typeof opts.gasTopup === "string"
          ? opts.gasTopup
          : DEFAULT_GAS_TOPUP_ETH;
    const result = await refillTreasury({
      project,
      suffix: opts.suffix,
      amountUsdc: opts.amount,
      gasTopupEth,
      dryRun: opts.dryRun,
    });
    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }
    console.log(dim(`source   ${result.from}  (${result.project})`));
    console.log(dim(`         ${result.sourceUsdcBefore} USDC · ${result.sourceEthBefore} ETH`));
    console.log(dim(`treasury ${result.to}`));
    console.log(dim(`         ${result.treasuryUsdcBefore} USDC`));
    if (result.amountUsdc === formatUsdcUnits(0n)) {
      console.log(green("✓ nothing to refill — source wallet holds no USDC"));
      return;
    }
    if (result.dryRun) {
      console.log(bold(`dry run: would refill ${result.amountUsdc} USDC`));
      if (result.gasTopupEth) {
        console.log(dim(`  + ${result.gasTopupEth} ETH gas top-up from treasury first`));
      }
      console.log(dim("re-run without --dry-run to execute (Touch ID)"));
      return;
    }
    if (result.gasTopupTx) {
      console.log(green(`✓ gas top-up ${result.gasTopupEth} ETH`));
      console.log(`  tx   ${bold(result.gasTopupTx)}`);
    }
    console.log(green(`✓ refilled ${result.amountUsdc} USDC`));
    console.log(`  tx   ${bold(result.txHash ?? "")}`);
    console.log(dim(`treasury USDC ${result.treasuryUsdcBefore} → ${result.treasuryUsdcAfter}`));
  } catch (err) {
    fail(err);
  }
}

function addRefillOptions(cmd: Command): Command {
  return cmd
    .argument("<project>", "vault project holding EVM_ADDRESS / EVM_PRIVATE_KEY")
    .option("--suffix <s>", "wallet var suffix from `abra keygen foundry -n`, e.g. _1")
    .option("--amount <usdc>", "USDC amount to move (default: full balance)")
    .option(
      "--gas-topup <eth>",
      `ETH sent from treasury when source has < ${formatEthWei(MIN_SOURCE_GAS_WEI)} ETH`,
      DEFAULT_GAS_TOPUP_ETH,
    )
    .option("--no-gas-topup", "fail instead of topping up gas")
    .option("--dry-run", "show balances and plan; no Touch ID, no transactions")
    .option("--json", "machine-readable output");
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

  const refillDesc =
    "Sweep Base USDC from a project wallet into the treasury (Touch ID; auto gas top-up)";
  addRefillOptions(treasury.command("refill").description(refillDesc)).action(runRefillCli);
  addRefillOptions(program.command("refill").description(`${refillDesc} — alias of treasury refill`)).action(runRefillCli);
}
