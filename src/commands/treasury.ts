import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Command } from "commander";
import {
  loadVault,
  saveVault,
  TREASURY_PROJECT,
  type Vault,
} from "../core/vault.js";
import { runCastWithKeystore, type CastExecFn } from "../core/castWithKeystore.js";
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

export function ensureCastAvailable(err: unknown): never {
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
export function readTreasuryPrivateKey(vault: Vault): string {
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

export async function castBalanceEth(address: string): Promise<{ eth: string; wei: string }> {
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

export async function castBalanceWei(address: string): Promise<bigint> {
  const { wei } = await castBalanceEth(address);
  return BigInt(wei.trim().split(/\s+/)[0] ?? "0");
}

export async function castUsdcBalance(address: string): Promise<bigint> {
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

export type TreasuryAsset = "usdc" | "eth";

/** Source wallet must hold at least this much ETH to pay for one USDC transfer on Base. */
export const MIN_SOURCE_GAS_WEI = 5_000_000_000_000n; // 0.000005 ETH
/** ETH left in the treasury after a native pay so the send itself can pay gas. */
export const ETH_PAY_GAS_RESERVE_WEI = MIN_SOURCE_GAS_WEI;
/** Default gas top-up sent from the treasury when the source wallet is under MIN_SOURCE_GAS_WEI. */
export const DEFAULT_GAS_TOPUP_ETH = "0.00002";

export function paymentAuthReason(args: {
  to: string;
  amount: string;
  reason: string;
  asset?: TreasuryAsset;
}): string {
  const label = (args.asset ?? "usdc") === "eth" ? "ETH" : "USDC";
  return `abracadabra treasury: pay ${args.amount} ${label} to ${args.to} — ${args.reason}`;
}

export interface PlanTreasuryPaymentInput {
  asset?: TreasuryAsset;
  to: string;
  amount: string;
  reason: string;
  treasuryAddress: string;
  ethBalanceWei: bigint;
  usdcBalanceUnits?: bigint;
}

export interface TreasuryPaymentPlan {
  asset: TreasuryAsset;
  to: string;
  amount: string;
  amountUnits: bigint;
  reason: string;
  reserveWei: bigint;
  /** Estimated ETH remaining after the transfer (send amount only; reserve stays for gas). */
  ethBalanceAfterWei: bigint | null;
  usdcBalanceAfterUnits: bigint | null;
  authReason: string;
}

/** Pure planning/validation for `abra treasury pay` (no I/O, no keys). */
export function planTreasuryPayment(input: PlanTreasuryPaymentInput): TreasuryPaymentPlan {
  const assetRaw = (input.asset ?? "usdc").toString().trim().toLowerCase();
  if (assetRaw !== "usdc" && assetRaw !== "eth") {
    throw new Error(`Unsupported asset "${input.asset}". Use --asset usdc|eth`);
  }
  const asset = assetRaw as TreasuryAsset;
  const reason = input.reason.trim();
  if (!reason) throw new Error("--reason is required");
  const amount = input.amount.trim();
  if (!amount) throw new Error("--amount is required");
  if (!isEthAddress(input.to.trim())) {
    throw new Error(`Invalid destination address: ${input.to}`);
  }
  const to = normalizeAddress(input.to);
  const treasury = normalizeAddress(input.treasuryAddress);
  if (to === treasury) {
    throw new Error("Cannot pay the treasury's own address");
  }

  if (asset === "eth") {
    const amountUnits = parseEthAmount(amount);
    const reserveWei = ETH_PAY_GAS_RESERVE_WEI;
    const needed = amountUnits + reserveWei;
    if (needed > input.ethBalanceWei) {
      throw new Error(
        `Treasury holds ${formatEthWei(input.ethBalanceWei)} ETH, need ${formatEthWei(needed)} (${formatEthWei(amountUnits)} + ${formatEthWei(reserveWei)} gas reserve)`,
      );
    }
    return {
      asset,
      to,
      amount,
      amountUnits,
      reason,
      reserveWei,
      ethBalanceAfterWei: input.ethBalanceWei - amountUnits,
      usdcBalanceAfterUnits: null,
      authReason: paymentAuthReason({ to, amount, reason, asset }),
    };
  }

  const amountUnits = parseUsdcAmount(amount);
  if (input.usdcBalanceUnits !== undefined && amountUnits > input.usdcBalanceUnits) {
    throw new Error(
      `Treasury holds ${formatUsdcUnits(input.usdcBalanceUnits)} USDC, cannot pay ${formatUsdcUnits(amountUnits)}`,
    );
  }
  return {
    asset: "usdc",
    to,
    amount,
    amountUnits,
    reason,
    reserveWei: 0n,
    ethBalanceAfterWei: null,
    usdcBalanceAfterUnits:
      input.usdcBalanceUnits !== undefined ? input.usdcBalanceUnits - amountUnits : null,
    authReason: paymentAuthReason({ to, amount, reason, asset: "usdc" }),
  };
}

/**
 * Run `cast send <args…>` via a throwaway keystore (key never on argv).
 * Returns the transaction hash. Never logs the private key.
 * If `args` already include `--rpc-url`, that wins; else uses live env / Base mainnet.
 */
export async function castSend(
  args: string[],
  privateKey: string,
  opts: { exec?: CastExecFn } = {},
): Promise<string> {
  const hasRpc = args.includes("--rpc-url");
  const rpc =
    process.env.ABRA_TREASURY_RPC?.trim() ||
    process.env.ABRA_LICENSE_RPC?.trim() ||
    BASE_RPC;
  const rpcArgs = hasRpc ? [] : ["--rpc-url", rpc];
  let stdout: string;
  try {
    const result = await runCastWithKeystore(
      ["send", ...args, ...rpcArgs, "--json"],
      privateKey,
      { exec: opts.exec },
    );
    stdout = result.stdout;
  } catch (err) {
    throw err instanceof Error ? err : new Error(String(err));
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
  /** Present for USDC pays (MCP + CLI). */
  amountUsdc: string;
  asset: TreasuryAsset;
  amountEth?: string;
  ethAfter?: string;
}

export interface TreasuryPaymentDryRun {
  dryRun: true;
  treasuryAddress: string;
  eth: string;
  ethWei: string;
  usdc: string;
  usdcRaw: string;
  plan: {
    asset: TreasuryAsset;
    amount: string;
    amountUnits: string;
    to: string;
    reason: string;
    reserveWei: string;
    reserveEth: string;
    ethBalanceAfter: string | null;
    usdcBalanceAfter: string | null;
    authReason: string;
  };
}

/**
 * Biometric-gated Base USDC or native ETH transfer from the abra treasury.
 * MCP callers keep `{ to, amountUsdc, reason }` (USDC). Never returns or logs the private key.
 */
export async function payFromTreasury(args: {
  to: string;
  amountUsdc?: string;
  amount?: string;
  asset?: TreasuryAsset;
  reason: string;
  dryRun: true;
}): Promise<TreasuryPaymentDryRun>;
export async function payFromTreasury(args: {
  to: string;
  amountUsdc?: string;
  amount?: string;
  asset?: TreasuryAsset;
  reason: string;
  dryRun?: false;
}): Promise<TreasuryPaymentResult>;
export async function payFromTreasury(args: {
  to: string;
  /** USDC amount — required for the default/MCP USDC path. */
  amountUsdc?: string;
  /** Amount for the selected asset; preferred when `asset` is set. */
  amount?: string;
  asset?: TreasuryAsset;
  reason: string;
  dryRun?: boolean;
}): Promise<TreasuryPaymentResult | TreasuryPaymentDryRun> {
  const asset = (args.asset ?? "usdc") as TreasuryAsset;
  const amount =
    asset === "eth"
      ? (args.amount ?? args.amountUsdc)?.trim()
      : (args.amountUsdc ?? args.amount)?.trim();
  if (!amount) throw new Error("--amount is required");

  // Public address + balances before Touch ID; private key only after authenticate.
  const vault = await loadVault();
  const treasuryAddress = readTreasuryAddress(vault);
  const ethBalanceWei = await castBalanceWei(treasuryAddress);
  const usdcBalanceUnits =
    asset === "usdc" || args.dryRun ? await castUsdcBalance(treasuryAddress) : undefined;

  const plan = planTreasuryPayment({
    asset,
    to: args.to,
    amount,
    reason: args.reason,
    treasuryAddress,
    ethBalanceWei,
    usdcBalanceUnits,
  });

  if (args.dryRun) {
    const usdcRaw = usdcBalanceUnits ?? 0n;
    return {
      dryRun: true,
      treasuryAddress,
      eth: formatEthWei(ethBalanceWei),
      ethWei: ethBalanceWei.toString(),
      usdc: formatUsdcUnits(usdcRaw),
      usdcRaw: usdcRaw.toString(),
      plan: {
        asset: plan.asset,
        amount: plan.amount,
        amountUnits: plan.amountUnits.toString(),
        to: plan.to,
        reason: plan.reason,
        reserveWei: plan.reserveWei.toString(),
        reserveEth: formatEthWei(plan.reserveWei),
        ethBalanceAfter:
          plan.ethBalanceAfterWei !== null ? formatEthWei(plan.ethBalanceAfterWei) : null,
        usdcBalanceAfter:
          plan.usdcBalanceAfterUnits !== null
            ? formatUsdcUnits(plan.usdcBalanceAfterUnits)
            : null,
        authReason: plan.authReason,
      },
    };
  }

  await authenticate(plan.authReason);

  const fresh = await loadVault();
  const from = readTreasuryAddress(fresh);
  const privateKey = readTreasuryPrivateKey(fresh);

  const txHash =
    plan.asset === "eth"
      ? await castSend([plan.to, "--value", plan.amountUnits.toString()], privateKey)
      : await castSend(
          [BASE_USDC, "transfer(address,uint256)", plan.to, plan.amountUnits.toString()],
          privateKey,
        );

  const ethAfter =
    plan.asset === "eth" ? formatEthWei(await castBalanceWei(from)) : undefined;

  return {
    approved: true,
    txHash,
    from,
    to: plan.to,
    amountUsdc: plan.asset === "usdc" ? plan.amount : "",
    asset: plan.asset,
    amountEth: plan.asset === "eth" ? plan.amount : undefined,
    ethAfter,
  };
}

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
 * Private keys reach `cast` via a throwaway keystore env (never on argv) and are never logged.
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
    .description(
      "Send Base USDC or native ETH from treasury (Touch ID: asset + amount + destination + reason)",
    )
    .requiredOption("--to <address>", "destination 0x address")
    .requiredOption("--amount <qty>", "amount, e.g. 0.008 USDC or 0.0006 ETH")
    .requiredOption("--reason <text>", "human-readable reason shown in Touch ID prompt")
    .option("--asset <usdc|eth>", "payment asset (default: usdc)", "usdc")
    .option("--dry-run", "show balances and plan; no Touch ID, no transactions")
    .option("--json", "machine-readable output")
    .action(
      async (opts: {
        to: string;
        amount: string;
        reason: string;
        asset?: string;
        dryRun?: boolean;
        json?: boolean;
      }) => {
        try {
          const assetRaw = (opts.asset ?? "usdc").trim().toLowerCase();
          if (assetRaw !== "usdc" && assetRaw !== "eth") {
            fail(`Unsupported asset "${opts.asset}". Use --asset usdc|eth`);
          }
          const asset = assetRaw as TreasuryAsset;
          const payArgs = {
            to: opts.to,
            amount: opts.amount,
            amountUsdc: asset === "usdc" ? opts.amount : undefined,
            asset,
            reason: opts.reason,
          };
          if (opts.dryRun) {
            const result = await payFromTreasury({ ...payArgs, dryRun: true });
            if (opts.json) {
              console.log(JSON.stringify(result, null, 2));
              return;
            }
            console.log(dim(`treasury ${result.treasuryAddress}`));
            console.log(dim(`         ${result.usdc} USDC · ${result.eth} ETH`));
            console.log(
              bold(
                `dry run: would pay ${result.plan.amount} ${result.plan.asset.toUpperCase()} to ${result.plan.to}`,
              ),
            );
            console.log(dim(`  reason  ${result.plan.reason}`));
            if (result.plan.asset === "eth") {
              console.log(
                dim(
                  `  reserve ${result.plan.reserveEth} ETH · after ≈ ${result.plan.ethBalanceAfter} ETH`,
                ),
              );
            } else if (result.plan.usdcBalanceAfter !== null) {
              console.log(dim(`  after ≈ ${result.plan.usdcBalanceAfter} USDC`));
            }
            console.log(dim("re-run without --dry-run to execute (Touch ID)"));
            return;
          }
          const result = await payFromTreasury(payArgs);
          if (opts.json) {
            console.log(JSON.stringify(result, null, 2));
            return;
          }
          const paid =
            result.asset === "eth"
              ? `${result.amountEth} ETH`
              : `${result.amountUsdc} USDC`;
          console.log(green(`✓ paid ${paid}`));
          console.log(dim(`  from ${result.from}`));
          console.log(dim(`  to   ${result.to}`));
          console.log(`  tx   ${bold(result.txHash)}`);
          if (result.ethAfter !== undefined) {
            console.log(dim(`  treasury ETH now ${result.ethAfter}`));
          }
        } catch (err) {
          fail(err);
        }
      },
    );

  const refillDesc =
    "Sweep Base USDC from a project wallet into the treasury (Touch ID; auto gas top-up)";
  addRefillOptions(treasury.command("refill").description(refillDesc)).action(runRefillCli);
  addRefillOptions(program.command("refill").description(`${refillDesc} — alias of treasury refill`)).action(runRefillCli);
}
