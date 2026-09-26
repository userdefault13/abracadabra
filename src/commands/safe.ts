import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Command } from "commander";
import { loadVault, saveVault, TREASURY_PROJECT, type Vault } from "../core/vault.js";
import { runCastWithKeystore, type CastExecFn } from "../core/castWithKeystore.js";
import { authenticate } from "../platform/index.js";
import { isEthAddress } from "../license/config.js";
import {
  BASE_RPC,
  BASE_USDC,
  castBalanceEth,
  castBalanceWei,
  castSend,
  castUsdcBalance,
  ensureCastAvailable,
  formatEthWei,
  formatUsdcUnits,
  parseUsdcAmount,
  readTreasuryAddress,
  readTreasuryPrivateKey,
} from "./treasury.js";

const execFileAsync = promisify(execFile);

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;

function fail(err: unknown): never {
  console.error(red(`✗ ${err instanceof Error ? err.message : String(err)}`));
  process.exit(1);
}

// ── constants ───────────────────────────────────────────────────────────────

/** Vault var (in __abra_treasury__) holding the linked Safe address. */
export const SAFE_ADDRESS_VAR = "SAFE_ADDRESS";
/** Optional vault var (secret) with a Safe Transaction Service API key (developer.safe.global). */
export const SAFE_API_KEY_VAR = "SAFE_API_KEY";

/** Canonical Safe v1.4.1 deployments — identical addresses on Base and most EVM chains. */
export const SAFE_CONTRACTS = {
  version: "1.4.1",
  singletonL2: "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762",
  proxyFactory: "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67",
  fallbackHandler: "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99",
} as const;

export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

/** Safe Transaction Service for Base mainnet (unauthenticated: 2 rps, 5k req/month). */
export const SAFE_TX_SERVICE =
  process.env.ABRA_SAFE_TX_SERVICE?.trim().replace(/\/+$/, "") ||
  "https://api.safe.global/tx-service/base/api/v1";

/** EIP-3770 chain prefix used by the Safe web app. */
export const SAFE_APP_CHAIN = "base";

export const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";

// ── pure helpers (unit-tested) ──────────────────────────────────────────────

export function safeAppUrl(safe: string): string {
  return `https://app.safe.global/transactions/queue?safe=${SAFE_APP_CHAIN}:${safe}`;
}

/** Parse `cast call … (address[])` output like `[0xabc…, 0xdef…]`. */
export function parseAddressArray(stdout: string): string[] {
  const inner = stdout.trim().replace(/^\[/, "").replace(/\]$/, "");
  return inner
    .split(",")
    .map((s) => s.trim())
    .filter((s) => isEthAddress(s));
}

/** First token of a `cast call` uint output: "123 [1.23e2]" → 123n, "0x…" → BigInt. */
export function parseUintOutput(stdout: string): bigint {
  const raw = stdout.trim().split(/\s+/)[0] ?? "0";
  if (raw.startsWith("0x")) return BigInt(raw);
  return BigInt(raw.replace(/_/g, ""));
}

export interface SafeTx {
  to: string;
  /** wei */
  value: bigint;
  data: string;
  /** 0 = CALL, 1 = DELEGATECALL */
  operation: 0 | 1;
  safeTxGas: bigint;
  baseGas: bigint;
  gasPrice: bigint;
  gasToken: string;
  refundReceiver: string;
  nonce: bigint;
}

/** Build a plain CALL SafeTx with no gas refund parameters. */
export function buildSafeTx(args: {
  to: string;
  data: string;
  nonce: bigint;
  value?: bigint;
}): SafeTx {
  return {
    to: args.to,
    value: args.value ?? 0n,
    data: args.data,
    operation: 0,
    safeTxGas: 0n,
    baseGas: 0n,
    gasPrice: 0n,
    gasToken: ZERO_ADDRESS,
    refundReceiver: ZERO_ADDRESS,
    nonce: args.nonce,
  };
}

/** ABI-encode an ERC-20 `transfer(address,uint256)` call without cast (pure). */
export function encodeErc20Transfer(to: string, units: bigint): string {
  if (!isEthAddress(to)) throw new Error(`Invalid address: ${to}`);
  const addr = to.slice(2).toLowerCase().padStart(64, "0");
  const amt = units.toString(16).padStart(64, "0");
  return `${ERC20_TRANSFER_SELECTOR}${addr}${amt}`;
}

export interface DecodedErc20Transfer {
  to: string;
  units: bigint;
}

/** Decode `transfer(address,uint256)` calldata, or null if it is something else. */
export function decodeErc20Transfer(data: string): DecodedErc20Transfer | null {
  const d = data.trim().toLowerCase();
  if (!d.startsWith(ERC20_TRANSFER_SELECTOR) || d.length !== 2 + 8 + 64 + 64) return null;
  const addrWord = d.slice(10, 74);
  if (!/^0{24}[0-9a-f]{40}$/.test(addrWord)) return null;
  return { to: `0x${addrWord.slice(24)}`, units: BigInt(`0x${d.slice(74)}`) };
}

export interface OwnerSignature {
  owner: string;
  /** 65-byte hex signature (0x + 130 hex chars) */
  signature: string;
}

/**
 * Concatenate owner signatures in the order the Safe contract requires:
 * ascending owner address. Only 65-byte EOA signatures are supported.
 */
export function packSignatures(sigs: OwnerSignature[]): string {
  const seen = new Set<string>();
  const cleaned = sigs.map((s) => {
    const owner = s.owner.toLowerCase();
    if (!isEthAddress(owner)) throw new Error(`Invalid owner address in signature: ${s.owner}`);
    if (seen.has(owner)) throw new Error(`Duplicate signature from owner ${s.owner}`);
    seen.add(owner);
    const sig = s.signature.trim().toLowerCase();
    if (!/^0x[0-9a-f]{130}$/.test(sig)) {
      throw new Error(
        `Unsupported signature from ${s.owner}: expected a 65-byte EOA signature (contract signatures are not supported)`,
      );
    }
    return { owner, sig: sig.slice(2) };
  });
  cleaned.sort((a, b) => (BigInt(a.owner) < BigInt(b.owner) ? -1 : 1));
  return `0x${cleaned.map((c) => c.sig).join("")}`;
}

export type SafePayMode = "execute" | "propose";

/** Decide whether one abra signature is enough to execute, or the tx must be proposed. */
export function planSafePayment(threshold: number): SafePayMode {
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new Error(`Invalid Safe threshold: ${threshold}`);
  }
  return threshold === 1 ? "execute" : "propose";
}

/** Human summary of a SafeTx for Touch ID prompts and CLI output. */
export function describeSafeTx(tx: { to: string; value: bigint; data: string; operation: number }): string {
  const xfer = tx.to.toLowerCase() === BASE_USDC.toLowerCase() ? decodeErc20Transfer(tx.data) : null;
  if (xfer && tx.operation === 0 && tx.value === 0n) {
    return `send ${formatUsdcUnits(xfer.units)} USDC to ${xfer.to}`;
  }
  const kind = tx.operation === 1 ? "DELEGATECALL" : "call";
  const eth = tx.value > 0n ? ` with ${formatEthWei(tx.value)} ETH` : "";
  const bytes = tx.data && tx.data !== "0x" ? ` (${(tx.data.length - 2) / 2} bytes calldata)` : "";
  return `${kind} ${tx.to}${eth}${bytes}`;
}

// ── cast wrappers ───────────────────────────────────────────────────────────

async function cast(args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync("cast", args, { maxBuffer: 4 * 1024 * 1024 });
    return stdout.trim();
  } catch (err) {
    if (err instanceof Error && "code" in err && (err as { code?: string }).code === "ENOENT") {
      ensureCastAvailable(err);
    }
    const stderr =
      err && typeof err === "object" && "stderr" in err
        ? String((err as { stderr: unknown }).stderr).trim()
        : "";
    throw new Error(stderr || (err instanceof Error ? err.message : String(err)));
  }
}

async function castCall(to: string, sig: string, ...args: string[]): Promise<string> {
  return cast(["call", to, sig, ...args, "--rpc-url", BASE_RPC]);
}

async function checksum(addr: string): Promise<string> {
  if (!isEthAddress(addr.trim())) throw new Error(`Invalid Ethereum address: ${addr}`);
  return cast(["to-check-sum-address", addr.trim()]);
}

async function codeSize(addr: string): Promise<number> {
  const code = await cast(["code", addr, "--rpc-url", BASE_RPC]);
  return Math.max(0, (code.length - 2) / 2);
}

/**
 * Sign a 32-byte hash directly (EIP-712 safeTxHash) → 65-byte sig with v ∈ {27,28}.
 * Uses a throwaway keystore so the key never appears on argv. Never logged.
 */
export async function signHash(
  hash: string,
  privateKey: string,
  opts: { exec?: CastExecFn } = {},
): Promise<string> {
  const { stdout } = await runCastWithKeystore(
    ["wallet", "sign", "--no-hash", hash],
    privateKey,
    { exec: opts.exec },
  );
  const sig = stdout.trim();
  if (!/^0x[0-9a-fA-F]{130}$/.test(sig)) throw new Error("unexpected signature output from cast");
  return sig.toLowerCase();
}

// ── on-chain reads ──────────────────────────────────────────────────────────

export interface SafeInfo {
  address: string;
  version: string;
  threshold: number;
  owners: string[];
  nonce: bigint;
}

export async function getSafeInfo(safe: string): Promise<SafeInfo> {
  if ((await codeSize(safe)) === 0) {
    throw new Error(`${safe} has no contract code on Base — not a Safe`);
  }
  let version: string;
  try {
    version = (await castCall(safe, "VERSION()(string)")).replace(/^"|"$/g, "");
  } catch {
    throw new Error(`${safe} does not look like a Safe (no VERSION())`);
  }
  // sequential: the public Base RPC rate-limits bursts of parallel calls
  const owners = parseAddressArray(await castCall(safe, "getOwners()(address[])"));
  const threshold = Number(parseUintOutput(await castCall(safe, "getThreshold()(uint256)")));
  const nonce = parseUintOutput(await castCall(safe, "nonce()(uint256)"));
  if (owners.length === 0 || threshold < 1) throw new Error(`${safe} returned no owners/threshold`);
  return { address: safe, version, threshold, owners, nonce };
}

async function getSafeTxHash(safe: string, tx: SafeTx): Promise<string> {
  const out = await castCall(
    safe,
    "getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256)(bytes32)",
    tx.to,
    tx.value.toString(),
    tx.data,
    String(tx.operation),
    tx.safeTxGas.toString(),
    tx.baseGas.toString(),
    tx.gasPrice.toString(),
    tx.gasToken,
    tx.refundReceiver,
    tx.nonce.toString(),
  );
  const hash = out.split(/\s+/)[0] ?? "";
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error("unexpected getTransactionHash output");
  return hash.toLowerCase();
}

/** Broadcast execTransaction from the treasury EOA (pays gas). Returns the tx hash. */
async function execTransaction(
  safe: string,
  tx: SafeTx,
  packedSignatures: string,
  privateKey: string,
): Promise<string> {
  return castSend(
    [
      safe,
      "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
      tx.to,
      tx.value.toString(),
      tx.data,
      String(tx.operation),
      tx.safeTxGas.toString(),
      tx.baseGas.toString(),
      tx.gasPrice.toString(),
      tx.gasToken,
      tx.refundReceiver,
      packedSignatures,
    ],
    privateKey,
  );
}

// ── vault access ────────────────────────────────────────────────────────────

export function readSafeAddress(vault: Vault): string {
  const addr = vault.projects[TREASURY_PROJECT]?.vars[SAFE_ADDRESS_VAR]?.value?.trim();
  if (!addr) throw new Error("No Safe linked. Run: abra safe link <address> (or abra safe create)");
  return addr;
}

function readSafeApiKey(vault: Vault): string | undefined {
  return (
    process.env.ABRA_SAFE_API_KEY?.trim() ||
    vault.projects[TREASURY_PROJECT]?.vars[SAFE_API_KEY_VAR]?.value?.trim() ||
    undefined
  );
}

async function storeSafeAddress(vault: Vault, address: string): Promise<void> {
  const now = Date.now();
  if (!vault.projects[TREASURY_PROJECT]) {
    vault.projects[TREASURY_PROJECT] = { createdAt: now, vars: {} };
  }
  vault.projects[TREASURY_PROJECT].vars[SAFE_ADDRESS_VAR] = {
    value: address,
    secret: false,
    updatedAt: now,
  };
  await saveVault(vault);
}

// ── Safe Transaction Service ────────────────────────────────────────────────

export interface ServiceConfirmation {
  owner: string;
  signature: string;
  signatureType?: string;
  submissionDate?: string;
}

export interface ServiceMultisigTx {
  safe: string;
  to: string;
  value: string;
  data: string | null;
  operation: number;
  gasToken: string;
  safeTxGas: number | string;
  baseGas: number | string;
  gasPrice: string;
  refundReceiver: string | null;
  nonce: number | string;
  safeTxHash: string;
  isExecuted: boolean;
  isSuccessful?: boolean | null;
  transactionHash?: string | null;
  confirmationsRequired: number;
  confirmations?: ServiceConfirmation[];
  proposer?: string | null;
  submissionDate?: string;
}

async function serviceFetch<T>(
  path: string,
  apiKey: string | undefined,
  init: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(init.body ? { "Content-Type": "application/json" } : {}),
    ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
  };
  let res: Response;
  try {
    res = await fetch(`${SAFE_TX_SERVICE}${path}`, { ...init, headers });
  } catch (err) {
    throw new Error(
      `Safe Transaction Service unreachable (${SAFE_TX_SERVICE}): ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const text = await res.text();
  if (!res.ok) {
    let detail = text.slice(0, 300);
    try {
      const j = JSON.parse(text) as { message?: string; detail?: string; nonFieldErrors?: string[] };
      detail = j.message || j.detail || j.nonFieldErrors?.join("; ") || detail;
    } catch {
      // keep raw
    }
    const hint =
      res.status === 429
        ? " — rate limited; set SAFE_API_KEY in __abra_treasury__ (developer.safe.global)"
        : "";
    throw new Error(`Safe Transaction Service ${res.status}${detail ? `: ${detail}` : ""}${hint}`);
  }
  if (!text.trim()) return undefined as T;
  return JSON.parse(text) as T;
}

/** Convert a service tx record into the on-chain SafeTx struct. */
export function serviceTxToSafeTx(rec: ServiceMultisigTx): SafeTx {
  return {
    to: rec.to,
    value: BigInt(rec.value || "0"),
    data: rec.data && rec.data !== "" ? rec.data : "0x",
    operation: rec.operation === 1 ? 1 : 0,
    safeTxGas: BigInt(rec.safeTxGas ?? 0),
    baseGas: BigInt(rec.baseGas ?? 0),
    gasPrice: BigInt(rec.gasPrice || "0"),
    gasToken: rec.gasToken || ZERO_ADDRESS,
    refundReceiver: rec.refundReceiver || ZERO_ADDRESS,
    nonce: BigInt(rec.nonce),
  };
}

async function proposeToService(args: {
  safe: string;
  tx: SafeTx;
  safeTxHash: string;
  sender: string;
  signature: string;
  apiKey?: string;
}): Promise<void> {
  const body = {
    to: await checksum(args.tx.to),
    value: args.tx.value.toString(),
    data: args.tx.data === "0x" ? null : args.tx.data,
    operation: args.tx.operation,
    gasToken: args.tx.gasToken,
    safeTxGas: Number(args.tx.safeTxGas),
    baseGas: Number(args.tx.baseGas),
    gasPrice: args.tx.gasPrice.toString(),
    refundReceiver: args.tx.refundReceiver,
    nonce: Number(args.tx.nonce),
    contractTransactionHash: args.safeTxHash,
    sender: await checksum(args.sender),
    signature: args.signature,
    origin: "abracadabra",
  };
  await serviceFetch<void>(`/safes/${await checksum(args.safe)}/multisig-transactions/`, args.apiKey, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

async function fetchServiceTx(safeTxHash: string, apiKey?: string): Promise<ServiceMultisigTx> {
  if (!/^0x[0-9a-fA-F]{64}$/.test(safeTxHash.trim())) {
    throw new Error(`Invalid safeTxHash: ${safeTxHash}`);
  }
  return serviceFetch<ServiceMultisigTx>(`/multisig-transactions/${safeTxHash.trim()}/`, apiKey);
}

async function confirmOnService(safeTxHash: string, signature: string, apiKey?: string): Promise<void> {
  await serviceFetch<void>(`/multisig-transactions/${safeTxHash}/confirmations/`, apiKey, {
    method: "POST",
    body: JSON.stringify({ signature }),
  });
}

async function fetchPendingFromService(safe: string, apiKey?: string): Promise<ServiceMultisigTx[]> {
  const res = await serviceFetch<{ results?: ServiceMultisigTx[] }>(
    `/safes/${await checksum(safe)}/multisig-transactions/?executed=false&limit=50&ordering=nonce`,
    apiKey,
  );
  return res?.results ?? [];
}

// ── public operations (CLI + MCP) ───────────────────────────────────────────

export interface SafeStatus {
  address: string;
  version: string;
  threshold: number;
  owners: { address: string; abra: boolean }[];
  signer: string;
  signerIsOwner: boolean;
  nonce: string;
  usdc: string;
  usdcRaw: string;
  eth: string;
  signerEth: string;
  pending?: { safeTxHash: string; nonce: string; summary: string; confirmations: number }[];
  pendingError?: string;
  appUrl: string;
  rpc: string;
  txService: string;
}

export async function getSafeStatus(opts: { pending?: boolean } = {}): Promise<SafeStatus> {
  const vault = await loadVault();
  const safe = readSafeAddress(vault);
  const signer = readTreasuryAddress(vault);
  const info = await getSafeInfo(safe);
  const usdcRaw = await castUsdcBalance(safe);
  const eth = (await castBalanceEth(safe)).eth;
  const signerEth = (await castBalanceEth(signer)).eth;
  const status: SafeStatus = {
    address: safe,
    version: info.version,
    threshold: info.threshold,
    owners: info.owners.map((o) => ({ address: o, abra: o.toLowerCase() === signer.toLowerCase() })),
    signer,
    signerIsOwner: info.owners.some((o) => o.toLowerCase() === signer.toLowerCase()),
    nonce: info.nonce.toString(),
    usdc: formatUsdcUnits(usdcRaw),
    usdcRaw: usdcRaw.toString(),
    eth,
    signerEth,
    appUrl: safeAppUrl(safe),
    rpc: BASE_RPC,
    txService: SAFE_TX_SERVICE,
  };
  if (opts.pending) {
    try {
      const pending = await fetchPendingFromService(safe, readSafeApiKey(vault));
      status.pending = pending.map((p) => ({
        safeTxHash: p.safeTxHash,
        nonce: String(p.nonce),
        summary: describeSafeTx(serviceTxToSafeTx(p)),
        confirmations: p.confirmations?.length ?? 0,
      }));
    } catch (err) {
      status.pendingError = err instanceof Error ? err.message : String(err);
    }
  }
  return status;
}

export interface LinkResult {
  address: string;
  info: SafeInfo;
  signer: string;
  signerIsOwner: boolean;
}

/** Verify an address is a Safe on Base and store it as the abra Safe. */
export async function linkSafe(addressRaw: string): Promise<LinkResult> {
  const vault = await loadVault();
  const signer = readTreasuryAddress(vault);
  const address = await checksum(addressRaw);
  const info = await getSafeInfo(address);
  await storeSafeAddress(vault, address);
  return {
    address,
    info,
    signer,
    signerIsOwner: info.owners.some((o) => o.toLowerCase() === signer.toLowerCase()),
  };
}

export async function unlinkSafe(): Promise<string> {
  const vault = await loadVault();
  const address = readSafeAddress(vault);
  delete vault.projects[TREASURY_PROJECT]?.vars[SAFE_ADDRESS_VAR];
  await saveVault(vault);
  return address;
}

export interface CreateSafeResult {
  address: string;
  owners: string[];
  threshold: number;
  saltNonce: string;
  deployer: string;
  txHash?: string;
  dryRun: boolean;
}

export function createSafeAuthReason(args: { owners: string[]; threshold: number }): string {
  return `abracadabra safe: deploy ${args.threshold}-of-${args.owners.length} Safe on Base (owners ${args.owners.join(", ")}) — gas from treasury`;
}

/**
 * Deploy a Safe v1.4.1 (L2 singleton) via the canonical proxy factory, paid by the treasury EOA.
 * The treasury address is always included as an owner. Links the new Safe on success.
 */
export async function createSafe(args: {
  owners?: string[];
  threshold?: number;
  saltNonce?: string;
  dryRun?: boolean;
}): Promise<CreateSafeResult> {
  const vault = await loadVault();
  const deployer = readTreasuryAddress(vault);
  const existing = vault.projects[TREASURY_PROJECT]?.vars[SAFE_ADDRESS_VAR]?.value;
  if (existing && !args.dryRun) {
    throw new Error(`A Safe is already linked (${existing}). Run: abra safe unlink first`);
  }

  const ownerSet = new Map<string, string>();
  const deployerCk = await checksum(deployer);
  ownerSet.set(deployerCk.toLowerCase(), deployerCk);
  for (const o of args.owners ?? []) {
    const ck = await checksum(o);
    ownerSet.set(ck.toLowerCase(), ck);
  }
  const owners = [...ownerSet.values()];
  const threshold = args.threshold ?? 1;
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > owners.length) {
    throw new Error(`threshold must be between 1 and ${owners.length} (number of owners)`);
  }
  const saltNonce = (args.saltNonce ?? String(Date.now())).trim();
  if (!/^\d+$/.test(saltNonce)) throw new Error(`--salt must be a non-negative integer`);

  const initializer = await cast([
    "calldata",
    "setup(address[],uint256,address,bytes,address,address,uint256,address)",
    `[${owners.join(",")}]`,
    String(threshold),
    ZERO_ADDRESS,
    "0x",
    SAFE_CONTRACTS.fallbackHandler,
    ZERO_ADDRESS,
    "0",
    ZERO_ADDRESS,
  ]);

  // eth_call the factory to learn the deterministic proxy address before spending gas
  const predicted = (
    await castCall(
      SAFE_CONTRACTS.proxyFactory,
      "createProxyWithNonce(address,bytes,uint256)(address)",
      SAFE_CONTRACTS.singletonL2,
      initializer,
      saltNonce,
    )
  ).split(/\s+/)[0];
  if (!isEthAddress(predicted)) throw new Error("factory did not return a proxy address");

  const base: CreateSafeResult = {
    address: predicted,
    owners,
    threshold,
    saltNonce,
    deployer,
    dryRun: Boolean(args.dryRun),
  };
  if (args.dryRun) return base;

  const deployerWei = await castBalanceWei(deployer);
  if (deployerWei === 0n) {
    throw new Error(`Treasury ${deployer} holds no ETH for gas — fund it on Base first`);
  }

  await authenticate(createSafeAuthReason({ owners, threshold }));
  const fresh = await loadVault();
  const txHash = await castSend(
    [
      SAFE_CONTRACTS.proxyFactory,
      "createProxyWithNonce(address,bytes,uint256)",
      SAFE_CONTRACTS.singletonL2,
      initializer,
      saltNonce,
    ],
    readTreasuryPrivateKey(fresh),
  );
  if ((await codeSize(predicted)) === 0) {
    throw new Error(`deploy tx ${txHash} mined but no code at ${predicted}`);
  }
  await storeSafeAddress(fresh, predicted);
  return { ...base, txHash };
}

export interface SafePayResult {
  approved: true;
  mode: SafePayMode;
  safe: string;
  to: string;
  amountUsdc: string;
  nonce: string;
  safeTxHash: string;
  threshold: number;
  confirmations: number;
  /** on-chain tx hash when executed */
  txHash?: string;
  /** where co-signers confirm when proposed */
  appUrl?: string;
  dryRun: boolean;
}

export function safePayAuthReason(args: {
  safe: string;
  to: string;
  amountUsdc: string;
  reason: string;
  mode: SafePayMode;
  threshold: number;
}): string {
  const tail =
    args.mode === "execute"
      ? ""
      : ` (sign 1 of ${args.threshold}; co-signers confirm in the Safe app)`;
  return `abracadabra safe: pay ${args.amountUsdc} USDC to ${args.to} from Safe ${args.safe} — ${args.reason}${tail}`;
}

/**
 * USDC transfer out of the linked Safe, signed by the treasury EOA (Touch ID).
 * threshold 1 → executed immediately; otherwise proposed to the Safe Transaction Service.
 */
export async function payFromSafe(args: {
  to: string;
  amountUsdc: string;
  reason: string;
  nonce?: string;
  dryRun?: boolean;
}): Promise<SafePayResult> {
  const reason = args.reason.trim();
  if (!reason) throw new Error("--reason is required");
  const amountUsdc = args.amountUsdc.trim();
  const units = parseUsdcAmount(amountUsdc);
  const to = await checksum(args.to);

  const vault = await loadVault();
  const safe = readSafeAddress(vault);
  const signer = readTreasuryAddress(vault);
  const info = await getSafeInfo(safe);
  if (!info.owners.some((o) => o.toLowerCase() === signer.toLowerCase())) {
    throw new Error(`Treasury ${signer} is not an owner of Safe ${safe}`);
  }
  const mode = planSafePayment(info.threshold);

  const safeUsdc = await castUsdcBalance(safe);
  if (safeUsdc < units) {
    throw new Error(`Safe holds ${formatUsdcUnits(safeUsdc)} USDC, cannot pay ${amountUsdc}`);
  }
  if (mode === "execute" && (await castBalanceWei(signer)) === 0n) {
    throw new Error(`Treasury ${signer} holds no ETH to pay gas for execTransaction`);
  }

  let nonce = info.nonce;
  if (args.nonce !== undefined) {
    if (!/^\d+$/.test(args.nonce.trim())) throw new Error(`Invalid --nonce: ${args.nonce}`);
    nonce = BigInt(args.nonce.trim());
    if (nonce < info.nonce) throw new Error(`--nonce ${nonce} already used (Safe nonce is ${info.nonce})`);
  }

  const tx = buildSafeTx({ to: BASE_USDC, data: encodeErc20Transfer(to, units), nonce });
  const safeTxHash = await getSafeTxHash(safe, tx);

  const base: SafePayResult = {
    approved: true,
    mode,
    safe,
    to,
    amountUsdc,
    nonce: nonce.toString(),
    safeTxHash,
    threshold: info.threshold,
    confirmations: 0,
    dryRun: Boolean(args.dryRun),
  };
  if (args.dryRun) return { ...base, appUrl: mode === "propose" ? safeAppUrl(safe) : undefined };

  await authenticate(
    safePayAuthReason({ safe, to, amountUsdc, reason, mode, threshold: info.threshold }),
  );
  // re-read after auth so the key is only held for the duration of the sign/send
  const fresh = await loadVault();
  const privateKey = readTreasuryPrivateKey(fresh);
  const signature = await signHash(safeTxHash, privateKey);

  if (mode === "execute") {
    const txHash = await execTransaction(
      safe,
      tx,
      packSignatures([{ owner: signer, signature }]),
      privateKey,
    );
    return { ...base, confirmations: 1, txHash };
  }

  await proposeToService({
    safe,
    tx,
    safeTxHash,
    sender: signer,
    signature,
    apiKey: readSafeApiKey(fresh),
  });
  return { ...base, confirmations: 1, appUrl: safeAppUrl(safe) };
}

interface VerifiedServiceTx {
  rec: ServiceMultisigTx;
  tx: SafeTx;
  info: SafeInfo;
  summary: string;
  confirmations: OwnerSignature[];
}

/**
 * Fetch a proposal from the service and verify it against chain state:
 * the hash must recompute on the Safe itself, and confirmations must come from current owners.
 */
async function loadVerifiedServiceTx(
  vault: Vault,
  safeTxHash: string,
): Promise<VerifiedServiceTx> {
  const safe = readSafeAddress(vault);
  const rec = await fetchServiceTx(safeTxHash, readSafeApiKey(vault));
  if (rec.safe.toLowerCase() !== safe.toLowerCase()) {
    throw new Error(`Transaction belongs to Safe ${rec.safe}, not the linked ${safe}`);
  }
  if (rec.isExecuted) {
    throw new Error(`Transaction already executed${rec.transactionHash ? ` (${rec.transactionHash})` : ""}`);
  }
  const tx = serviceTxToSafeTx(rec);
  const info = await getSafeInfo(safe);
  const recomputed = await getSafeTxHash(safe, tx);
  if (recomputed !== safeTxHash.trim().toLowerCase()) {
    throw new Error(
      `safeTxHash mismatch: service fields recompute to ${recomputed} — refusing to sign`,
    );
  }
  const ownerSet = new Set(info.owners.map((o) => o.toLowerCase()));
  const confirmations: OwnerSignature[] = [];
  for (const c of rec.confirmations ?? []) {
    if (!ownerSet.has(c.owner.toLowerCase())) continue; // stale owner
    if (confirmations.some((x) => x.owner.toLowerCase() === c.owner.toLowerCase())) continue;
    confirmations.push({ owner: c.owner, signature: c.signature });
  }
  return { rec, tx, info, summary: describeSafeTx(tx), confirmations };
}

export interface SafeConfirmResult {
  approved: true;
  safe: string;
  safeTxHash: string;
  nonce: string;
  summary: string;
  threshold: number;
  confirmations: number;
  executed: boolean;
  txHash?: string;
  appUrl: string;
}

export function confirmAuthReason(args: {
  nonce: string;
  summary: string;
  safe: string;
  exec?: boolean;
}): string {
  const tail = args.exec ? " (and execute if this meets the threshold; gas from treasury)" : "";
  return `abracadabra safe: confirm tx #${args.nonce} on ${args.safe} — ${args.summary}${tail}`;
}

export function execAuthReason(args: { nonce: string; summary: string; safe: string }): string {
  return `abracadabra safe: execute tx #${args.nonce} on ${args.safe} — ${args.summary} (gas from treasury)`;
}

/** Co-sign a pending proposal with the treasury EOA; optionally execute once the threshold is met. */
export async function confirmSafeTx(
  safeTxHash: string,
  opts: { exec?: boolean } = {},
): Promise<SafeConfirmResult> {
  const vault = await loadVault();
  const signer = readTreasuryAddress(vault);
  const v = await loadVerifiedServiceTx(vault, safeTxHash);
  const hash = safeTxHash.trim().toLowerCase();
  if (!v.info.owners.some((o) => o.toLowerCase() === signer.toLowerCase())) {
    throw new Error(`Treasury ${signer} is not an owner of Safe ${v.info.address}`);
  }
  const already = v.confirmations.some((c) => c.owner.toLowerCase() === signer.toLowerCase());

  let confirmations = v.confirmations;
  if (!already) {
    await authenticate(
      confirmAuthReason({
        nonce: v.tx.nonce.toString(),
        summary: v.summary,
        safe: v.info.address,
        exec: opts.exec,
      }),
    );
    const fresh = await loadVault();
    const signature = await signHash(hash, readTreasuryPrivateKey(fresh));
    await confirmOnService(hash, signature, readSafeApiKey(fresh));
    confirmations = [...v.confirmations, { owner: signer, signature }];
  }

  const base: SafeConfirmResult = {
    approved: true,
    safe: v.info.address,
    safeTxHash: hash,
    nonce: v.tx.nonce.toString(),
    summary: v.summary,
    threshold: v.info.threshold,
    confirmations: confirmations.length,
    executed: false,
    appUrl: safeAppUrl(v.info.address),
  };
  if (!opts.exec || confirmations.length < v.info.threshold) return base;

  const txHash = await executeVerified(v, confirmations, { skipAuth: !already });
  return { ...base, executed: true, txHash };
}

async function executeVerified(
  v: VerifiedServiceTx,
  confirmations: OwnerSignature[],
  opts: { skipAuth?: boolean } = {},
): Promise<string> {
  if (confirmations.length < v.info.threshold) {
    throw new Error(
      `Only ${confirmations.length} of ${v.info.threshold} required confirmations — co-signers must confirm first: ${safeAppUrl(v.info.address)}`,
    );
  }
  if (v.tx.nonce !== v.info.nonce) {
    throw new Error(
      `Transaction nonce ${v.tx.nonce} is not next (Safe nonce is ${v.info.nonce}) — execute earlier queued txs first`,
    );
  }
  const packed = packSignatures(confirmations.slice(0, v.info.threshold));
  if (!opts.skipAuth) {
    await authenticate(
      execAuthReason({ nonce: v.tx.nonce.toString(), summary: v.summary, safe: v.info.address }),
    );
  }
  const fresh = await loadVault();
  const signer = readTreasuryAddress(fresh);
  if ((await castBalanceWei(signer)) === 0n) {
    throw new Error(`Treasury ${signer} holds no ETH to pay gas for execTransaction`);
  }
  return execTransaction(v.info.address, v.tx, packed, readTreasuryPrivateKey(fresh));
}

export interface SafeExecResult {
  approved: true;
  safe: string;
  safeTxHash: string;
  nonce: string;
  summary: string;
  confirmations: number;
  threshold: number;
  txHash: string;
}

/** Execute a fully-confirmed proposal from the service; the treasury EOA pays gas (Touch ID). */
export async function execSafeTx(safeTxHash: string): Promise<SafeExecResult> {
  const vault = await loadVault();
  const v = await loadVerifiedServiceTx(vault, safeTxHash);
  const txHash = await executeVerified(v, v.confirmations);
  return {
    approved: true,
    safe: v.info.address,
    safeTxHash: safeTxHash.trim().toLowerCase(),
    nonce: v.tx.nonce.toString(),
    summary: v.summary,
    confirmations: v.confirmations.length,
    threshold: v.info.threshold,
    txHash,
  };
}

export interface PendingSafeTx {
  safeTxHash: string;
  nonce: string;
  summary: string;
  to: string;
  confirmations: number;
  threshold: number;
  confirmedBy: string[];
  abraSigned: boolean;
  ready: boolean;
  proposer?: string | null;
  submissionDate?: string;
}

export async function listPendingSafeTxs(): Promise<{ safe: string; nonce: string; pending: PendingSafeTx[]; appUrl: string }> {
  const vault = await loadVault();
  const safe = readSafeAddress(vault);
  const signer = readTreasuryAddress(vault).toLowerCase();
  const info = await getSafeInfo(safe);
  const recs = await fetchPendingFromService(safe, readSafeApiKey(vault));
  const pending = recs.map((r) => {
    const confirmedBy = (r.confirmations ?? []).map((c) => c.owner);
    return {
      safeTxHash: r.safeTxHash,
      nonce: String(r.nonce),
      summary: describeSafeTx(serviceTxToSafeTx(r)),
      to: r.to,
      confirmations: confirmedBy.length,
      threshold: r.confirmationsRequired || info.threshold,
      confirmedBy,
      abraSigned: confirmedBy.some((o) => o.toLowerCase() === signer),
      ready: confirmedBy.length >= (r.confirmationsRequired || info.threshold) && BigInt(r.nonce) === info.nonce,
      proposer: r.proposer,
      submissionDate: r.submissionDate,
    };
  });
  return { safe, nonce: info.nonce.toString(), pending, appUrl: safeAppUrl(safe) };
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function printJson(v: unknown): void {
  console.log(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x), 2));
}

export function registerSafeCommands(program: Command): void {
  const safe = program
    .command("safe")
    .description("Gnosis Safe multisig on Base — treasury wallet signs, Touch ID gates every signature");

  safe
    .command("create")
    .description("Deploy a Safe v1.4.1 with the treasury as an owner (gas from treasury; Touch ID)")
    .option("--owner <address...>", "additional owner 0x addresses (treasury is always included)")
    .option("--threshold <n>", "signatures required per transaction", "1")
    .option("--salt <n>", "salt nonce for the deterministic proxy address (default: timestamp)")
    .option("--dry-run", "predict the address only; no Touch ID, no transaction")
    .option("--json", "machine-readable output")
    .action(async (opts: { owner?: string[]; threshold: string; salt?: string; dryRun?: boolean; json?: boolean }) => {
      try {
        const result = await createSafe({
          owners: opts.owner,
          threshold: Number(opts.threshold),
          saltNonce: opts.salt,
          dryRun: opts.dryRun,
        });
        if (opts.json) return printJson(result);
        console.log(dim(`${result.threshold}-of-${result.owners.length} Safe v${SAFE_CONTRACTS.version} (L2)`));
        for (const o of result.owners) {
          const tag = o.toLowerCase() === result.deployer.toLowerCase() ? dim("  (abra treasury)") : "";
          console.log(dim(`  owner ${o}${tag}`));
        }
        if (result.dryRun) {
          console.log(bold(`dry run: would deploy to ${result.address}`) + dim(`  (salt ${result.saltNonce})`));
          console.log(dim("re-run without --dry-run to deploy (Touch ID)"));
          return;
        }
        console.log(green(`✓ Safe deployed and linked → ${TREASURY_PROJECT}.${SAFE_ADDRESS_VAR}`));
        console.log(`  ${bold(result.address)}`);
        console.log(`  tx   ${result.txHash}`);
        console.log(dim(`  ${safeAppUrl(result.address)}`));
        console.log();
        console.log(dim(`Fund the Safe with USDC on Base (${BASE_USDC}); keep a little ETH in the treasury for gas.`));
      } catch (err) {
        fail(err);
      }
    });

  safe
    .command("link <address>")
    .description("Link an existing Safe on Base (verifies on-chain; treasury should be an owner)")
    .action(async (address: string) => {
      try {
        const r = await linkSafe(address);
        console.log(green(`✓ linked Safe v${r.info.version} → ${TREASURY_PROJECT}.${SAFE_ADDRESS_VAR}`));
        console.log(`  ${bold(r.address)}`);
        console.log(dim(`  ${r.info.threshold}-of-${r.info.owners.length}, nonce ${r.info.nonce}`));
        if (!r.signerIsOwner) {
          console.log(yellow(`⚠ treasury ${r.signer} is not an owner — add it in the Safe app before abra can sign`));
        }
      } catch (err) {
        fail(err);
      }
    });

  safe
    .command("unlink")
    .description("Forget the linked Safe (on-chain funds are untouched)")
    .action(async () => {
      try {
        console.log(green(`✓ unlinked ${await unlinkSafe()}`));
      } catch (err) {
        fail(err);
      }
    });

  safe
    .command("address")
    .description("Print the linked Safe address")
    .action(async () => {
      try {
        console.log(readSafeAddress(await loadVault()));
      } catch (err) {
        fail(err);
      }
    });

  safe
    .command("status")
    .description("Owners, threshold, nonce, Base USDC + ETH, and pending proposals")
    .option("--no-pending", "skip the Safe Transaction Service lookup")
    .option("--json", "machine-readable output")
    .action(async (opts: { pending: boolean; json?: boolean }) => {
      try {
        const s = await getSafeStatus({ pending: opts.pending });
        if (opts.json) return printJson(s);
        console.log(`${bold("safe")}      ${s.address}  ${dim(`v${s.version}`)}`);
        console.log(`${bold("policy")}    ${s.threshold}-of-${s.owners.length}  ${dim(`nonce ${s.nonce}`)}`);
        for (const o of s.owners) {
          console.log(`          ${o.address}${o.abra ? dim("  (abra treasury)") : ""}`);
        }
        if (!s.signerIsOwner) {
          console.log(yellow(`⚠ treasury ${s.signer} is not an owner of this Safe`));
        }
        console.log(`${bold("USDC")}      ${s.usdc}  ${dim(`(Base ${BASE_USDC})`)}`);
        console.log(`${bold("ETH")}       ${s.eth}  ${dim(`(Safe) · ${s.signerEth} (treasury, pays gas)`)}`);
        if (s.pending) {
          console.log(`${bold("pending")}   ${s.pending.length}`);
          for (const p of s.pending) {
            console.log(`  #${p.nonce}  ${p.summary}  ${dim(`${p.confirmations}/${s.threshold} · ${p.safeTxHash}`)}`);
          }
        } else if (s.pendingError) {
          console.log(dim(`pending   (unavailable: ${s.pendingError})`));
        }
        console.log(dim(`app ${s.appUrl}`));
        console.log(dim(`rpc ${s.rpc}`));
      } catch (err) {
        fail(err);
      }
    });

  safe
    .command("pay")
    .description("Send Base USDC from the Safe (Touch ID; 1-of-N executes, else proposes for co-signers)")
    .requiredOption("--to <address>", "destination 0x address")
    .requiredOption("--amount <usdc>", "USDC amount, e.g. 0.008")
    .requiredOption("--reason <text>", "human-readable reason shown in Touch ID prompt")
    .option("--nonce <n>", "Safe nonce to use (default: current on-chain nonce)")
    .option("--dry-run", "show the plan and safeTxHash; no Touch ID, no signature")
    .option("--json", "machine-readable output")
    .action(async (opts: { to: string; amount: string; reason: string; nonce?: string; dryRun?: boolean; json?: boolean }) => {
      try {
        const r = await payFromSafe({
          to: opts.to,
          amountUsdc: opts.amount,
          reason: opts.reason,
          nonce: opts.nonce,
          dryRun: opts.dryRun,
        });
        if (opts.json) return printJson(r);
        console.log(dim(`safe ${r.safe}  ${r.threshold > 1 ? `${r.threshold} signatures required` : "1 signature"}`));
        if (r.dryRun) {
          console.log(bold(`dry run: would ${r.mode} ${r.amountUsdc} USDC → ${r.to}`) + dim(`  (nonce ${r.nonce})`));
          console.log(dim(`  safeTxHash ${r.safeTxHash}`));
          console.log(dim("re-run without --dry-run to sign (Touch ID)"));
          return;
        }
        if (r.mode === "execute") {
          console.log(green(`✓ paid ${r.amountUsdc} USDC from Safe`));
          console.log(dim(`  to   ${r.to}`));
          console.log(`  tx   ${bold(r.txHash ?? "")}`);
          return;
        }
        console.log(green(`✓ proposed ${r.amountUsdc} USDC → ${r.to}  (${r.confirmations}/${r.threshold} signed)`));
        console.log(`  safeTxHash ${bold(r.safeTxHash)}`);
        console.log(dim(`  co-signers confirm at ${r.appUrl}`));
        console.log(dim(`  then: abra safe exec ${r.safeTxHash}`));
      } catch (err) {
        fail(err);
      }
    });

  safe
    .command("pending")
    .description("List unexecuted proposals from the Safe Transaction Service")
    .option("--json", "machine-readable output")
    .action(async (opts: { json?: boolean }) => {
      try {
        const r = await listPendingSafeTxs();
        if (opts.json) return printJson(r);
        if (r.pending.length === 0) {
          console.log(green(`✓ no pending transactions on ${r.safe}`) + dim(`  (nonce ${r.nonce})`));
          return;
        }
        for (const p of r.pending) {
          const state = p.ready ? green("ready") : p.abraSigned ? dim("waiting on co-signers") : yellow("needs abra");
          console.log(`#${p.nonce}  ${bold(p.summary)}  ${dim(`${p.confirmations}/${p.threshold}`)}  ${state}`);
          console.log(dim(`     ${p.safeTxHash}`));
        }
        console.log(dim(`confirm: abra safe confirm <safeTxHash> [--exec]   ·   ${r.appUrl}`));
      } catch (err) {
        fail(err);
      }
    });

  safe
    .command("confirm <safeTxHash>")
    .description("Co-sign a pending proposal with the treasury key (Touch ID; verified against chain)")
    .option("--exec", "execute right away once the threshold is met")
    .option("--json", "machine-readable output")
    .action(async (hash: string, opts: { exec?: boolean; json?: boolean }) => {
      try {
        const r = await confirmSafeTx(hash, { exec: opts.exec });
        if (opts.json) return printJson(r);
        console.log(green(`✓ confirmed #${r.nonce}: ${r.summary}  (${r.confirmations}/${r.threshold})`));
        if (r.executed) {
          console.log(`  tx   ${bold(r.txHash ?? "")}`);
        } else if (r.confirmations >= r.threshold) {
          console.log(dim(`  ready — execute with: abra safe exec ${r.safeTxHash}`));
        } else {
          console.log(dim(`  waiting on co-signers: ${r.appUrl}`));
        }
      } catch (err) {
        fail(err);
      }
    });

  safe
    .command("exec <safeTxHash>")
    .description("Execute a fully-confirmed proposal; treasury pays gas (Touch ID)")
    .option("--json", "machine-readable output")
    .action(async (hash: string, opts: { json?: boolean }) => {
      try {
        const r = await execSafeTx(hash);
        if (opts.json) return printJson(r);
        console.log(green(`✓ executed #${r.nonce}: ${r.summary}`));
        console.log(`  tx   ${bold(r.txHash)}`);
      } catch (err) {
        fail(err);
      }
    });
}
