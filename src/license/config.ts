/** Base mainnet — Abra License NFT deployment target. */
export const DEFAULT_LICENSE_CHAIN_ID = 8453;

export const DEFAULT_BASE_RPC =
  process.env.ABRA_LICENSE_RPC?.trim() || "https://mainnet.base.org";

/** ERC-721 balanceOf(address) */
export const ERC721_BALANCE_OF_SELECTOR = "0x70a08231";

export function licenseContractAddress(): string | null {
  const raw = process.env.ABRA_LICENSE_NFT?.trim();
  if (!raw) return null;
  return isEthAddress(raw) ? raw : null;
}

export function licenseChainId(): number {
  const raw = process.env.ABRA_LICENSE_CHAIN_ID?.trim();
  if (!raw) return DEFAULT_LICENSE_CHAIN_ID;
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`Invalid ABRA_LICENSE_CHAIN_ID: ${raw}`);
  }
  return n;
}

export function licenseRpcUrl(): string {
  return DEFAULT_BASE_RPC;
}

/** Dev/CI only — skip NFT gate (never set in production docs). */
export function licenseEnforcementSkipped(): boolean {
  return process.env.ABRA_SKIP_LICENSE === "1";
}

/** Gate is active only when a contract is configured and skip is off. */
export function licenseEnforcementEnabled(): boolean {
  return !licenseEnforcementSkipped() && Boolean(licenseContractAddress());
}

export function isEthAddress(addr: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(addr);
}

export function normalizeAddress(addr: string): string {
  const a = addr.trim();
  if (!isEthAddress(a)) throw new Error(`Invalid Ethereum address: ${addr}`);
  return a.toLowerCase();
}
