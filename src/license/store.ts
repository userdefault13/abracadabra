import fs from "node:fs";
import { ensureDir, licenseFile } from "../core/paths.js";
import { licenseChainId, licenseContractAddress, normalizeAddress } from "./config.js";

export interface LicenseActivation {
  version: 1;
  wallet: string;
  chainId: number;
  contract: string;
  activatedAt: string;
  /** balanceOf at activation time */
  balance: string;
}

export function readActivation(): LicenseActivation | null {
  try {
    const raw = JSON.parse(fs.readFileSync(licenseFile(), "utf8")) as LicenseActivation;
    if (raw?.version !== 1 || !raw.wallet || !raw.contract) return null;
    return raw;
  } catch {
    return null;
  }
}

export function writeActivation(input: {
  wallet: string;
  balance: bigint;
  contract?: string;
  chainId?: number;
}): LicenseActivation {
  const contract = input.contract ?? licenseContractAddress();
  if (!contract) throw new Error("ABRA_LICENSE_NFT is not configured");
  ensureDir();
  const record: LicenseActivation = {
    version: 1,
    wallet: normalizeAddress(input.wallet),
    chainId: input.chainId ?? licenseChainId(),
    contract: contract.toLowerCase(),
    activatedAt: new Date().toISOString(),
    balance: input.balance.toString(),
  };
  const file = licenseFile();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(record, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file);
  return record;
}

export function clearActivation(): void {
  try {
    fs.rmSync(licenseFile(), { force: true });
  } catch {
    // ignore
  }
}
