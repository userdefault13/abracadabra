import {
  licenseContractAddress,
  licenseEnforcementEnabled,
  licenseEnforcementSkipped,
} from "./config.js";
import { readActivation } from "./store.js";
import { walletHoldsLicense } from "./verify.js";

export { licenseContractAddress, licenseEnforcementEnabled, licenseEnforcementSkipped } from "./config.js";
export { readActivation, writeActivation, clearActivation } from "./store.js";
export type { LicenseActivation } from "./store.js";
export { fetchNftBalance, walletHoldsLicense } from "./verify.js";
export { buildActivationMessage, createActivationChallenge } from "./siwe.js";
export type { ActivationChallenge } from "./siwe.js";

export class LicenseRequiredError extends Error {
  constructor(message?: string) {
    super(
      message ??
        "Abra License required — mint at aarcadeghst.com/concierge/terminal, then run: abra activate <wallet>",
    );
    this.name = "LicenseRequiredError";
  }
}

export interface LicenseStatus {
  enforcement: boolean;
  contract: string | null;
  activated: boolean;
  wallet: string | null;
  onChainOk: boolean | null;
  activatedAt: string | null;
  skip: boolean;
}

export async function getLicenseStatus(): Promise<LicenseStatus> {
  const contract = licenseContractAddress();
  const skip = licenseEnforcementSkipped();
  const enforcement = licenseEnforcementEnabled();
  const activation = readActivation();
  let onChainOk: boolean | null = null;

  if (activation?.wallet && contract) {
    try {
      onChainOk = await walletHoldsLicense(activation.wallet);
    } catch {
      onChainOk = null;
    }
  }

  return {
    enforcement,
    contract,
    activated: Boolean(activation),
    wallet: activation?.wallet ?? null,
    onChainOk,
    activatedAt: activation?.activatedAt ?? null,
    skip,
  };
}

/** True when user may use licensed features (serve, secret export, mcp). */
export async function isLicensed(): Promise<boolean> {
  if (!licenseEnforcementEnabled()) return true;
  const activation = readActivation();
  if (!activation?.wallet) return false;
  try {
    return await walletHoldsLicense(activation.wallet);
  } catch {
    return false;
  }
}

export async function assertLicensed(): Promise<void> {
  if (!licenseEnforcementEnabled()) return;
  const ok = await isLicensed();
  if (!ok) {
    const activation = readActivation();
    if (!activation) {
      throw new LicenseRequiredError();
    }
    throw new LicenseRequiredError(
      `License not valid for ${activation.wallet} — ensure the wallet holds an Abra License NFT, then: abra activate ${activation.wallet}`,
    );
  }
}
