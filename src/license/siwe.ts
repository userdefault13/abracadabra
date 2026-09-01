import crypto from "node:crypto";
import { normalizeAddress } from "./config.js";

/**
 * EIP-4361-style challenge for wallet proof (B3: verify signature in-app).
 * B1 stores the challenge in activation metadata when --prove is used later.
 */
export function buildActivationMessage(wallet: string, opts?: { nonce?: string; issuedAt?: string }): string {
  const nonce = opts?.nonce ?? crypto.randomBytes(16).toString("hex");
  const issuedAt = opts?.issuedAt ?? new Date().toISOString();
  const addr = normalizeAddress(wallet);
  return [
    "abracadabra.app wants you to activate your Abra License.",
    "",
    `Wallet: ${addr}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join("\n");
}

export interface ActivationChallenge {
  message: string;
  nonce: string;
  issuedAt: string;
  wallet: string;
}

export function createActivationChallenge(wallet: string): ActivationChallenge {
  const nonce = crypto.randomBytes(16).toString("hex");
  const issuedAt = new Date().toISOString();
  return {
    wallet: normalizeAddress(wallet),
    nonce,
    issuedAt,
    message: buildActivationMessage(wallet, { nonce, issuedAt }),
  };
}
