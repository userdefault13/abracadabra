import { createHash } from "node:crypto";

/** Match AarcadeGh-t lib/cartridgeSim.cjs stableStringify (top-level key sort). */
export function stableStringify(obj: Record<string, unknown>): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

export function hashGameState(gameState: Record<string, unknown>): string {
  return `0x${createHash("sha256").update(stableStringify(gameState)).digest("hex")}`;
}

export function buildCheckpointSignMessage(opts: {
  cartridgeId: string;
  nonce: number;
  gameState: Record<string, unknown>;
}): string {
  const stateHash = hashGameState(opts.gameState);
  return [
    "Aarcade cartridge checkpoint",
    `cartridgeId: ${opts.cartridgeId}`,
    `nonce: ${opts.nonce}`,
    `stateHash: ${stateHash}`,
  ].join("\n");
}
