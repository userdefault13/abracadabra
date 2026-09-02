import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { abraDir } from "../core/paths.js";
import { ABRA_CARTRIDGE_GAME_ID, cartridgeApiBase } from "./config.js";

export interface CartridgeMeta {
  cartridgeId: string;
  owner: string;
  gameId: string;
}

function metaPath(): string {
  return `${abraDir()}/cartridge.json`;
}

export function readCartridgeMeta(): CartridgeMeta | null {
  try {
    const raw = JSON.parse(readFileSync(metaPath(), "utf8")) as CartridgeMeta;
    if (raw?.cartridgeId && raw?.owner) return raw;
  } catch {
    /* none */
  }
  return null;
}

export function writeCartridgeMeta(meta: CartridgeMeta): void {
  mkdirSync(abraDir(), { recursive: true });
  writeFileSync(metaPath(), `${JSON.stringify(meta, null, 2)}\n`, { mode: 0o600 });
}

async function parseJson(res: Response): Promise<Record<string, unknown>> {
  try {
    return (await res.json()) as Record<string, unknown>;
  } catch {
    return { error: await res.text() };
  }
}

export async function fetchRules(): Promise<Record<string, unknown>> {
  const res = await fetch(`${cartridgeApiBase()}/rules/${ABRA_CARTRIDGE_GAME_ID}`);
  const body = await parseJson(res);
  if (!res.ok) throw new Error(String(body.error || res.statusText));
  return body;
}

export async function ensureCartridge(owner: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${cartridgeApiBase()}/cartridges/ensure`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ owner: owner.toLowerCase(), gameId: ABRA_CARTRIDGE_GAME_ID }),
  });
  const body = await parseJson(res);
  if (!res.ok) {
    throw new Error(String(body.error || body.message || res.statusText));
  }
  const cartridgeId = String(body.cartridgeId || body.id || "");
  if (cartridgeId) {
    writeCartridgeMeta({
      cartridgeId,
      owner: owner.toLowerCase(),
      gameId: ABRA_CARTRIDGE_GAME_ID,
    });
  }
  return body;
}

export async function getCartridge(cartridgeId: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${cartridgeApiBase()}/cartridges/${encodeURIComponent(cartridgeId)}`);
  const body = await parseJson(res);
  if (!res.ok) throw new Error(String(body.error || res.statusText));
  return body;
}

export async function saveCheckpoint(opts: {
  cartridgeId: string;
  gameState: Record<string, unknown>;
  message: string;
  signature: string;
  label?: string;
}): Promise<Record<string, unknown>> {
  const res = await fetch(
    `${cartridgeApiBase()}/cartridges/${encodeURIComponent(opts.cartridgeId)}/checkpoint`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        gameState: opts.gameState,
        message: opts.message,
        signature: opts.signature,
        label: opts.label,
      }),
    },
  );
  const body = await parseJson(res);
  if (!res.ok) throw new Error(String(body.error || res.statusText));
  return body;
}
