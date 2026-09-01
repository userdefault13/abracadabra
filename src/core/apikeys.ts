import crypto from "node:crypto";
import type { ApiKey, Vault } from "./vault.js";

export const KEY_PREFIX = "abra";

export function hashKey(fullKey: string): string {
  return crypto.createHash("sha256").update(fullKey, "utf8").digest("hex");
}

/**
 * Mint a new API key: `abra_<8-hex-id>_<43-char secret>`.
 * The full key is returned ONCE; only the hash is persisted.
 */
export function generateApiKey(
  name: string,
  projects: string[] | null,
  opts?: { expiresInDays?: number },
): { record: ApiKey; fullKey: string } {
  const id = crypto.randomBytes(4).toString("hex"); // 8 hex chars
  const secret = crypto.randomBytes(32).toString("base64url");
  const fullKey = `${KEY_PREFIX}_${id}_${secret}`;
  const record: ApiKey = {
    id,
    name,
    keyHash: hashKey(fullKey),
    prefix: fullKey.slice(0, 13), // "abra_xxxxxxx"
    projects: projects && projects.length > 0 ? [...projects] : null,
    createdAt: Date.now(),
    ...(opts?.expiresInDays ? { expiresAt: Date.now() + opts.expiresInDays * 86_400_000 } : {}),
  };
  return { record, fullKey };
}

/** Constant-time validation of a bearer token against the vault's keys. */
export function findValidApiKey(vault: Vault, token: string): ApiKey | undefined {
  const m = /^abra_([0-9a-f]{8})_([A-Za-z0-9_-]+)$/.exec(token);
  if (!m) return undefined;
  const record = vault.apiKeys?.[m[1]];
  if (!record) return undefined;
  const a = Buffer.from(hashKey(token), "hex");
  const b = Buffer.from(record.keyHash, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return undefined;
  if (record.expiresAt && Date.now() > record.expiresAt) return undefined;
  return record;
}

export function apiKeyHasAccess(record: ApiKey, project: string): boolean {
  return record.projects === null || record.projects.includes(project);
}
