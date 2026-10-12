import crypto, { type KeyObject } from "node:crypto";
import type { SyncIdentity, Vault } from "../core/vault.js";

/**
 * `abra sync` device identity.
 *
 * Key encoding: base64 (standard, padded) of the raw 32-byte key — the JWK
 * `x` value for public keys and `d` for private keys (Ed25519 seed / X25519
 * scalar). Private halves live only in the encrypted vault (`Vault.syncIdentity`).
 */

export const ID_FINGERPRINT_DOMAIN = "abra-sync-id-v1";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface PublicSyncIdentity {
  id: string;
  ed25519: string;
  x25519: string;
  fingerprint: string;
}

type OkpCurve = "Ed25519" | "X25519";

function b64urlToB64(s: string): string {
  return Buffer.from(s, "base64url").toString("base64");
}

function b64ToB64url(s: string): string {
  return Buffer.from(s, "base64").toString("base64url");
}

function exportRaw(key: KeyObject, part: "x" | "d"): string {
  const jwk = key.export({ format: "jwk" }) as { x?: string; d?: string };
  const v = jwk[part];
  if (!v) throw new Error(`missing ${part} in exported key`);
  return b64urlToB64(v);
}

/** Strict base64 → exactly 32 bytes (rejects lenient decodes and wrong lengths). */
export function decodeRawKey(b64: string): Buffer {
  if (typeof b64 !== "string") throw new Error("key must be a base64 string");
  const buf = Buffer.from(b64, "base64");
  if (buf.length !== 32 || buf.toString("base64") !== b64) {
    throw new Error("key must be base64 of exactly 32 bytes");
  }
  return buf;
}

function publicKeyObject(crv: OkpCurve, b64: string): KeyObject {
  decodeRawKey(b64);
  return crypto.createPublicKey({ key: { kty: "OKP", crv, x: b64ToB64url(b64) }, format: "jwk" });
}

export function ed25519PublicKey(b64: string): KeyObject {
  return publicKeyObject("Ed25519", b64);
}

export function x25519PublicKey(b64: string): KeyObject {
  return publicKeyObject("X25519", b64);
}

export function ed25519PrivateKey(identity: SyncIdentity): KeyObject {
  decodeRawKey(identity.ed25519.privateKey);
  return crypto.createPrivateKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: b64ToB64url(identity.ed25519.publicKey),
      d: b64ToB64url(identity.ed25519.privateKey),
    },
    format: "jwk",
  });
}

export function x25519PrivateKey(identity: SyncIdentity): KeyObject {
  decodeRawKey(identity.x25519.privateKey);
  return crypto.createPrivateKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      x: b64ToB64url(identity.x25519.publicKey),
      d: b64ToB64url(identity.x25519.privateKey),
    },
    format: "jwk",
  });
}

/** Raw 32-byte public key (base64) of an OKP KeyObject. */
export function rawPublicKey(key: KeyObject): string {
  return exportRaw(key, "x");
}

/** Both public keys parse as valid curve points of the right type. */
export function assertValidPublicKeys(ed25519: string, x25519: string): void {
  ed25519PublicKey(ed25519);
  x25519PublicKey(x25519);
}

export function isUuid(id: unknown): id is string {
  return typeof id === "string" && UUID_RE.test(id);
}

export function generateSyncIdentity(
  now: number = Date.now(),
  newId: () => string = () => crypto.randomUUID(),
): SyncIdentity {
  const ed = crypto.generateKeyPairSync("ed25519");
  const x = crypto.generateKeyPairSync("x25519");
  return {
    id: newId(),
    createdAt: now,
    ed25519: { publicKey: exportRaw(ed.publicKey, "x"), privateKey: exportRaw(ed.privateKey, "d") },
    x25519: { publicKey: exportRaw(x.publicKey, "x"), privateKey: exportRaw(x.privateKey, "d") },
  };
}

function isValidIdentity(identity: SyncIdentity | undefined): identity is SyncIdentity {
  if (!identity || !isUuid(identity.id)) return false;
  try {
    assertValidPublicKeys(identity.ed25519.publicKey, identity.x25519.publicKey);
    decodeRawKey(identity.ed25519.privateKey);
    decodeRawKey(identity.x25519.privateKey);
    return true;
  } catch {
    return false;
  }
}

/**
 * Pure: returns the vault (a new object when an identity was minted) plus the
 * identity. Callers persist with saveVault only after approval.
 * A present-but-corrupt identity throws rather than being silently replaced.
 */
export function getOrCreateSyncIdentity(
  vault: Vault,
  opts: { now?: number } = {},
): { vault: Vault; identity: SyncIdentity; created: boolean } {
  if (vault.syncIdentity !== undefined) {
    if (!isValidIdentity(vault.syncIdentity)) {
      throw new Error("vault sync identity is malformed — refusing to replace it automatically");
    }
    return { vault, identity: vault.syncIdentity, created: false };
  }
  const identity = generateSyncIdentity(opts.now);
  return { vault: { ...vault, syncIdentity: identity }, identity, created: true };
}

/** Unambiguous concatenation: u32 BE length before every part. */
export function lengthPrefixed(parts: Buffer[]): Buffer {
  const out: Buffer[] = [];
  for (const p of parts) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(p.length);
    out.push(len, p);
  }
  return Buffer.concat(out);
}

/**
 * SHA-256 over ("abra-sync-id-v1", ed25519 raw, x25519 raw), each length-prefixed.
 * Rendered as the first 16 bytes in 8 lowercase hex groups of 4.
 */
export function identityFingerprint(ed25519Pub: string, x25519Pub: string): string {
  const digest = crypto
    .createHash("sha256")
    .update(
      lengthPrefixed([
        Buffer.from(ID_FINGERPRINT_DOMAIN, "utf8"),
        decodeRawKey(ed25519Pub),
        decodeRawKey(x25519Pub),
      ]),
    )
    .digest("hex")
    .slice(0, 32);
  return (digest.match(/.{4}/g) ?? []).join(" ");
}

export function publicIdentity(identity: SyncIdentity): PublicSyncIdentity {
  return {
    id: identity.id,
    ed25519: identity.ed25519.publicKey,
    x25519: identity.x25519.publicKey,
    fingerprint: identityFingerprint(identity.ed25519.publicKey, identity.x25519.publicKey),
  };
}
