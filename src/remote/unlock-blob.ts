import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { abraDir } from "../core/paths.js";
import { decodeRawKey, isUuid, lengthPrefixed } from "../sync/identity.js";
import {
  ensureRemoteDir,
  readPrivateFile,
  remoteDir,
  writePrivateFile,
} from "./private-fs.js";

/**
 * Receiver-side wrapped master key for remote unlock.
 *
 *   remote-unlock.blob = AES-256-GCM_W(masterKey)
 *   AAD bound to deviceId + master-key fingerprint (never the key itself)
 *
 * File: `<abraDir>/remote/remote-unlock.blob` (0600). Useless without W
 * (held only in the hub vault under syncPeers[id].unlockWrap).
 */

export const UNLOCK_BLOB_FILENAME = "remote-unlock.blob";
export const UNLOCK_BLOB_DOMAIN = "abra-remote-unlock-blob-v1";
export const MASTER_KEY_FP_DOMAIN = "abra-remote-master-fp-v1";

const GCM_IV_BYTES = 12;
const MASTER_KEY_BYTES = 32;
const WRAP_KEY_BYTES = 32;

export interface UnlockBlobFile {
  v: 1;
  deviceId: string;
  masterKeyFingerprint: string;
  iv: string;
  tag: string;
  ct: string;
}

export class ReEnrollNeededError extends Error {
  constructor(
    message = "remote unlock blob is stale (master key changed) — re-enroll needed",
  ) {
    super(message);
    this.name = "ReEnrollNeededError";
  }
}

export function unlockBlobFile(base: string = abraDir()): string {
  return path.join(remoteDir(base), UNLOCK_BLOB_FILENAME);
}

/**
 * SHA-256 over ("abra-remote-master-fp-v1", masterKey), length-prefixed —
 * same 8×4 hex rendering as device/sync fingerprints. Never the key itself.
 */
export function masterKeyFingerprint(masterKey: Buffer): string {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== MASTER_KEY_BYTES) {
    throw new Error("master key must be 32 bytes");
  }
  const digest = crypto
    .createHash("sha256")
    .update(lengthPrefixed([Buffer.from(MASTER_KEY_FP_DOMAIN, "utf8"), masterKey]))
    .digest("hex")
    .slice(0, 32);
  return (digest.match(/.{4}/g) ?? []).join(" ");
}

function blobAad(deviceId: string, fingerprint: string): Buffer {
  return lengthPrefixed([
    Buffer.from(UNLOCK_BLOB_DOMAIN, "utf8"),
    Buffer.from(deviceId, "utf8"),
    Buffer.from(fingerprint, "utf8"),
  ]);
}

function corruptBlobError(): Error {
  return new Error("remote unlock blob is malformed — refusing to use it");
}

function isValidBlob(raw: unknown): raw is UnlockBlobFile {
  if (!raw || typeof raw !== "object") return false;
  const b = raw as UnlockBlobFile;
  if (b.v !== 1 || !isUuid(b.deviceId) || typeof b.masterKeyFingerprint !== "string") return false;
  if (typeof b.iv !== "string" || typeof b.tag !== "string" || typeof b.ct !== "string") return false;
  try {
    const iv = Buffer.from(b.iv, "base64");
    const tag = Buffer.from(b.tag, "base64");
    const ct = Buffer.from(b.ct, "base64");
    if (iv.length !== GCM_IV_BYTES || tag.length !== 16 || ct.length === 0) return false;
    if (iv.toString("base64") !== b.iv || tag.toString("base64") !== b.tag || ct.toString("base64") !== b.ct) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function parseBlob(text: string): UnlockBlobFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw corruptBlobError();
  }
  if (!isValidBlob(parsed)) throw corruptBlobError();
  return parsed;
}

/** Generate a fresh 32-byte wrap key W. Caller must zero it after sealing. */
export function generateWrapKey(): Buffer {
  return crypto.randomBytes(WRAP_KEY_BYTES);
}

/**
 * Encrypt masterKey under W. Pure — does not touch disk.
 * AAD = domain ‖ deviceId ‖ masterKeyFingerprint (fingerprint of masterKey).
 */
export function wrapMasterKey(
  masterKey: Buffer,
  wrapKey: Buffer,
  deviceId: string,
  opts: { iv?: Buffer } = {},
): UnlockBlobFile {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== MASTER_KEY_BYTES) {
    throw new Error("master key must be 32 bytes");
  }
  if (!Buffer.isBuffer(wrapKey) || wrapKey.length !== WRAP_KEY_BYTES) {
    throw new Error("wrap key must be 32 bytes");
  }
  if (!isUuid(deviceId)) throw new Error("deviceId must be a UUID");

  const fingerprint = masterKeyFingerprint(masterKey);
  const iv = opts.iv ?? crypto.randomBytes(GCM_IV_BYTES);
  if (iv.length !== GCM_IV_BYTES) throw new Error("iv must be 12 bytes");

  const cipher = crypto.createCipheriv("aes-256-gcm", wrapKey, iv);
  cipher.setAAD(blobAad(deviceId, fingerprint));
  const ct = Buffer.concat([cipher.update(masterKey), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    v: 1,
    deviceId,
    masterKeyFingerprint: fingerprint,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ct: ct.toString("base64"),
  };
}

/**
 * Decrypt the blob with W. If `expectedMasterKey` is given and its fingerprint
 * does not match the blob's stored fingerprint → ReEnrollNeededError.
 * Wrong W → decrypt failure (does not reveal key material).
 */
export function unwrapMasterKey(
  blob: UnlockBlobFile,
  wrapKey: Buffer,
  opts: { expectedMasterKey?: Buffer } = {},
): Buffer {
  if (!isValidBlob(blob)) throw corruptBlobError();
  if (!Buffer.isBuffer(wrapKey) || wrapKey.length !== WRAP_KEY_BYTES) {
    throw new Error("wrap key must be 32 bytes");
  }

  if (opts.expectedMasterKey) {
    const current = masterKeyFingerprint(opts.expectedMasterKey);
    if (current !== blob.masterKeyFingerprint) {
      throw new ReEnrollNeededError();
    }
  }

  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      wrapKey,
      Buffer.from(blob.iv, "base64"),
    );
    decipher.setAAD(blobAad(blob.deviceId, blob.masterKeyFingerprint));
    decipher.setAuthTag(Buffer.from(blob.tag, "base64"));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(blob.ct, "base64")),
      decipher.final(),
    ]);
    if (plain.length !== MASTER_KEY_BYTES) {
      plain.fill(0);
      throw new Error("remote unlock blob decrypted to unexpected length");
    }
    return plain;
  } catch (err) {
    if (err instanceof ReEnrollNeededError) throw err;
    throw new Error("remote unlock blob could not be decrypted (wrong wrap key?)");
  }
}

/**
 * Compare blob fingerprint to the current master key without unwrapping.
 * Throws ReEnrollNeededError on mismatch.
 */
export function assertBlobMatchesMasterKey(blob: UnlockBlobFile, masterKey: Buffer): void {
  if (!isValidBlob(blob)) throw corruptBlobError();
  if (masterKeyFingerprint(masterKey) !== blob.masterKeyFingerprint) {
    throw new ReEnrollNeededError();
  }
}

/** Atomic 0600 write into the remote dir. */
export function writeUnlockBlob(blob: UnlockBlobFile, base: string = abraDir()): void {
  if (!isValidBlob(blob)) throw corruptBlobError();
  ensureRemoteDir(base);
  writePrivateFile(unlockBlobFile(base), `${JSON.stringify(blob, null, 2)}\n`);
}

/** Null when missing. Fail closed on bad perms / corrupt JSON. */
export function readUnlockBlob(base: string = abraDir()): UnlockBlobFile | null {
  const file = unlockBlobFile(base);
  if (!fs.existsSync(file)) return null;
  return parseBlob(readPrivateFile(file, base));
}

export function clearUnlockBlob(base: string = abraDir()): void {
  fs.rmSync(unlockBlobFile(base), { force: true });
}

/** Convenience: wrap + write; returns the blob (W stays with the caller to seal). */
export function createAndWriteUnlockBlob(
  masterKey: Buffer,
  wrapKey: Buffer,
  deviceId: string,
  opts: { base?: string; iv?: Buffer } = {},
): UnlockBlobFile {
  const blob = wrapMasterKey(masterKey, wrapKey, deviceId, { iv: opts.iv });
  writeUnlockBlob(blob, opts.base ?? abraDir());
  return blob;
}

/** Strict base64 → 32-byte wrap key (for hub vault storage). */
export function decodeWrapKey(b64: string): Buffer {
  return decodeRawKey(b64);
}

export function encodeWrapKey(wrapKey: Buffer): string {
  if (!Buffer.isBuffer(wrapKey) || wrapKey.length !== WRAP_KEY_BYTES) {
    throw new Error("wrap key must be 32 bytes");
  }
  return wrapKey.toString("base64");
}
