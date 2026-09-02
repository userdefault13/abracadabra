import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";

/**
 * A passphrase-encrypted, portable backup of the vault.
 *
 * The local vault is only decryptable with the machine's Keychain master key,
 * so a portable bundle must carry both the encrypted vault file AND the master
 * key — wrapped together under a user-chosen passphrase (scrypt → AES-256-GCM).
 */
export interface VaultEnvelope {
  iv: string;
  tag: string;
  data: string;
}

export interface BundleMeta {
  createdAt: number;
  hostname: string;
}

interface KdfParams {
  algo: "scrypt";
  salt: string;
  N: number;
  r: number;
  p: number;
  keyLen: number;
}

export interface BackupBundle {
  format: "abracadabra-backup";
  version: 1;
  /** unauthenticated copy for `usb list` previews; the real one lives in the payload */
  meta: BundleMeta;
  kdf: KdfParams;
  iv: string;
  tag: string;
  data: string;
}

export interface BundlePayload {
  vaultEnc: VaultEnvelope;
  masterKey: string;
  meta: BundleMeta;
}

export const BACKUP_MAGIC = "abracadabra-backup";

function deriveKey(passphrase: string, kdf: KdfParams): Buffer {
  if (kdf.algo !== "scrypt") throw new Error(`Unsupported KDF: ${kdf.algo}`);
  return crypto.scryptSync(passphrase.normalize("NFKC"), Buffer.from(kdf.salt, "base64"), kdf.keyLen, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: 128 * kdf.N * kdf.r * 2,
  });
}

export function sealBundle(
  vaultEnc: VaultEnvelope,
  masterKey: Buffer,
  passphrase: string,
  opts?: { kdf?: Partial<Pick<KdfParams, "N" | "r" | "p" | "keyLen">> },
): BackupBundle {
  const kdf: KdfParams = {
    algo: "scrypt",
    salt: crypto.randomBytes(16).toString("base64"),
    N: opts?.kdf?.N ?? 16384,
    r: opts?.kdf?.r ?? 8,
    p: opts?.kdf?.p ?? 1,
    keyLen: opts?.kdf?.keyLen ?? 32,
  };
  const payload: BundlePayload = {
    vaultEnc,
    masterKey: masterKey.toString("base64"),
    meta: { createdAt: Date.now(), hostname: os.hostname() },
  };
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveKey(passphrase, kdf), iv);
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: BACKUP_MAGIC,
    version: 1,
    meta: payload.meta,
    kdf,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: ciphertext.toString("base64"),
  };
}

export function openBundle(
  bundle: BackupBundle,
  passphrase: string,
): BundlePayload {
  if (bundle.format !== BACKUP_MAGIC) throw new Error("Unrecognized backup file");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    deriveKey(passphrase, bundle.kdf),
    Buffer.from(bundle.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(bundle.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(bundle.data, "base64")),
    decipher.final(), // throws on wrong passphrase (GCM tag mismatch)
  ]);
  return JSON.parse(plaintext.toString("utf8")) as BundlePayload;
}

/** Read + structurally validate a .abrabak file from disk. */
export function readBundleFile(filePath: string): BackupBundle {
  const raw = JSON.parse(fs.readFileSync(filePath, "utf8")) as BackupBundle;
  if (raw.format !== BACKUP_MAGIC) throw new Error(`Not a backup bundle: ${filePath}`);
  return raw;
}
