import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import type { Project } from "./vault.js";

/**
 * A passphrase-encrypted, portable backup of the vault.
 *
 * The local vault is only decryptable with the machine's Keychain master key,
 * so a portable bundle must carry both the encrypted vault file AND the master
 * key — wrapped together under a user-chosen passphrase (scrypt → AES-256-GCM).
 *
 * Scoped bundles carry only named projects (no master key) and are merge-only.
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
  /**
   * Unauthenticated hint for previews (`usb list`). The authenticated inner
   * `kind` from the decrypted payload is what code trusts.
   */
  kind?: "scoped-projects";
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

export interface ScopedBundlePayload {
  kind: "scoped-projects";
  version: 1;
  scope: string[];
  projects: Record<string, Project>;
  meta: BundleMeta;
}

export const BACKUP_MAGIC = "abracadabra-backup";

export class ScopedBundleError extends Error {
  constructor(
    message = "scoped bundle — it can only be merged, not restored/synced as a full vault",
  ) {
    super(message);
    this.name = "ScopedBundleError";
  }
}

function deriveKey(passphrase: string, kdf: KdfParams): Buffer {
  if (kdf.algo !== "scrypt") throw new Error(`Unsupported KDF: ${kdf.algo}`);
  return crypto.scryptSync(passphrase.normalize("NFKC"), Buffer.from(kdf.salt, "base64"), kdf.keyLen, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: 128 * kdf.N * kdf.r * 2,
  });
}

function sealPayload(
  payload: BundlePayload | ScopedBundlePayload,
  passphrase: string,
  opts?: { kdf?: Partial<Pick<KdfParams, "N" | "r" | "p" | "keyLen">>; kind?: "scoped-projects" },
): BackupBundle {
  const kdf: KdfParams = {
    algo: "scrypt",
    salt: crypto.randomBytes(16).toString("base64"),
    N: opts?.kdf?.N ?? 16384,
    r: opts?.kdf?.r ?? 8,
    p: opts?.kdf?.p ?? 1,
    keyLen: opts?.kdf?.keyLen ?? 32,
  };
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveKey(passphrase, kdf), iv);
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const bundle: BackupBundle = {
    format: BACKUP_MAGIC,
    version: 1,
    meta: payload.meta,
    kdf,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: ciphertext.toString("base64"),
  };
  if (opts?.kind) bundle.kind = opts.kind;
  return bundle;
}

function decryptPayload(bundle: BackupBundle, passphrase: string): unknown {
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
  return JSON.parse(plaintext.toString("utf8"));
}

function isScopedPayload(payload: unknown): payload is ScopedBundlePayload {
  return (
    typeof payload === "object" &&
    payload !== null &&
    (payload as ScopedBundlePayload).kind === "scoped-projects"
  );
}

export function sealBundle(
  vaultEnc: VaultEnvelope,
  masterKey: Buffer,
  passphrase: string,
  opts?: { kdf?: Partial<Pick<KdfParams, "N" | "r" | "p" | "keyLen">> },
): BackupBundle {
  const payload: BundlePayload = {
    vaultEnc,
    masterKey: masterKey.toString("base64"),
    meta: { createdAt: Date.now(), hostname: os.hostname() },
  };
  return sealPayload(payload, passphrase, opts);
}

/** Seal only the named projects — no master key, no other vault fields. */
export function sealScopedBundle(
  projects: Record<string, Project>,
  scope: string[],
  passphrase: string,
  opts?: { kdf?: Partial<Pick<KdfParams, "N" | "r" | "p" | "keyLen">> },
): BackupBundle {
  const payload: ScopedBundlePayload = {
    kind: "scoped-projects",
    version: 1,
    scope: [...scope],
    projects,
    meta: { createdAt: Date.now(), hostname: os.hostname() },
  };
  return sealPayload(payload, passphrase, { ...opts, kind: "scoped-projects" });
}

/**
 * Open a full vault bundle. Throws ScopedBundleError if the decrypted payload
 * is scoped (so legacy restore/sync paths never treat it as a full vault).
 */
export function openBundle(bundle: BackupBundle, passphrase: string): BundlePayload {
  const payload = decryptPayload(bundle, passphrase);
  if (isScopedPayload(payload)) {
    throw new ScopedBundleError();
  }
  return payload as BundlePayload;
}

/** Open either a full or scoped bundle; callers must branch on `kind`. */
export function openAnyBundle(
  bundle: BackupBundle,
  passphrase: string,
):
  | { kind: "full"; payload: BundlePayload }
  | { kind: "scoped"; payload: ScopedBundlePayload } {
  const payload = decryptPayload(bundle, passphrase);
  if (isScopedPayload(payload)) {
    return { kind: "scoped", payload };
  }
  return { kind: "full", payload: payload as BundlePayload };
}

/** Read + structurally validate a .abrabak file from disk. */
export function readBundleFile(filePath: string): BackupBundle {
  const raw = JSON.parse(fs.readFileSync(filePath, "utf8")) as BackupBundle;
  if (raw.format !== BACKUP_MAGIC) throw new Error(`Not a backup bundle: ${filePath}`);
  return raw;
}
