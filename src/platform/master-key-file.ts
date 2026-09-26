import crypto from "node:crypto";
import fs from "node:fs";
import { masterKeyFile, ensureDir } from "../core/paths.js";

export const MASTER_KEY_FORMAT = "abracadabra-master-key";

/** Minimum vault passphrase length (Unicode code points after NFKC). */
export const VAULT_PASSPHRASE_MIN = 12;

export const V2_SCRYPT_N = 131072; // 2^17
export const V2_SCRYPT_R = 8;
export const V2_SCRYPT_P = 1;
export const V2_KEY_LEN = 32;
export const V2_SALT_BYTES = 16;

/** Explicit floor so N=2^17,r=8 (128 MiB working set) fits with headroom. */
const SCRYPT_MAXMEM_FLOOR = 256 * 1024 * 1024;

const V1_N = 16384;
const V1_R = 8;
const V1_P = 1;

/** Overridable defaults so unit tests can use a low N (suite stays fast). */
let testKdfDefaults: { N?: number; r?: number; p?: number } | null = null;

/** Test hook — pass null to restore production v2 defaults (N=2^17). */
export function setDefaultKdfForTests(
  defaults: { N?: number; r?: number; p?: number } | null,
): void {
  testKdfDefaults = defaults;
}

export interface MasterKeyKdf {
  algo: "scrypt";
  salt: string;
  N: number;
  r: number;
  p: number;
  keyLen: number;
}

export interface MasterKeyFileV1 {
  format: typeof MASTER_KEY_FORMAT;
  version: 1;
  kdf: MasterKeyKdf;
  iv: string;
  tag: string;
  data: string;
}

export interface MasterKeyFileV2 {
  format: typeof MASTER_KEY_FORMAT;
  version: 2;
  kdf: MasterKeyKdf;
  iv: string;
  tag: string;
  data: string;
}

export type MasterKeyFile = MasterKeyFileV1 | MasterKeyFileV2;

export type SealOptions = {
  /** Override KDF fields (tests use low N). */
  kdf?: Partial<Omit<MasterKeyKdf, "algo" | "salt">> & { salt?: Buffer };
  /** Force version; default 2. */
  version?: 1 | 2;
};

/** Unicode code-point length after NFKC (vault passphrase policy). */
export function passphraseCodePointLength(passphrase: string): number {
  return [...passphrase.normalize("NFKC")].length;
}

export function assertVaultPassphraseMin(passphrase: string): void {
  const n = passphraseCodePointLength(passphrase);
  if (n < VAULT_PASSPHRASE_MIN) {
    throw new Error(
      `Vault passphrase must be at least ${VAULT_PASSPHRASE_MIN} characters (got ${n})`,
    );
  }
}

function isPowerOfTwo(n: number): boolean {
  return Number.isInteger(n) && n > 0 && (n & (n - 1)) === 0;
}

/**
 * Reject absurd scrypt params before allocating (DoS on read).
 * N: power of two in [2^14, 2^20]; r: 1..32; p: 1..16; keyLen: 32; salt ≥ 16 bytes.
 */
export function validateKdfParams(kdf: MasterKeyKdf): void {
  if (kdf.algo !== "scrypt") throw new Error("Unsupported KDF algorithm");
  if (!Number.isInteger(kdf.N) || !isPowerOfTwo(kdf.N) || kdf.N < 2 ** 14 || kdf.N > 2 ** 20) {
    throw new Error("Invalid scrypt N (need power of two in 2^14..2^20)");
  }
  if (!Number.isInteger(kdf.r) || kdf.r < 1 || kdf.r > 32) {
    throw new Error("Invalid scrypt r (need 1..32)");
  }
  if (!Number.isInteger(kdf.p) || kdf.p < 1 || kdf.p > 16) {
    throw new Error("Invalid scrypt p (need 1..16)");
  }
  if (kdf.keyLen !== 32) throw new Error("Invalid scrypt keyLen (need 32)");
  const salt = Buffer.from(kdf.salt, "base64");
  if (salt.length < 16) throw new Error("Invalid scrypt salt (need ≥ 16 bytes)");
}

function scryptMaxmem(kdf: MasterKeyKdf): number {
  // Node's scrypt needs roughly 128*N*r; floor at 256 MiB for v2 defaults.
  return Math.max(SCRYPT_MAXMEM_FLOOR, 128 * kdf.N * kdf.r);
}

function deriveKey(passphrase: string, kdf: MasterKeyKdf): Buffer {
  validateKdfParams(kdf);
  return crypto.scryptSync(passphrase.normalize("NFKC"), Buffer.from(kdf.salt, "base64"), kdf.keyLen, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: scryptMaxmem(kdf),
  });
}

/** Canonical AAD for v2 — binds format, version, and full kdf object (incl. salt). */
export function masterKeyAad(file: Pick<MasterKeyFileV2, "format" | "version" | "kdf">): Buffer {
  const kdf = file.kdf;
  const canonical = JSON.stringify({
    format: file.format,
    version: file.version,
    kdf: {
      algo: kdf.algo,
      N: kdf.N,
      r: kdf.r,
      p: kdf.p,
      keyLen: kdf.keyLen,
      salt: kdf.salt,
    },
  });
  return Buffer.from(canonical, "utf8");
}

function defaultKdfV2(overrides?: SealOptions["kdf"]): MasterKeyKdf {
  const saltBuf = overrides?.salt ?? crypto.randomBytes(V2_SALT_BYTES);
  if (saltBuf.length < V2_SALT_BYTES) throw new Error("Salt must be ≥ 16 bytes");
  return {
    algo: "scrypt",
    salt: saltBuf.toString("base64"),
    N: overrides?.N ?? testKdfDefaults?.N ?? V2_SCRYPT_N,
    r: overrides?.r ?? testKdfDefaults?.r ?? V2_SCRYPT_R,
    p: overrides?.p ?? testKdfDefaults?.p ?? V2_SCRYPT_P,
    keyLen: overrides?.keyLen ?? V2_KEY_LEN,
  };
}

function defaultKdfV1(): MasterKeyKdf {
  return {
    algo: "scrypt",
    salt: crypto.randomBytes(16).toString("base64"),
    N: V1_N,
    r: V1_R,
    p: V1_P,
    keyLen: 32,
  };
}

export function masterKeyFileExists(): boolean {
  return fs.existsSync(masterKeyFile());
}

export function loadMasterKeyFileRaw(): MasterKeyFile {
  const raw = JSON.parse(fs.readFileSync(masterKeyFile(), "utf8")) as MasterKeyFile;
  if (raw.format !== MASTER_KEY_FORMAT) throw new Error("Unrecognized master key file");
  if (raw.version !== 1 && raw.version !== 2) throw new Error("Unsupported master key file version");
  validateKdfParams(raw.kdf);
  return raw;
}

export function sealMasterKeyFile(
  masterKey: Buffer,
  passphrase: string,
  opts?: SealOptions,
): MasterKeyFile {
  if (masterKey.length !== 32) throw new Error("Master key must be 32 bytes");
  const version = opts?.version ?? 2;
  const kdf = version === 1 ? defaultKdfV1() : defaultKdfV2(opts?.kdf);
  validateKdfParams(kdf);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveKey(passphrase, kdf), iv);
  if (version === 2) {
    cipher.setAAD(
      masterKeyAad({ format: MASTER_KEY_FORMAT, version: 2, kdf }),
    );
  }
  const ciphertext = Buffer.concat([cipher.update(masterKey), cipher.final()]);
  const base = {
    format: MASTER_KEY_FORMAT,
    kdf,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: ciphertext.toString("base64"),
  } as const;
  return version === 1
    ? ({ ...base, version: 1 } satisfies MasterKeyFileV1)
    : ({ ...base, version: 2 } satisfies MasterKeyFileV2);
}

export function openMasterKeyFile(file: MasterKeyFile, passphrase: string): Buffer {
  if (file.format !== MASTER_KEY_FORMAT) throw new Error("Unrecognized master key file");
  if (file.version !== 1 && file.version !== 2) throw new Error("Unsupported master key file version");
  validateKdfParams(file.kdf);
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    deriveKey(passphrase, file.kdf),
    Buffer.from(file.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(file.tag, "base64"));
  if (file.version === 2) {
    decipher.setAAD(masterKeyAad(file));
  }
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(file.data, "base64")),
      decipher.final(),
    ]);
  } catch {
    throw new WrongPassphraseError();
  }
  if (plaintext.length !== 32) throw new Error("Invalid master key length");
  return plaintext;
}

/** GCM auth failure / wrong passphrase — used to drive unlock backoff. */
export class WrongPassphraseError extends Error {
  constructor() {
    super("Wrong passphrase");
    this.name = "WrongPassphraseError";
  }
}

export function writeMasterKeyFile(
  masterKey: Buffer,
  passphrase: string,
  opts?: SealOptions,
): void {
  ensureDir();
  const enc = sealMasterKeyFile(masterKey, passphrase, opts);
  atomicWriteMasterKeyJson(enc);
}

function atomicWriteMasterKeyJson(enc: MasterKeyFile): void {
  ensureDir();
  const file = masterKeyFile();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(enc, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/**
 * Open the on-disk master key. On successful v1 unlock with a passphrase that
 * meets the 12-char minimum, re-wrap atomically to v2. Shorter passphrases stay
 * on v1 with a one-line stderr warning (never block unlock).
 */
export function readMasterKeyFile(passphrase: string): Buffer {
  const raw = loadMasterKeyFileRaw();
  const key = openMasterKeyFile(raw, passphrase);
  if (raw.version === 1) {
    if (passphraseCodePointLength(passphrase) >= VAULT_PASSPHRASE_MIN) {
      writeMasterKeyFile(key, passphrase, { version: 2 });
    } else {
      process.stderr.write(
        "abracadabra: vault passphrase is shorter than 12 characters — change it to upgrade to the stronger v2 wrap\n",
      );
    }
  }
  return key;
}
