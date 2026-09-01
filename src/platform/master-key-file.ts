import crypto from "node:crypto";
import fs from "node:fs";
import { masterKeyFile, ensureDir } from "../core/paths.js";

export const MASTER_KEY_FORMAT = "abracadabra-master-key";

export interface MasterKeyKdf {
  algo: "scrypt";
  salt: string;
  N: number;
  r: number;
  p: number;
  keyLen: number;
}

export interface MasterKeyFile {
  format: typeof MASTER_KEY_FORMAT;
  version: 1;
  kdf: MasterKeyKdf;
  iv: string;
  tag: string;
  data: string;
}

function deriveKey(passphrase: string, kdf: MasterKeyKdf): Buffer {
  return crypto.scryptSync(passphrase.normalize("NFKC"), Buffer.from(kdf.salt, "base64"), kdf.keyLen, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: 128 * kdf.N * kdf.r * 2,
  });
}

function defaultKdf(): MasterKeyKdf {
  return {
    algo: "scrypt",
    salt: crypto.randomBytes(16).toString("base64"),
    N: 16384,
    r: 8,
    p: 1,
    keyLen: 32,
  };
}

export function masterKeyFileExists(): boolean {
  return fs.existsSync(masterKeyFile());
}

export function sealMasterKeyFile(masterKey: Buffer, passphrase: string): MasterKeyFile {
  const kdf = defaultKdf();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveKey(passphrase, kdf), iv);
  const ciphertext = Buffer.concat([cipher.update(masterKey), cipher.final()]);
  return {
    format: MASTER_KEY_FORMAT,
    version: 1,
    kdf,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: ciphertext.toString("base64"),
  };
}

export function openMasterKeyFile(file: MasterKeyFile, passphrase: string): Buffer {
  if (file.format !== MASTER_KEY_FORMAT) throw new Error("Unrecognized master key file");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    deriveKey(passphrase, file.kdf),
    Buffer.from(file.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(file.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(file.data, "base64")),
    decipher.final(),
  ]);
  if (plaintext.length !== 32) throw new Error("Invalid master key length");
  return plaintext;
}

export function writeMasterKeyFile(masterKey: Buffer, passphrase: string): void {
  ensureDir();
  const enc = sealMasterKeyFile(masterKey, passphrase);
  const file = masterKeyFile();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(enc, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function readMasterKeyFile(passphrase: string): Buffer {
  const raw = JSON.parse(fs.readFileSync(masterKeyFile(), "utf8")) as MasterKeyFile;
  return openMasterKeyFile(raw, passphrase);
}
