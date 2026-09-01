import fs from "node:fs";
import crypto from "node:crypto";
import { vaultFile, ensureDir } from "./paths.js";
import { getKeystore } from "../platform/index.js";

export interface VarEntry {
  value: string;
  secret: boolean;
  updatedAt: number;
}

export interface Project {
  createdAt: number;
  vars: Record<string, VarEntry>;
}

export interface Connection {
  provider: string;
  label?: string;
  createdAt: number;
  /** Non-secret metadata (key name, org id, scopes…). */
  meta: Record<string, string>;
  /** Credentials, stored like vars (secret flag respected). */
  vars: Record<string, VarEntry>;
}

/** A registered WebAuthn passkey for unlocking the web dash. */
export interface PasskeyCredential {
  /** base64url credential ID */
  id: string;
  /** COSE public key, base64 */
  publicKey: string;
  counter: number;
  /** rpID the credential was registered under (e.g. "localhost") */
  rpId: string;
  label?: string;
  createdAt: number;
}

/**
 * A bearer token for the local HTTP API (POST /secret). Requests carrying a
 * valid key skip the per-use Touch ID prompt — meant for AI agents and
 * long-running scripts. Only a hash is stored; the full key is shown once.
 */
export interface ApiKey {
  id: string; // short hex id, part of the full key
  name: string; // human label, e.g. "opencode-agent"
  keyHash: string; // sha256 hex of the full secret
  prefix: string; // display-safe prefix of the full key
  /** projects this key may read; null = all projects */
  projects: string[] | null;
  createdAt: number;
  expiresAt?: number;
}

export interface Vault {
  version: 1;
  projects: Record<string, Project>;
  connections?: Record<string, Connection>;
  passkeys?: PasskeyCredential[];
  apiKeys?: Record<string, ApiKey>;
}

export interface EncryptedFile {
  format: "abracadabra-vault";
  version: 1;
  iv: string;
  tag: string;
  data: string;
}export function emptyVault(): Vault {
  return { version: 1, projects: {}, connections: {} };
}

export function assertConnection(vault: Vault, provider: string): Connection {
  const conn = vault.connections?.[provider];
  if (!conn) throw new Error(`No connection for "${provider}". Run: abra connect ${provider}`);
  return conn;
}

function encrypt(vault: Vault, key: Buffer): EncryptedFile {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(vault), "utf8");
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: "abracadabra-vault",
    version: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
}

function decrypt(file: unknown, key: Buffer): Vault {
  const f = file as EncryptedFile;
  if (f.format !== "abracadabra-vault") throw new Error("Unrecognized vault file");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(f.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(f.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(f.data, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf8")) as Vault;
}

export async function loadVault(): Promise<Vault> {
  const key = await getKeystore().getOrCreateMasterKey();
  if (!fs.existsSync(vaultFile())) return emptyVault();
  const raw = JSON.parse(fs.readFileSync(vaultFile(), "utf8"));
  const vault = decrypt(raw, key);
  vault.connections ??= {};
  vault.apiKeys ??= {};
  return vault;
}

export async function saveVault(vault: Vault): Promise<void> {
  ensureDir();
  const key = await getKeystore().getOrCreateMasterKey();
  const enc = encrypt(vault, key);
  const file = vaultFile();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(enc, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function assertProject(vault: Vault, name: string): Project {
  const project = vault.projects[name];
  if (!project) throw new Error(`Project not found: ${name}`);
  return project;
}

/** Encrypt a vault into the portable envelope shape (usb backup). */
export function encryptVault(vault: Vault, key: Buffer): EncryptedFile {
  return encrypt(vault, key);
}

/** Decrypt an envelope that came from outside this machine (usb restore/sync). */
export function decryptEnvelope(
  env: { iv: string; tag: string; data: string },
  key: Buffer,
): Vault {
  return decrypt({ format: "abracadabra-vault", version: 1, ...env }, key);
}

/** Atomically persist an envelope to VAULT_FILE (usb restore). */
export function writeEncryptedFile(enc: {
  iv: string;
  tag: string;
  data: string;
}): void {
  ensureDir();
  const file = vaultFile();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(enc, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}
