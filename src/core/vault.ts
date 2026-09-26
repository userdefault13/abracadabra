import fs from "node:fs";
import crypto from "node:crypto";
import { vaultFile, ensureDir } from "./paths.js";
import { getKeystore } from "../platform/index.js";
import { resolveMasterKey } from "./masterKey.js";
import {
  isAgentUnavailable,
  loadVaultViaAgent,
  saveVaultViaAgent,
  shouldTryAgent,
} from "../agent/client.js";

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
}

export function emptyVault(): Vault {
  return { version: 1, projects: {}, connections: {} };
}

export function assertConnection(vault: Vault, provider: string): Connection {
  const conn = vault.connections?.[provider];
  if (!conn) throw new Error(`No connection for "${provider}". Run: abra connect ${provider}`);
  return conn;
}

/** Shared AES-256-GCM encrypt — used by vault I/O and the abra agent. */
export function encryptVault(vault: Vault, key: Buffer): EncryptedFile {
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

/** Shared AES-256-GCM decrypt of a vault.enc envelope. */
export function decryptVault(file: unknown, key: Buffer): Vault {
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

/** Atomically persist an EncryptedFile to vault.enc (mode 0600). */
export function writeEncryptedVaultFile(
  enc: EncryptedFile,
  file = vaultFile(),
): void {
  ensureDir();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(enc, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

async function loadVaultDirect(): Promise<Vault> {
  const key = await resolveMasterKey(getKeystore());
  if (!fs.existsSync(vaultFile())) return emptyVault();
  const raw = JSON.parse(fs.readFileSync(vaultFile(), "utf8"));
  const vault = decryptVault(raw, key);
  vault.connections ??= {};
  vault.apiKeys ??= {};
  return vault;
}

async function saveVaultDirect(vault: Vault): Promise<void> {
  const key = await resolveMasterKey(getKeystore());
  const enc = encryptVault(vault, key);
  writeEncryptedVaultFile(enc);
}

export async function loadVault(): Promise<Vault> {
  if (shouldTryAgent()) {
    try {
      return await loadVaultViaAgent();
    } catch (e) {
      if (!isAgentUnavailable(e)) throw e;
      // no socket / no answer / connect timeout → direct keystore path
    }
  }
  return loadVaultDirect();
}

export async function saveVault(vault: Vault): Promise<void> {
  if (shouldTryAgent()) {
    try {
      await saveVaultViaAgent(vault);
      return;
    } catch (e) {
      if (!isAgentUnavailable(e)) throw e;
    }
  }
  await saveVaultDirect(vault);
}

export function assertProject(vault: Vault, name: string): Project {
  const project = vault.projects[name];
  if (!project) throw new Error(`Project not found: ${name}`);
  return project;
}

/** Reserved vault project for the user-funded abra treasury wallet (not founder). */
export const TREASURY_PROJECT = "__abra_treasury__";

/** Projects starting with this prefix are system-managed — not for `abra project new`. */
export const RESERVED_PROJECT_PREFIX = "__abra_";

export function isReservedProjectName(name: string): boolean {
  return name.startsWith(RESERVED_PROJECT_PREFIX);
}

/** Decrypt an envelope that came from outside this machine (usb restore/sync). */
export function decryptEnvelope(
  env: { iv: string; tag: string; data: string },
  key: Buffer,
): Vault {
  return decryptVault({ format: "abracadabra-vault", version: 1, ...env }, key);
}

/** Atomically persist an envelope to VAULT_FILE (usb restore). */
export function writeEncryptedFile(enc: {
  iv: string;
  tag: string;
  data: string;
}): void {
  writeEncryptedVaultFile({
    format: "abracadabra-vault",
    version: 1,
    iv: enc.iv,
    tag: enc.tag,
    data: enc.data,
  });
}
